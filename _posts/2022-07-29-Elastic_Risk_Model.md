---
title: Building a Risk Model in Elastic
date: 2022-07-29 20:39 +0200
categories: [elastic]
tags: [elastic, howto]
---

Lately I have been thinking about how to do a risk scoring model in Elasticsearch.
Yes I am aware that there are risk models
for [users](https://www.elastic.co/guide/en/security/current/user-risk-score.html) and
for [hosts](https://www.elastic.co/guide/en/security/current/host-risk-score.html)
But these are heavily dependent on machine learning, and since I have no ML license, I thought it may be interesting to
build something without ML.
QRadar does this in a very similar fashion.

## The Process

I built the whole thing on top of the existing logic, every alert has a risk score of 0-100.
Additionally, I implemented building blocks that I will call "risk blocks" for additional scoring without affecting the
normal alerting engine, no need to generate alerts for simple things like brute force attacks against someone.
The risk of these alerts and risk blocks together, grouped by user.name will make up the risk score.
This will result in a score of 0 to infinity for every user.
The score is multiplied by 2, if the user is an admin, this is to get a better visibility of admins.
Not perfect, but it's a start and has zero ML

Every hour the existing user risk will be deprecated by 25% (subject to change).
When the risk hits 10, it will be set to 0

Every 10 minutes an alert rule called "User Risk Score High" will check if any user has a score over a threshold of X.
This rule of course is excluded from adding risk to a user, wouldn't be fair otherwise ;)

{% include mermaid_start.liquid %}
graph LR;
RB[Risk Block] -..->|Set Risk| ER[Event Risk 0-100];
AR[Alert Rule] -.->|Set Risk| ER;
RC --> |Every 5 minutes get risk| ER;
RC -->|Every 5 minutesIncrement by risk| EN["Entitiy Risk"];
EN -->|if Admin multiply by 2| EN;
RD -->|Every hour Decrease risk by 25%| EN;
subgraph Alerting Engine;
alert[User Risk Score High];
RB;
AR;
end;
alert --->|Alert if over threshold| EN;
subgraph Script;
RC[Risk Builder];
RD[Risk Decrementer];
end;
{% include mermaid_end.liquid %}

## The script(s)

There are two scripts, one which runs every 5 minutes to calculate risk and build a history, and another that runs
hourly, to deprecate the risk.

### Indexes

First thing to do, is build the indexes.

| Index                       | Fields                                                         | Usage                                                      |
|-----------------------------|----------------------------------------------------------------|------------------------------------------------------------|
| security.risk_score         | @timestamp<br/>user.name<br/>user.risk_score<br/>event.dataset | Tracking active user risk score                            |
| security.risk_score_history | @timestamp<br/>user.name<br/>user.risk_score<br/>event.dataset | Tracking historical user risk score                        |
| security.store              | @timestamp<br/>alert_uuid<br/>event.dataset                    | Tracking which alerts where already used to calculate risk |

{: file='./build_indexes.py'}

````python
from elasticsearch import Elasticsearch


def remove_risk():
  try:
    es.indices.delete(index="security.risk_score", ignore=[400, 404])
  except:
    print("Unable to remove old index")

  index_mapping = {
    "properties": {
      "@timestamp": {"type": "date"},
      "user": {
        "properties": {
          "name": {"type": "keyword"},
          "risk_score": {"type": "long"},
        }
      },
      "event": {
        "properties": {"dataset": {"type": "keyword", "ignore_above": 1024}}
      },
    }
  }
  es.indices.create(index="security.risk_score", mappings=index_mapping)


def remove_risk_history():
  try:
    es.indices.delete(index="security.risk_score_history", ignore=[400, 404])
  except:
    print("Unable to remove old index")

  index_mapping = {
    "properties": {
      "@timestamp": {"type": "date"},
      "user": {
        "properties": {
          "name": {"type": "keyword"},
          "risk_score": {"type": "long"},
        }
      },
      "event": {
        "properties": {"dataset": {"type": "keyword", "ignore_above": 1024}}
      },
    }
  }
  es.indices.create(index="security.risk_score_history", mappings=index_mapping)


def remove_store():
  try:
    es.indices.delete(index="security.store", ignore=[400, 404])
  except:
    print("Unable to remove old index")

  index_mapping = {
    "properties": {
      "@timestamp": {"type": "date"},
      "alert_uuid": {"type": "keyword"},
      "event": {
        "properties": {"dataset": {"type": "keyword", "ignore_above": 1024}}
      },
    }
  }
  es.indices.create(index="security.store", mappings=index_mapping)


es = Elasticsearch("https://localhost:9200",
                   basic_auth=("user",
                               "password"))
remove_risk()
remove_store()
remove_risk_history()
````

### Risk Scoring

Now we need a script to build a bit of logic around the existing alerts, and combine them into risk by user.
Appended is a bare-bones script on how this could be done.

{: file='./risk_scoring.py'}

````python
import datetime
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


def get_current_risk(client):
  """
  This Function is built to get the current risk of the users
  :param client: Elasticsearch DSL Client
  :return: User risk
  """
  s = Search(using=client, index="security.risk_score")
  s = s.filter("exists", field="user")
  response = s.scan()
  users = {}
  for element in response:
    element = element.to_dict()
    users[element["user"]["name"]] = element["user"]["risk_score"]
  return users


def get_stored_uuids(client):
  """
  This function is built to get all stored UUIDs so we don't accidentally use an alert twice to increase risk.
  :param client: Elasticsearch DSL Client
  :return: Stored UUIDs
  """
  s = Search(using=client, index="security.store")
  s = s.filter("exists", field="alert_uuid")
  response = s.scan()
  uuids = []
  for element in response:
    element = element.to_dict()
    uuids.append(element["alert_uuid"])
  return uuids


def calculate_risk(client, users, uuids):
  """
  This function calculates the risk of all users by accumulating the seen alert risk score by user.
  This score is then doubled if the user is in fact an admin
  :param client: Elasticsearch DSL Client
  :param users: dict: All existing users and their risk
  :param uuids: list: All stored uuids of previous alerts
  :return:
  """
  s = Search(using=client, index=".internal.alerts-security.alerts-*")
  s = s.filter("exists", field="user.name")
  s = s.exclude("match", kibana__alert__rule__name="User Risk Score High")
  s = s.filter("range", **{"@timestamp": {"gte": "now-30d"}})
  response = s.scan()
  # users = {}
  alerts = []
  changed_users = []

  for alert in response:
    alert = alert.to_dict()
    if "kibana.alert.uuid" in alert:
      if alert["kibana.alert.uuid"] not in uuids:
        alerts.append(alert["kibana.alert.uuid"])
        if "user.name" in alert or "user" in alert:
          if "user.name" in alert:
            user = alert["user.name"]
          elif "user" in alert:
            user = alert["user"]["name"]
          user = (
            user.lower()
          )
          risk = alert["kibana.alert.risk_score"]
          if user in users:
            users[user] += risk
          else:
            users[user] = risk
          if user not in changed_users:
            changed_users.append(user)
  # Cleanup List to avoid chaos
  # Only updated users need to be pushed again
  remove_users = []
  for user in users:
    if user not in changed_users:
      remove_users.append(user)
  for user in remove_users:
    del users[user]
  return users, alerts


def push_risk(es, users):
  """
  This function is used to push the risk of all changed users to elasticsearch
  :param es: Elasticsearch client (not DSL)
  :param users: dict: List of all changed users
  :return: Returns True or False based if data was pushed or not
  """
  date = datetime.datetime.now(datetime.timezone.utc)
  es_array = []
  date = datetime.datetime.now(datetime.timezone.utc)
  for user in users:
    risk_score = users[user]
    if "admin" in user:
      risk_score = risk_score * 2
    es_array.append({"index": {"_index": "security.risk_score", "_id": user}})
    es_array.append(
      {
        "user": {"name": user, "risk_score": risk_score},
        "event.dataset": "user.risk_score",
        "@timestamp": str(date.isoformat()),
      }
    )
  if len(es_array) > 0:
    es.bulk(operations=es_array)


def push_uuids(es, uuids):
  """
  This function stores all uuids used in elasticsearch
  :param es:
  :param uuids:
  :return: nothing
  """
  date = datetime.datetime.now(datetime.timezone.utc)
  es_array = []
  for alert in uuids:
    es_array.append({"index": {"_index": "security.store", "_id": alert}})
    es_array.append({"alert_uuid": alert,
                     "event.dataset": "risk_score.stored",
                     "@timestamp": str(date.isoformat())})
  if len(es_array) > 0:
    es.bulk(operations=es_array)


def risk_history(client, es):
  """
  This function duplicates the current risk of a user to a secondary table for history
  :param client: Elasticsearch DSL Client
  :param es: Elasticsearch client (not DSL)
  :return: nothing
  """
  s = Search(using=client, index="security.risk_score")
  s = s.filter("exists", field="user.name")
  response = s.scan()

  es_array = []
  for user in response:
    date = datetime.datetime.now(datetime.timezone.utc)
    user = user.to_dict()
    es_array.append({"index": {"_index": "security.risk_score_history"}})
    es_array.append(
      {
        "user": {
          "name": user["user"]["name"],
          "risk_score": user["user"]["risk_score"],
        },
        "event.dataset": "user.risk_score_history",
        "@timestamp": str(date.isoformat()),
      }
    )
  es.bulk(operations=es_array)


def main():
  client = Elasticsearch("https://localhost:9200",
                         basic_auth=("user",
                                     "password"))
  es = Elasticsearch("https://localhost:9200",
                     basic_auth=("user",
                                 "password"))
  users = get_current_risk(client)
  uuids = get_stored_uuids(client)
  users, uuids = calculate_risk(client, users, uuids)
  if len(users) > 0:
    push_risk(es, users)
  push_uuids(es, uuids)
  risk_history(client, es)


if __name__ == '__main__':
  main()
````

###

At last, we need a little script to deprecate the risk over time.
In this example I let the risk deprecate by 25% everytime it is run, and I run it once an hour

{: file='./risk_deprecation.py'}

````python
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


def deprecate_risk(client, es):
  s = Search(using=client, index="security.risk_score")
  s = s.filter("exists", field="user")
  response = s.scan()

  es_array = []
  for user in response:
    user = user.to_dict()
    username = user["user"]["name"]
    timestamp = user["@timestamp"]
    risk_score = user["user"]["risk_score"] * 0.75
    if risk_score < 10:
      risk_score = 0
    es_array.append({"index": {"_index": "security.risk_score", "_id": username}})
    es_array.append(
      {
        "user": {"name": username, "risk_score": risk_score},
        "event.dataset": "user.risk_score",
        "@timestamp": timestamp,
      }
    )
  es.bulk(operations=es_array)


def main():
  client = Elasticsearch("https://localhost:9200",
                         basic_auth=("user",
                                     "password"))
  es = Elasticsearch("https://localhost:9200",
                     basic_auth=("user",
                                 "password"))
  deprecate_risk(client, es)


if __name__ == '__main__':
  main()
````



