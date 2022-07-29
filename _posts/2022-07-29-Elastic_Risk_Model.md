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
But these are heavily dependent on machine learning, and sind I have no ML license, I thought it may be interesting to
build something without ML

## The Process

I buildt the whole thing on top of the existing logic, every alert has a risk score of 0-100.
Additionally, I implemented building blocks that I called "risk blocks" for additional scoring without affecting alerts.
The risk of these alerts and risk blocks together, aggregated by user.name will make up the risk score.
This will make a scoring of 0 to infinity for every user.
The score is multiplied by 2, if the user is an admin, this is to get a better visibility of admins.
Not perfect, but other products do it like that too ;)

Every hour the existing user risk will be deprecated by 25% (subject to change).
When the risk hits 10, it will be set to 0

{% include mermaid_start.liquid %}
sequenceDiagram;
Risk Block->>Event Risk (0-100): Set Risk;
Alert Rule->>Event Risk (0-100): Set Risk;
loop Every 5 minutes;
Risk Builder->>Event Risk (0-100): Get Risk;
Risk Builder->>Entity Risk: Increment by Risk;
Entity Risk->>Entity Risk: If admin multiply risk by 2;
end;
loop Every 60 minutes;
Risk Builder->>Entity Risk: Decrease by 0.75*Entity Risk;
end;
{% include mermaid_end.liquid %}

## The script

There are two scripts, one which runs every 5 minutes to calculate risk and build a history, and another that runs
hourly, to deprecate the risk.

````python
import datetime
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


def get_current_risk(client):
  s = Search(using=client, index="security.risk_score")
  s = s.filter("exists", field="user")
  response = s.scan()
  users = {}
  for element in response:
    element = element.to_dict()
    users[element["user"]["name"]] = element["user"]["risk_score"]
  return users


def get_stored_uuids(client):
  s = Search(using=client, index="security.store")
  s = s.filter("exists", field="alert_uuid")
  response = s.scan()
  uuids = []
  for element in response:
    element = element.to_dict()
    uuids.append(element["alert_uuid"])
  return uuids


def calculate_risk(client, users, uuids):
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

{: file='./risk_scoring.py'}

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

{: file='./risk_deprecation.py'}

````python
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


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
      "host": {
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
      "host": {
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

{: file='./build_indexes.py'}
