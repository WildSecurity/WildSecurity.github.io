---
title: Building Home Security
date: 2022-06-09 17:39 +0200
categories: [elastic]
tags: [elastic, howto, thehive, elastalert]
---

Recently I have been revamping my home security setup.
In this Blog I will try and reflect on what all used to build it and how I am planning to improve.

# Architecture

{% include mermaid_start.liquid %}
graph LR;
EDR[Elastic Endpoint Security] --> Fleet[Elastic Fleet];
Foritgate --> Filebeat;
Netflow --> Filebeat;
Filebeat --> Fleet;
Fleet --> SIEM[Elastic Search];
SIEM --> Elastalert;
TI[Threat Intelligence] --> Logstash;
Logstash --> SIEM;
Elastalert -->|Pull| theHive;
theHive --> ST2[Stack Storm];
cortex --> |Enrichment| theHive;
{% include mermaid_end.liquid %}

# Setup

## Elastic Stack

For my whole Elastic Stack I used the awesome Project of [deviantony](https://github.com/deviantony/docker-elk/tree/tls)
Basically just follow the documentation over there, it's very detailed.
Detailed setup of the security part itself will follow in another blog

## theHive

For theHive I used the official image from
theHive's [github](https://github.com/TheHive-Project/Docker-Templates/tree/main/docker/thehive4-berkleydb-cortex31)
Setup is very easy, the basic steps are logging in with default credendials (resetting them) establishing a new org and
at least one user for that org.

## Elastalert

For the integration between Elasticsearch and theHive I used Elastalert2,
this is subject to change however in case I get annoyed enough.
My setup of Elastalert2 (not to be confused with the original elastalert) is a very simple docker container with config
and rules.

Folder Hierarchy:

````bash
└── root
    ├── docker-compose.yml
    ├── elastalert.yaml
    └── rules
        └── rule.yaml
````

### Docker Compose

The compose file should be more or less selfexplanatory, the volumes are used to get the config into the right places.
And for the image I used the officiall elastalert2 image

````yaml
version: '3.8'
services:
  elastalert2:
    container_name: elastalert
    restart: unless-stopped
    volumes:
      - './elastalert.yaml:/opt/elastalert/config.yaml'
      - './rules:/opt/elastalert/rules'
    image: jertel/elastalert2
````

{: file='./docker-compose.yml'}

### Elastalert Config

The config I kept very simple for now.
Basic parameters which are needed are of course elasticsearch credentials and frequency.

````yaml
rules_folder: /opt/elastalert/rules
run_every:
  seconds: 10
buffer_time:
  minutes: 15
es_host: elastic.host.name
es_port: 443
use_ssl: true
es_username: XXXX
es_password: XXXX
writeback_index: elastalert-status
alert_time_limit:
  days: 2
````

{: file='./elastalert.yaml'}

### Rule Example

The rules are a bit more tricky, I've tried to use aggregation methods to reduce duplicate alerts
(as Elastic doesn't dedub itself).
In this example I aggregate based on the user.name and wait for 10min before triggering the alert.
I would love to have a bit more power here, what if I see another alert in two days of the same user?
That is a question for another day, I might write my own integration for that.
Another big painpoint, the Title of the alert sent cannot be a variable, which is just stupid.
I did notice that there is an ongoing [discussion](https://github.com/jertel/elastalert2/discussions/676) on this
topic...

````yaml
name: "Elasticsearch User"
type: "any"
index: ".siem-signals-default"
is_enabled: true
aggregation:
  minutes: 10
terms_size: 50
query_key: 'user.name'
aggregation_key: 'user.name'
aggregation_by_match_time: true

timestamp_field: "@timestamp"
timestamp_type: "iso"

filter:
  - term:
      signal.status: "open"
  - query:
      wildcard:
        user.name: "*"

alert: hivealerter
hive_connection:
  hive_host: http://thehive
  hive_port: 9000
  hive_apikey: XXXXXXXXXXX
hive_alert_config:
  type: 'external'
  source: 'elastalert'
  severity: 2
  tags: [ signal.rule.name, agent.name, user.name ]
  tlp: 3
  status: 'New'
  follow: True
  description_args: [ rule.name ]
  description: '{0}'
hive_observable_data_mapping:
  - ip: source.ip
  - ip: destination.ip
  - ip: host.ip
  - domain: source.domain
  - domain: destination.domain
  - domain: host.name
  - domain: dns.question.name
  - hash: hash.md5
  - hash: hash.sha1
  - hash: hash.sha256
````

{: file='rules/rule.yaml'}

### Stack Storm

This I've not been able to build to my satisfaction yet.
But the basic premisses are simple get this [project](https://github.com/StackStorm/st2-docker)
and ````docker-compose up -d````
