---
title: Building Elastic Security
date: 2022-06-09 18:40 +0200
categories: [elastic]
tags: [elastic, howto]
---

Recently I have started to rebuild my home security setup.
This included getting my Elastic Security up and running again.
And in this blog entry I want to write a bit about it.
However, since Elastic is such a vast topic, I will assume your stack is already up and running, no tshooting of that
from me ;)

# Architecture

In my personal opinion a modern installation of Elasticstack should looks something like this:
{% include mermaid_start.liquid %}
graph TD;
Logfile --> Filebeat;
Syslog --> Filebeat;
Filebeat --> agent[Elastic Agent];
Winlog[Windows Logs] --> Winlogbeat --> agent;
ND[Network Data] --> Packetbeat --> agent;
Metricbeat --> agent;
EDR[Endpoint Security] --> agent;
agent--> fleet[Fleet Server];
fleet --> Logstash;
Logstash --> pipeline[Ingest pipelines];
pipeline --> Elasticsearch;
Kibana -->|Consume| Elasticsearch;
enrichmentLS[Enrichments:<br>DNS<br>DB Lookups<br>Aggregations<br>etc.] -.-> Logstash;
enrichmentES[Enrichments:<br>Correlations<br>Geolookup<br>Inference<br>Network Direction<br>etc.] -.-> pipeline;
{% include mermaid_end.liquid %}

Of course in a more professional setup it would be intelligent to add load balancing and message queues.
Feel free to pepper in some kafka, RabbitMQ, Kemp, F5 etc. but for my home lab that is definitely not needed.

## Endpoint Security

This is more or less the EDR component of the elastic stack and more or less on feature parity to Endgame.
It is used to gather additional telemetry but can also block malicious behaviour.

## Beats

If possible, always use beats wherever you can.
The most common beat of course is filebeat since it is used to process logfiles, cloud logs as well as syslog streams.

Often Metricbeat and Packetbeat are added to the mix to enrich data. In my opinion Packetbeat is particularly useful
for endpoint security.

## Elastic Agent

The elastic agent is used to configure the endpoints with the correct beats, gather the data from the different beats
and elastic endpoint agent and then ship it either directly to logstash or via a Fleet Server to elasticsearch.

## Fleet Server

A fleet server can accept data from one or more elastic agents and ship it into Elasticsearch.
This is very useful if you don't want to bother with logstash.

## Logstash

Logstash is used to extract and enrich data it recieves, preferably via an elastic agent.
This data is then sent to elasticsearch for indexing.
Some enrichments like DNS Lookups or Elastic DB Lookups are only available in Logstash, and cannot so far be replicated
by Ingest pipelines.
For me this is the only reason to still use logstash.

## Ingest pipelines

The ingest pipelines are used for log extraction directly in elasticsearch.
It is much easier to used compared with logstash and has some unique features which are not available in Logstash, for
example inference (Machine Learning).
I personally try and use more ingest pipelines and less logstash if possible

## Elasticsearch

This the Database :)

## Kibana

The frontend UI for the whole stack, and also the place we will be in the most time.
