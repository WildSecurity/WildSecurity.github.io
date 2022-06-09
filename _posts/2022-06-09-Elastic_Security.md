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

In my personal opinion a modern installation of Elasticstack should look something like this:
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

# Getting Data

Now that we know a bit about what our setup looks like, let's get into configuring the security parts, and some other
additional things if necessary.
But as stated before, I have no intention of writing elastic stack basics.

## Fleet

### Settings

First we need data and for that, I utilise elastic fleet you can get there via the main menu -> Management -> Fleet
Step one go to settings, and setup an output (most likely an elasticsearch node, since logstash is in beta)

### Agent Policy

After that setup your first Agent Policy, for simplicity I also deploy a Fleet Server in the same policy.

Some interesting integrations (for Windows):

* Fleet Server
* Endpoint Security
* Prebuilt Security Detection Rules
* System
* Windows

Some interesting integrations (for Linux):

* Fleet Server
* Endpoint Security
* Prebuilt Security Detection Rules
* System
* Auditd

Most integrations are very straight forward to deploy (just add them to the correct policy), except "Endpoint Security",
on Linux make sure to add the flag "Include Session Data" {: .prompt-info } This is only possible *after* adding the
integration to the agent policy and then editing it again.

### Agent

Go to Agents and click "Add agent" in the following prompts select the correct policy, select "Quick Start"
(of course, don't do that in production).
Under add fleet server host if you are deploying a fleet server in the policy point to https://127.0.0.1:8220 (default),
otherwise point to wherever your fleet server host is.
After that you can generate a service token and deploy an agent wherever you want.
As soon as the agent is deployed it should pull its configuration and start sending the data you selected.

# Elastic Security

## Default Rules

First let's enable the default rules by going to Security -> Alerts -> Rules and downloading the default policies.
