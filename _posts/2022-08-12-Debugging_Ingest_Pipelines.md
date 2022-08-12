---
title: Debugging Elastic Pipelines
date: 2022-08-12 10:08 +0200
categories: [elastic]
tags: [elastic, howto]
---

Over the past weeks I have been migrating to Elasticsearch 8.x with Fleet Agents.
This brought some more annoying challenges, namely debugging Ingest Pipelines and trying to figure out how this could be
done in a more relaxed way.
So here we go.

## The Ingest Pipelines

First let's get into what Ingest Pipelines are, and how they work.

### What are they?

Dumbed down, they are a way to run an ELK Stack without the L (Logstash) part.

So basically we have log source, which either gets Pulled or Pushed to Filebeat and from there via an Ingest Pipeline to
an Elasticsearch Index.
The Ingest Pipelines are part of Elasticsearch nodes (they need the "ingest" role) and will handle extracting data from
the incoming events.
Basically if you know Logstash and Grok, yes Pipelines also have a Grok Processer etc.
Of course Ingest Pipelines are much more complicated than that, but for now this is enough to get you started.

Here is a very basic design of how this process could look.

{% include mermaid_start.liquid %}
graph LR;
LS[Log Source] --> Filebeat;
Filebeat --> IP[Ingest Pipeline];
subgraph Elasticsearch;
IP --> |Process Data| IP;
IP --> ES[Elasticsearch Index];
end;
{% include mermaid_end.liquid %}

And here one with Fleet integration, we will mostly talk about the fleet version, but it's pretty much the same to
Filebeat without fleet.

{% include mermaid_start.liquid %}
graph LR;
EAS -.-> |Pull Config| ES;
EAS[Fleet Server] -..-> |Push Config| EA;
EA[Elastic Agent] -..-> |Push Config| Filebeat;
LS[Log Source] --->|Send Data| Filebeat;
Filebeat ---> |Send Data| IP[Ingest Pipeline];
subgraph Elasticsearch;
IP --> |Process Data| IP;
IP ---> |Index Data| ES[Elasticsearch Index];
end;
{% include mermaid_end.liquid %}

### Where do they come from?

So now that we know what an Ingest Pipeline is, where the fuck do they come from?
Basically there are 3 ways to get one.

- From Fleet
- From Filebeat
- Manually made

Focus here of course on Fleet, but basically Filebeat can push Ingest Pipeline config to Elasticsearch.
The Fleet uses Integrations, which are either automatically or manually updated.
These Integrations build the Ingest Pipeline and an Index Template
(for Linking the Index to the correct Ingest Pipeline).
I personally would not enable automated updating of Ingest Pipelines, but you do you ;)

### And what if it fails?

Now that, is the actual question I had to answer for myself.
If an Ingest Pipeline fails, it will run through "failure processors".
Usually these Processors look something like this:

```json
[
  {
    "set": {
      "field": "error.message",
      "value": [
        "{{ _ingest.on_failure_message}}"
      ]
    }
  }
]
```

This will set a field called "error.message" to the value of the failed processors dying words.
So yes, we will have an error message in the document.
However, we have zero idea which Ingest Pipeline failed, and even if we knew that, we still don't know which processor
failed.
So to make it simple, the default error handling of Ingest Pipelines is not actually usable.
It will just tell you something fucked up, and now you're sherlock, go do your thing.

Luckily in
the [official documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/ingest.html#handling-pipeline-failures)
there is a bit of information about other on_failure fields.

- on_failure_message
- on_failure_processor_type
- on_failure_processor_tag
- on_failure_pipeline

From this list we can already see, the field "on_failure_pipeline" is very interesting, because it will tell us which
pipeline failed.
On top of that the "on_failure_processor_type" is interesting because it will tell us what failed on a processor (the
processor itself or for example a condition).
And the last one "on_failure_processor_tag" is interesting because it will throw out the tags of a processor.
However, a processor by default doesn't have tags, so let's fix that later.

All in all I build my failure processor like this (yes I stole that from the documentation):

```json
[
  {
    "append": {
      "field": "error.message",
      "value": [
        "Processor {{ _ingest.on_failure_processor_type }} with tag {{ _ingest.on_failure_processor_tag }} in pipeline {{ _ingest.on_failure_pipeline }} failed with message: {{ _ingest.on_failure_message }}"
      ]
    }
  }
]
```

Now this will really help us a lot already, even without tags.
Speaking of tags, I am not sure how good of an idea it is to set too many, may have a performance impact.
Anyway, we have a processor now, and we can attach this to every Ingest Pipeline by hand......?
Or we could do some simple scripting to automatically set the processor.

Sample Script:

````python
from elasticsearch import Elasticsearch


def get_pipelines(es):
  return es.ingest.get_pipeline()


def put_pipelines(es, pipelines, search="logs_"):
  failure_processor = [
    {
      "append": {
        "field": "error.message",
        "value": [
          "Processor {{ _ingest.on_failure_processor_type }} with tag {{ _ingest.on_failure_processor_tag }} in pipeline {{ _ingest.on_failure_pipeline }} failed with message: {{ _ingest.on_failure_message }}"
        ],
      }
    }
  ]
  for pipeline_name in pipelines:
    if search in pipeline_name:
      print(pipeline_name)
      es.ingest.put_pipeline(
        id=pipeline_name,
        processors=pipelines[pipeline_name]["processors"],
        on_failure=failure_processor,
        description=pipelines[pipeline_name]["description"],
      )


es = Elasticsearch(
  "elastic_hosts",
  basic_auth=("username", "password"),
  verify_certs=True,
  ca_certs="../ca.crt",
  request_timeout=300,
  max_retries=3,
)

pipelines = get_pipelines(es)
put_pipelines(es, pipelines, search="logs_")
````

This script will attach our processor to all Ingest Pipelines that have the word "logs_" in the name.
Since every pipeline starting with logs_ has the same default failure processors, it's pretty safe to overwrite them.

Now we are set for error messages.
We can use the "error.message" field to debug our problems.
As soon as I get an error.message I usually identify the pipeline, and then add tags to all processors inside of it.
For this I have another little script

```python
def put_pipelines_tags(es, pipelines, search="logs_cisco.asa"):
  for pipeline_name in pipelines:
    if search in pipeline_name:
      processors = pipelines[pipeline_name]["processors"]
      logger.info(f"Processing {pipeline_name}")
      stepper = 1
      for processor in processors:
        # pprint(processor)
        for processor_type in processor:
          processor[processor_type]["tag"] = str(stepper)
          stepper += 1
        # pprint(processor)
      es.ingest.put_pipeline(
        id=pipeline_name,
        processors=processors,
        on_failure=pipelines[pipeline_name]["on_failure"],
        description=pipelines[pipeline_name]["description"],
      )


put_pipelines_tags(es, pipelines)
```

And like this, I get a very good indicator of what failed and where.
Now the only last thing to do is, use our brains to find out what went wrong.
Or just set the processor to ignore failures.
