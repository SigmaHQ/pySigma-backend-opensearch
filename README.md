![Tests](https://github.com/SigmaHQ/pySigma-backend-opensearch/actions/workflows/test.yml/badge.svg)
![Coverage
Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/andurin/e95ff0904786bd5883f19105b6a3a1ee/raw/SigmaHQ-pySigma-backend-opensearch.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Opensearch Lucene Backend

This is the Opensearch Lucene backend for pySigma. It provides the package `sigma.backends.opensearch` with the `OpensearchLuceneBackend` class.

It supports the following output formats:

* default: plain Opensearch queries in Lucene Syntax 
  * **Hint:** In Dashboard you have to switch from DQL to Lucene
* monitor_rule: JSON Structure to import Opensearch Alerting Rules

This backend is currently maintained by:

* [Hendrik Bäcker](https://github.com/andurin/)

# Background

Since Lucene based queries are very identical to Elasticsearch Lucene queries, most 
of the code for this Backend comes from [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch). 

Opensearch specific changes and output formats are done in this 
backend (eg. Monitor Rules).

# Howto

## Create Output - sigma-cli

```
sigma convert \
  -t opensearch \
  -p ecs_windows \
  -f monitor_rule \
  /data/sigma/rules/windows/process_creation/proc_creation_win_whoami_priv.yml
```

## Create Alerting Rules - Python

```
from sigma.backends.opensearch import OpensearchLuceneBackend

from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows

from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

# Create our pipeline resolver
piperesolver = ProcessingPipelineResolver()

# Add wanted pipelines
piperesolver.add_pipeline_class(ecs_windows())
piperesolver.add_pipeline_class(sysmon_pipeline())

# Create a single sorted and prioritzed pipeline
resolved_pipeline = piperesolver.resolve(piperesolver.pipelines)

# Instantiate backend, using our resolved pipeline
# and some backend parameter
backend = OpensearchLuceneBackend(resolved_pipeline, index_names=['logs-*-*', 'beats-*'], monitor_interval=10, monitor_interval_unit="MINUTES")

rules = SigmaCollection.from_yaml("""
title: Run Whoami Showing Privileges
id: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
status: experimental
description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privieleges. This is often used after a privilege escalation attempt. 
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Florian Roth
date: 2021/05/05
modified: 2022/05/13
tags:
    - attack.privilege_escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains: '/priv'
    condition: all of selection*
falsepositives:
    - Administrative activity (rare lookups on current privileges)
level: high
""")

# Print converted rule in Lucene syntax
print("Lucene Result: \n" + "\n".join(backend.convert(rules)))

# Print converted rule ready for dsl syntax
print("DSL Result: \n" + json.dumps(backend.convert(rules, output_format="dsl_lucene")[0], indent=2))

# Generate a JSON structure to be imported as monitor rule
print("Monitor Rule Result: \n" + backend.convert(rules, output_format="monitor_rule"))

```

Lucene Result: 
```
winlog.channel:Microsoft\-Windows\-Sysmon\/Operational AND (event.code:1 AND ((process.executable:*\\whoami.exe OR process.pe.original_file_name:whoami.exe) AND process.command_line:*\/priv*))
```

DSL Result: 
```
{
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "winlog.channel:Microsoft\\-Windows\\-Sysmon\\/Operational AND (event.code:1 AND (winlog.channel:Microsoft\\-Windows\\-Sysmon\\/Operational AND (event.code:1 AND ((process.executable:*\\\\whoami.exe OR process.pe.original_file_name:whoami.exe) AND process.command_line:*\\/priv*))))",
            "analyze_wildcard": true
          }
        }
      ]
    }
  }
}
```

Monitor Rule Result: 

```
{
  "type": "monitor",
  "name": "SIGMA - Run Whoami Showing Privileges",
  "description": "Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privieleges. This is often used after a privilege escalation attempt.",
  "enabled": true,
  "schedule": {
    "period": {
      "interval": 10,
      "unit": "MINUTES"
    }
  },
  "inputs": [
    {
      "search": {
        "indices": [
          "logs-*-*",
          "beats-*"
        ],
        "query": {
          "size": 1,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "winlog.channel:Microsoft\\-Windows\\-Sysmon\\/Operational AND (event.code:1 AND (winlog.channel:Microsoft\\-Windows\\-Sysmon\\/Operational AND (event.code:1 AND (winlog.channel:Microsoft\\-Windows\\-Sysmon\\/Operational AND (event.code:1 AND ((process.executable:*\\\\whoami.exe OR process.pe.original_file_name:whoami.exe) AND process.command_line:*\\/priv*))))))",
                    "analyze_wildcard": true
                  }
                }
              ]
            }
          }
        }
      }
    }
  ],
  "tags": [
    "attack-privilege_escalation",
    "attack-discovery",
    "attack-t1033"
  ],
  "triggers": [
    {
      "name": "generated-trigger",
      "severity": 2,
      "condition": {
        "script": {
          "source": "ctx.results[0].hits.total.value > 0",
          "lang": "painless"
        }
      },
      "actions": []
    }
  ],
  "sigma_meta_data": {
    "rule_id": "97a80ec7-0e2f-4d05-9ef4-65760e634f6b",
    "threat": []
  },
  "references": [
    "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami"
  ]
}
```