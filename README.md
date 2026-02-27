![Tests](https://github.com/SigmaHQ/pySigma-backend-opensearch/actions/workflows/test.yml/badge.svg)
![Coverage
Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/andurin/e95ff0904786bd5883f19105b6a3a1ee/raw/SigmaHQ-pySigma-backend-opensearch.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma OpenSearch Backend

This is the OpenSearch backend for pySigma. It provides the package `sigma.backends.opensearch` with two backend classes:

* **`OpensearchLuceneBackend`** - Converts Sigma rules to Lucene query syntax
* **`OpenSearchPPLBackend`** - Converts Sigma rules to PPL (Piped Processing Language) queries

## Lucene Backend

The Lucene backend supports the following output formats:

* default: plain Opensearch queries in Lucene Syntax 
  * **Hint:** In Dashboard you have to switch from DQL to Lucene
* monitor_rule: JSON Structure to import Opensearch Alerting Rules

This backend is currently maintained by:

* [Hendrik Bäcker](https://github.com/andurin/)

# Background

## Lucene Backend

Since Lucene based queries are very identical to Elasticsearch Lucene queries, most 
of the code for this Backend comes from [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch). 

Opensearch specific changes and output formats are done in this 
backend (eg. Monitor Rules).

## PPL Backend

The PPL (Piped Processing Language) backend is implemented from scratch to support OpenSearch's native query language. PPL provides:
* **Correlation support** - Built-in support for Sigma correlation rules

### Correlation Rules Support

The PPL backend fully supports Sigma correlation rules, enabling detection of complex multi-event scenarios:

* **event_count** - Count occurrences of events (e.g., brute force detection)
* **value_count** - Count distinct values of a field (e.g., password spraying)
* **temporal** - Multiple different events within a time window (e.g., multi-stage attacks)

# Howto

## Create Output - sigma-cli

### Lucene Backend

```
sigma convert \
  -t opensearch \
  -p ecs_windows \
  -f monitor_rule \
  /data/sigma/rules/windows/process_creation/proc_creation_win_whoami_priv.yml
```

### PPL Backend

```
sigma convert \
  -t opensearch-ppl \
  -p ecs_windows \
  /data/sigma/rules/windows/process_creation/proc_creation_win_whoami_priv.yml
```

## Create Alerting Rules - Python

### Lucene Backend

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

### PPL Backend

```python
from sigma.backends.opensearch.opensearch_ppl import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

# Instantiate PPL backend
backend = OpenSearchPPLBackend()

# Use the same rule as above
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

# Print converted rule in PPL syntax
print("PPL Result: \n" + "\n".join(backend.convert(rules)))
```

PPL Result:
```
source=windows-process_creation-* | where (LIKE(Image, "%\whoami.exe") OR OriginalFileName="whoami.exe") AND LIKE(CommandLine, "%/priv%")
```

## PPL Correlation Rules Example

```python
from sigma.backends.opensearch.opensearch_ppl import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

backend = OpenSearchPPLBackend()

# Brute force detection using event_count correlation
rules = SigmaCollection.from_yaml("""
title: Windows Failed Logon Event
name: failed_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  filter:
    SubjectUserName|endswith: $
  condition: selection and not filter
---
title: Brute Force Attack Detection
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
    - TargetDomainName
  timespan: 5m
  condition:
    gte: 10
""")

print("Correlation PPL Result: \n" + "\n".join(backend.convert(rules)))
```

Correlation PPL Result:
```
| search source=windows-security-* | where EventID=4625 AND NOT LIKE(SubjectUserName, "%$") | stats count() as event_count by TargetUserName, TargetDomainName | where event_count >= 10
```

# Custom Attributes

PPL Backend supports custom attributes in Sigma rules.

## PPL Backend Custom Attributes

The PPL backend supports the following custom attributes that can be specified in the `custom` section of a Sigma rule:

```yaml
custom:
  opensearch_ppl_index: "custom-logs-*"        # Override default index pattern
  opensearch_ppl_min_time: "-30d"              # Set query time window start
  opensearch_ppl_max_time: "now"               # Set query time window end
```

### Example with Custom Attributes

This example shows how custom attributes work with correlation rules, where individual detection rules can have their own time windows or inherit from the correlation rule:

```yaml
title: Detection Rule 1 - With Own Time Filter
id: 10000400-0000-0000-0000-000000000004
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'malware'
  condition: selection
custom:
  opensearch_ppl_min_time: "-7d"    # This rule uses 7 days
  opensearch_ppl_max_time: "now"
---
title: Detection Rule 2 - No Time Filter
id: 10000401-0000-0000-0000-000000000004
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort: 443
  condition: selection
# No custom attributes - will inherit from correlation
---
title: Correlation - Mixed Time Filters
id: 10000402-0000-0000-0000-000000000004
correlation:
  type: temporal
  rules:
    - 10000400-0000-0000-0000-000000000004
    - 10000401-0000-0000-0000-000000000004
  group-by:
    - Computer
  timespan: 5m
custom:
  opensearch_ppl_min_time: "-30d"   # Rule 2 inherits this (30 days)
  opensearch_ppl_max_time: "now"
```

**Result**: 
- Detection Rule 1 will search the last **7 days** (its own custom attribute)
- Detection Rule 2 will search the last **30 days** (inherited from correlation rule)

### Backend Options

You can also set default values when instantiating the backend:

```python
backend = OpenSearchPPLBackend(
    custom_logsource="default-logs-*",  # Default index pattern for all rules
    min_time="-24h",                    # Default time window start
    max_time="now"                      # Default time window end
)
```

Custom attributes in individual rules will override these backend-level defaults.
