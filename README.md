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

---

# OpenSearch PPL Backend for Sigma Rules

A pySigma backend that converts Sigma detection rules into PPL (Piped Processing Language) queries for OpenSearch.

## Overview

Converts Sigma rules (regular and correlation) to OpenSearch PPL queries. Built on pySigma's `TextQueryBackend` class.

## Usage

### Basic Example

```python
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

# Load rule
rule_yaml = """
title: Mimikatz Detection
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\mimikatz.exe'
  condition: selection
"""

# Convert
backend = OpenSearchPPLBackend()
sigma_rules = SigmaCollection.from_yaml(rule_yaml)
ppl_queries = backend.convert(sigma_rules)

print(ppl_queries[0])
# Output: source=windows-process_creation-* | where LIKE(Image, "%\\mimikatz.exe")
```

### Correlation Rules

**Event Count Example** (Brute Force):
```python
rule_yaml = """
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
"""

backend = OpenSearchPPLBackend()
collection = SigmaCollection.from_yaml(rule_yaml)
queries = backend.convert(collection)

# Output: | search source=windows-security-* | where EventID=4625 AND NOT LIKE(SubjectUserName, "%$") | stats count() as event_count by TargetUserName, TargetDomainName | where event_count >= 10
```

**Value Count Example** (Password Spraying):
```python
rule_yaml = """
title: Failed Logon Event
name: failed_logon_event
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Password Spraying Detection
correlation:
  type: value_count
  rules:
    - failed_logon_event
  group-by:
    - IpAddress
  timespan: 30m
  condition:
    gte: 10
    field: TargetUserName
"""

backend = OpenSearchPPLBackend()
collection = SigmaCollection.from_yaml(rule_yaml)
queries = backend.convert(collection)

# Output: | search source=windows-security-* | where EventID=4625 | stats dc(TargetUserName) as value_count by IpAddress | where value_count >= 10
```

**Temporal Example** (Multi-rule correlation):
```python
rule_yaml = """
title: Windows Failed Logon
name: win_failed_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Windows Successful Logon
name: win_successful_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
  condition: selection
---
title: Successful Brute Force
correlation:
  type: temporal
  rules:
    - win_failed_logon
    - win_successful_logon
  group-by:
    - IpAddress
    - TargetUserName
  timespan: 10m
"""

backend = OpenSearchPPLBackend()
collection = SigmaCollection.from_yaml(rule_yaml)
queries = backend.convert(collection)

# Output: | multisearch [search source=windows-security-* | where EventID=4625] [search source=windows-security-* | where EventID=4624 AND LogonType=3] | stats dc(EventID) as unique_rules by span(@timestamp, 10m), IpAddress, TargetUserName | where unique_rules >= 2
```

### Backend Options & Custom Attributes

**Backend Options** - Apply to all rules:
```python
backend = OpenSearchPPLBackend(
    custom_logsource="security-logs-*",
    min_time="-7d",
    max_time="now"
)
```

**Custom Attributes** - Override per-rule in YAML:
```yaml
custom:
  opensearch_ppl_index: "custom-logs-*"
  opensearch_ppl_min_time: "-30d"
  opensearch_ppl_max_time: "now"
```

**Complex Example** - Combining both:
```python
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

# Backend with default time window (last 7 days)
backend = OpenSearchPPLBackend(
    min_time="-7d",
    max_time="now"
)

rule_yaml = """
title: Suspicious PowerShell Execution
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
---
title: Critical System File Access (Extended Window)
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|contains: '\\System32\\config\\'
  condition: selection
custom:
  opensearch_ppl_index: "windows-audit-*"
  opensearch_ppl_min_time: "-30d"
  opensearch_ppl_max_time: "now"
"""

collection = SigmaCollection.from_yaml(rule_yaml)
queries = backend.convert(collection)

# First rule uses backend default (7 days):
# source=windows-process_creation-* | where (LIKE(Image, "%\\powershell.exe")) AND (CommandLine in ("-enc", "-encodedcommand")) AND (@timestamp >= now() - 7d AND @timestamp <= now())

# Second rule overrides with custom attributes (30 days + custom index):
# source=windows-audit-* | where (LIKE(TargetFilename, "%\\System32\\config\\")) AND (@timestamp >= now() - 30d AND @timestamp <= now())
```

**Complex Correlation Example** - Mixed time filters (detection rules with different time windows):
```python
from sigma_backend.backends.opensearch_ppl import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

# Backend with default settings
backend = OpenSearchPPLBackend(
    min_time="-24h",
    max_time="now"
)

rule_yaml = """
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
  opensearch_ppl_min_time: "-7d"
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
---
title: Correlation - Mixed Time Filters
id: 10000402-0000-0000-0000-000000000004
description: Temporal correlation with mixed time filters - one detection rule has its own (7d), one inherits from correlation (30d)
correlation:
  type: temporal
  rules:
    - 10000400-0000-0000-0000-000000000004
    - 10000401-0000-0000-0000-000000000004
  group-by:
    - Computer
  timespan: 5m
custom:
  opensearch_ppl_min_time: "-30d"
  opensearch_ppl_max_time: "now"
"""

collection = SigmaCollection.from_yaml(rule_yaml)
queries = backend.convert(collection)

# Output - Each detection rule uses its own time window:
# Rule 1 keeps its own time filter (7 days):
#   | multisearch [search source=windows-process_creation-* | where LIKE(CommandLine, "%malware%") AND (@timestamp >= now() - 7d AND @timestamp <= now())]
# Rule 2 inherits from correlation (30 days):
#   [search source=windows-network_connection-* | where DestinationPort=443 AND (@timestamp >= now() - 30d AND @timestamp <= now())]
# Final aggregation:
#   | stats dc(EventID) as unique_rules by span(@timestamp, 5m), Computer | where unique_rules >= 2
```
