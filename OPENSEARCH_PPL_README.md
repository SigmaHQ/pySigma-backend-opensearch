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
