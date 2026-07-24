import pytest
from sigma.collection import SigmaCollection
from sigma.backends.opensearch.opensearch_ppl import OpenSearchPPLBackend


@pytest.fixture
def os_ppl_backend():
    return OpenSearchPPLBackend()


# ============================================================================
# SIMPLE RULES TESTS
# ============================================================================


def test_automated_case_insensitive_match(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Case Insensitive Match
            id: 00000002-0005-0005-0005-000000000005
            status: test
            description: Tests case insensitive matching (default in Sigma)
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|contains:
                        - 'WHOAMI'
                        - 'netstat'
                        - 'IpConfig'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "%WHOAMI%", false) OR LIKE(CommandLine, "%netstat%", false) OR LIKE(CommandLine, "%IpConfig%", false)"""
    ]


def test_automated_cidr_network_range(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: CIDR Network Range
            id: 00000005-0002-0002-0002-000000000002
            status: test
            description: Tests CIDR notation for IP address ranges
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    EventID: 3
                    DestinationIp|cidr: '192.168.1.0/24'
                condition: selection
        """)
    ) == [
        r"""source=windows-network_connection-* | where EventID=3 AND cidrmatch(DestinationIp, "192.168.1.0/24")"""
    ]


def test_automated_field_null_check(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Field Existence Check
            id: 00000005-0003-0003-0003-000000000003
            status: test
            description: Tests checking if a field exists
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    EventID: 1
                    CommandLine: null
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where EventID=1 AND isnull(CommandLine)"""
    ]


def test_automated_lateral_movement_psexec(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Lateral Movement via PsExec
            id: 00000006-0004-0004-0004-000000000004
            status: test
            description: Detects lateral movement using PsExec tool
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\PsExec.exe'
                    CommandLine|contains: '\\\\' # plain value \\
                filter:
                    User|contains: 'SYSTEM'
                condition: selection and not filter
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(Image, "%\\PsExec.exe", false) AND LIKE(CommandLine, "%\\\\%", false) AND NOT LIKE(User, "%SYSTEM%", false)"""
    ]


def test_automated_linux_suspicious_bash_commands(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious Bash Commands
            id: 00000001-0005-0005-0005-000000000005
            status: test
            description: Detects suspicious bash command patterns on Linux
            logsource:
                category: process_creation
                product: linux
            detection:
                selection:
                    Image|endswith:
                        - '/bash'
                        - '/sh'
                    CommandLine|contains:
                        - 'wget'
                        - 'curl'
                        - 'chmod +x'
                condition: selection
        """)
    ) == [
        r"""source=linux-process_creation-* | where (LIKE(Image, "%/bash", false) OR LIKE(Image, "%/sh", false)) AND (LIKE(CommandLine, "%wget%", false) OR LIKE(CommandLine, "%curl%", false) OR LIKE(CommandLine, "%chmod +x%", false))"""
    ]


def test_automated_logical_and_condition(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: AND Condition Test
            id: 00000003-0001-0001-0001-000000000001
            status: test
            description: Tests AND logic between multiple conditions
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    EventID: 1
                    Image|endswith: '\cmd.exe'
                    CommandLine|contains: '/c'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where EventID=1 AND LIKE(Image, "%\\cmd.exe", false) AND LIKE(CommandLine, "%/c%", false)"""
    ]


def test_automated_logical_complex_nested(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Complex Nested Condition
            id: 00000003-0004-0004-0004-000000000004
            status: test
            description: Tests complex nested AND/OR/NOT conditions
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_image:
                    Image|endswith:
                        - '\powershell.exe'
                        - '\cmd.exe'
                selection_cmdline:
                    CommandLine|contains:
                        - '-enc'
                        - 'bypass'
                filter_user:
                    User|endswith: '\Administrator'
                condition: (selection_image and selection_cmdline) and not filter_user
        """)
    ) == [
        r"""source=windows-process_creation-* | where (LIKE(Image, "%\\powershell.exe", false) OR LIKE(Image, "%\\cmd.exe", false)) AND (LIKE(CommandLine, "%-enc%", false) OR LIKE(CommandLine, "%bypass%", false)) AND NOT LIKE(User, "%\\Administrator", false)"""
    ]


def test_automated_logical_multiple_selections(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Multiple Selections Combined
            id: 00000003-0005-0005-0005-000000000005
            status: test
            description: Tests combination of multiple named selections
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_suspicious_process:
                    Image|endswith:
                        - '\net.exe'
                        - '\net1.exe'
                selection_suspicious_args:
                    CommandLine|contains:
                        - 'user'
                        - 'group'
                        - 'localgroup'
                filter_legitimate:
                    ParentImage|endswith: '\services.exe'
                condition: (selection_suspicious_process and selection_suspicious_args) and not filter_legitimate
        """)
    ) == [
        r"""source=windows-process_creation-* | where (LIKE(Image, "%\\net.exe", false) OR LIKE(Image, "%\\net1.exe", false)) AND (LIKE(CommandLine, "%user%", false) OR LIKE(CommandLine, "%group%", false) OR LIKE(CommandLine, "%localgroup%", false)) AND NOT LIKE(ParentImage, "%\\services.exe", false)"""
    ]


def test_automated_logical_not_condition(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: NOT Condition Test
            id: 00000003-0003-0003-0003-000000000003
            status: test
            description: Tests NOT logic for filtering out legitimate processes
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    EventID: 1
                    CommandLine|contains: 'powershell'
                filter:
                    User|contains: 'SYSTEM'
                condition: selection and not filter
        """)
    ) == [
        r"""source=windows-process_creation-* | where EventID=1 AND LIKE(CommandLine, "%powershell%", false) AND NOT LIKE(User, "%SYSTEM%", false)"""
    ]


def test_automated_logical_or_condition(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: OR Condition Test
            id: 00000003-0002-0002-0002-000000000002
            status: test
            description: Tests OR logic between multiple selections
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_cmd:
                    Image|endswith: '\cmd.exe'
                selection_powershell:
                    Image|endswith: '\powershell.exe'
                selection_wscript:
                    Image|endswith: '\wscript.exe'
                condition: selection_cmd or selection_powershell or selection_wscript
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(Image, "%\\cmd.exe", false) OR LIKE(Image, "%\\powershell.exe", false) OR LIKE(Image, "%\\wscript.exe", false)"""
    ]


def test_automated_mimikatz_execution(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Mimikatz Execution Detection
            id: 00000006-0003-0003-0003-000000000003
            status: test
            description: Detects potential Mimikatz execution through various indicators
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_cli:
                    CommandLine|contains:
                        - 'sekurlsa'
                        - 'logonpasswords'
                        - 'lsadump'
                selection_image:
                    Image|endswith: '\mimikatz.exe'
                    OriginalFileName: 'mimikatz.exe'
                condition: selection_cli or selection_image
        """)
    ) == [
        r'''source=windows-process_creation-* | where LIKE(CommandLine, "%sekurlsa%", false) OR LIKE(CommandLine, "%logonpasswords%", false) OR LIKE(CommandLine, "%lsadump%", false) OR LIKE(Image, "%\\mimikatz.exe", false) AND OriginalFileName="mimikatz.exe"'''
    ]


def test_automated_modifier_base64(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Base64 Modifier Test
            id: 00000006-0001-0001-0001-000000000002
            status: test
            description: Tests base64 modifier for encoded command detection
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|base64|contains: 'powershell'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "%cG93ZXJzaGVsbA==%", false)"""
    ]


def test_automated_modifier_base64offset(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Base64 Offset Modifier Test
            id: 00000006-0001-0001-0001-000000000001
            status: test
            description: Tests base64offset modifier for shell usage in HTTP web traffic
            logsource:
                category: web
                product: proxy
            detection:
                selection:
                    c-uri|base64offset|contains:
                        - '/bin/bash'
                        - '/bin/sh'
                        - '/bin/zsh'
                condition: selection
        """)
    ) == [
        r"""source=proxy-web-* | where LIKE(`c-uri`, "%L2Jpbi9iYXNo%", false) OR LIKE(`c-uri`, "%9iaW4vYmFza%", false) OR LIKE(`c-uri`, "%vYmluL2Jhc2%", false) OR LIKE(`c-uri`, "%L2Jpbi9za%", false) OR LIKE(`c-uri`, "%9iaW4vc2%", false) OR LIKE(`c-uri`, "%vYmluL3No%", false) OR LIKE(`c-uri`, "%L2Jpbi96c2%", false) OR LIKE(`c-uri`, "%9iaW4venNo%", false) OR LIKE(`c-uri`, "%vYmluL3pza%", false)"""
    ]


def test_automated_modifier_cased(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Cased Modifier Test
            id: 00000006-0002-0002-0002-000000000001
            status: test
            description: Tests cased modifier for case-sensitive value matching
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|cased|contains: 'CaseSensitiveValue'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "%CaseSensitiveValue%", true)"""
    ]


def test_automated_modifier_contains_all(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Contains All Modifier Test
            id: 00000002-0004-0004-0004-000000000004
            status: test
            description: Tests contains|all modifier requiring all values to match
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|contains|all:
                        - 'powershell'
                        - '-enc'
                        - 'bypass'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "%powershell%", false) AND LIKE(CommandLine, "%-enc%", false) AND LIKE(CommandLine, "%bypass%", false)"""
    ]


def test_automated_modifier_endswith(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: EndsWith Modifier Test
            id: 00000002-0003-0003-0003-000000000003
            status: test
            description: Tests endswith modifier for file extension matching
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith:
                        - '.exe'
                        - '.bat'
                        - '.ps1'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(Image, "%.exe", false) OR LIKE(Image, "%.bat", false) OR LIKE(Image, "%.ps1", false)"""
    ]


def test_automated_modifier_exists_false(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Exists Modifier Test - False
            id: 00000006-0003-0003-0003-000000000002
            status: test
            description: Tests exists modifier with false value to check field non-existence
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    User|exists: false
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where isnull(User)"""]


def test_automated_modifier_exists_true(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Exists Modifier Test - True
            id: 00000006-0003-0003-0003-000000000001
            status: test
            description: Tests exists modifier with true value to check field existence
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    User|exists: true
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where isnotnull(User)"""]


def test_automated_modifier_fieldref(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Fieldref Modifier Test
            id: 00000006-0004-0004-0004-000000000001
            status: test
            description: Tests fieldref modifier for comparing field values
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    User|fieldref: TargetUser
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where User=TargetUser"""]


def test_automated_modifier_gt(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Greater Than Modifier Test
            id: 00000006-0005-0005-0005-000000000001
            status: test
            description: Tests gt modifier for greater than comparison
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ProcessId|gt: 1000
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where ProcessId>1000"""]


def test_automated_modifier_gte(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Greater Than or Equal Modifier Test
            id: 00000006-0005-0005-0005-000000000002
            status: test
            description: Tests gte modifier for greater than or equal comparison
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ProcessId|gte: 1000
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where ProcessId>=1000"""]


def test_automated_modifier_lt(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Less Than Modifier Test
            id: 00000006-0005-0005-0005-000000000003
            status: test
            description: Tests lt modifier for less than comparison
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ProcessId|lt: 5000
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where ProcessId<5000"""]


def test_automated_modifier_lte(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Less Than or Equal Modifier Test
            id: 00000006-0005-0005-0005-000000000004
            status: test
            description: Tests lte modifier for less than or equal comparison
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ProcessId|lte: 5000
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where ProcessId<=5000"""]


def test_automated_modifier_startswith(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: StartsWith Modifier Test
            id: 00000002-0002-0002-0002-000000000002
            status: test
            description: Tests startswith modifier for path matching
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    TargetFilename|startswith: 'C:\Temp\'
                condition: selection
        """)
    ) == [
        r"""source=windows-file_event-* | where LIKE(TargetFilename, "C:\\Temp\\%", false)"""
    ]


def test_automated_modifier_wide_base64offset(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Wide Base64 Offset Modifier Test
            id: 00000006-0006-0006-0006-000000000001
            status: test
            description: Tests wide|base64offset modifier chain for UTF-16 encoded commands
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|wide|base64offset|contains: 'ping'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "%cABpAG4AZw%", false) OR LIKE(CommandLine, "%AAaQBuAGcA%", false) OR LIKE(CommandLine, "%wAGkAbgBnA%", false)"""
    ]


def test_automated_modifier_windash(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Windash Modifier Test
            id: 00000006-0007-0007-0007-000000000001
            status: test
            description: Tests windash modifier for Windows command-line argument variations
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|windash|contains:
                        - ' -param-name '
                        - ' -f '
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "% -param-name %", false) OR LIKE(CommandLine, "% /param-name %", false) OR LIKE(CommandLine, "% –param-name %", false) OR LIKE(CommandLine, "% —param-name %", false) OR LIKE(CommandLine, "% ―param-name %", false) OR LIKE(CommandLine, "% -f %", false) OR LIKE(CommandLine, "% /f %", false) OR LIKE(CommandLine, "% –f %", false) OR LIKE(CommandLine, "% —f %", false) OR LIKE(CommandLine, "% ―f %", false)"""
    ]


def test_automated_numeric_greater_than(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Numeric Comparison Greater Than
            id: 00000004-0001-0001-0001-000000000001
            status: test
            description: Tests numeric greater than comparison
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    EventID: 1
                    ProcessId|gt: 1000
                condition: selection
        """)
    ) == [r"""source=windows-process_creation-* | where EventID=1 AND ProcessId>1000"""]


def test_automated_numeric_high_privilege(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: High Privilege Level Detection
            id: 00000004-0004-0004-0004-000000000004
            status: test
            description: Tests detection of processes with high integrity level
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    IntegrityLevel: 'System'
                    ProcessId|gt: 0
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where IntegrityLevel="System" AND ProcessId>0"""
    ]


def test_automated_numeric_less_than(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Numeric Comparison Less Than
            id: 00000004-0002-0002-0002-000000000002
            status: test
            description: Tests numeric less than comparison
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    EventID: 3
                    DestinationPort|lt: 1024
                condition: selection
        """)
    ) == [
        r"""source=windows-network_connection-* | where EventID=3 AND DestinationPort<1024"""
    ]


def test_automated_numeric_range_check(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Numeric Range Check
            id: 00000004-0003-0003-0003-000000000003
            status: test
            description: Tests numeric range with gte and lte
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    EventID: 3
                    DestinationPort|gte: 8000
                    DestinationPort|lte: 9000
                condition: selection
        """)
    ) == [
        r"""source=windows-network_connection-* | where EventID=3 AND DestinationPort>=8000 AND DestinationPort<=9000"""
    ]


def test_automated_numeric_suspicious_port(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious Port Range
            id: 00000004-0005-0005-0005-000000000005
            status: test
            description: Tests detection of connections to suspicious port ranges
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    EventID: 3
                    DestinationPort|gte: 4444
                    Initiated: 'true'
                condition: selection
        """)
    ) == [
        r'''source=windows-network_connection-* | where EventID=3 AND DestinationPort>=4444 AND Initiated="true"'''
    ]


def test_automated_regex_base64_command(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Base64 Encoded Command Detection
            id: 00000005-0004-0004-0004-000000000004
            status: test
            description: Tests regex for detecting base64 encoded commands
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|re: '(?i).*-e(nc(odedcommand)?|c)\s+[A-Za-z0-9+/]{50,}={0,2}.*'
                condition: selection
        """)
    ) == [
        r'''source=windows-process_creation-* | regex CommandLine="(?i).*-e(nc(odedcommand)?|c)\\s+[A-Za-z0-9+/]{50,}={0,2}.*"'''
    ]


def test_automated_regex_pattern_match(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Regex Pattern Matching
            id: 00000005-0001-0001-0001-000000000001
            status: test
            description: Tests regular expression pattern matching
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|re: '.*powershell.*-[eE]nc.*'
                condition: selection
        """)
    ) == [
        r'''source=windows-process_creation-* | regex CommandLine=".*powershell.*-[eE]nc.*"'''
    ]


def test_automated_registry_key_modification(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Registry Key Modification
            id: 00000005-0006-0006-0006-000000000006
            status: test
            description: Tests detection of suspicious registry modifications
            logsource:
                category: registry_event
                product: windows
            detection:
                selection:
                    EventID: 13
                    TargetObject|startswith:
                        - 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
                        - 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
                condition: selection
        """)
    ) == [
        r"""source=windows-registry_event-* | where EventID=13 AND (LIKE(TargetObject, "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%", false) OR LIKE(TargetObject, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%", false))"""
    ]


def test_automated_scheduled_task_creation(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Scheduled Task Creation
            id: 00000006-0006-0006-0006-000000000006
            status: test
            description: Detects suspicious scheduled task creation
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\schtasks.exe'
                    CommandLine|contains|all:
                        - '/create'
                        - '/tn'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(Image, "%\\schtasks.exe", false) AND LIKE(CommandLine, "%/create%", false) AND LIKE(CommandLine, "%/tn%", false)"""
    ]


def test_automated_special_chars_in_path(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Special Characters in Path
            id: 00000005-0005-0005-0005-000000000005
            status: test
            description: Tests handling of special characters in file paths
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    TargetFilename|contains:
                        - '\Users\Public\'
                        - '\AppData\Roaming\'
                        - '\ProgramData\'
                condition: selection
        """)
    ) == [
        r"""source=windows-file_event-* | where LIKE(TargetFilename, "%\\Users\\Public\\%", false) OR LIKE(TargetFilename, "%\\AppData\\Roaming\\%", false) OR LIKE(TargetFilename, "%\\ProgramData\\%", false)"""
    ]


def test_automated_suspicious_dns_query(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious DNS Query
            id: 00000006-0008-0008-0008-000000000008
            status: test
            description: Detects DNS queries to suspicious domains
            logsource:
                category: dns_query
                product: windows
            detection:
                selection:
                    QueryName|endswith:
                        - '.tk'
                        - '.ml'
                        - '.ga'
                        - '.gq'
                condition: selection
        """)
    ) == [
        r"""source=windows-dns_query-* | where LIKE(QueryName, "%.tk", false) OR LIKE(QueryName, "%.ml", false) OR LIKE(QueryName, "%.ga", false) OR LIKE(QueryName, "%.gq", false)"""
    ]


def test_automated_suspicious_service_install(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious Service Installation
            id: 00000006-0007-0007-0007-000000000007
            status: test
            description: Detects installation of suspicious Windows services
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_image:
                    Image|endswith: '\sc.exe'
                selection_command:
                    CommandLine|contains:
                        - 'create'
                        - 'config'
                selection_binpath:
                    CommandLine|contains: 'binpath'
                condition: selection_image and selection_command and selection_binpath
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(Image, "%\\sc.exe", false) AND (LIKE(CommandLine, "%create%", false) OR LIKE(CommandLine, "%config%", false)) AND LIKE(CommandLine, "%binpath%", false)"""
    ]


def test_automated_suspicious_wmi_execution(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious WMI Execution
            id: 00000006-0005-0005-0005-000000000005
            status: test
            description: Detects suspicious WMI process executions
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ParentImage|endswith: '\wmiprvse.exe'
                    Image|endswith:
                        - '\powershell.exe'
                        - '\cmd.exe'
                        - '\wscript.exe'
                        - '\cscript.exe'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(ParentImage, "%\\wmiprvse.exe", false) AND (LIKE(Image, "%\\powershell.exe", false) OR LIKE(Image, "%\\cmd.exe", false) OR LIKE(Image, "%\\wscript.exe", false) OR LIKE(Image, "%\\cscript.exe", false))"""
    ]


def test_or_regex_not_implemented(os_ppl_backend: OpenSearchPPLBackend):
    with pytest.raises(NotImplementedError):
        os_ppl_backend.convert(
            SigmaCollection.from_yaml(r"""
            title: Suspicious WMI Execution
            id: 00000006-0005-0005-0005-000000000005
            status: test
            description: Detects suspicious WMI process executions
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    - ParentImage|re: '.*\\wmiprvse.exe'
                    - Image|re:
                        - '.*\\powershell.exe'
                        - '.*\\cmd.exe'
                        - '.*\\wscript.exe'
                        - '.*\\cscript.exe'
                condition: selection
            """)
        )


def test_automated_wildcard_pattern_match(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Wildcard Pattern Match
            id: 00000002-0001-0001-0001-000000000001
            status: test
            description: Tests wildcard pattern matching with * and ?
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|contains:
                        - '*malware*'
                        - '*backdoor*'
                        - 'cmd?.exe'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(CommandLine, "%malware%", false) OR LIKE(CommandLine, "%backdoor%", false) OR LIKE(CommandLine, "%cmd_.exe%", false)"""
    ]


def test_automated_windows_file_creation_sensitive(
    os_ppl_backend: OpenSearchPPLBackend,
):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Sensitive File Creation
            id: 00000001-0004-0004-0004-000000000004
            status: test
            description: Detects creation of files in sensitive directories
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    EventID: 11
                    TargetFilename|startswith:
                        - 'C:\Windows\System32\'
                        - 'C:\Windows\SysWOW64\'
                condition: selection
        """)
    ) == [
        r"""source=windows-file_event-* | where EventID=11 AND (LIKE(TargetFilename, "C:\\Windows\\System32\\%", false) OR LIKE(TargetFilename, "C:\\Windows\\SysWOW64\\%", false))"""
    ]


def test_automated_windows_network_connection_suspicious(
    os_ppl_backend: OpenSearchPPLBackend,
):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious Network Connection
            id: 00000001-0003-0003-0003-000000000003
            status: test
            description: Detects suspicious outbound network connections
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    EventID: 3
                    DestinationPort:
                        - 4444
                        - 5555
                        - 8080
                    Initiated: 'true'
                condition: selection
        """)
    ) == [
        r'''source=windows-network_connection-* | where EventID=3 AND (DestinationPort in (4444, 5555, 8080)) AND Initiated="true"'''
    ]


def test_automated_windows_process_creation_basic(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Windows Process Creation - Basic
            id: 00000001-0001-0001-0001-000000000001
            status: test
            description: Basic process creation detection testing exact match
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    EventID: 1
                    Image: 'C:\Windows\System32\calc.exe'
                condition: selection
        """)
    ) == [
        r'''source=windows-process_creation-* | where EventID=1 AND Image="C:\\Windows\\System32\\calc.exe"'''
    ]


def test_automated_windows_suspicious_powershell(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Suspicious PowerShell Execution
            id: 00000001-0002-0002-0002-000000000002
            status: test
            description: Detects suspicious PowerShell command line patterns
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\powershell.exe'
                    CommandLine|contains:
                        - '-EncodedCommand'
                        - '-enc'
                        - '-NoProfile'
                condition: selection
        """)
    ) == [
        r"""source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe", false) AND (LIKE(CommandLine, "%-EncodedCommand%", false) OR LIKE(CommandLine, "%-enc%", false) OR LIKE(CommandLine, "%-NoProfile%", false))"""
    ]


# ============================================================================
# CORRELATION RULES TESTS
# ============================================================================


def test_correlation_account_manipulation(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: User Account Created
name: user_account_created
status: test
description: Detects user account creation
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
---
title: User Added to Privileged Group
name: user_added_to_group
status: test
description: Detects user being added to a privileged group
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
        TargetUserName:
            - Administrators
            - Domain Admins
            - Enterprise Admins
    condition: selection
---
title: Rapid Account Creation and Privilege Escalation
status: test
description: Detects quick succession of account creation followed by adding the account to a privileged group
correlation:
    type: temporal
    rules:
        - user_account_created
        - user_added_to_group
    aliases:
        user:
            user_account_created: TargetUserName
            user_added_to_group: MemberName
    group-by:
        - user
    timespan: 5m
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1136
    - attack.t1098
level: critical
falsepositives:
    - Legitimate administrative operations
    - Automated provisioning systems
        """)
    ) == [
        r"""| multisearch [search source=windows-security-* | where EventID=4720 | eval event_type="user_account_created" | rename TargetUserName as user] [search source=windows-security-* | where EventID=4732 AND (TargetUserName in ("Administrators", "Domain Admins", "Enterprise Admins")) | eval event_type="user_added_to_group" | rename MemberName as user] | stats dc(event_type) as unique_rules by span(@timestamp, 5m), user | where unique_rules >= 2"""
    ]


def test_correlation_brute_force_detection(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: Windows Failed Logon Event
name: failed_logon
status: test
description: Detects failed logon events on Windows systems.
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
title: Multiple failed logons for a single user (possible brute force attack)
status: test
description: Detects multiple failed logon attempts within a short timeframe which may indicate a brute force attack
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
tags:
    - attack.credential_access
    - attack.t1110
level: high
falsepositives:
    - User entering wrong password multiple times
        """)
    ) == [
        r"""source=windows-security-* | where EventID=4625 AND NOT LIKE(SubjectUserName, "%$", false) | stats count() as event_count by span(@timestamp, 5m), TargetUserName, TargetDomainName | where event_count >= 10"""
    ]


def test_correlation_data_exfiltration(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: File Access to Sensitive Location
name: sensitive_file_access
status: test
description: Detects access to sensitive files and directories
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectName|contains:
            - '\Users\'
            - '\Documents\'
            - '\Desktop\'
            - 'confidential'
            - 'secret'
        AccessMask: '0x1'  # Read access
    condition: selection
---
title: Large Data Transfer
name: large_data_transfer
status: test
description: Detects large outbound network data transfers
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        BytesSent|gte: 10485760  # 10 MB
    condition: selection
---
title: Potential Data Exfiltration
status: test
description: Detects potential data exfiltration by correlating sensitive file access with large network transfers
correlation:
    type: temporal
    rules:
        - sensitive_file_access
        - large_data_transfer
    group-by:
        - User
        - ComputerName
    timespan: 10m
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.t1048
level: high
falsepositives:
    - Legitimate file synchronization
    - Backup operations
    - Cloud storage services
        """)
    ) == [
        r"""| multisearch [search source=windows-security-* | where EventID=4663 AND (LIKE(ObjectName, "%\\Users\\%", false) OR LIKE(ObjectName, "%\\Documents\\%", false) OR LIKE(ObjectName, "%\\Desktop\\%", false) OR LIKE(ObjectName, "%confidential%", false) OR LIKE(ObjectName, "%secret%", false)) AND AccessMask="0x1" | eval event_type="sensitive_file_access"] [search source=windows-network_connection-* | where Initiated="true" AND BytesSent>=10485760 | eval event_type="large_data_transfer"] | stats dc(event_type) as unique_rules by span(@timestamp, 10m), User, ComputerName | where unique_rules >= 2"""
    ]


def test_correlation_lateral_movement_detection(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: Remote Service Creation
name: remote_service_creation
status: test
description: Detects remote service creation which may indicate lateral movement
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceFileName|contains:
            - '\\\\*\\' # plain value \\<wildcard>\
            - 'ADMIN$'
    condition: selection
---
title: Remote Process Creation
name: remote_process_creation
status: test
description: Detects process creation from remote source
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\services.exe'
        Image|contains:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wmic.exe'
    condition: selection
---
title: Lateral Movement Activity
status: test
description: Detects potential lateral movement by correlating remote service creation with suspicious process execution
correlation:
    type: temporal
    rules:
        - remote_service_creation
        - remote_process_creation
    group-by:
        - ComputerName
    timespan: 2m
tags:
    - attack.lateral_movement
    - attack.t1021
    - attack.t1569
level: high
falsepositives:
    - Legitimate administrative activity
    - Remote management tools

""")
    ) == [
        r"""| multisearch [search source=windows-system-* | where EventID=7045 AND (LIKE(ServiceFileName, "%\\\\%\\%", false) OR LIKE(ServiceFileName, "%ADMIN$%", false)) | eval event_type="remote_service_creation"] [search source=windows-process_creation-* | where LIKE(ParentImage, "%\\services.exe", false) AND (LIKE(Image, "%\\cmd.exe%", false) OR LIKE(Image, "%\\powershell.exe%", false) OR LIKE(Image, "%\\wmic.exe%", false)) | eval event_type="remote_process_creation"] | stats dc(event_type) as unique_rules by span(@timestamp, 2m), ComputerName | where unique_rules >= 2"""
    ]


def test_correlation_password_spraying(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: Failed Logon Event
name: failed_logon_event
status: test
description: Detects failed logon attempts
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Password Spraying Attack Detection
status: test
description: Detects password spraying attacks by identifying multiple failed logon attempts across different user accounts from the same source
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
tags:
    - attack.credential_access
    - attack.t1110.003
level: high
falsepositives:
    - Misconfigured authentication systems
    - Legitimate authentication attempts during account migration
""")
    ) == [
        r"""source=windows-security-* | where EventID=4625 | stats dc(TargetUserName) as value_count by span(@timestamp, 30m), IpAddress | where value_count >= 10"""
    ]


def test_correlation_privileged_group_enumeration(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: High-privilege group enumeration
name: privileged_group_enumeration
status: stable
description: Detects enumeration of high-privilege Active Directory groups
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4799
        CallerProcessId: 0x0
        TargetUserName:
            - Administrators
            - Remote Desktop Users
            - Remote Management Users
            - Distributed COM Users
    condition: selection
level: informational
falsepositives:
    - Administrative activity
    - Directory assessment tools
---
title: Enumeration of multiple high-privilege groups by tools like BloodHound
status: stable
description: Detects enumeration of multiple high-privilege AD groups within a short time frame, which may indicate BloodHound or similar tool usage
correlation:
    type: value_count
    rules:
        - privileged_group_enumeration
    group-by:
        - SubjectUserName
    timespan: 15m
    condition:
        gte: 4
        field: TargetUserName
tags:
    - attack.discovery
    - attack.t1087
level: high
falsepositives:
    - Administrative activity
    - Directory assessment tools

""")
    ) == [
        r"""source=windows-security-* | where EventID=4799 AND CallerProcessId=0 AND (TargetUserName in ("Administrators", "Remote Desktop Users", "Remote Management Users", "Distributed COM Users")) | stats dc(TargetUserName) as value_count by span(@timestamp, 15m), SubjectUserName | where value_count >= 4"""
    ]


def test_correlation_successful_brute_force(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: Windows Failed Logon
name: win_failed_logon
status: test
description: Detects failed logon events on Windows
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
status: test
description: Detects successful logon events on Windows
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3  # Network logon
    condition: selection
---
title: Successful Brute Force Attack Detection
status: test
description: Detects a successful brute force attack by correlating failed logons followed by a successful logon from the same source
correlation:
    type: temporal
    rules:
        - win_failed_logon
        - win_successful_logon
    group-by:
        - IpAddress
        - TargetUserName
    timespan: 10m
tags:
    - attack.credential_access
    - attack.t1110
level: critical
falsepositives:
    - Users legitimately entering wrong password before successful login

""")
    ) == [
        r"""| multisearch [search source=windows-security-* | where EventID=4625 | eval event_type="win_failed_logon"] [search source=windows-security-* | where EventID=4624 AND LogonType=3 | eval event_type="win_successful_logon"] | stats dc(event_type) as unique_rules by span(@timestamp, 10m), IpAddress, TargetUserName | where unique_rules >= 2"""
    ]


def test_correlation_suspicious_network_connection(
    os_ppl_backend: OpenSearchPPLBackend,
):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: Suspicious Process Execution
name: suspicious_process
status: test
description: Detects execution of commonly abused system binaries
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\regsvr32.exe'
    condition: selection
---
title: Network Connection to Suspicious Port
name: suspicious_network_connection
status: test
description: Detects network connections to commonly used C2 or suspicious ports
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationPort:
            - 4444
            - 5555
            - 8080
            - 9999
    condition: selection
---
title: Process Execution with Suspicious Network Activity
status: test
description: Correlates suspicious process execution with network connections to potentially malicious ports
correlation:
    type: temporal
    rules:
        - suspicious_process
        - suspicious_network_connection
    aliases:
        process:
            suspicious_process: ProcessId
            suspicious_network_connection: ProcessId
    group-by:
        - process
        - ComputerName
    timespan: 60s
tags:
    - attack.execution
    - attack.command_and_control
    - attack.t1059
    - attack.t1071
level: high
falsepositives:
    - Legitimate administrative scripts
    - Development and testing activities

""")
    ) == [
        r"""| multisearch [search source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe", false) OR LIKE(Image, "%\\cmd.exe", false) OR LIKE(Image, "%\\wscript.exe", false) OR LIKE(Image, "%\\cscript.exe", false) OR LIKE(Image, "%\\regsvr32.exe", false) | eval event_type="suspicious_process" | rename ProcessId as process] [search source=windows-network_connection-* | where Initiated="true" AND (DestinationPort in (4444, 5555, 8080, 9999)) | eval event_type="suspicious_network_connection" | rename ProcessId as process] | stats dc(event_type) as unique_rules by span(@timestamp, 60s), process, ComputerName | where unique_rules >= 2"""
    ]


# ============================================================================
# CUSTOM ATTRIBUTE TESTS
# ============================================================================


def test_custom_attr_logsource(os_ppl_backend: OpenSearchPPLBackend):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test All Custom Attributes
            id: 10000004-0000-0000-0000-000000000004
            status: test
            description: Test using all custom attributes in one rule
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    CommandLine: test.exe
                condition: selection
            opensearch_ppl_backend:
                index: "complete-test-*"
        """)
    ) == [r'''source=complete-test-* | where CommandLine="test.exe"''']


def test_custom_attr_correlation_mixed_logsource(
    os_ppl_backend: OpenSearchPPLBackend,
):
    assert os_ppl_backend.convert(
        SigmaCollection.from_yaml(r"""
title: Detection Rule 1 - With Own Time Filter
id: 10000400-0000-0000-0000-000000000004
status: test
description: Detection rule with its own custom time attributes
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'malware'
    condition: selection
opensearch_ppl_backend:
    index: windows-*
---
title: Detection Rule 2 - No Time Filter
id: 10000401-0000-0000-0000-000000000004
status: test
description: Detection rule without custom time attributes (will inherit from correlation)
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationPort: 443
    condition: selection
opensearch_ppl_backend:
    index: windows-network-*
---
title: Correlation - Mixed Time Filters
id: 10000402-0000-0000-0000-000000000004
status: test
description: Test temporal correlation with mixed time filters - one detection rule has its own, one inherits
correlation:
    type: temporal
    rules:
        - 10000400-0000-0000-0000-000000000004
        - 10000401-0000-0000-0000-000000000004
    group-by:
        - Computer
    timespan: 5m
        """)
    ) == [
        r"""| multisearch [search source=windows-* | where LIKE(CommandLine, "%malware%", false) | eval event_type="10000400-0000-0000-0000-000000000004"] [search source=windows-network-* | where DestinationPort=443 | eval event_type="10000401-0000-0000-0000-000000000004"] | stats dc(event_type) as unique_rules by span(@timestamp, 5m), Computer | where unique_rules >= 2"""
    ]


# ============================================================================
# OPTION TESTS
# ============================================================================


def test_backend_option_logsource_time():
    backend = OpenSearchPPLBackend(
        custom_logsource="security-logs-*", min_time="-24h", max_time="now"
    )
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
title: Test Combined Options
id: 12345678-1234-1234-1234-123456789007
status: test
description: Test rule with custom logsource AND time filters
author: Adrian
date: 2026/02/28
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Invoke-'
    condition: selection
level: medium
        """)
    ) == [
        r"""earliest=-24h latest=now source=security-logs-* | where LIKE(Image, "%\\powershell.exe", false) AND LIKE(CommandLine, "%Invoke-%", false)"""
    ]


def test_backend_option_correlation_event_count_relative_time():
    backend = OpenSearchPPLBackend(min_time="-24h", max_time="now")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
title: Detection Rule - Failed Login
id: 20000100-0000-0000-0000-000000000001
status: test
description: Detect failed login attempts
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: high
---
title: Correlation - Brute Force Detection
id: 20000101-0000-0000-0000-000000000001
status: test
description: Test event_count correlation with backend options
author: Adrian
date: 2026/03/01
correlation:
    type: event_count
    rules:
        - 20000100-0000-0000-0000-000000000001
    group-by:
        - SourceIP
    timespan: 5m
    condition:
        gte: 5
level: critical
        """)
    ) == [
        r"""earliest=-24h latest=now source=windows-security-* | where EventID=4625 | stats count() as event_count by span(@timestamp, 5m), SourceIP | where event_count >= 5"""
    ]


def test_backend_option_correlation_temporal_absolute_time():
    backend = OpenSearchPPLBackend(
        min_time="2026-02-01T00:00:00", max_time="2026-02-28T23:59:59"
    )
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
title: Detection Rule 1 - Suspicious Process
id: 20000300-0000-0000-0000-000000000003
status: test
description: Detect suspicious process execution
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'suspicious'
    condition: selection
level: medium
---
title: Detection Rule 2 - Network Connection
id: 20000301-0000-0000-0000-000000000003
status: test
description: Detect network connection initiated
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Initiated: 'true'
    condition: selection
level: low
---
title: Correlation - Temporal Correlation
id: 20000302-0000-0000-0000-000000000003
status: test
description: Test temporal correlation with backend options
author: Adrian
date: 2026/03/01
correlation:
    type: temporal
    rules:
        - 20000300-0000-0000-0000-000000000003
        - 20000301-0000-0000-0000-000000000003
    group-by:
        - Computer
    timespan: 2m
level: high
        """)
    ) == [
        r"""| multisearch [search earliest='2026-02-01 00:00:00' latest='2026-02-28 23:59:59' source=windows-process_creation-* | where LIKE(CommandLine, "%suspicious%", false) | eval event_type="20000300-0000-0000-0000-000000000003"] [search earliest='2026-02-01 00:00:00' latest='2026-02-28 23:59:59' source=windows-network_connection-* | where Initiated="true" | eval event_type="20000301-0000-0000-0000-000000000003"] | stats dc(event_type) as unique_rules by span(@timestamp, 2m), Computer | where unique_rules >= 2"""
    ]


def test_backend_option_correlation_value_count_time():
    backend = OpenSearchPPLBackend(min_time="-7d", max_time="now")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
title: Detection Rule - PowerShell Execution
id: 20000200-0000-0000-0000-000000000002
status: test
description: Detect PowerShell execution
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
level: medium
---
title: Correlation - Distinct PowerShell Commands
id: 20000201-0000-0000-0000-000000000002
status: test
description: Test value_count correlation with backend options
author: Adrian
date: 2026/03/01
correlation:
    type: value_count
    rules:
        - 20000200-0000-0000-0000-000000000002
    group-by:
        - User
    timespan: 10m
    condition:
        field: CommandLine
        gte: 3
level: high
        """)
    ) == [
        r"""earliest=-7d latest=now source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe", false) | stats dc(CommandLine) as value_count by span(@timestamp, 10m), User | where value_count >= 3"""
    ]


def test_option_correlation_with_custom_index():
    backend = OpenSearchPPLBackend(
        custom_logsource="threat-intel-*", min_time="-48h", max_time="now"
    )
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
title: Detection Rule - Malware Execution
id: 20000400-0000-0000-0000-000000000004
status: test
description: Detect malware execution
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'malware'
    condition: selection
level: critical
---
title: Correlation - Malware Activity Pattern
id: 20000401-0000-0000-0000-000000000004
status: test
description: Test event_count correlation with custom index from backend option
author: Adrian
date: 2026/03/01
correlation:
    type: event_count
    rules:
        - 20000400-0000-0000-0000-000000000004
    group-by:
        - Computer
    timespan: 15m
    condition:
        gte: 3
level: critical
        """)
    ) == [
        r"""earliest=-48h latest=now source=threat-intel-* | where LIKE(CommandLine, "%malware%", false) | stats count() as event_count by span(@timestamp, 15m), Computer | where event_count >= 3"""
    ]


def test_backend_option_custom_logsource_precedence():
    backend = OpenSearchPPLBackend(custom_logsource="my-custom-logs-*")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test Custom Logsource
            id: 12345678-1234-1234-1234-123456789002
            status: test
            description: Test rule with custom logsource override
            author: Adrian
            date: 2026/02/28
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\powershell.exe'
                    CommandLine|contains: 'Invoke-'
                condition: selection
            level: medium
            opensearch_ppl_backend:
                index: correct-custom-logs-*
        """)
    ) == [
        r"""source=correct-custom-logs-* | where LIKE(Image, "%\\powershell.exe", false) AND LIKE(CommandLine, "%Invoke-%", false)"""
    ]


def test_backend_option_correlation_custom_logsource_precedence():
    backend = OpenSearchPPLBackend(custom_logsource="my-custom-logs-*")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
title: Detection Rule 1 - Suspicious Process
id: 20000300-0000-0000-0000-000000000003
status: test
description: Detect suspicious process execution
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'suspicious'
    condition: selection
level: medium
opensearch_ppl_backend:
    index: correct-custom-logs1-*
---
title: Detection Rule 2 - Network Connection
id: 20000301-0000-0000-0000-000000000003
status: test
description: Detect network connection initiated
author: Adrian
date: 2026/03/01
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Initiated: 'true'
    condition: selection
level: low
---
title: Correlation - Temporal Correlation
id: 20000302-0000-0000-0000-000000000003
status: test
description: Test temporal correlation with backend options
author: Adrian
date: 2026/03/01
correlation:
    type: temporal
    rules:
        - 20000300-0000-0000-0000-000000000003
        - 20000301-0000-0000-0000-000000000003
    group-by:
        - Computer
    timespan: 2m
level: high
        """)
    ) == [
        r"""| multisearch [search source=correct-custom-logs1-* | where LIKE(CommandLine, "%suspicious%", false) | eval event_type="20000300-0000-0000-0000-000000000003"] [search source=my-custom-logs-* | where Initiated="true" | eval event_type="20000301-0000-0000-0000-000000000003"] | stats dc(event_type) as unique_rules by span(@timestamp, 2m), Computer | where unique_rules >= 2"""
    ]


def test_backend_option_time_max_only():
    backend = OpenSearchPPLBackend(max_time="now")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test Max Time Filter Only
            id: 12345678-1234-1234-1234-123456789006
            status: test
            description: Test rule with only maximum time filter
            author: Adrian
            date: 2026/02/28
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\powershell.exe'
                    CommandLine|contains: 'Invoke-'
                condition: selection
            level: medium
        """)
    ) == [
        r"""latest=now source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe", false) AND LIKE(CommandLine, "%Invoke-%", false)"""
    ]


def test_backend_option_time_min_only():
    backend = OpenSearchPPLBackend(min_time="-7d")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test Min Time Filter Only
            id: 12345678-1234-1234-1234-123456789005
            status: test
            description: Test rule with only minimum time filter
            author: Adrian
            date: 2026/02/28
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\powershell.exe'
                    CommandLine|contains: 'Invoke-'
                condition: selection
            level: medium
        """)
    ) == [
        r"""earliest=-7d source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe", false) AND LIKE(CommandLine, "%Invoke-%", false)"""
    ]


def test_backend_option_time_rounding():
    backend = OpenSearchPPLBackend(min_time="-1d@d", max_time="-30m@m")
    assert backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test Relative Time Filters
            id: 12345678-1234-1234-1234-123456789003
            status: test
            description: Test rule with rounding time filters
            author: Adrian
            date: 2026/02/28
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image|endswith: '\powershell.exe'
                    CommandLine|contains: 'Invoke-'
                condition: selection
            level: medium
        """)
    ) == [
        r"""earliest='-1d@d' latest='-30m@m' source=windows-process_creation-* | where LIKE(Image, "%\\powershell.exe", false) AND LIKE(CommandLine, "%Invoke-%", false)"""
    ]
