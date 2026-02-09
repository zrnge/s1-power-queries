# Query Index

Quick reference guide to all available queries in this repository.

## Threat Hunting Queries

### Suspicious Process Execution
**File**: `queries/threat-hunting/suspicious-process-execution.kql`
**Purpose**: Detect potentially malicious process executions based on common attack patterns
**Data Required**: ProcessEvents
**Key Indicators**: PowerShell obfuscation, encoded commands, suspicious scripts

### Lateral Movement Detection
**File**: `queries/threat-hunting/lateral-movement-detection.kql`
**Purpose**: Identify attackers moving through the network using remote execution tools
**Data Required**: ProcessEvents, NetworkEvents
**Key Indicators**: PSExec, WMI, remote PowerShell, multiple destination hosts

### Credential Access
**File**: `queries/threat-hunting/credential-access.kql`
**Purpose**: Detect credential dumping and password harvesting activities
**Data Required**: ProcessEvents, FileEvents
**Key Indicators**: Mimikatz, LSASS dumps, credential file access

## Threat Detection Queries

### Ransomware Behavior
**File**: `queries/threat-detection/ransomware-behavior.kql`
**Purpose**: Early detection of ransomware activity through behavioral patterns
**Data Required**: FileEvents, ProcessEvents
**Key Indicators**: Mass file encryption, ransom notes, suspicious file extensions

### Malicious Network Connections
**File**: `queries/threat-detection/malicious-network-connections.kql`
**Purpose**: Identify suspicious outbound connections to potential C2 infrastructure
**Data Required**: NetworkEvents
**Key Indicators**: Uncommon ports, IP addresses instead of domains, suspicious TLDs

### Persistence Mechanisms
**File**: `queries/threat-detection/persistence-mechanisms.kql`
**Purpose**: Detect common persistence techniques used by malware
**Data Required**: RegistryEvents, FileEvents
**Key Indicators**: Run keys, startup folders, scheduled tasks, service modifications

## Incident Response Queries

### Host Investigation Timeline
**File**: `queries/incident-response/host-investigation-timeline.kql`
**Purpose**: Create comprehensive timeline of activities for specific host
**Data Required**: All event types
**Customization**: Device name
**Use Case**: Forensic investigation, incident reconstruction

### User Activity Investigation
**File**: `queries/incident-response/user-activity-investigation.kql`
**Purpose**: Track all activities associated with specific user account
**Data Required**: All event types
**Customization**: User account name
**Use Case**: Compromised account investigation, insider threat analysis

### File Hash Investigation
**File**: `queries/incident-response/file-hash-investigation.kql`
**Purpose**: Search for all occurrences of specific file hash across environment
**Data Required**: FileEvents, ProcessEvents
**Customization**: File hash (SHA256/SHA1/MD5)
**Use Case**: Malware propagation tracking, IOC hunting

## Data Analysis Queries

### Top Process Activity
**File**: `queries/data-analysis/top-process-activity.kql`
**Purpose**: Summarize most active processes across environment
**Data Required**: ProcessEvents
**Use Case**: Baseline establishment, anomaly detection preparation

### Network Traffic Analysis
**File**: `queries/data-analysis/network-traffic-analysis.kql`
**Purpose**: Analyze network connection patterns and identify trends
**Data Required**: NetworkEvents
**Use Case**: Network behavior understanding, bandwidth analysis

### Endpoint Security Posture
**File**: `queries/data-analysis/endpoint-security-posture.kql`
**Purpose**: Overview of endpoint security health and coverage
**Data Required**: ProcessEvents, ThreatEvents
**Use Case**: Security posture assessment, compliance reporting

## Query Selection Guide

### By MITRE ATT&CK Tactic

**Initial Access**
- Suspicious Process Execution

**Execution**
- Suspicious Process Execution
- Top Process Activity

**Persistence**
- Persistence Mechanisms

**Credential Access**
- Credential Access

**Lateral Movement**
- Lateral Movement Detection
- Malicious Network Connections

**Impact**
- Ransomware Behavior

**Discovery**
- Host Investigation Timeline
- User Activity Investigation

### By Investigation Type

**Proactive Hunting**
- Suspicious Process Execution
- Lateral Movement Detection
- Credential Access

**Reactive Investigation**
- Host Investigation Timeline
- User Activity Investigation
- File Hash Investigation

**Continuous Monitoring**
- Ransomware Behavior
- Malicious Network Connections
- Persistence Mechanisms

**Reporting & Analysis**
- Top Process Activity
- Network Traffic Analysis
- Endpoint Security Posture

## Common Use Cases

### Investigating a Potential Compromise
1. Start with **Host Investigation Timeline** (incident-response)
2. Check **User Activity Investigation** (incident-response)
3. Look for **Persistence Mechanisms** (threat-detection)
4. Review **Malicious Network Connections** (threat-detection)

### Proactive Threat Hunting
1. Begin with **Top Process Activity** (data-analysis) for baseline
2. Hunt with **Suspicious Process Execution** (threat-hunting)
3. Check **Lateral Movement Detection** (threat-hunting)
4. Investigate **Credential Access** (threat-hunting)

### Ransomware Response
1. Run **Ransomware Behavior** (threat-detection)
2. Create **Host Investigation Timeline** (incident-response)
3. Check **File Hash Investigation** (incident-response) for propagation
4. Review **Network Traffic Analysis** (data-analysis) for C2 activity

### Security Posture Review
1. **Endpoint Security Posture** (data-analysis)
2. **Top Process Activity** (data-analysis)
3. **Network Traffic Analysis** (data-analysis)

## Query Performance Tips

- Start with shorter time ranges (1h, 24h) and expand as needed
- Use specific device or user filters when possible
- Limit result sets with `take` or `top` operators
- Add early `where` filters to reduce dataset size
- Use `summarize` to aggregate large datasets

## Need Help?

- Review the main [README.md](README.md) for general guidance
- Check [CONTRIBUTING.md](CONTRIBUTING.md) for query development
- Open an issue for specific questions or problems
