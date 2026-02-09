# SentinelOne Power Queries

A curated collection of KQL (Kusto Query Language) queries for SentinelOne security operations, threat hunting, incident response, and data analysis. These queries are designed to help security teams efficiently detect threats, investigate incidents, and analyze security data from SentinelOne endpoints.

## 📋 Table of Contents

- [Overview](#overview)
- [Query Categories](#query-categories)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Query Structure](#query-structure)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This repository contains production-ready KQL queries specifically designed for SentinelOne data analysis. Each query includes:
- Clear descriptions of functionality
- Specific use cases
- Required data sources
- Instructions for customization
- Expected outputs

## 📁 Query Categories

### Threat Hunting
Proactive queries for identifying potential threats and suspicious activities:
- **Suspicious Process Execution**: Detects potentially malicious process executions
- **Lateral Movement Detection**: Identifies attackers moving through the network
- **Credential Access**: Detects credential dumping and password harvesting

### Threat Detection
Real-time detection queries for immediate threat identification:
- **Ransomware Behavior**: Early detection of ransomware activity patterns
- **Malicious Network Connections**: Identifies suspicious C2 communications
- **Persistence Mechanisms**: Detects malware persistence techniques

### Incident Response
Investigation queries for security incident analysis:
- **Host Investigation Timeline**: Comprehensive timeline of host activities
- **User Activity Investigation**: Tracks all activities for specific users
- **File Hash Investigation**: Tracks malware propagation across systems

### Data Analysis
Queries for understanding baseline behavior and trends:
- **Top Process Activity**: Summary of most active processes
- **Network Traffic Analysis**: Network connection patterns and anomalies
- **Endpoint Security Posture**: Security health assessment

## 🚀 Getting Started

### Prerequisites
- Access to SentinelOne with query capabilities
- Microsoft Azure Monitor/Sentinel (if integrating with Azure)
- Basic understanding of KQL syntax

### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/zrnge/s1-power-queries.git
   cd s1-power-queries
   ```

2. Browse the `queries/` directory to find relevant queries for your use case

3. Copy the desired query to your SentinelOne or Azure Sentinel query interface

## 💡 Usage

### Basic Usage
1. Navigate to the appropriate category folder
2. Open the `.kql` file for the query you want to use
3. Review the query description and data sources required
4. Copy the query to your environment
5. Customize parameters if needed (marked with `<PARAMETER_NAME>`)
6. Execute the query

### Customization Example
Many queries include customizable parameters:

```kql
// Replace this placeholder
let DeviceToInvestigate = "<DEVICE_NAME>";

// With your actual value
let DeviceToInvestigate = "LAPTOP-ABC123";
```

### Time Range Adjustment
Most queries include time filters that can be adjusted:

```kql
// Default: Last 24 hours
| where TimeGenerated > ago(24h)

// Adjust to last 7 days
| where TimeGenerated > ago(7d)

// Adjust to last hour
| where TimeGenerated > ago(1h)
```

## 🏗️ Query Structure

Each query follows a consistent structure:

```kql
// Query Title
// Description: What the query does
// Use Case: When to use this query
// Data Source: Required SentinelOne data tables
// Instructions: (Optional) Steps for customization

<KQL Query Code>
```

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork this repository
2. Create a new branch (`git checkout -b feature/new-query`)
3. Add your query following the existing structure
4. Include clear documentation
5. Test your query
6. Submit a pull request

### Query Submission Guidelines
- Follow the existing query structure
- Include clear descriptions and use cases
- Test queries before submission
- Document any required customization
- Ensure queries are optimized for performance

## 📊 Data Sources

These queries are designed to work with the following SentinelOne data sources:
- `ProcessEvents` - Process creation and execution data
- `NetworkEvents` - Network connection information
- `FileEvents` - File system activity
- `RegistryEvents` - Registry modifications
- `ThreatEvents` - Detected threats and alerts

## ⚠️ Important Notes

- **Performance**: Some queries may return large result sets. Adjust time ranges as needed
- **Customization**: Replace placeholder values (marked with `<>`) with actual values
- **Testing**: Always test queries in a non-production environment first
- **False Positives**: Tune queries based on your environment to reduce noise

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [SentinelOne Documentation](https://www.sentinelone.com/resources/)
- [KQL Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## 📧 Contact

For questions, issues, or suggestions, please open an issue in this repository.

---

**Disclaimer**: These queries are provided as-is for educational and security operations purposes. Always test in a controlled environment and adjust for your specific needs.
