# Data Sources Quick Reference

This reference covers data sources across all 4 supported SIEM platforms. Use the field name mapping table below to translate between platforms when writing or converting detections.

## Common Windows Data Sources

| Data Source | Key Events | Use For |
|-------------|-----------|---------|
| Sysmon EventID 1 | Process Creation | Process monitoring, parent-child |
| Sysmon EventID 3 | Network Connection | Outbound connections, C2 |
| Sysmon EventID 7 | Image Load (DLL) | DLL side-loading |
| Sysmon EventID 10 | Process Access | Credential dumping (LSASS) |
| Sysmon EventID 11 | File Create | File drops, staging |
| Sysmon EventID 13 | Registry Set | Persistence, config changes |
| Sysmon EventID 22 | DNS Query | DNS-based C2 |
| Security 4624 | Successful Logon | Authentication tracking |
| Security 4625 | Failed Logon | Brute force detection |
| Security 4688 | Process Creation | Basic process monitoring |
| Security 4672 | Special Privileges | Privilege escalation |
| PowerShell 4104 | Script Block Logging | Script content analysis |

## Common Linux Data Sources

| Data Source | Key Events | Use For |
|-------------|-----------|---------|
| Sysmon for Linux EventID 1 | Process Creation | Command execution |
| Sysmon for Linux EventID 3 | Network Connection | Outbound connections |
| Sysmon for Linux EventID 11 | File Create | File operations |
| auditd SYSCALL | System calls | Process execution, file access |
| auditd PATH | File paths | File access monitoring |

## Common Cloud Data Sources

| Platform | Data Source | Use For |
|----------|-----------|---------|
| AWS | CloudTrail | API calls, IAM changes |
| AWS | VPC Flow Logs | Network traffic |
| AWS | GuardDuty | Threat detection findings |
| Azure | Azure AD Sign-in Logs | Authentication |
| Azure | Azure AD Audit Logs | Configuration changes |
| Azure | Activity Logs | Resource changes |
| O365 | Unified Audit Log | User/admin activity |
| GCP | Cloud Audit Logs | API activity |

## Field Name Mapping Across Platforms

| Concept | Splunk CIM | Elastic ECS | Sigma | KQL |
|---------|-----------|-------------|-------|-----|
| Source IP | src_ip | source.ip | src_ip | SourceIP |
| Dest IP | dest_ip | destination.ip | dst_ip | DestinationIP |
| Process name | process_name | process.name | Image | FileName |
| Parent process | parent_process_name | process.parent.name | ParentImage | InitiatingProcessFileName |
| Username | user | user.name | User | AccountName |
| Hostname | dest | host.name | Computer | DeviceName |
| Command line | process | process.command_line | CommandLine | ProcessCommandLine |

## SIEM-Specific Data Source Tables

### Splunk CIM Data Models

| Data Model | Use For | Key Fields |
|------------|---------|------------|
| `Endpoint.Processes` | Process execution | `process_name`, `parent_process_name`, `process`, `user`, `dest` |
| `Endpoint.Filesystem` | File operations | `file_name`, `file_path`, `action`, `dest` |
| `Endpoint.Registry` | Registry changes | `registry_path`, `registry_value_name`, `registry_value_data` |
| `Network_Traffic.All_Traffic` | Network connections | `src_ip`, `dest_ip`, `dest_port`, `transport` |
| `Authentication.Authentication` | Logon events | `user`, `src`, `dest`, `action`, `authentication_method` |

### Microsoft Sentinel / KQL Tables

| Table | Use For | Key Fields |
|-------|---------|------------|
| `DeviceProcessEvents` | Process creation | `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `AccountName`, `DeviceName` |
| `DeviceNetworkEvents` | Network connections | `RemoteIP`, `RemotePort`, `LocalIP`, `InitiatingProcessFileName` |
| `DeviceFileEvents` | File operations | `FileName`, `FolderPath`, `ActionType`, `DeviceName` |
| `DeviceRegistryEvents` | Registry changes | `RegistryKey`, `RegistryValueName`, `RegistryValueData` |
| `DeviceLogonEvents` | Authentication | `AccountName`, `LogonType`, `DeviceName`, `RemoteIP` |
| `SigninLogs` | Azure AD sign-ins | `UserPrincipalName`, `IPAddress`, `ResultType`, `AppDisplayName` |
| `EmailEvents` | Email activity | `SenderFromAddress`, `RecipientEmailAddress`, `Subject` |

### Elastic ECS Index Patterns

| Index Pattern | Use For | Key Fields |
|--------------|---------|------------|
| `logs-endpoint.events.process-*` | Process events | `process.name`, `process.command_line`, `process.parent.name`, `user.name`, `host.name` |
| `logs-endpoint.events.network-*` | Network events | `source.ip`, `destination.ip`, `destination.port`, `process.name` |
| `logs-endpoint.events.file-*` | File events | `file.name`, `file.path`, `event.action`, `host.name` |
| `logs-endpoint.events.registry-*` | Registry events | `registry.path`, `registry.data.strings`, `process.name` |
| `logs-system.auth-*` | Auth events | `user.name`, `source.ip`, `event.outcome` |

### Sigma Logsource Categories

| Category | Product | Use For | Maps To |
|----------|---------|---------|---------|
| `process_creation` | `windows` | Process execution | Sysmon 1 / Security 4688 |
| `network_connection` | `windows` | Outbound connections | Sysmon 3 |
| `file_event` | `windows` | File creation | Sysmon 11 |
| `registry_event` | `windows` | Registry changes | Sysmon 13 |
| `dns_query` | `windows` | DNS resolution | Sysmon 22 |
| `image_load` | `windows` | DLL loading | Sysmon 7 |
| `process_access` | `windows` | Process access (LSASS) | Sysmon 10 |
| `process_creation` | `linux` | Linux process execution | Sysmon for Linux 1 / auditd |

## Technique to Data Source Mapping

| Technique | Primary Data Source | Alternative |
|-----------|-------------------|-------------|
| T1003.001 (LSASS) | Sysmon EventID 10 | EDR process access |
| T1059.001 (PowerShell) | PowerShell 4104 | Sysmon EventID 1 |
| T1059.003 (cmd.exe) | Sysmon EventID 1 | Security 4688 |
| T1547.001 (Run Keys) | Sysmon EventID 13 | EDR registry |
| T1021.001 (RDP) | Security 4624 Type 10 | Network logs |
| T1055 (Process Injection) | Sysmon EventID 8/10 | EDR process events |
| T1027 (Obfuscation) | PowerShell 4104 | Sysmon EventID 1 |

## Technique to SIEM Table Mapping

| Technique | Splunk CIM | KQL Table | Elastic Index | Sigma Category |
|-----------|-----------|-----------|---------------|----------------|
| T1003.001 | `Endpoint.Processes` | `DeviceProcessEvents` | `logs-endpoint.events.process-*` | `process_access` |
| T1059.001 | `Endpoint.Processes` | `DeviceProcessEvents` | `logs-endpoint.events.process-*` | `process_creation` |
| T1547.001 | `Endpoint.Registry` | `DeviceRegistryEvents` | `logs-endpoint.events.registry-*` | `registry_event` |
| T1021.001 | `Authentication` | `DeviceLogonEvents` | `logs-system.auth-*` | `process_creation` + network |
| T1055 | `Endpoint.Processes` | `DeviceProcessEvents` | `logs-endpoint.events.process-*` | `process_access` |
