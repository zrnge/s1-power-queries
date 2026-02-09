# SentinelOne Power Queries KQL
Power Query collection for SentinelOne - KQL queries, data transformations, and analysis templates for security operations and threat hunting
---
## DDoS Dtection
```KQL
event.dns.request = *
| group count=count() by endpoint.name   , timestamp = timebucket(timestamp, "1m") 
| filter  count >= 1000 //change the threshold based on your environment
```
---
## Suspicious Use of rundll32
```KQL
event.type = "Process Creation"
and tgt.process.name = "rundll32.exe"
and tgt.process.cmdline matches "(?i)(javascript|url.dll|ShellExec_RunDLL|htafile|vbscript)"
| group hits = count() by endpoint.name,tgt.process.cmdline
| let alert = format("Suspicious rundll32 use (%d) on %s  from %s", hits, endpoint.name ,tgt.process.cmdline)
| columns alert
```
## Encrypted Command - Powershell
```KQL
event.type = "Process Creation"
and tgt.process.cmdline contains "powershell"
and tgt.process.cmdline matches "(?i)(-enc|-EncodedCommand|frombase64)"
| group count = count() by endpoint.name 
| let flag = format("Encoded PowerShell seen %,d times on %s", count, endpoint.name)
| columns flag
```
---
## Detect persistence by creating a registry entry in the Run key
```KQL
endpoint.os = "windows" and event.type = "Registry Value Create" and registry.keyPath contains "Windows\CurrentVersion\Run" and registry.value = *
| columns endpoint.name, registry.keyPath, registry.value, src.process.cmdline, src.process.parent.name, src.process.name, event.type, event.time
| sort -event.time
```
