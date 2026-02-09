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
