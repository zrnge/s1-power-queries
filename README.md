# SentinelOne Power Queries KQL
Power Query collection for SentinelOne - KQL queries, data transformations, and analysis templates for security operations and threat hunting
---
## Potential DNS tunneling detected.
```KQL
//Remember to exclude the DNS servers to reduce false positives.
event.dns.response matches '[A-Za-z0-9+/]{20,}\.' 
| group total = count() by endpoint.name ,timestamp = timebucket(timestamp, "1m") 
| filter total > 50 // change the rate
```
---
## DDoS Dtection
```KQL
event.dns.request = *
| group count=count() by endpoint.name , timestamp = timebucket(timestamp, "1m") 
| filter  count >= 1000 //change the rate
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
---
## Detect every Registery created by (cmd.exe)
```KQL
src.process.name in ("cmd.exe")  and (event.type = "Registry Value Create" or event.type = "Registry Value Modified" or event.type = "Registry Key Create")
| columns endpoint.name, src.process.cmdline, src.process.parent.name, src.process.name, event.type, event.time
| sort -event.time
```
## Detect every Registery created by (winword.exe > cmd.exe)
```KQL
src.process.name in ("cmd.exe") and src.process.parent.name in ("winword.exe") and (event.type = "Registry Value Create" or event.type = "Registry Value Modified" or event.type = "Registry Key Create")
| columns endpoint.name, src.process.cmdline, src.process.parent.name, src.process.name, event.type, event.time
| sort -event.time
```
---
## Detect unsuccessful login attempts
```KQL
event.type = "Login" and event.login.loginIsSuccessful = false and src.process.netConnCount > "30" 
| columns endpoint.name, endpoint.os, src.process.netConnCount, event.login.loginIsSuccessful, event.login.type, event.type, event.category, event.time
```
