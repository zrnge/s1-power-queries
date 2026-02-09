# SentinelOne Power Queries KQL
Power Query collection for SentinelOne - KQL queries, data transformations, and analysis templates for security operations and threat hunting

## DDoS Dtection
```KQL
event.dns.request = *
| group count=count() by endpoint.name   , timestamp = timebucket(timestamp, "1m") 
| filter  count >= 1000 //change the threshhold based on your environment
```
