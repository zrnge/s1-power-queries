# s1-power-queries
Power Query collection for SentinelOne - KQL queries, data transformations, and analysis templates for security operations and threat hunting

```KQL
event.dns.request = *
| group count=count() by endpoint.name   , timestamp = timebucket(timestamp, "1m") 
| filter  count >= 1000 change the threshhold based on the environment
```
