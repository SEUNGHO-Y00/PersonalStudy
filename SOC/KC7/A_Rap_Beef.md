# A Rap Beef (START HERE)

This analyst investigated a themed scenario involving rival hip-hop artists. They used key cybersecurity skills to identify suspicious communications and activities, analyzing internal messages to track unauthorized exchanges and uncover patterns. This exercise reinforced critical skills in data analysis, threat detection, and the application of cybersecurity principles in unconventional contexts.

```KQL
Employees
| where role == "CEO"

InboundNetworkEvents
| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00"))
| where src_ip has "18.66.52.227"

InboundNetworkEvents
| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00"))
| where url has_any("washington", "fluffy")
| where src_ip has "18.66.52.227"

PassiveDns
| where ip == "18.66.52.227"

Email
| take 10

Email
| where link has "betterlyrics4u.com"

let _targets = Email
| where link has "betterlyrics4u.com"
| distinct recipient;
Employees
| where email_addr in (_targets)

Email
| where link has "betterlyrics4u.com"

OutboundNetworkEvents
| where url == "http://betterlyrics4u.com/share/online/published/enter"
| where src_ip == "10.10.0.5"

AuthenticationEvents
| where username == "dwaudrey"
| where src_ip == "18.66.52.227"

InboundNetworkEvents
| where timestamp between (datetime("2024-04-12T00:00:00") .. datetime("2024-05-01T00:00:00"))
| where url has "dwaudrey" 
| where src_ip has "18.66.52.227"
```
