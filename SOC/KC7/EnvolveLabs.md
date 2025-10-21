# Envolve Labs

This analyst completed the "Envolve Labs" module. They demonstrated skills in using Kusto Query Language (KQL) in their investigation that included identifying phishing campaigns, analyzing command-line activities, and uncovering credential theft and data exfiltration. They also learned to cluster and attribute attacks to specific threat actors, connecting malicious domains and email addresses to threat actor behavior.

```kql
// 1-1
AuthenticationEvents
| take 10

// 1-2
Employees
| count 

// 1-3
Employees
| where ip_addr == "192.168.0.191"

// 1-4
Email
| where recipient contains "Laura_Parrish"

// 1-5
Email
| where subject contains "vaccine" and recipient contains "envolvelabs.com"
| distinct recipient

// 1-6
Employees
| where name contains "Keith"

OutboundBrowsing
| where src_ip == "192.168.1.177"

// 1-7, 1-8
PassiveDns
| where domain contains "vaccine"
| distinct domain

// 1-9
let Karen_ip =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundBrowsing
| where src_ip in (Karen_ip)
| distinct url

// 2-1, 2-2
FileCreationEvents
| where path contains "ResearchBibliographyGenerator.zip"
// 2022-01-07 13:24:12.328613

Employees
| where hostname contains "DLY5-DESKTOP"

// 2-3c, 2-3b, 2-3a
Email
| where recipient contains "terry_simpson@envolvelabs.com"

Email
| where subject contains "Research opportunties! Apply today"

// 2-3d, 2-3e, 2-3
Email
| where subject contains "interview"

// 2-4
PassiveDns
| where domain contains ".science"

// 2-5, 2-5b, 2-5c, 2-6
ProcessEvents
| where timestamp between (datetime(2022-01-07)..2d)
| where hostname contains "DLY5-DESKTOP"
// https://www.virustotal.com/gui/file/1dc1dbfc1d636fed5cebe43787a7abf2df4fbb51e1beaec34ba72dd5152edc81

// 3-1a, 3-1b, 3-1c, 3-1d
Email
| where link contains "clan.io"

// 3-2a
Employees
| where email_addr contains "erica_wilson@envolvelabs.com"

AuthenticationEvents
| where username contains "erwilson"

// 3-2b
AuthenticationEvents
| where src_ip == "223.80.243.56"
| where result contains "successful"

// 3-3
PassiveDns
| where domain contains ".info"
| where ip contains "223.80.243.56"

// 3-4a
let employees_ips =
Employees
| distinct ip_addr;
AuthenticationEvents
| where src_ip !in (employees_ips)
| where result contains "failed"
| summarize dcount(username) by password_hash

// 3-5
let threat_ips =
PassiveDns
| where domain contains "swindled.bio";
InboundBrowsing
| where src_ip in (threat_ips)

// 3-6
PassiveDns
| where ip contains "223.80.243.56"

// 3-7
Email
| where link contains "activists.tk"
```
