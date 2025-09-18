# Cowboy Couture

This analyst completed the "Celestial Cowboy Couture" module, where they investigated a targeted phishing attack that resulted in data exfiltration and intellectual property theft. They demonstrated proficiency in using Kusto Query Language (KQL) to trace the attack, analyzing network traffic and credential misuse. The investigation involved connecting threat actor tactics, including the exploitation of an employee’s LinkedIn post to craft a convincing phishing email. By uncovering the full attack chain, the analyst successfully identified the real culprit and restored the company’s reputation.

```KQL
Employees
| where role == "Director of Happiness"

Employees
| where name == "Mary Ellen Kennel"

Employees
| where role contains "model"

Employees
| where name == "John Strand"
// PFW2-DESKTOP
// john_strand@celestialcowboycouture.com

Email
|where recipient == "john_strand@celestialcowboycouture.com"
| count

ProcessEvents
| where hostname == "PFW2-DESKTOP"
| distinct process_commandline

Employees
| where role == "Lead Fashion Designer"
// ITCK-MACHINE

FileCreationEvents
| where hostname == "ITCK-MACHINE"
| order by timestamp desc

FileCreationEvents
| where hostname == "ITCK-MACHINE"
| order by timestamp desc
| where path contains "zip"

FileCreationEvents
| where hostname == "ITCK-MACHINE"
| where path contains "advanced"

ProcessEvents
| where hostname == "ITCK-MACHINE"
| where process_name == "advanced-uploader.exe"

// CyberChef
// Base64
// Reverse

AuthenticationEvents
| where username == "melucia"
|where result == "Successful Login"

AuthenticationEvents
| where src_ip == "192.124.249.15" and result == "Successful Login"
| count

AuthenticationEvents
| where src_ip == "192.124.249.15" and result == "Successful Login"
// jahartley

Employees
| where username == "jahartley"
// JHTJ-DESKTOP

ProcessEvents
|where hostname == "JHTJ-DESKTOP"
| where timestamp between (datetime(2024-09-19T06:25:59Z) .. datetime(2024-09-20T15:25:27Z))

PassiveDns
| where ip == "192.124.249.15"

 PassiveDns
 | where domain in ("secure-celestial.com","celestialcowboy-support.com")
 // 142.250.191.78

 let all_ips = PassiveDns
|where domain in ("secure-celestial.com", 
    "celestialcowboy-support.com")
|distinct ip;
PassiveDns
| where ip in (all_ips)
|distinct domain

OutboundNetworkEvents
| where url has_any ("cccouture-hr-update.com", 
 "celestialcowboy-support.com",
 "secure-celestial.com")

 Email
 | where link has_any ("cccouture-hr-update.com", 
 "celestialcowboy-support.com",
 "secure-celestial.com")
```
