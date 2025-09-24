# AzureCrest

This analyst investigated a ransomware attack, where cost-cutting measures led to a single point of failure in their systems. This exercise highlighted the risks associated with prioritizing cost over security and reinforced skills in identifying vulnerabilities and understanding the broader implications of inadequate security measures in a healthcare context.

```KQL
Employees
| take 10

Employees
| count

Employees
| where role == "Chief Financial Officer"
// penny_pincher@azurecresthospital.med
// 10.10.0.1

Email
| where recipient == "penny_pincher@azurecresthospital.med"
| count
// billie_france@emergencycarepartners.com

Email
| where sender has "pharmabest.net"
| distinct sender
| count

OutboundNetworkEvents
| where src_ip == "10.10.0.1"
| distinct url
| count 

PassiveDns
| where domain contains "health"
| distinct domain

PassiveDns
| where domain == "bit.ly"
// 134.177.143.174 // 42.143.126.108

let mary_ips = 
Employees
| where name has "mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url

let em_username = Employees
| where name has "mary"
| distinct username;
AuthenticationEvents
| where username in (em_username)
| count

SecurityAlerts
| where description contains "quarantined"

Employees
| where hostname contains "ZQHM-LAPTOP"
// 10.10.0.174

FileCreationEvents
| where hostname contains "ZQHM-LAPTOP"
| where path contains "download"

OutboundNetworkEvents
| where src_ip contains "10.10.0.174"
| where url contains "health"

OutboundNetworkEvents
| where timestamp between (datetime("2024-03-14") .. datetime("2024-03-15"))
| where url contains "partners"

Employees
| where hostname contains "ZQHM-LAPTOP"
//jerry_jones@azurecresthospital.med

Email
| where recipient contains "jerry_jones@azurecresthospital.med"
| where link contains "health"

Email
| where recipient contains "jerry_jones@azurecresthospital.med"
| where sender contains "healthupdate@gmail.com"

Email
| where link contains ".docm"
| distinct recipient

Email
| where link contains ".docm"
| distinct subject | sort by subject

Email
| where link contains ".docm"
| distinct link

Email
| where link contains ".docm"
| extend domain_name = tostring(parse_path(link).DirectoryPath)
| distinct domain_name | sort by domain_name

FileCreationEvents
| where filename contains "docm"
| distinct username

FileCreationEvents
| where filename contains "docm"

FileCreationEvents
| where hostname contains "P3EX-DESKTOP"
| where timestamp between (datetime("2024-03-01") .. datetime("2024-03-02"))

FileCreationEvents
| where path contains "Heartburn"
| distinct filename

ProcessEvents
| where process_commandline contains "zip"

ProcessEvents
| where process_commandline contains "putty"
// 93.142.203.80

ProcessEvents
| where process_commandline contains "putty"
| extend ssh_commend = tostring(parse_path(process_commandline).Filename)
| distinct ssh_commend

ProcessEvents
| where process_name contains "cmd.exe"
| distinct process_commandline

ProcessEvents
| where process_commandline contains "putty"

InboundNetworkEvents
| where user_agent contains "Opera"

Employees
| where name contains "roy"
// Roy Trenneman

Employees
| where role contains "chief"
//10.10.0.1
//Penny Pincher

InboundNetworkEvents
| where user_agent contains "Opera"

Employees
| where name contains "roy"
// roy_trenneman@azurecresthospital.med
// SUPER-DB-SERVER-9000

Email
| where recipient contains "roy_trenneman@azurecresthospital.med"
| where link contains "docm"

FileCreationEvents
| where filename contains "docm"
| where hostname contains "SUPER-DB-SERVER-9000"

ProcessEvents
| where hostname contains "SUPER-DB-SERVER-9000"
| where process_commandline contains "file"

ProcessEvents
| where hostname contains "SUPER-DB-SERVER-9000"
| where process_name contains "dbhunter.exe"

ProcessEvents
| where process_commandline contains "meme"

FileCreationEvents
| where process_name contains "UrTottalyPwned.bat"

FileCreationEvents
| where hostname contains "SUPER-DB-SERVER-9000"
| where timestamp between (datetime("2024-04-01") .. datetime("2024-04-06"))

ProcessEvents
| where hostname contains "SUPER-DB-SERVER-9000"
| where timestamp between (datetime("2024-04-01") .. datetime("2024-04-06"))

InboundNetworkEvents
| where url contains "https://azurecresthospital.med/news/research"

ProcessEvents
| where process_commandline contains "-"
| where process_commandline contains ".exe"
| distinct process_commandline
```
