# Solvi Systems

This analyst investigated a cybersecurity incident at Solvi Systems by identifying an attempted XSS attack and tracking a phishing email campaign. Using Kusto Query Language (KQL), they uncovered the threat actor’s reconnaissance efforts, system compromises, and malware activities, providing critical insights for enhancing security measures.

```KQL
Employees
| take 10

Employees
| count

Employees
| where role == "CTO"
//alexis_khoza@solvisystems.com

Email
| where recipient == "alexis_khoza@solvisystems.com"
| count

Email
| where sender has "eskom"
| distinct sender
| count

OutboundNetworkEvents
| where src_ip == "10.10.0.7"
| distinct url
| count

PassiveDns
| where domain contains "real"
| distinct domain
| count

PassiveDns
| where domain == "bit.ly"
| distinct ip

let mary_ips = 
Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url
| count 

let Auth_Mary = Employees
| where name has "Mary"
| distinct username;
AuthenticationEvents
| where username in (Auth_Mary)
| count

InboundNetworkEvents
| where url contains "alert"

InboundNetworkEvents
| where user_agent contains "Opera"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))

InboundNetworkEvents
| where user_agent contains "Opera"

let threat_ips = 
InboundNetworkEvents
| where user_agent contains "Opera"
| where url contains "DOCKS"
| distinct src_ip;
PassiveDns
| where ip in (threat_ips)
| distinct domain
// eco-awareness-update.net
// news-on-industry.com
// energy-trends4u.net

let threat_actor_ips =
InboundNetworkEvents
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| where user_agent contains "Opera/8.64"
| distinct src_ip;
let threat_actor_domains = 
PassiveDns
| where ip in (threat_actor_ips)
| distinct domain;
Email
| where link has_any (threat_actor_domains)
| distinct sender

let threat_actor_ips =
InboundNetworkEvents
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| where user_agent contains "Opera/8.64"
| distinct src_ip;
let threat_actor_domains = 
PassiveDns
| where ip in (threat_actor_ips)
| distinct domain;
Email
| where link has_any (threat_actor_domains)
| extend file_name = tostring(parse_path(link).Filename)
| distinct file_name

let threat_actor_ips =
InboundNetworkEvents
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| where user_agent contains "Opera/8.64"
| distinct src_ip;
let threat_actor_domains = 
PassiveDns
| where ip in (threat_actor_ips)
| distinct domain;
let email_recipients = 
Email
| where link has_any (threat_actor_domains)
| extend email_recipient = parse_path(recipient).Filename
| distinct tostring(email_recipient);
Employees
| where email_addr in (email_recipients)
| distinct role

let threat_actor_ips =
InboundNetworkEvents
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| where user_agent contains "Opera/8.64"
| distinct src_ip;
let threat_actor_domains = 
PassiveDns
| where ip in (threat_actor_ips)
| distinct domain;
let email_recipients = 
Email
| where link has_any (threat_actor_domains)
| extend email_recipient = parse_path(recipient).Filename
| distinct tostring(email_recipient);
Employees
| where email_addr in (email_recipients)
| where role == 'Customer Support Specialist'
| count

let threat_actor_ips =
InboundNetworkEvents
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| where user_agent contains "Opera/8.64"
| distinct src_ip;
let threat_actor_domains = 
PassiveDns
| where ip in (threat_actor_ips)
| distinct domain;
Email
| where link has_any (threat_actor_domains)

let carla_ip =
Employees
| where email_addr == 'carla_wharton@solvisystems.com'
| project ip_addr;
OutboundNetworkEvents
| where src_ip in (carla_ip)
| where url contains "Energy_Industry_Trends_2024_4_Solvi.docx"

let carla =
Employees
| where email_addr == 'carla_wharton@solvisystems.com'
| project username;
FileCreationEvents
| where username in (carla)
| where timestamp between (datetime(2024-05-01T15:58:29Z) .. datetime(2024-05-01T16:58:29Z))

FileCreationEvents
| where filename contains "ecobug"

ProcessEvents
| where process_commandline contains "ecobug"

let carla =
Employees
| where email_addr == 'carla_wharton@solvisystems.com'
| project ip_addr;
NetworkFlow
| where src_ip in (carla)
| where dest_ip == '98.117.26.236'

NetworkFlow
| where dest_ip == '98.117.26.236'
| distinct src_ip

ProcessEvents
| where process_commandline contains "add"

let carla =
Employees
| where name startswith "carla"
| project username;
ProcessEvents
| where username in (carla)
| where timestamp between (datetime(2024-05-02) .. datetime(2024-05-05))

ProcessEvents
| where process_commandline has "net use /"
| distinct hostname

ProcessEvents
| where process_commandline has "net use /"

Employees
| where hostname contains "SJ9V-MACHINE"
// Alexei Petrov

ProcessEvents
| where process_commandline contains "SoftwareDevelopment"

ProcessEvents
| where timestamp between (datetime(2024-05-27T16:23:10Z) .. datetime(2024-05-27T18:00:00))
| where username == "alpetrov"

ProcessEvents
| where timestamp between (datetime(2024-05-28) .. datetime(2024-05-29))
| where process_commandline contains "exfi"

ProcessEvents
| where process_commandline contains "CollectedData"

InboundNetworkEvents
| where url has ".solvisystems.com"

let compromised_email =
Employees
| where username == "jalee"
| project email_addr;
Email
| where sender in (compromised_email)
| where timestamp between (datetime(2024-05-20T16:23:10Z) .. datetime(2024-05-29))
```
