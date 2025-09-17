# Frognado in Valdoria

* [Resource](https://medium.com/@Abdalla116/kql-kc7-frognado-in-valdoria-part-2-13556e01adfb)

```KQL
Employees
| where role == 'Web Administrator'
// Anita Bath
// MYZB-LAPTOP
// 10.10.0.8

ProcessEvents
| where hostname == 'MYZB-LAPTOP'
| where process_commandline has 'Shadow Truth'

ProcessEvents
| where hostname == 'MYZB-LAPTOP'
| where process_commandline contains 'frog_mall_meme'

FileCreationEvents
| where hostname == 'MYZB-LAPTOP'
| where filename startswith 'frog_mall_meme'

OutboundNetworkEvents
| where src_ip == '10.10.0.8'
| where url contains 'frog_mall_meme'
| extend domain = parse_url(url).Host
| distinct tostring(domain)

ProcessEvents
| where hostname == 'MYZB-LAPTOP'
| where process_commandline has 'password'

ProcessEvents
| where hostname == 'MYZB-LAPTOP'
| where process_commandline contains 'passwords'

PassiveDns
| where domain == 'newdevelopmentupdates.org'

PassiveDns
| where domain == 'newdevelopmentupdates.org'
| distinct ip
| lookup PassiveDns on ip
| distinct domain

let TA_ips =
PassiveDns
| where domain == 'newdevelopmentupdates.org'
| distinct ip;
AuthenticationEvents
| where src_ip in (TA_ips)
| where username == 'anbath'

Employees
| where name == 'Anita Bath'
| distinct email_addr

let TA_domains =
PassiveDns
| where domain == 'newdevelopmentupdates.org'
| distinct ip
| lookup PassiveDns on ip
| distinct domain;
Email
| where recipient == 'anita_bath@framtidxdevcorp.com'
| where link has_any(TA_domains)

OutboundNetworkEvents
| where src_ip == '10.10.0.8'
| where url == 'https://greenprojectnews.net/share/modules/files/share/enter'

OutboundNetworkEvents
| where src_ip == '10.10.0.8'
| where url startswith 'https://greenprojectnews.net/share/modules/files/share/enter'
| where url has 'anbath'

Email
| where recipient contains "anita_bath@framtidxdevcorp.com" and link contains "greenprojectnews"

Employees
| count

Employees
| where role contains "CEO"

Employees
| where name has "mona"
// 10.10.0.131

Email
| where recipient == "mona_hunter@framtidxdevcorp.com"
| count

Email
| where sender has "techinnovators.io"
| distinct sender
| count

OutboundNetworkEvents
| where src_ip == "10.10.0.131"
| distinct url
| count

PassiveDns
| where domain contains "green"
| distinct domain
| count

let dorothy_ips =
Employees
| where name has "dorothy"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (dorothy_ips)
| distinct url

let dorothy_name =
Employees
| where name has "dorothy"
| distinct username;
AuthenticationEvents
| where username in (dorothy_name)

Employees
| where role contains "chief"
// erik_bjorn@framtidxdevcorp.com
// sofia_lindgren@framtidxdevcorp.com

Email
| where recipient contains "erik_bjorn@framtidxdevcorp.com"

let TA_IP = 
PassiveDns
| where domain contains "greenprojectnews"
| distinct ip;
InboundNetworkEvents
| where src_ip in (TA_IP)
| distinct url
| count

let TA_IP = 
PassiveDns
| where domain contains "greenprojectnews"
| distinct ip;
InboundNetworkEvents
| where src_ip in (TA_IP)
| summarize count() by referrer
| sort by count_ asc

let chief_architect_ips =
Employees
| where role contains "chief"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (chief_architect_ips)
| where url contains "greenprojectnews" and url contains "password"

let TA_IP = 
PassiveDns
| where domain contains "greenprojectnews"
| distinct ip;
AuthenticationEvents
| where username contains "solindgren"
| where src_ip in (TA_IP)

let chief_architect_hostname =
Employees
| where role contains "chief"
| distinct hostname;
ProcessEvents
| where hostname in (chief_architect_hostname)
| where process_commandline contains "remove"

let chief_architect_hostname =
Employees
| where role contains "chief"
| distinct hostname;
ProcessEvents
| where hostname in (chief_architect_hostname)
| where timestamp between (datetime(2024-07-09) .. datetime(2024-07-10))

Employees
| where name contains "Alex Johnson"

Email
| where sender == "alex_johnson@framtidxdevcorp.com"
| where recipient contains "framtidxdevcorp"
| where link contains "green" or link contains "development"

let phishing_email =
Email
| where sender == "alex_johnson@framtidxdevcorp.com"
| where recipient contains "framtidxdevcorp"
| where link contains "green" or link contains "development"
| distinct recipient;
Employees
| where email_addr in (phishing_email)
| distinct role
| count

let phishing_email =
Email
| where sender == "alex_johnson@framtidxdevcorp.com"
| where recipient contains "framtidxdevcorp"
| where link contains "green" or link contains "development"
| distinct recipient;
Employees
| where email_addr in (phishing_email)

Email
| where sender == "alex_johnson@framtidxdevcorp.com"
| where recipient contains "framtidxdevcorp"
| where link contains "green" or link contains "development"

let TA_IP = 
PassiveDns
| where domain contains "greenprojectnews"
| distinct ip;
InboundNetworkEvents
| where src_ip in (TA_IP)
| where url contains "secret"

Employees
| where name contains "Johanna"
// BLVR-MACHINE

AuthenticationEvents
| where hostname contains "BLVR-MACHINE"
// 239.72.6.38

ProcessEvents
| where process_commandline contains "document"

Email
| where recipient contains "Johanna"
| summarize count() by sender
| sort by count_ asc

let johanna_email = 
Employees
| where role =~ "ceo"
| project email_addr;
Email
| where sender in (johanna_email, "erik.stevens@valdoriapublicworks.gov")
| where recipient in (johanna_email, "erik.stevens@valdoriapublicworks.gov")
| where sender != recipient

ProcessEvents
| where process_commandline contains "zip"

Email
| where timestamp between (datetime(2024-07-08T14:40) .. datetime(2024-07-12T10:00))
| summarize count() by recipient
| sort by count_ asc

Email
| where sender contains "ceo@framtidxdevcorp.com"

```

