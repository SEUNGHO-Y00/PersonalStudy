# HopsNStuff

This analyst completed the "HopsNStuff" module, investigating a cyber attack through the analysis of endpoint process events and command-line activities. They demonstrated skills in identifying anomalous file behavior by using Kusto Query Language (KQL) to uncover malicious activities. The investigation highlighted their ability to analyze and deobfuscate malicious PowerShell commands, effectively identifying and responding to data exfiltration techniques.

```KQL
// 1-2
Employees
| count 

// 1-3
Employees
| where ip_addr == "192.168.2.191"

// 1-4
Employees
| where name contains "Simeon Kakpovi"

Email
| where recipient contains "simeon_kakpovi@hopsnstuff.com"

// 1-5
Email
| where sender contains "easterdelights.org"
| distinct sender

// 1-6
Employees
| where name contains "Arthur Raymond"

OutboundNetworkEvents
| where src_ip has "192.168.1.18"
| extend domain = tostring(parse_url(url).Host)
| distinct domain

OutboundNetworkEvents
| where src_ip has "192.168.1.18"
| distinct url

// 1-7
PassiveDns
| where domain contains "automation"
| distinct domain

// 1-8
PassiveDns
| where domain has "automationpackages.com"

// 1-9
let Karen_ips =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (Karen_ips)
| distinct url

// 2-1
SecurityAlerts
| where timestamp between (datetime(2023-03-31)..2d)

// 2-2
Employees
| where hostname has "QBYQ-DESKTOP"

// 2-3, 2-4
FileCreationEvents
| where filename contains "Dev-Requirements.zip"

// 2-5
Employees
| where hostname has "FTVO-LAPTOP"

// 2-6
Email
| where recipient has "meghann_geisinsky@hopsnstuff.com"
| where sender !contains "hopsnstuff.com"

// 2-7
let threat_hosts =
FileCreationEvents
| where filename contains "Dev-Requirements.zip"
| distinct hostname;
let threat_hosts_emails =
Employees
| where hostname in (threat_hosts)
| distinct email_addr;
Email
| where recipient in (threat_hosts_emails)
| where sender !contains "hopsnstuff.com"

// 2-8
let threat_hosts =
FileCreationEvents
| where filename contains "Dev-Requirements.zip"
| distinct hostname;
let threat_hosts_emails =
Employees
| where hostname in (threat_hosts)
| distinct email_addr;
Email
| where recipient in (threat_hosts_emails)
| where sender !contains "hopsnstuff.com"
| where verdict has "BLOCKED"

// 2-9
// https://www.misk.com/tools/#whois/yandex.com

// 2-10, 2-11, 2-12, 2-16
let threat_hosts =
FileCreationEvents
| where filename contains "Dev-Requirements.zip"
| distinct hostname;
let threat_hosts_emails =
Employees
| where hostname in (threat_hosts)
| distinct email_addr;
Email
| where recipient in (threat_hosts_emails)
| where sender !contains "hopsnstuff.com"
| where verdict has "Suspicious"
| where link contains ".zip"

// 2-13
PassiveDns
| where domain contains "development-module.com"

// 2-14
OutboundNetworkEvents
| where url contains "development-module.com"

// 2-15
OutboundNetworkEvents
| where url contains "Requirements.zip"

// 2-17
ProcessEvents
| where process_commandline contains "python"

// 2-18
ProcessEvents
| where process_commandline contains "python"
| distinct hostname

// 2-19, 2-21
ProcessEvents
| where parent_process_name has "nettor.dll" or parent_process_name has "rabbitmq.exe"

// 2-20
ProcessEvents
| where parent_process_name has "nettor.dll" or parent_process_name has "rabbitmq.exe"
| distinct hostname

// 2-21, 2-22, 2-23, 2-25
FileCreationEvents
| where filename has "nettor.dll" or filename has "rabbitmq.exe"

// 2-24
// https://www.virustotal.com/gui/file/30bb094cc616fb4715cef4398a24b76570031ae23f86c4da4f8fd7e5c03ddfc5/details

// 2-26
let threat_hosts =
ProcessEvents
| where process_commandline contains "python"
| distinct hostname;
FileCreationEvents
| where hostname in (threat_hosts)
| where path contains "Public"

// 2-27, 2-28, 2-29
ProcessEvents
| where parent_process_name has "nettor.dll" or parent_process_name has "rabbitmq.exe" or parent_process_name has "go.dll"

// 2-30
ProcessEvents
| where parent_process_name has "nettor.dll" or parent_process_name has "rabbitmq.exe" or parent_process_name has "go.dll"
| where process_commandline contains "search" or process_commandline contains "regsvr"
| distinct process_commandline

// 2-31, 2-32, 2-33, 2-34
let threat_hosts =
ProcessEvents
| where parent_process_name has "nettor.dll" or parent_process_name has "rabbitmq.exe" or parent_process_name has "go.dll"
| where process_commandline contains "search" or process_commandline contains "regsvr"
| distinct hostname;
let threat_hosts_emails =
Employees
| where hostname in (threat_hosts)
| distinct email_addr;
Email
| where recipient in (threat_hosts_emails)
| where link contains "python"

// 3-1
OutboundNetworkEvents
| where url contains "Ginger_beer_secret_recipe.pdf"

Employees
| where ip_addr == "192.168.0.162"

// 3-2
FileCreationEvents
| where hostname has "KBBH-MACHINE"

// 3-3
FileCreationEvents
| where filename has "Ginger_beer_secret_recipe.pdf"
| distinct hostname

// 3-4
let threat_hosts =
FileCreationEvents
| where filename has "Ginger_beer_secret_recipe.pdf"
| distinct hostname;
Employees
| where hostname in (threat_hosts)

// 3-5
let threat_hosts =
FileCreationEvents
| where filename has "Ginger_beer_secret_recipe.pdf"
| distinct hostname;
FileCreationEvents
| where hostname in (threat_hosts)
| where path contains "downloads"

// 3-6
let threat_hosts =
FileCreationEvents
| where filename has "Ginger_beer_secret_recipe.pdf"
| distinct hostname;
FileCreationEvents
| where hostname in (threat_hosts)
| where path contains "downloads"
| where filename contains "pdf"

// 3-7, 3-8
let threat_hosts =
FileCreationEvents
| where filename has "Ginger_beer_secret_recipe.pdf"
| distinct hostname;
FileCreationEvents
| where hostname in (threat_hosts)
| where path contains "downloads"
| where filename contains "pdf"
| distinct filename

// 3-9
FileCreationEvents
| where filename has "Brewery_layout.pdf"
| distinct hostname
// NSM0-MACHINE

// 3-10
Email
| where link contains "Brewery_layout.pdf" or link contains "Ginger_beer_secret_recipe.pdf"

// 3-11
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"

// 3-12
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain

// 3-13
let threat_domain =
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain;
OutboundNetworkEvents
| extend domain = tostring(parse_url(url).Host)
| where domain in (threat_domain)
| extend files = tostring(parse_path(url).Filename)
| distinct files

// 3-15
let threat_domain =
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain;
let threat_ips =
OutboundNetworkEvents
| extend domain = tostring(parse_url(url).Host)
| where domain in (threat_domain)
| extend files = tostring(parse_path(url).Filename)
| distinct src_ip;
let threat_hosts =
Employees
| where ip_addr in (threat_ips)
| distinct hostname;
ProcessEvents
| where hostname in (threat_hosts)
| where process_commandline contains "search"

// 3-16, 3-17
let threat_domain =
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain;
let threat_ips =
OutboundNetworkEvents
| extend domain = tostring(parse_url(url).Host)
| where domain in (threat_domain)
| extend files = tostring(parse_path(url).Filename)
| distinct src_ip;
let threat_hosts =
Employees
| where ip_addr in (threat_ips)
| distinct hostname;
let insfected_file =
ProcessEvents
| where hostname in (threat_hosts)
| where process_commandline contains "cmd.exe whoami"
| distinct parent_process_name;
FileCreationEvents
| where hostname in (threat_hosts)
| where filename in (insfected_file)
| distinct path

// 3-18, 3-19, 3-20
let threat_domain =
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain;
let threat_ips =
OutboundNetworkEvents
| extend domain = tostring(parse_url(url).Host)
| where domain in (threat_domain)
| extend files = tostring(parse_path(url).Filename)
| distinct src_ip;
let threat_users =
Employees
| where ip_addr in (threat_ips)
| distinct username;
AuthenticationEvents
| where username in (threat_users)
| where src_ip !in (threat_ips)
| distinct src_ip

// 3-21
let threat_domain =
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain;
let threat_ips =
OutboundNetworkEvents
| extend domain = tostring(parse_url(url).Host)
| where domain in (threat_domain)
| extend files = tostring(parse_path(url).Filename)
| distinct src_ip;
let threat_hosts =
Employees
| where ip_addr in (threat_ips)
| distinct hostname;
ProcessEvents
| where hostname in (threat_hosts)
| where process_commandline contains "transfer"
//| where process_commandline contains "exfiltrate"

// 3-22
let threat_domain =
OutboundNetworkEvents
| where url contains "Brewery_layout.pdf" or url contains "Ginger_beer_secret_recipe.pdf"
| extend domain = tostring(parse_url(url).Host)
| distinct domain;
let threat_ips =
OutboundNetworkEvents
| extend domain = tostring(parse_url(url).Host)
| where domain in (threat_domain)
| extend files = tostring(parse_path(url).Filename)
| distinct src_ip;
let threat_hosts =
Employees
| where ip_addr in (threat_ips)
| distinct hostname;
ProcessEvents
| where hostname in (threat_hosts)
| where process_commandline contains "transfer"
| distinct process_commandline

// 3-23
PassiveDns
| where domain contains "moneybags.biz"

// 3-24
InboundNetworkEvents
| where url has "egg"
| distinct src_ip

// 3-25
ProcessEvents
| where process_commandline contains ".bat"

// 3-28
PassiveDns
| where domain contains "moneybags"

// 3-29
let threat_hosts =
Employees
| where name contains "Robert Boyce"
| distinct hostname;
FileCreationEvents
| where hostname in (threat_hosts)
| where timestamp between (datetime(2023-02-08)..1d)

// 3-30, 3-31
Employees
| where name contains "Cindy Lozano"

InboundNetworkEvents
| where url contains "cilozano"

// 3-32, 3-33, 3-34, 3-35
let threat_ips =
InboundNetworkEvents
| where url has "login_user" and url has "mailbox_folder"
| distinct src_ip;
let threat_domain =
PassiveDns
| where ip in (threat_ips)
| distinct domain;
Email
| extend domain = parse_url(link).Host
| where domain in (threat_domain)

// 4-1
InboundNetworkEvents
| where url has "login_user" and url has "mailbox_folder"
| where src_ip == "158.235.158.156"

// 4-2, 4-3
AuthenticationEvents
| where src_ip == "158.235.158.156"
| where result has "successful"
// leonard_bedford@hopsnstuff.com

// 4-4
let threat_users =
AuthenticationEvents
| where src_ip == "158.235.158.156"
| where result has "successful"
| distinct username;
let threat_emails =
Employees
| where username in (threat_users)
| distinct email_addr;
Email
| where recipient in (threat_emails)
| where timestamp < datetime(2023-03-01)
| where verdict contains "Suspicious"

// 4-5
Email
| where subject has "Exclusive Invitation to our Candy Themed Beer Festival"

// 4-6
Email
| where subject has "[EXTERNAL] Exclusive Invitation to our Candy Themed Beer Festival"
| extend domain = tostring(parse_url(link).Host)
| distinct domain

// 4-7, 4-8
let threat_domain =
Email
| where subject has "[EXTERNAL] Exclusive Invitation to our Candy Themed Beer Festival"
| extend domain = tostring(parse_url(link).Host)
| distinct domain;
PassiveDns
| where domain in (threat_domain)

// 4-9
let threat_domain =
Email
| where subject has "Exclusive Invitation to our Candy Themed Beer Festival"
| extend domain = tostring(parse_url(link).Host)
| distinct domain;
let threat_ips =
PassiveDns
| where domain in (threat_domain)
| distinct ip;
PassiveDns
| where ip in (threat_ips)
| distinct domain

//beer|candy|ginger|hops|sweet|malt|craft

PassiveDns
| extend ThreatDomain = tolower(domain)
| where ThreatDomain matches regex @"^(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)\."
| distinct domain

// 4-10
let entire_threat_domain =
PassiveDns
| extend ThreatDomain = tolower(domain)
| where ThreatDomain matches regex @"^(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)\."
| distinct domain;
Email
| where link has_any (entire_threat_domain)

// 4-11
let entire_threat_domain =
PassiveDns
| extend ThreatDomain = tolower(domain)
| where ThreatDomain matches regex @"^(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)\."
| distinct domain;
Email
| where link has_any (entire_threat_domain)
| where verdict !has "BLOCKED"

// 4-12
let entire_threat_domain =
PassiveDns
| extend ThreatDomain = tolower(domain)
| where ThreatDomain matches regex @"^(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)\."
| distinct domain;
OutboundNetworkEvents
| where url has_any (entire_threat_domain)
| summarize clickedon =dcount(url) by src_ip
| where clickedon >= 2
| distinct src_ip

// 4-13
let threat_ips =
PassiveDns
| extend ThreatDomain = tolower(domain)
| where ThreatDomain matches regex @"^(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)\."
| distinct ip;
AuthenticationEvents
| where src_ip has_any (threat_ips)

let threat_ips =
PassiveDns
| extend ThreatDomain = tolower(domain)
| where ThreatDomain matches regex @"^(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)(-)?(beer|candy|ginger|hops|sweet|malt|craft)\."
| distinct ip;
let infected_users =
AuthenticationEvents
| where src_ip has_any (threat_ips)
| where result == "Successful Login"
| distinct username;
InboundNetworkEvents
| where url has_any (infected_users)
| where src_ip  in (threat_ips)
```
