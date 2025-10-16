# Krusty Krab

This analyst completed the "Krusty Krab" module, investigating a phishing attack and data exfiltration. They used Kusto Query Language (KQL) to analyze email and network logs, revealing the use of deceptive email addresses and malicious domains. This exercise emphasized their ability to pivot and connect malicious domains to threat actor behavior, showcasing their proficiency in threat detection and analysis.

``` KQL
//1-2
Employees
| count

//1-3
Employees
| where ip_addr == "192.168.1.191"

//1-4
let Hector_email =
Employees
| where name contains "Hector"
| distinct email_addr;
Email
| where recipient in (Hector_email)

//1-5
Email
| where sender has "bikini-bottom-fish.com"
| distinct sender

// 1-6
let Lynch_ip = 
Employees
| where name has "Christopher Lynch"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (Lynch_ip)
| distinct url

// 1-7
PassiveDns
| where domain contains "scary"
| distinct domain

// 1-8
PassiveDns
| where domain contains "scarynight.com"

// 1-9
let Karen_ip = 
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (Karen_ip)
| distinct url

// 2-1, 2-2, 2-3, 2-4
Email
| where sender contains "nosferatu.hash@hotmail.com"

// 2-5, 2-6, 2-7, 2-8, 2-9, 2-10
Email
| where sender contains "nosferatu@gmail.com"

// 2-11
let Hong_email = 
Employees
| where name contains "Julie Hong"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (Hong_email) and url contains "scarynight"

// 2-12
OutboundNetworkEvents
| where url contains "scarynight.net"

// 2-13
Employees
| where ip_addr contains "192.168.1.243"

// 2-14
OutboundNetworkEvents
| where url contains "sleeve-dark.net"

// 2-16
OutboundNetworkEvents
| where url contains "sleeve"

// 2-17
OutboundNetworkEvents
| where url contains "night"
| distinct src_ip

// 2-18
OutboundNetworkEvents
| where url contains "midnight"
| distinct src_ip

// 2-19
OutboundNetworkEvents
| where url contains "midnight"

// 2-20,  2-21, 2-22
AuthenticationEvents
| where src_ip contains "54.17.157.246"

// 2-24
AuthenticationEvents
| where src_ip contains "136.61.241.165"

Employees
| where username contains "timorrow"

// 2-25, 2-26, 2-27
InboundNetworkEvents
| where src_ip contains "136.61.241.165"

// 2-28
InboundNetworkEvents
| where src_ip contains "54.17.157.246"

// 2-29
PassiveDns
| where ip contains "54.17.157.246"

// 2-30
let threat_ip =
PassiveDns
| where domain contains "scarysleeve.org"
| distinct ip;
PassiveDns
| where ip in (threat_ip)
| distinct domain

// 3-1, 3-2, 3-3
Email
| where link contains "nightshift.com"

// 3-4
PassiveDns
| where domain contains "nightshift.com"

// 3-5, 3-6
// brad_kasky@krustykrab.com
Employees
| where email_addr contains "brad_kasky@krustykrab.com"

// 3-7
let kasky_ip =
Employees
| where email_addr contains "brad_kasky@krustykrab.com"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (kasky_ip)
| where url contains "nightshift.com"

// 3-8, 3-9
Employees
| where email_addr contains "brad_kasky@krustykrab.com"

// 3-10
let kasky_ip =
Employees
| where email_addr contains "brad_kasky@krustykrab.com"
| distinct ip_addr;
AuthenticationEvents
| where src_ip in (kasky_ip)

// 3-11, 3-12, 3-13, 3-14
AuthenticationEvents
|where username == "brkasky"
|where timestamp > datetime(2023-03-02T08:49:23Z)

// 3-15, 3-17
let threat_user =
Email
| where link contains "nightshift.com"
| distinct recipient;
Employees
| where email_addr in (threat_user)

// 3-16
OutboundNetworkEvents
| where src_ip contains "192.168.2.157" and url contains "nightshift.com"

// 3-18
AuthenticationEvents
| where username contains "maharber"

// 3-19, 3-20
AuthenticationEvents
| where src_ip contains "50.6.66.245"

// 3-21
Employees
| where username contains "juhong"

// 3-22
Email
| where link contains "nightshift.com"

Email
| where recipient contains "julie_hong@krustykrab.com"
| where subject contains "Krabby Patty Worm Detected"

// 3-23
Email
| where sender contains "nosferatu.hash@hotmail.com"
| distinct recipient

// 3-24
Email
| where sender contains "nosferatu.hash@hotmail.com"

// 3-25
// scarynight.net
PassiveDns
| where ip contains "50.6.66.245"

// 3-26, 3-27, 3-28
InboundNetworkEvents
| where src_ip contains "50.6.66.245"

// 4-1, 4-2, 4-3
Email
| where recipient contains "Timothy"
| where timestamp >= (datetime(2023-03-28))

// 4-4
OutboundNetworkEvents
| where url contains "chumsecret"

// 4-5, 4-6
let timothy_username =
Employees
| where ip_addr contains "192.168.0.146"
| distinct username;
FileCreationEvents
| where username in (timothy_username)
| where path contains "Jellyfish"

// 4-7, 4-8
FileCreationEvents
| where username contains "tigraham"
| where timestamp > datetime(2023-03-28)

// 4-9
ProcessEvents
| where username contains "tigraham"
| where timestamp > datetime(2023-03-28)

// 4-10
Email
| where recipient contains "Timothy_g"
| where timestamp >= (datetime(2023-03-28))

// 4-11
ProcessEvents
| where parent_process_name contains "krabbypatty.exe"
| distinct hostname

// 4-12
ProcessEvents
| where parent_process_name contains "krabbypatty.exe"
| sort by process_commandline

// 4-13, 4-14
ProcessEvents
| where process_commandline contains "Block Outgoing Traffic"
| distinct hostname

// 4-15
ProcessEvents
| where process_commandline contains "Block Outgoing Traffic"

// 4-16, 4-18
ProcessEvents
| where timestamp > datetime(2023-03-17)

// 4-17
ProcessEvents
|where parent_process_name == "rclone.exe"

// 4-19
let block_hostname =
ProcessEvents
| where process_commandline contains "Block Outgoing Traffic"
| distinct hostname;
ProcessEvents
| where hostname in (block_hostname)
| where process_commandline contains "download"

// 4-20
FileCreationEvents
| where timestamp between (datetime(2023-03-16)..2d)
| where hostname == "7EJH-LAPTOP"

// 4-21
let block_hostname =
ProcessEvents
| where process_commandline contains "Block Outgoing Traffic"
| distinct hostname;
Employees
| where hostname in (block_hostname)

// 4-22, 4-23
OutboundNetworkEvents
| where src_ip contains "192.168.2.76"
| where timestamp between (datetime(2023-03-16)..2d)

// 4-24
Email
| where recipient == "robert_vinson@krustykrab.com"
| where link contains "burger"

// 4-25
let threat_ip =
PassiveDns
| where domain contains "burgers-formula"
| distinct ip;
PassiveDns
| where ip in (threat_ip)
| distinct domain

// 4-26
let threat_ip =
PassiveDns
| where domain contains "burgers-formula"
| distinct ip;
let threat_domain =
PassiveDns
| where ip in (threat_ip)
| distinct domain;
Email
| where link has_any (threat_domain)
| distinct recipient

// 5-1
AuthenticationEvents
| where username contains "lushearer"
| where timestamp between (datetime(2023-03-07)..2d)

// 5-2
let fake_ip =
AuthenticationEvents
| where username contains "lushearer"
| where timestamp between (datetime(2023-03-07)..2d)
| distinct src_ip;
AuthenticationEvents
| where src_ip in (fake_ip)

// 5-3
Email
| where recipient contains "Hector_Duncan"

// 5-4, 5-5
Email
| where subject contains "[EXTERNAL] IMPORTANT: Krabby Patty Security Alert"

// 5-6, 5-7
Email
| where sender contains "legal@gmail.com"

// 5-8
Employees
| where username contains "chanderson"

FileCreationEvents
| where hostname contains "XYI4-LAPTOP"

// 5-9
Email
| where recipient contains "christine_anderson@krustykrab.com"

// 5-10
Email
| where sender contains "legal.human_resources@yandex.com"
| distinct recipient

// 5-11
SecurityAlerts
| where timestamp between (datetime(2023-03-19)..2d)

FileCreationEvents
| where hostname contains "CJMB-DESKTOP"
| where timestamp between (datetime(2023-03-20)..2d)

// 5-12
Employees
| where hostname contains "CJMB-DESKTOP"

OutboundNetworkEvents
| where src_ip contains "192.168.0.38"
| where timestamp between (datetime(2023-03-20)..2d)

// 5-13
Employees
| where username contains "lecostain"

Email
| where recipient contains "les_costain@krustykrab.com"
| where timestamp between (datetime(2023-03-14)..2d)
```
