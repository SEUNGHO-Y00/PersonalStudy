# Titan Shield (with Microsoft Defender XDR)

This analyst successfully investigated two highly sophisticated cyberattacks against TitanShield’s sensitive projects, demonstrating advanced investigative skills in identifying social engineering tactics, malicious file execution, and data exfiltration strategies. Using Kusto Query Language (KQL), they unraveled Moonstone Sleet's phishing campaign targeting Project Omega and Crimson Sandstorm’s romance scheme aimed at harvesting critical system and user information. This exercise reinforced skills in threat actor profiling, recognizing social engineering-based reconnaissance on social media, and assessing the broader security implications of protecting intellectual property in a high-stakes defense context.

```KQL
Employees
| where name == "James Douglas"
// UB9I-DESKTOP

FileCreationEvents
| where hostname == "UB9I-DESKTOP"
| where filename has "DeTankWar"

Email
| where link has "detankwar.com"

Email
| where link has "DeTankWar"
| distinct recipient

Email
| where link has "DeTankWar"
| distinct recipient
| join kind=inner Employees on $left.recipient==$right.email_addr
| distinct email_addr, name, role

FileCreationEvents
| where filename in~ ("nvunityplugin.dll","unityplayer.dll")

ProcessEvents
| where process_commandline has "curl" and process_commandline  has_any ("mingeloem.com","matrixane.com")

ProcessEvents
| where process_commandline has "TopSecret.zip"

ProcessEvents
| where process_commandline has "StagingArea"

Employees
| where username == "chtaylor"
// IL5M-DESKTOP

ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline has "whoami"

ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline has_all("echo", ">>", "logs.txt")

Employees
| where username == "chtaylor"

ProcessEvents
| where process_commandline has_all("echo", ">>", "logs.txt")

ProcessEvents
| where process_commandline has_all("echo", ">>", "logs.txt")
| distinct hostname

ProcessEvents
| where process_commandline has_all("echo", ">>", "logs.txt")
| distinct hostname
| join kind=inner Employees on $left.hostname==$right.hostname
| distinct hostname, name, role

ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline contains "Logs.txt"

ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where timestamp between (datetime(2024-07-17) ..  datetime(2024-07-18))

FileCreationEvents
| where hostname == "IL5M-DESKTOP"
| where filename  == "New_Diet_Plan_For_My_Love.xlsx"

OutboundNetworkEvents
| take 10

Employees
| where username == "chtaylor"
// 10.10.0.79

OutboundNetworkEvents
| where src_ip == "10.10.0.79"
| where url has "New_Diet_Plan_For_My_Love.xlsx"

Email
| where link has "https://healthylifestyle.com/share/New_Diet_Plan_For_My_Love.xlsx"

Email
| where sender contains "marcella_flores@gmail.com"

Email
| where sender == "marcella_flores@gmail.com"
| extend domain = parse_url(link).Host
| distinct tostring(domain)

PassiveDns
| where domain in ("healthylifestyle.com", "healthylifestyle.com")
| distinct ip

InboundNetworkEvents
| where src_ip in ("202.241.233.180","208.199.30.154")

Email
| where subject contains "Data exfiltration"

Employees
| where email_addr contains "david_jackson@titanshield.com"
// 10.10.0.8

OutboundNetworkEvents
| where src_ip has "10.10.0.8"
| where url contains "EDR"

OutboundNetworkEvents
| where src_ip has "10.10.0.8"
| where timestamp between (datetime(2024-08-03) ..  datetime(2024-08-04))
```
