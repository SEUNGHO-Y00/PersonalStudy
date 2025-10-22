# Critical Compromise (ICS)

This analyst completed the Critical Compromise in Chicago module, demonstrating their ability to investigate a malware-based attack on a SCADA system. Through their use of Kusto Query Language (KQL), they uncovered the deployment of malicious software that disrupted the power grid. Their investigation helped identify the attack's origin and provided insights into the attackers’ methods, ultimately contributing to the restoration of normal operations and improving defenses for critical infrastructure.

```kql
// 1-4, 1-5, 1-6, 1-7, 1-8, 1-9, 1-10
ProcessEvents
| where process_commandline contains "scada"

// 1-12, 1-13, 1-14
ProcessEvents
| where process_commandline contains "blackenergy.exe"

// 1-15, 1-16
Employees
| where hostname contains "BDC0-DESKTOP"

// 1-17
FileCreationEvents
| where hostname contains "BDC0-DESKTOP"

// 1-18
OutboundNetworkEvents
| where url contains "Urgent_Cyber_Threat_Alert.zip"

// 1-19
FileCreationEvents
| where hostname == 'BDC0-DESKTOP'
| where timestamp >= datetime(2024-08-29T08:28:01Z)
|take 2

// 1-20
ProcessEvents
| where process_commandline contains "Urgent_Cyber_Threat_Alert.zip"

// 1-21
ProcessEvents
| where process_commandline contains "BlackEnergy"

// 2-2
Email
| where link contains "chicagogridupdates"

Email
| where subject contains "Critical: Grid Security Update Required"

// 2-3
let threat_ip =
PassiveDns
| where domain contains "chicagogridupdates.com"
| distinct ip;
InboundNetworkEvents
| where src_ip in (threat_ip)
// 87.250.252.242, 104.244.42.129

// 2-4
let threat_ip =
PassiveDns
| where domain contains "chicagogridupdates.com"
| distinct ip;
InboundNetworkEvents
| where src_ip in (threat_ip)
| where url contains "SCADA"

// 2-5
Email
| where link contains "Urgent_Cyber_Threat_Alert"

let threat_ip =
PassiveDns
| where domain contains "chicagogridupdates.com"
| distinct ip;
let Authentication_user =
AuthenticationEvents
| where src_ip in (threat_ip)
| distinct username;
let threat_Email =
Employees
| where username in (Authentication_user)
| distinct email_addr;
Email
| where recipient in (threat_Email)

// 2-6
Email
| where sender contains "thresher_libero@hotmail.com" or sender contains "chopping_asbestosis@verizon.com"
    or sender contains "dissemblelebanon@aol.com" or sender contains "sculpturalmintiest@protonmail.com"

Email
| where link contains "citygridsolutions.net" or link contains "infrastructurewatch.org" or link contains "chicagogridupdates.com"
| distinct recipient

// 2-7
let threat_employee =
Email
| where link contains "citygridsolutions.net" or link contains "infrastructurewatch.org" or link contains "chicagogridupdates.com"
| distinct recipient;
let threat_host =
Employees
| where email_addr in (threat_employee)
| distinct hostname;
ProcessEvents
| where hostname in (threat_host)
| where process_commandline contains "/dclist:"

// 2-8
let threat_employee =
Email
| where link contains "citygridsolutions.net" or link contains "infrastructurewatch.org" or link contains "chicagogridupdates.com"
| distinct recipient;
let threat_host =
Employees
| where email_addr in (threat_employee)
| distinct hostname;
FileCreationEvents
| where hostname in (threat_host)
| where timestamp >= (datetime(2024-08-29))
| where path contains "password"

// 2-9
let threat_ip =
PassiveDns
| where domain contains "chicagogridupdates.com"
| distinct ip;
InboundNetworkEvents
| where src_ip in (threat_ip)
| where url contains "upcoming"

// 2-10
let threat_employee =
Email
| where link contains "citygridsolutions.net" or link contains "infrastructurewatch.org" or link contains "chicagogridupdates.com"
| distinct recipient;
let threat_host =
Employees
| where email_addr in (threat_employee)
| distinct hostname;
ProcessEvents
| where hostname in (threat_host)
| where timestamp >= (datetime(2024-09-10))
```
