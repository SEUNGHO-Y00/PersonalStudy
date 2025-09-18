# Valdoria Votes

This analyst successfully investigated a hacktivist intrusion on FramtidX system. Through their use of Kusto Query Language (KQL), they discovered how the intruders managed to deface the company’s website and internal documents. They followed the activities of the threat actor, from reconnaissance to exfiltration, and uncovered the use of an internal account to further their compromise.

```KQL
Employees
| where role == "Deputy Commissioner"

Employees
| where name == "Dora Thomas"

Employees
| where role contains "supervisor"

Employees
| where name == "Barry Schmelly"
// 10.10.0.12
// GCH3-DESKTOP
// barry_schmelly@valdoriavotes.gov

Email
|where recipient ==  "barry_schmelly@valdoriavotes.gov"
| count

ProcessEvents
| where hostname == "GCH3-DESKTOP"
| distinct process_commandline

let wills_ips =
Employees
| where name has "William"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (wills_ips)
| distinct url

let w_username = Employees
|where name has "William"
|distinct username;
AuthenticationEvents
| where username in (w_username)

Email
| take 10

AuthenticationEvents
| take 10

InboundNetworkEvents
| take 5

OutboundNetworkEvents
| take 10

PassiveDns
| where ip contains "55.49"

PassiveDns
| where domain contains "valdoriavotes"

let ips = PassiveDns
| where domain == "valdoriavotesgov.com"
| distinct ip;
InboundNetworkEvents
| where src_ip  in (ips)

OutboundNetworkEvents
| where url contains "valdoriavotesgov"

Employees
| where username contains "ansnooper"

AuthenticationEvents
| where username == "ansnooper"
| where timestamp between(datetime(2024-10-05T10:46:47Z) .. datetime(2024-10-11T10:46:47Z))

Email
| where recipient contains "snooper"

Employees
| where name contains "barry"

Email
| where recipient contains "barry" and sender contains "snooper"

Employees
| where username contains "ansnooper"

InboundNetworkEvents
| where src_ip contains "10.10.0.4"

AIPrompts
| where prompt contains "voting machines"

AIPrompts
| where response contains "votes"

AIPrompts
| where response contains "vendor"

AIPrompts
| where prompt contains "Election Commissioner"

Employees
| where role contains "Election"

Employees
| where name contains "bobama"
// arbobama
// arrack_bobama@valdoriavotes.gov

AuthenticationEvents
| where username contains "arbobama"

Email
| where recipient contains "bobama"
```
