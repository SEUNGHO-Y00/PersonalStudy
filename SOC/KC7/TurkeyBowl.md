# Turkey Bowl

```kql
// 1-2
Employees
| take 10

// 1-3
Employees
| count

// 1-4
Employees
| where role == "Lead Coach"

// 1-5
Email
| where recipient has "dill_delichick@go-oxford-owls.edu"

// 1-6
Email
| where recipient has "go-oxford-owls.edu"
| where subject has "turkey"
| distinct recipient

// 1-7
Employees
| where name contains "Patrick Stump"
// 10.10.0.25

OutboundNetworkEvents
| where src_ip == "10.10.0.25"
| distinct url

// 1-8
PassiveDns
| where domain contains "owls"
| distinct domain

// 1-9
let mary_ips = 
Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url

// 2-1, 2-2
Employees
| where name contains "Tac Zaylor"
// 10.10.0.13

// 2-3, 2-5, 2-6, 2-8
Email
| where recipient contains "tac_zaylor@go-oxford-owls.edu"
| where sender contains "go-oxford-owls.edu"

// 2-4
let student =
Email
| where recipient contains "tac_zaylor@go-oxford-owls.edu"
| where sender contains "go-oxford-owls.edu"
| distinct sender;
Employees
| where email_addr has_any (student)
| where role contains "student"

// 2-7
Employees
| where email_addr has "brover_pham@go-oxford-owls.edu"

// 2-9
Email
| where links contains "Help_with_Playbook-Heres_What_I_tried.pdf"

// 2-10, 2-11
FileCreationEvents
| where filename contains "Help_with_Playbook-Heres_What_I_tried.pdf"

// 2-12, 2-13
FileCreationEvents
| where username has "tazaylor"
| where timestamp between (datetime(2024-11-15) .. 2d)

// 2-15, 3-1, 3-2
ProcessEvents
| where username has "tazaylor"
| where timestamp >= datetime(2024-11-15)

// 2-16, 2-17
PassiveDns
| where ip contains "66.159.94.55"
| distinct domain

// 2-19, 2-20, 2-22, 2-23
InboundNetworkEvents
| where src_ip == "66.159.94.55"

// 3-3, 3-5
FileCreationEvents
| where username has "tazaylor"
| where timestamp >= (datetime(2024-11-15))

// 3-4
OutboundNetworkEvents
| where url contains "Advanced_IP_Scanner_2.5.3850.exe"

// 3-6, 3-7, 3-8, 3-9, 3-10
ProcessEvents
| where username has "tazaylor"
| where timestamp >= (datetime(2024-11-27))

// 3-11, 3-16, 3-17, 3-18, 3-19, 3-20
ProcessEvents
| where parent_process_hash == "614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f"
| where username has "tazaylor"

// 3-21
InboundNetworkEvents
| where url contains "playbooks"
```
