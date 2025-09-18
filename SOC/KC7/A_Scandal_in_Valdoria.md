# A Scandal in Valdoria

This analyst investigated an email phishing attack in Valdoria that uncovered a politically motivated influence campaign. Using Kusto Query Language (KQL), they analyzed employee roles, email communications, and computer process events, revealing evidence of data exfiltration and manipulation. This exercise reinforced skill in querying data and understanding data integrity within a cybersecurity context.

```KQL
Employees
| take 10

Employees
| count

Employees
| where role == "Editorial Director"

Email
| where recipient == "nene_leaks@valdoriantimes.news"
| count

Email
| where sender has "weprinturstuff.com"
| count

Employees
| where name == "Lois Lane"

OutboundNetworkEvents
| where src_ip == "10.10.0.22"

PassiveDns
| where domain contains "hire"

PassiveDns
| where domain == "jobhire.org"

Employees
| where name has "Mary"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip == "10.10.0.50"

let Mary = Employees
| where name has "Mary"
| distinct username;
AuthenticationEvents
| where username in (Mary)
| count

Employees
| where role == "Editorial Intern"

Employees
| where name == "Clark Kent"
// ronnie_mclovin@valdoriantimes.news

Employees
| where role == "Editorial Intern"

Employees
| where name == "Clark Kent"

Email
| where recipient has "clark_kent@valdoriantimes.news"

Employees
| where name == "Sonia Gose"
// sonia_gose@valdoriantimes.news

Email
| where recipient has "sonia_gose@valdoriantimes.news"

Employees
| where name has "Sonia Gose"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip == "10.10.0.3"

Employees
| where name == "Sonia Gose"

FileCreationEvents
| where hostname contains "UL0M-MACHINE"

ProcessEvents
| where hostname contains "UL0M-MACHINE" and process_commandline contains "plink.exe"

ProcessEvents
| where hostname contains "UL0M-MACHINE"

Email
| where sender has "valdorias_best_recruiter@gmail.com"

Employees
| where name == "Ronnie McLovin"
//A37A-DESKTOP

Email
| where recipient has "ronnie_mclovin@valdoriantimes.news" and sender has "valdorias_best_recruiter@gmail.com"

ProcessEvents
| where hostname contains "A37A-DESKTOP" and process_commandline contains "valdorian"

FileCreationEvents
| where hostname contains "A37A-DESKTOP"

Employees
| where name has "Ronnie McLovin"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip == "10.10.0.19" and url contains "docx"

FileCreationEvents
| where hostname contains "A37A-DESKTOP"

ProcessEvents
| where hostname contains "A37A-DESKTOP" and process_commandline contains "plink.exe"

OutboundNetworkEvents
| where src_ip == "10.10.0.19" and url contains "docx"

FileCreationEvents
| where hostname contains "A37A-DESKTOP" and filename contains "fake"

ProcessEvents
| where hostname contains "A37A-DESKTOP" and process_commandline contains "fake"

Employees
| where name has "Ronnie McLovin"
//ronnie_mclovin@valdoriantimes.news

Email
| where sender has "ronnie_mclovin@valdoriantimes.news"

ProcessEvents
| where timestamp between (datetime(2024-01-21 07:00:00) .. datetime(2024-01-21 12:00:00))
| where hostname == "A37A-DESKTOP"
| order by timestamp asc

FileCreationEvents
| where hostname contains "A37A-DESKTOP" and filename contains "7z"

ProcessEvents
| where hostname contains "A37A-DESKTOP" and process_commandline contains "7z"
```
