Jojo's Hospital

```KQL
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname

FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"

FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
| count

FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
// AMFB-MACHINE
// andavis

Employees
| where username contains "andavis"

ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) ..  datetime(2024-06-18))

OutboundNetworkEvents
| where url has "patient_data_exporter.exe"

PassiveDns
| where domain == "secure-health-access.com"

PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")

InboundNetworkEvents
| where src_ip  in ("203.0.113.1", "203.0.113.2")

InboundNetworkEvents
| where src_ip  in ("203.0.113.1", "203.0.113.2")
| where url has "bypass"

InboundNetworkEvents
| where src_ip  in ("203.0.113.1", "203.0.113.2")
| where url has "patient"

AuthenticationEvents
| where src_ip  in ("203.0.113.1", "203.0.113.2")

Employees
| where username == "andavis"

OutboundNetworkEvents
| where url contains "raisinkanes"
| distinct src_ip

OutboundNetworkEvents
| where url contains "raisinkanes"

OutboundNetworkEvents
| where url contains "docx"

OutboundNetworkEvents
| where url contains "pdf"

FileCreationEvents
| where filename == "Raisin_Kane_Promo_Offer.docx"

FileCreationEvents
| where hostname == "RQJQ-MACHINE"

ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))

ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-02) .. datetime(2024-05-04))

InboundNetworkEvents
| where src_ip contains "93.238.22.122"

ProcessEvents
| where process_commandline contains "cobalt"
| where hostname contains "AMFB-MACHINE"

ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-05-13) .. datetime(2024-05-17))

```
