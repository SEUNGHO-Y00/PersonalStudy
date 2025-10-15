# Clout Defender

This analyst unraveled a targeted phishing and social engineering attack against a rising influencer. Through OSINT, phishing analysis, and log forensics, they uncovered how personal details shared on social media were exploited to compromise her accounts. Using Kusto Query Language (KQL), they analyzed employee logs, inbound and outbound traffic, and passive DNS data to trace the attacker’s steps and infrastructure. This exercise strengthened skills in threat analysis, digital forensics, and understanding the real-world risks of oversharing online.

```KQL
Employees
| where name contains "afomiya"

Employees
| where name contains "afomiya"
| distinct mfa_enabled

Email
| where recipient == "afomiya_storm@clouthaus.com"
| where subject contains "Dior" or links contains "Dior"

OutboundNetworkEvents
| where url contains "https://super-brand-offer.com/login"

PassiveDns
| where domain contains "super-brand-offer.com"

PassiveDns
| where ip contains "198.51.100.12"
| distinct domain

AuthenticationEvents
| where username == "afstorm"

PassiveDns
| where ip == "182.45.67.89"

InboundNetworkEvents
| where src_ip contains "182.45.67.89"

Email
| where reply_to contains "afomiya"

```
