# Frognado in Valdoria Part2

* [Resource](https://medium.com/@Abdalla116/kql-kc7-frognado-in-valdoria-part-2-13556e01adfb)

* How many distinct roles were targeted by the spearphishing emails?

```KQL
let phishing_email =
Email
| where sender == "alex_johnson@framtidxdevcorp.com"
| where recipient contains "framtidxdevcorp"
| where link contains "green" or link contains "development"
| distinct recipient;
Employees
| where email_addr in (phishing_email)
| distinct role
| count
```

* What is the email address of that person?

```KQL
Email
| where recipient contains "Johanna"
| summarize count() by sender
| sort by count_ asc
```

