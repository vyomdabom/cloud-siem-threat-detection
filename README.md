# Cloud SIEM Threat Detection (Azure + Microsoft Sentinel)

##  Project Overview

This project demonstrates the deployment of a publicly exposed Windows honeypot in Microsoft Azure to simulate real-world attack activity. Security events were centralized into Microsoft Sentinel (SIEM), where KQL queries were developed to detect and analyze brute-force authentication attempts (Event ID 4625). Log data was enriched using a GeoIP watchlist to attribute attack sources geographically and visualize global threat activity through a custom Sentinel attack map.
---

##  Architecture

- Azure Windows 10 Virtual Machine (Honeypot)
- Network Security Group (Open inbound rule for attack simulation)
- Windows Security Event Logs
- Azure Log Analytics Workspace
- Microsoft Sentinel (SIEM)
- GeoIP Watchlist (Log Enrichment)
- Sentinel Workbook (Attack Map Visualization)

---

##  Detection Engineering

Failed login attempts were detected using:

Event ID: **4625**

Example KQL Query:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

---

##  Findings & Analysis

During a 24-hour observation period, the exposed Azure virtual machine recorded:

- **65,187 total failed login attempts**
- **12 unique external attacker IP addresses**
- Peak attack window: **23,817 failed attempts within a single hour**

###  Most Targeted Accounts

- EAST – 31,883 attempts  
- ADMINISTRATOR – 19,800 attempts  
- ADMIN – 4,857 attempts  
- USER – 4,319 attempts  

This pattern indicates automated brute-force and credential-spraying activity targeting common administrative usernames.

###  Geographic Distribution of Attack Sources

Top originating countries:

1. Vietnam – 20,261 attempts  
2. Netherlands – 11,622 attempts  
3. New Zealand – 8,751 attempts  
4. Philippines – 8,604 attempts  
5. Taiwan – 7,011 attempts  
6. South Korea – 3,536 attempts  

The distributed geographic activity suggests botnet-driven automated attack behavior rather than a single targeted actor.

---

##  Attack Map Visualization

<img width="1572" height="968" alt="Screenshot 2026-03-04 101520" src="https://github.com/user-attachments/assets/b9adf360-bbca-45e4-9dee-3b6137e1d549" />

---

##  Security Recommendations

Based on observed brute-force activity, the following controls are recommended:

- Restrict RDP exposure using Network Security Group rules
- Implement Azure Bastion instead of public RDP access
- Enforce Multi-Factor Authentication (MFA)
- Configure Sentinel analytic rules for automated alerting
- Enable account lockout policies
- Use Just-In-Time (JIT) VM access

This project demonstrates the importance of centralized logging, detection engineering, and layered cloud security controls.
