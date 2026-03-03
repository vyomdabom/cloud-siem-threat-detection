# Cloud SIEM Threat Detection (Azure + Microsoft Sentinel)

##  Project Overview

This project demonstrates the deployment of a Windows-based honeypot in Microsoft Azure to simulate real-world attack exposure. Security logs were centralized into Microsoft Sentinel, where KQL queries were developed to detect brute-force authentication attempts (Event ID 4625). Logs were enriched using a GeoIP watchlist to visualize global attack origins through a custom Sentinel attack map.

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
| summarize FailedAttempts = count() by IpAddress
| order by FailedAttempts desc
