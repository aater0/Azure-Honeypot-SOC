# 🛡️ Azure Honeypot SOC Lab with Microsoft Sentinel

## Overview
This repository documents my hands-on cybersecurity lab using **Microsoft Azure** and **Microsoft Sentinel** to create a **honeypot virtual machine**, log **failed login attempts**, enrich those logs with geographic data, and visualize attacker activity on an **interactive map**.

This lab simulates a **Security Operations Center (SOC)** setup, giving me practice with **Kusto Query Language (KQL)**, log analysis, and real-world detection workflows.

---

## 💪 Lab Objectives
- Set up an Azure subscription
- Deploy and configure a honeypot VM
- Generate failed login attempts
- Collect and query logs using Microsoft Sentinel and KQL
- Enrich logs with geolocation data
- Visualize attack data on a custom map dashboard

---

## 📌 Tools & Technologies Used
- **Microsoft Azure**
- **Microsoft Sentinel**
- **Log Analytics Workspace (LAW)**
- **Windows 10 Virtual Machine**
- **KQL (Kusto Query Language)**
- **GeoIP Data**
- **Sentinel Workbooks**

---

## 📌 Lab Checklist & Steps

### 🔹 Part 1: Azure Subscription Setup
- Created a free Azure subscription via [azure.microsoft.com](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)
- Logged in to Azure Portal: [https://portal.azure.com](https://portal.azure.com)

### 🔹 Part 2: Deploying the Honeypot VM
- Created a **Windows 10 Virtual Machine**
- Configured **inbound rules** in the Network Security Group to allow all traffic
- Disabled Windows Firewall via `wf.msc`

![VM Setup](images/vm-setup.png)

---

### 🔹 Part 3: Simulating Failed Logins
- Failed 3 login attempts using the username `employee`
- Logged into the VM and opened **Event Viewer**
- Verified failed login logs (Event ID: **4625**)

![Failed Logins in Event Viewer](images/event-viewer.png)

---

### 🔹 Part 4: Sentinel Setup & KQL Querying
- Created a **Log Analytics Workspace (LAW)**
- Created a **Microsoft Sentinel instance** and connected it to LAW
- Enabled the **Security Events via AMA** connector
- Queried logs using KQL:

```kql
SecurityEvent
| where EventID == 4625
```

![KQL Query in Sentinel](images/kql-query.png)

---

### 🔹 Part 5: Log Enrichment with GeoIP Data
- Imported a `geoip-summarized.csv` file as a **Sentinel Watchlist** (alias: `geoip`)
- Used KQL to enrich SecurityEvent logs with location data:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<attacker IP address>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

![GeoIP Watchlist Enrichment](images/geoip-enrichment.png)

---

### 🔹 Part 6: Creating the Attack Map
- Created a **Sentinel Workbook**
- Deleted default elements and added a **Query element**
- Loaded JSON from `map.json` into the advanced editor to build an **interactive attack map**

![Attack Map Screenshot](images/attack-map.png)

---

## 📊 Sample Output

Here’s what the final output looked like:

- ✔️ Failed login attempts tracked by IP and username
- ✔️ Logs enriched with geographic data
- ✔️ Interactive workbook showing real-time attacker origin

![Sample Dashboard](images/final-dashboard.png)

---

## 🧠 Key Skills Learned
- Building a honeypot in Azure
- Setting up Microsoft Sentinel with LAW
- Writing KQL queries to analyze security data
- Enriching logs using Watchlists and external data
- Visualizing data with custom Sentinel dashboards

---
