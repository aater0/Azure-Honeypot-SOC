# 🛡️ Azure Honeypot SOC Lab with Microsoft Sentinel

![Goal overview](https://github.com/user-attachments/assets/bdd757f1-def5-48fe-8fcc-5376e8630e7a)



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
- Created a free Azure subscription (New users get a free tiral and everyone else has to pay for what you use)
- Logged in to Azure Portal

### 🔹 Part 2: Deploying the Honeypot VM
- Created a **Windows 10 Virtual Machine**

![Create virtual Machine](https://github.com/user-attachments/assets/22fa3230-165c-45d4-89c4-7d5275ce652e)


- Configured **inbound rules** in the Network Security Group to allow all traffic

![Creating inbound security rule](https://github.com/user-attachments/assets/535d9acc-d153-4768-a75a-a77c9b306842)

  
- Disabled Windows Firewall via `wf.msc`

![Turning Firewall off](https://github.com/user-attachments/assets/172ab238-2205-42a3-ac61-986aade29c1e)


---

### 🔹 Part 3: Simulating Failed Logins
- Failed 3 login attempts using the username `employee`
- Logged into the VM and opened **Event Viewer**
- Verified failed login logs (Event ID: **4625**)

![Event Viewer logs](https://github.com/user-attachments/assets/be90e441-96ee-44be-8deb-e8d821c60770)


---

### 🔹 Part 4: Sentinel Setup & KQL Querying
- Created a **Log Analytics Workspace (LAW)**

![Creating a LAW](https://github.com/user-attachments/assets/347bab68-b459-4cbd-af53-13f7d8579c83)

  
- Created a **Microsoft Sentinel instance** and connected it to LAW

![Sentinal page](https://github.com/user-attachments/assets/2c5c4a86-2f9e-4d03-886c-de9fc7764240)
![Merging LAW with Sentinal](https://github.com/user-attachments/assets/7b90d2fa-9b84-488e-8f2b-86573fe372cd)

  
- Enabled the **Security Events via AMA** connector

![Connector page](https://github.com/user-attachments/assets/3b77caee-dddc-4da5-8fb8-c9eda9b65de3)


- Queried logs using KQL:

![Runing Secuirty event query 2](https://github.com/user-attachments/assets/1503bef4-a9d3-4854-8190-54507fe65a5c)



```kql
SecurityEvent
| where EventID == 4625
```

---

### 🔹 Part 5: Log Enrichment with GeoIP Data
- Imported a `geoip-summarized.csv` file as a **Sentinel Watchlist** (alias: `geoip`)

![Uploaded ip address info](https://github.com/user-attachments/assets/2b9acad9-3a21-46aa-936e-d23aa0b3a94f)


- Used KQL to enrich SecurityEvent logs with location data:

![With projections](https://github.com/user-attachments/assets/5158b94e-6231-4261-9874-dbff09ea00a6)


```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<attacker IP address>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

---

### 🔹 Part 6: Creating the Attack Map
- Created a **Sentinel Workbook**

![Workbook](https://github.com/user-attachments/assets/8397607c-00e2-43eb-b5ed-47765036e421)


- Deleted default elements and added a **Query element**
- Built a geolocation heatmap in Sentinel Workbooks to visually display the geographic origin of attacks—automatically enriched with location data using built-in visualization tools.

![Map view 2](https://github.com/user-attachments/assets/f67322e4-9c21-4132-8d95-e559c5f8022a)



---

## 📊 Sample Output

Here’s what the final output looked like:

- ✔️ Failed login attempts tracked by IP and username
- ✔️ Logs enriched with geographic data
- ✔️ Interactive workbook showing real-time attacker origin

![Map view 1](https://github.com/user-attachments/assets/a53bfddd-947f-40f4-80c6-d9022eecd9fc)


---

## 🧠 Key Skills Learned
- Building a honeypot in Azure
- Setting up Microsoft Sentinel with LAW
- Writing KQL queries to analyze security data
- Enriching logs using Watchlists and external data
- Visualizing data with custom Sentinel dashboards

---
