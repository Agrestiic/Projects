# Projects
Azure Sentinel Honeypot with Live Cyber-Attacks
This project demonstrates setting up a honeypot using Azure Sentinel, ingesting system and geographic logs, and visualizing attack data on a map.

## Prerequisites

- Azure account
- Azure VM setup
- Log Analytics Workspace (LAW)
- Microsoft Defender for Cloud
- Microsoft Sentinel
- IP Geolocation API key from [ipgeolocation.io](https://ipgeolocation.io/)

## Setup Instructions

### 1. Create and Configure Azure VM
1. Create a VM in Azure.
2. Set up an inbound rule to allow all traffic so it can be discoverable.

### 2. Create Log Analytics Workspace
1. Create a Log Analytics Workspace to ingest system event logs and geographic logs.

### 3. Enable Microsoft Defender for Cloud
1. Go to Microsoft Defender for Cloud.
2. Enable it for the LAW-honeypot and disable SQL as it is not needed.

### 4. Connect VM to Log Analytics Workspace
1. Go to the Log Analytics Workspace.
2. Connect it to your virtual machine by selecting the VM from the classic tab.

### 5. Connect Microsoft Sentinel
1. Go to Microsoft Sentinel.
2. Connect it to the LAW-honeypot.

### 6. Ingest Custom Logs
1. Use the public IP of the VM to sign in via Remote Desktop Protocol (RDP) using the login details set up earlier.
2. Generate data by deliberately failing RDP logins (Event ID 4625 in Event Viewer -> Security tab).

### 7. Make VM Discoverable
1. Disable the firewall within the VM if it is receiving request timeouts.

### 8. Download and Configure Custom Log Exporter
1. Download the custom log exporter script from [here](https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1).
2. Create an account with ipgeolocation.io, get your API key, and paste it into the script.
3. Save the script to the desktop, run it in PowerShell ISE, and save logs to `C:\programdata\failed_rdp.log`.

### 9. Create Custom Log in Azure
1. In Azure LAW-honeypot, go to Tables -> Create -> New Custom Log (MMA-Based).
2. Set the collection path to `C:\programdata\failed_rdp.log`.

### 10. Query and Visualize Data
1. After about 15 minutes, query the log with the naming convention `Failed_RDP_with_GEO_CL` (case-sensitive).
2. Use the following KQL query:


```kql
Failed_RDP_with_GEO_CL
| extend username = extract(@"username:([^]+)", 1, RawData)
         timestamp = extract(@"timestamp:([^]+)", 1, RawData)
         latitude = extract(@"latitude:([^]+)", 1, RawData)
         longitude = extract(@"longitude:([^]+)", 1, RawData)
         sourcehost = extract(@"sourcehost:([^]+)", 1, RawData)
         state = extract(@"state:([^]+)", 1, RawData)
         label = extract(@"label:([^]+)", 1, RawData)
         destination = extract(@"destinationhost:([^]+)", 1, RawData)
         country = extract(@"country:([^]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
```

###Change the visualization to a map, select full view, and adjust the metric label to label.

###Visualization Example

##T#his visualization shows the geolocation of threat actors attempting to log into the honeypot.

![image](https://github.com/Agrestiic/Projects/assets/114885541/c65d3134-681f-471e-b2a2-d53355ba3dd8)




