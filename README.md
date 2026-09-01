# Azure Cloud Honeypot & SOC Lab

A hands-on project simulating a small Security Operations Center (SOC) pipeline in Microsoft Azure: deploying an intentionally exposed Windows VM as a honeypot, capturing real-world attack traffic, centralizing logs, enriching them with geolocation data, and visualizing global attacker distribution.

## Summary

This project stands up a minimal but complete detection pipeline using free-tier Azure resources:

1. An internet-exposed Windows 10 VM configured to attract unsolicited login attempts
2. Centralized log forwarding into a Log Analytics Workspace (LAW)
3. A Microsoft Sentinel (SIEM) instance connected to that workspace
4. KQL-based log analysis of failed authentication attempts (Event ID 4625)
5. Geolocation enrichment of attacker IP addresses
6. A geographic visualization showing where attacks originated

Within hours of deployment, the honeypot recorded thousands of failed login attempts from sources across dozens of countries — a concrete demonstration of how quickly unprotected infrastructure gets discovered and targeted on the public internet.

## Architecture

```
Azure Subscription
└── Resource Group (rg-soc-lab)
    ├── Virtual Network + Subnet
    ├── Windows 10 VM ("honeypot")
    │   ├── Public IP — wide open Network Security Group (all inbound allowed)
    │   ├── Windows Defender Firewall — disabled
    │   └── Azure Monitor Agent → forwards Security event logs
    ├── Log Analytics Workspace (central log repository)
    ├── Microsoft Sentinel instance (connected to the LAW)
    └── Storage Account (added mid-project, see below)
        └── Blob container — hosts GeoIP CSV for lookup
```

## Build process

### 1. Subscription and networking
Created a free Azure subscription, a resource group, and a virtual network/subnet to host the lab.

### 2. Honeypot VM
Deployed a Windows 10 VM into the virtual network. To make it attractive to opportunistic internet scanners:
- Replaced the default Network Security Group rule with one allowing **all inbound traffic, all ports, all protocols**
- Disabled the in-guest Windows Defender Firewall entirely
- Verified reachability from an external network with a basic `ping` test

### 3. Baseline log inspection
Before configuring any forwarding, intentionally triggered failed logins (e.g. attempting to log on as a nonexistent `employee` account) and confirmed they appeared in the local **Event Viewer → Windows Logs → Security** log as **Event ID 4625** (An account failed to log on).

### 4. Centralized logging pipeline
- Created a **Log Analytics Workspace** as the central log repository
- Deployed a **Microsoft Sentinel** instance and connected it to the workspace
- Installed the **Windows Security Events via AMA** data connector
- Created a **Data Collection Rule (DCR)** scoping log collection to the honeypot VM
- Confirmed the Azure Monitor Agent installed successfully and logs began flowing into the workspace (~20–40 minutes for first events to appear)

### 5. Querying with KQL
With logs flowing, used Kusto Query Language (KQL) in Log Analytics to filter and inspect events, for example:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, AccountName, IpAddress
| order by TimeGenerated desc
```

Within the first hour, the honeypot had already logged **thousands of failed login attempts** from public IP addresses around the world — attackers attempting common usernames (`admin`, `administrator`, etc.) against the exposed RDP-adjacent surface.

## Challenge: Sentinel Watchlist and Workbook outage

The standard version of this lab uses two native Sentinel features to finish the pipeline:
- A **Watchlist** — an uploaded CSV mapping IP ranges (CIDR blocks) to city/country/lat-long, used to enrich logs with geolocation via the `ipv4_lookup()` KQL plugin
- A **Workbook** — a Sentinel dashboard that visualizes enriched data on an interactive world map

During this build, both the Watchlist and Workbook blades in the Azure/Defender portal were affected by a known, actively-reported platform issue: clicking into either page redirected back to **Settings → Microsoft Sentinel → SIEM Workspaces** in a loop, regardless of account permissions, browser, or session state. This was confirmed as a broader Sentinel/Defender-portal migration issue affecting multiple users at the time, not a misconfiguration on this deployment.

Rather than wait on a platform-side fix, I re-implemented the same functionality using tools that don't depend on the broken UI.

### Workaround: replacing the Watchlist

A Sentinel Watchlist is fundamentally just a managed lookup table. The same result can be achieved with KQL's built-in `externaldata()` operator, which fetches a CSV from any URL at query time — no Sentinel feature required.

**Steps taken:**
1. Provisioned an Azure Storage Account (in the same resource group) with a Blob container
2. Enabled anonymous blob-level read access (scoped to just that container, not the whole account) and uploaded the GeoIP CSV
3. Queried the hosted CSV directly from Log Analytics, joining it against attacker IPs using the `ipv4_lookup()` plugin (the same CIDR-matching function the Watchlist-based approach would have used):

```kql
let geoip = externaldata(network:string, latitude:real, longitude:real, cityname:string, countryname:string)
["https://<storageaccount>.blob.core.windows.net/geodata/geoip-summarized.csv"]
with (format="csv", ignoreFirstRecord=true);
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, AttackerIP = IpAddress
| evaluate ipv4_lookup(geoip, AttackerIP, network)
| summarize AttackCount = count() by cityname, countryname, latitude, longitude
| order by AttackCount desc
```

This produced identical output to the native Watchlist join: each failed-login event enriched with the attacker's city, country, and coordinates.

### Workaround: replacing the Workbook map

With the Workbook editor also inaccessible, the aggregated, geo-enriched query results were exported directly from Log Analytics (Export → CSV) and rendered as a standalone interactive world map — attacker location as a bubble, bubble size and color intensity scaled to attack volume, with hover tooltips showing exact city/country/count.

## Results

The final enriched dataset showed failed login attempts originating from at least 15 countries within the observation window, including large volumes from the Netherlands, Argentina, the United States, Brazil, and Mexico, down to single-digit probing attempts from countries like Egypt, India, and Indonesia — illustrating both high-volume automated scanning and low-volume opportunistic attempts hitting the same exposed host simultaneously.

| Metric | Value |
|---|---|
| Failed login events captured (Event ID 4625) | 6,000+ within the first hour; tens of thousands over the observation period |
| Distinct source locations identified | 15+ countries |
| Top source | Netherlands (11,949 failed attempts from a single resolved location) |
| Time to first external discovery | Under 1 hour of public exposure |

## Skills demonstrated

- Azure resource provisioning: resource groups, virtual networks, VMs, storage accounts
- Network security group and OS-level firewall configuration
- Log Analytics Workspace and Microsoft Sentinel deployment and configuration
- Windows Security event log analysis (Event Viewer, Event ID interpretation)
- KQL (Kusto Query Language): filtering, projection, aggregation, and the `externaldata()` and `ipv4_lookup()` plugins
- Log enrichment techniques for threat intelligence / geolocation correlation
- Troubleshooting and adapting when a managed platform feature is unavailable, including building an equivalent pipeline from lower-level primitives
- Basic Azure Blob Storage configuration, including scoped anonymous access

## Cleanup

All resources (VM, storage account, Log Analytics Workspace, Sentinel instance, resource group) were deprovisioned after the lab to avoid ongoing Azure charges. In a production environment, this pipeline's components — log forwarding, enrichment, and dashboarding — would be left running continuously and backed by an automatically-updating threat intelligence feed rather than a static CSV.
