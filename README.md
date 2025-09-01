# TP-Link Router Info Fetcher

## 📌 Overview
This Python script collects and displays **router information, connected devices, and system stats** from multiple TP-Link models:
- **TL-WR941HP**
- **Archer C6**
- **Archer C54**

It parses DHCP clients, wireless clients, WAN/LAN details, traffic statistics, firmware info, and more. Output is also saved as JSON for further analysis or integration.

---

## 🚀 Why is this Important?
- **Network Security:** Quickly identify all connected devices to detect intruders.  
- **Troubleshooting:** Check WAN/LAN status, DNS, and connection types in one shot.  
- **Monitoring:** Log router stats (traffic, system info, wireless SSID) for auditing or debugging.  
- **Automation:** No need to manually log in to router dashboards—data is fetched programmatically.

---

## 🎯 Who Can Use This?
- **Home users** who want to monitor their Wi-Fi and check for unauthorized devices.  
- **IT admins / Network engineers** managing small offices or labs.  
- **Researchers & developers** interested in parsing router data for analytics or security testing.  

---

## ⚡ Features
- Supports **three router models** with tailored functions.  
- Retrieves and prints **device lists, LAN/WAN/Wi-Fi info, system details, traffic stats**.  
- Saves outputs in **structured JSON**.  
- Works with both **HTTP APIs** and **Selenium scraping** (for modern router UIs).  
- CLI-based: simple to run, no GUI needed.
