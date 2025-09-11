# TP-Link Router Information Fetcher

## Description

A Python script that fetches router information such as connected devices, router status, and product info from various TP-Link routers, including models like TL-WR941HP, Archer C6, Archer C54, TL-WR720N, TL-WR802N, and TL-WR3002X. The script supports multiple formats, including HTML, JSON, and DHCP data.

## Why is This Important?

This tool is essential for network administrators, home users, and developers who want to monitor, manage, or troubleshoot their TP-Link routers. It automates the process of fetching critical network data such as connected devices, IP addresses, wireless settings, and router status, helping users maintain their network effectively. It also provides insights into router performance and device behavior, which can be useful for network optimization and security auditing.

## Who Can Use This?

- **Network Administrators**: To monitor connected devices and network settings for efficient management of the network.
- **Home Users**: For easy access to information about connected devices, IP addresses, and router status.
- **Developers and Enthusiasts**: For automating router data fetching, integration into larger systems, or testing router functionality.
- **Security Auditors**: To check connected devices and review the security status of the network.

## Features

- **Fetch Connected Devices**: Get details of all connected devices including MAC address, IP address, and lease time.
- **Router Status Information**: Collect status data for LAN, WAN, wireless networks, and system stats.
- **Support for Multiple Router Models**: Works with several TP-Link router models such as TL-WR941HP, Archer C6, Archer C54, TL-WR720N, TL-WR802N, and TL-WR3002X.
- **Headless Browsing Support**: Uses `Selenium` for scraping dynamic pages where necessary.
- **Output as JSON**: Save fetched data in JSON format for easy analysis and reporting.
- **Works with Emulator URLs**: The script supports both local router URLs and publicly available emulator links for different TP-Link router models.
- **Wi-Fi and Traffic Stats**: Provides detailed stats about your wireless networks (SSID, radio status, channel) and traffic data (bytes received/sent).

## Requirements

- Python 3.x
- Libraries: `requests`, `beautifulsoup4`, `selenium`
- Install dependencies: `pip install requests beautifulsoup4 selenium`
