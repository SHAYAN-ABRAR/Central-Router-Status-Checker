import requests
import hashlib
import base64
from urllib.parse import urlparse
import re
import time
import json
import os
import logging
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# TL-WR941HP Functions
def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_auth_cookie(username, password, use_md5=True):
    if use_md5:
        password = md5_hash(password)
    auth_str = f"{username}:{password}"
    b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    return f"Basic {b64_auth}"

def login_wr941hp(router_url, username, password, login_path="/userRpm/LoginRpm.htm"):
    session = requests.Session()
    auth_cookie = get_auth_cookie(username, password, use_md5=True)
    domain = urlparse(router_url).netloc
    session.cookies.set("Authorization", auth_cookie, path="/", domain=domain)
    login_url = router_url + login_path
    params = {"Save": "Save"}
    try:
        resp = session.get(login_url, params=params, allow_redirects=True)
        if resp.status_code == 200:
            return session, resp.url, resp.text
        else:
            return None, None, None
    except requests.exceptions.RequestException:
        return None, None, None

def extract_token_from_url(url):
    match = re.search(r'/([A-Za-z0-9]+)/userRpm/Index\.htm', url)
    if match:
        return match.group(1)
    return None

def extract_token_from_response(resp_text):
    match = re.search(r'/([A-Za-z0-9]+)/userRpm/Index\.htm', resp_text)
    if match:
        return match.group(1)
    return None

def parse_response(resp_text):
    match = re.search(r'href\s*=\s*"([^"]+)"', resp_text)
    if match:
        url = match.group(1)
        path_parts = urlparse(url).path.strip("/").split("/")
        if len(path_parts) >= 2:
            return path_parts[0]
    return None

def retrieve_dhcp_clients(session, token, router_url):
    time.sleep(0.5)
    status_url = f"{router_url}/{token}/userRpm/AssignedIpAddrListRpm.htm"
    headers = {
        "Referer": f"{router_url}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def retrieve_wireless_clients_html(session, token, router_url, page=1, vap_idx=0):
    time.sleep(0.5)
    status_url = f"{router_url}/{token}/userRpm/WlanStationRpm.htm?Page={page}&vapIdx={vap_idx}"
    headers = {
        "Referer": f"{router_url}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def retrieve_router_status(session, token, router_url):
    time.sleep(0.5)
    status_url = f"{router_url}/{token}/userRpm/StatusRpm.htm"
    headers = {
        "Referer": f"{router_url}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def save_to_json(data, output_file="router_status.json"):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

def print_connected_devices_and_status(session, token, router_url, output_file):
    output_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "devices": [],
        "router_status": {
            "lan": {},
            "wan": {},
            "wireless": {},
            "system": {},
            "traffic": {}
        }
    }
    # Fetch wireless MACs
    wireless_macs = set()
    html_text = retrieve_wireless_clients_html(session, token, router_url)
    if html_text:
        try:
            match = re.search(r'var hostList = new Array(\s*(.*?)\s*);', html_text, re.DOTALL)
            if match:
                array_str = match.group(1).strip()
                elements = re.findall(r'"([^"]*)"|(\d+)', array_str)
                elements = [e[0] if e[0] else e[1] for e in elements]
                field_count = 5
                html_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
                wireless_macs = {device[0].lower() for device in html_devices}
        except Exception:
            pass
    # Fetch and parse DHCP clients
    dhcp_text = retrieve_dhcp_clients(session, token, router_url)
    devices = []
    if dhcp_text:
        try:
            match = re.search(r'var DHCPDynList = new Array(\s*(.*?)\s*);', dhcp_text, re.DOTALL)
            if match:
                array_str = match.group(1).strip()
                elements = re.findall(r'"([^"]*)"', array_str)
                field_count = 4
                dhcp_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
                
                devices = [
                    {"name": dev[0], "mac_addr": dev[1], "ip_addr": dev[2], "lease_time": dev[3]}
                    for dev in dhcp_devices if not wireless_macs or dev[1].lower() in wireless_macs
                ]
                
                output_data["devices"] = devices
                print(f"Total connected wireless devices (from DHCP): {len(devices)}")
                for idx, device in enumerate(devices, 1):
                    print(f"{idx}. Details:")
                    print(f" HOST NAME: {device['name']}")
                    print(f" MAC ADDRESS: {device['mac_addr']}")
                    print(f" IP ADDRESS: {device['ip_addr']}")
                    print(f" LEASE TIME: {device['lease_time']}")
        except Exception:
            pass
    # Fetch and parse router status
    status_text = retrieve_router_status(session, token, router_url)
    if status_text:
        try:
            print("\nRouter Status Information:")
            
            # Parse lanPara
            lan_match = re.search(r'var lanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if lan_match:
                lan_elements = re.findall(r'"([^"]*)"|(\d+)', lan_match.group(1))
                lan_elements = [e[0] if e[0] else e[1] for e in lan_elements]
                output_data["router_status"]["lan"] = {
                    "mac_address": lan_elements[0] if len(lan_elements) > 0 else "N/A",
                    "ip_address": lan_elements[1] if len(lan_elements) > 1 else "N/A",
                    "subnet_mask": lan_elements[2] if len(lan_elements) > 2 else "N/A"
                }
            
            # Parse wanPara
            wan_match = re.search(r'var wanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if wan_match:
                wan_elements = re.findall(r'"([^"]*)"|(\d+)', wan_match.group(1))
                wan_elements = [e[0] if e[0] else e[1] for e in wan_elements]
                connection_type = "Dynamic IP" if wan_elements[0] == "4" else "N/A"
                output_data["router_status"]["wan"] = {
                    "mac_address": wan_elements[1] if len(wan_elements) > 1 else "N/A",
                    "ip_address": wan_elements[2] if len(wan_elements) > 2 else "N/A",
                    "subnet_mask": wan_elements[4] if len(wan_elements) > 4 else "N/A",
                    "gateway": wan_elements[7] if len(wan_elements) > 7 else "N/A",
                    "dns": wan_elements[11] if len(wan_elements) > 11 else "N/A",
                    "connection_type": connection_type
                }
            
            # Parse wlanPara
            wlan_match = re.search(r'var wlanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if wlan_match:
                wlan_elements = re.findall(r'"([^"]*)"|(\d+)', wlan_match.group(1))
                wlan_elements = [e[0] if e[0] else e[1] for e in wlan_elements]
                ssids = [wlan_elements[1]] if len(wlan_elements) > 1 and wlan_elements[1] else []
                if len(wlan_elements) > 11 and wlan_elements[11]:
                    ssids.append(wlan_elements[11])
                output_data["router_status"]["wireless"] = {
                    "ssid": ", ".join(ssids) if ssids else "N/A"
                }
            
            # Parse statusPara
            status_match = re.search(r'var statusPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if status_match:
                status_elements = re.findall(r'"([^"]*)"|(\d+)', status_match.group(1))
                status_elements = [e[0] if e[0] else e[1] for e in status_elements]
                output_data["router_status"]["system"] = {
                    "firmware_version": status_elements[5] if len(status_elements) > 5 else "N/A",
                    "hardware_version": status_elements[6] if len(status_elements) > 6 else "N/A"
                }
            
            # Parse statistList
            stat_match = re.search(r'var statistList = new Array\((.*?)\);', status_text, re.DOTALL)
            if stat_match:
                stat_elements = re.findall(r'"([^"]*)"|(\d+)', stat_match.group(1))
                stat_elements = [e[0] if e[0] else e[1] for e in stat_elements]
                output_data["router_status"]["traffic"] = {
                    "bytes_received": stat_elements[0] if len(stat_elements) > 0 else "N/A",
                    "bytes_sent": stat_elements[1] if len(stat_elements) > 1 else "N/A",
                    "packets_received": stat_elements[2] if len(stat_elements) > 2 else "N/A",
                    "packets_sent": stat_elements[3] if len(stat_elements) > 3 else "N/A"
                }
            
            # Print parsed information
            print(" LAN:")
            print(f" MAC Address: {output_data['router_status']['lan'].get('mac_address', 'N/A')}")
            print(f" IP Address: {output_data['router_status']['lan'].get('ip_address', 'N/A')}")
            print(f" Subnet Mask: {output_data['router_status']['lan'].get('subnet_mask', 'N/A')}")
            
            print(" WAN:")
            print(f" MAC Address: {output_data['router_status']['wan'].get('mac_address', 'N/A')}")
            print(f" IP Address: {output_data['router_status']['wan'].get('ip_address', 'N/A')}")
            print(f" Subnet Mask: {output_data['router_status']['wan'].get('subnet_mask', 'N/A')}")
            print(f" Gateway: {output_data['router_status']['wan'].get('gateway', 'N/A')}")
            print(f" DNS: {output_data['router_status']['wan'].get('dns', 'N/A')}")
            print(f" Connection Type: {output_data['router_status']['wan'].get('connection_type', 'N/A')}")
            
            print(" Wireless:")
            print(f" Name (SSID): {output_data['router_status']['wireless'].get('ssid', 'N/A')}")
            
            print(" System:")
            print(f" Firmware Version: {output_data['router_status']['system'].get('firmware_version', 'N/A')}")
            print(f" Hardware Version: {output_data['router_status']['system'].get('hardware_version', 'N/A')}")
            
            print(" Traffic Statistics:")
            print(f" Bytes received: {output_data['router_status']['traffic'].get('bytes_received', 'N/A')}")
            print(f" Bytes sent: {output_data['router_status']['traffic'].get('bytes_sent', 'N/A')}")
            print(f" Packets received: {output_data['router_status']['traffic'].get('packets_received', 'N/A')}")
            print(f" Packets sent: {output_data['router_status']['traffic'].get('packets_sent', 'N/A')}")
        except Exception:
            pass
    # Save to JSON file
    save_to_json(output_data, output_file)
    print(f"\n***Output saved to {output_file}***")

def get_wr941hp_info(router_url, username, password):
    output_file = "wr941hp_status.json"
    session, final_url, resp_text = login_wr941hp(router_url, username, password)
    if session:
        token = extract_token_from_url(final_url)
        if not token:
            token = extract_token_from_response(resp_text)
            if not token:
                token = parse_response(resp_text)
        if token:
            index_url = f"{router_url}/{token}/userRpm/Index.htm"
            response = session.get(index_url)
            if response.ok:
                print_connected_devices_and_status(session, token, router_url, output_file)

# Archer C6 Functions
def fetch_c6_info(url, output_file="archer_c6_status.json"):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        devices = data.get("access_devices_wired", [])
        
        wan_status = {
            "MAC Address": data.get("wan_macaddr", "N/A"),
            "IP Address": data.get("wan_ipv4_ipaddr", "N/A"),
            "Subnet Mask": data.get("wan_ipv4_netmask", "N/A"),
            "Default Gateway": data.get("wan_ipv4_gateway", "N/A"),
            "Primary DNS": data.get("wan_ipv4_pridns", "N/A"),
            "Secondary DNS": data.get("wan_ipv4_snddns", "N/A"),
            "Connection Type": "Dynamic IP" if data.get("wan_ipv4_conntype") == "dhcp" else data.get("wan_ipv4_conntype", "N/A")
        }
        
        lan_status = {
            "MAC Address": data.get("lan_macaddr", "N/A"),
            "IP Address": data.get("lan_ipv4_ipaddr", "N/A"),
            "Subnet Mask": data.get("lan_ipv4_netmask", "N/A"),
            "DHCP": "On" if data.get("lan_ipv4_dhcp_enable") == "On" else "Off"
        }
        
        wireless_2g_status = {
            "Network Name (SSID)": data.get("wireless_2g_ssid", "N/A"),
            "Wireless Radio": "On" if data.get("wireless_2g_enable") == "on" else "Off",
            "Mode": data.get("wireless_2g_hwmode", "N/A").replace("bgn", "802.11b/g/n mixed"),
            "Channel Width": data.get("wireless_2g_htmode", "N/A").capitalize(),
            "Channel": f"{data.get('wireless_2g_channel', 'N/A')} (Current Channel {data.get('wireless_2g_current_channel', 'N/A')})" if data.get("wireless_2g_current_channel") else data.get("wireless_2g_channel", "N/A"),
            "MAC Address": data.get("wireless_2g_macaddr", "N/A"),
            "WDS Status": "Disabled" if data.get("wireless_2g_wds_status") == "disable" else "Enabled"
        }
        
        guest_2g_status = {
            "Network Name (SSID)": data.get("guest_2g_ssid", "N/A"),
            "Hide SSID": "Off" if data.get("guest_2g_hidden") == "off" else "On",
            "Wireless Radio": "Off" if data.get("guest_2g_enable") == "off" else "On",
            "Allow guests to see each other": "Off" if data.get("guest_isolate") == "off" else "On"
        }
        
        product_status = {
            "Firmware Version": data.get("firmware_version", "1.0 Build 20190101 rel.12345"),
            "Hardware Version": data.get("hardware_version", "Archer C6 v2.0")
        }
        
        output_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "devices": devices,
            "router_status": {
                "WAN": wan_status,
                "LAN": lan_status,
                "Wireless 2.4GHz": wireless_2g_status,
                "Guest Network 2.4GHz": guest_2g_status,
                "Product Info": product_status
            }
        }
        
        print("Connected Devices:")
        print(f"Total connected devices: {len(devices)}")
        for idx, device in enumerate(devices, 1):
            print(f"{idx}. Details:")
            print(f" Wire Type: {device.get('wire_type', 'N/A')}")
            print(f" MAC Address: {device.get('macaddr', 'N/A')}")
            print(f" IP Address: {device.get('ipaddr', 'N/A')}")
            print(f" Hostname: {device.get('hostname', 'N/A')}")
        
        print("\nRouter Information:")
        print(" WAN:")
        for key, value in wan_status.items():
            print(f" {key}: {value}")
        
        print(" LAN:")
        for key, value in lan_status.items():
            print(f" {key}: {value}")
        
        print(" Wireless 2.4GHz:")
        for key, value in wireless_2g_status.items():
            print(f" {key}: {value}")
        
        print(" Guest Network 2.4GHz:")
        for key, value in guest_2g_status.items():
            print(f" {key}: {value}")
        
        print(" Product Info:")
        for key, value in product_status.items():
            print(f" {key}: {value}")
        
        save_to_json(output_data, output_file)
        print(f"\n***Output saved to {output_file}***")
        
        return output_data
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"Error parsing JSON: {e}")
        return None

def get_archer_c6_info(url):
    fetch_c6_info(url)

# Archer C54 Functions
def clean_text(text):
    return text.strip().replace('\n', '').replace('\t', '') if text else 'Not Found'

def scrape_c54_info(network_status_url, network_map_url):
    try:
        for url in [network_status_url, network_map_url]:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.error(f"Invalid URL provided: {url}")
                return None
        
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        driver = webdriver.Chrome(options=chrome_options)
        logger.info(f"Navigating to {network_status_url}")
        driver.get(network_status_url)
        
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "userName")))
            username_field = driver.find_element(By.ID, "userName")
            password_field = driver.find_element(By.ID, "pcPassword")
            login_button = driver.find_element(By.ID, "loginBtn")
            username_field.send_keys("admin")  # Default for Archer C54
            password_field.send_keys("admin")  # Default for Archer C54
            login_button.click()
            logger.info("Logged in successfully")
            WebDriverWait(driver, 10).until(EC.invisibility_of_element_located((By.ID, "loginBtn")))
        except TimeoutException:
            logger.info("Login fields not found; assuming login not required")
        
        router_info = {
            'Internet': {'Model': 'TP-LINK Archer C54'},
            'LAN': {},
            'DHCP Server': {},
            'Dynamic DNS': {},
            'Connected Devices': []
        }
        section_mapping = {
            'Internet': router_info['Internet'],
            'LAN': router_info['LAN'],
            'DHCP Server': router_info['DHCP Server'],
            'Dynamic DNS': router_info['Dynamic DNS']
        }
        skip_fields = {'Dynamic DNS': ['Status']}
        
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "div.panel-content-container")))
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        panels = soup.select("div[widget='panel']")
        for panel in panels:
            content_container = panel.find('div', class_='panel-content-container')
            if not content_container:
                continue
            title_label = content_container.find('div', class_='status-label-title')
            if not title_label:
                continue
            section_name = clean_text(title_label.find('label', class_='widget-fieldlabel').text)
            logger.info(f"Found section: {section_name}")
            labels = content_container.find_all('div', {'widget': 'displaylabel'}, class_=lambda x: x != 'status-label-title')
            section_data = {}
            has_valid_data = False
            for label in labels:
                field = label.find('label', class_='widget-fieldlabel')
                value = label.find('span', class_='text-wrap-display')
                if field and value:
                    key = clean_text(field.text)
                    val = clean_text(value.text)
                    if section_name in skip_fields and key in skip_fields[section_name]:
                        continue
                    section_data[key] = val
                    if val != 'Not Found':
                        has_valid_data = True
            if section_name in section_mapping and has_valid_data:
                section_mapping[section_name].update(section_data)
        
        logger.info(f"Navigating to {network_map_url}")
        driver.get(network_map_url)
        try:
            driver.execute_script("window.location.hash = '#networkMap';")
            WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.CSS_SELECTOR, "tbody.grid-content-data tr")))
            time.sleep(2)
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            table_body = soup.select_one('tbody.grid-content-data')
            if not table_body:
                table_body = soup.select_one('table:has(tbody.grid-content-data) tbody')
                logger.info("Using fallback selector for table body")
            if table_body:
                logger.info("Found Connected Devices table body")
                rows = table_body.find_all('tr')
                logger.info(f"Found {len(rows)} rows in the table")
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 6:
                        device_name_elem = cols[1].select_one('div.td-content div.content')
                        device_name = clean_text(device_name_elem.text) if device_name_elem else 'Not Found'
                        mac_elem = cols[2].select_one('div.device-info-container div.mac')
                        ip_elem = cols[2].select_one('div.device-info-container div.ip')
                        mac_address = clean_text(mac_elem.text) if mac_elem else 'Not Found'
                        ip_address = clean_text(ip_elem.text) if ip_elem else 'Not Found'
                        connection_elem = cols[5].select_one('div.connection-container')
                        connection_type = clean_text(connection_elem.text) if connection_elem else 'Not Found'
                        if any(val != 'Not Found' for val in [device_name, mac_address, ip_address, connection_type]):
                            device = {
                                'Device Name': device_name,
                                'MAC Address': mac_address,
                                'IP Address': ip_address,
                                'Connection Type': connection_type
                            }
                            router_info['Connected Devices'].append(device)
        except TimeoutException:
            logger.warning("Timeout waiting for Connected Devices table rows")
        
        # Print router information
        for section, data in router_info.items():
            if section != 'Connected Devices':
                print(f"\n**{section}**")
                for key, value in data.items():
                    print(f"{key}: {value}")
        print("\n**Connected Devices**")
        if router_info['Connected Devices']:
            print("| Device Name | MAC Address | IP Address | Connection Type |")
            print("|-------------|-------------|------------|-----------------|")
            for device in router_info['Connected Devices']:
                print(f"| {device['Device Name']} | {device['MAC Address']} | {device['IP Address']} | {device['Connection Type']} |")
        else:
            print("No connected devices found")
        
        return router_info
    except Exception as e:
        logger.error(f"Error scraping URLs: {str(e)}", exc_info=True)
        return None
    finally:
        driver.quit()

def get_archer_c54_info(network_status_url, network_map_url):
    scrape_c54_info(network_status_url, network_map_url)

# TL-WR720N Functions
def scrape_wr720n_info(status_url, dhcp_url):
    """
    Scrapes router information from a TP-Link TL-WR720N_V2 emulator's status and DHCP client list pages.
    """
    try:
        # Validate URLs
        for url in [status_url, dhcp_url]:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.error(f"Invalid URL provided: {url}")
                return None

        # Fetch status HTML content dynamically
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response_status = requests.get(status_url, headers=headers, timeout=10)
        response_status.raise_for_status()
        html_status = response_status.text

        # Save raw status HTML for debugging
        with open("fetched_status_wr720n.html", "w", encoding="utf-8") as f:
            f.write(html_status)
        logger.info(f"Fetched status HTML saved to fetched_status_wr720n.html (length: {len(html_status)} bytes)")

        # Fetch DHCP client list HTML content dynamically
        response_dhcp = requests.get(dhcp_url, headers=headers, timeout=10)
        response_dhcp.raise_for_status()
        html_dhcp = response_dhcp.text

        # Save raw DHCP HTML for debugging
        with open("fetched_dhcp_wr720n.html", "w", encoding="utf-8") as f:
            f.write(html_dhcp)
        logger.info(f"Fetched DHCP HTML saved to fetched_dhcp_wr720n.html (length: {len(html_dhcp)} bytes)")

        # Extract JavaScript arrays from status page
        scripts_status = re.findall(r'var\s+(\w+Para|\w+List)\s*=\s*new\s+Array\s*\((.*?)\);', html_status, re.DOTALL)

        data_arrays = {}
        for match in scripts_status:
            array_name = match[0]
            array_values_str = match[1]
            values = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', array_values_str)
            array_values = [re.sub(r'^["\']|["\']$', '', v.strip()) for v in values]
            data_arrays[array_name] = [clean_text(val) for val in array_values]
        logger.info(f"Extracted arrays from status page: {list(data_arrays.keys())}")

        # Initialize dictionary with router model name
        router_info = {
            'Status': {'Model': 'TP-LINK TL-WR720N_V2'},
            'LAN': {},
            'Wireless': {},
            'WAN': {},
            'Connected Devices': []
        }

        # Map data to sections based on array indices from status page
        if 'statusPara' in data_arrays and len(data_arrays['statusPara']) > 6:
            status_data = data_arrays['statusPara']
            router_info['Status']['Firmware Version'] = status_data[5] or 'Not Found'
            router_info['Status']['Hardware Version'] = status_data[6] or 'Not Found'

        if 'lanPara' in data_arrays and len(data_arrays['lanPara']) > 2:
            lan_data = data_arrays['lanPara']
            router_info['LAN']['MAC Address'] = lan_data[0] or 'Not Found'
            router_info['LAN']['IP Address'] = lan_data[1] or 'Not Found'
            router_info['LAN']['Subnet Mask'] = lan_data[2] or 'Not Found'

        if 'wlanPara' in data_arrays and len(data_arrays['wlanPara']) > 11:
            wlan_data = data_arrays['wlanPara']
            router_info['Wireless']['Wireless Radio'] = 'Disabled' if wlan_data[0] == '0' else 'Enabled'
            router_info['Wireless']['Name (SSID)'] = wlan_data[1] or 'Not Found'
            router_info['Wireless']['Channel'] = 'Auto' if wlan_data[2] == '0' else (wlan_data[2] or 'Not Found')
            router_info['Wireless']['Mode'] = '11bgn mixed' if wlan_data[3] == '5' else 'Not Found'
            router_info['Wireless']['MAC Address'] = wlan_data[4] or 'Not Found'

        if 'wanPara' in data_arrays and len(data_arrays['wanPara']) > 12:
            wan_data = data_arrays['wanPara']
            router_info['WAN']['Status'] = 'Disabled' if wan_data[0] == '0' else 'Link Up'
            router_info['WAN']['MAC Address'] = wan_data[1] or 'Not Found'
            router_info['WAN']['IP Address'] = wan_data[2] or 'Not Found'
            router_info['WAN']['Subnet Mask'] = wan_data[4] or 'Not Found'
            router_info['WAN']['Default Gateway'] = wan_data[7] or 'Not Found'

        # Parse DHCP client list for Connected Devices
        soup_dhcp = BeautifulSoup(html_dhcp, 'html.parser')
        tables = soup_dhcp.find_all('table')
        logger.info(f"Found {len(tables)} tables in DHCP page")

        if tables:
            for table in tables:
                rows = table.find_all('tr')
                logger.info(f"Found {len(rows)} rows in a DHCP table")
                # Try to detect header to determine column order
                header_row = rows[0] if rows and rows[0].find_all('th') else None
                headers = [clean_text(th.text) for th in header_row.find_all('th')] if header_row else []
                logger.info(f"Detected headers: {headers}")

                for i, row in enumerate(rows[1:], 1):  # Skip header row, start from 1
                    cells = row.find_all('td')
                    if len(cells) >= 4:  # Expecting at least Client Name, IP, MAC, Lease Time
                        device = {
                            'Client Name': clean_text(cells[0].text) if len(cells) > 0 else 'Not Found',
                            'IP Address': clean_text(cells[1].text) if len(cells) > 1 else 'Not Found',
                            'MAC Address': clean_text(cells[2].text) if len(cells) > 2 else 'Not Found',
                            'Lease Time': clean_text(cells[3].text) if len(cells) > 3 else 'Not Found'
                        }
                        # Enhanced filter to exclude invalid entries
                        valid_count = sum(1 for value in device.values() if value not in ['Not Found', ''])
                        if valid_count > 1 or (valid_count == 1 and any(value not in ['0', 'Not Found'] for value in device.values())):
                            router_info['Connected Devices'].append(device)

        # Fallback to JS arrays in DHCP page if table parsing fails
        dhcp_scripts = re.findall(r'var\s+(\w+List|dhcpPara)\s*=\s*new\s+Array\s*\((.*?)\);', html_dhcp, re.DOTALL)
        if dhcp_scripts and not router_info['Connected Devices']:
            logger.info(f"Found DHCP JS arrays: {dhcp_scripts[0][0] if dhcp_scripts else 'None'}")
            for match in dhcp_scripts:
                array_name = match[0]
                array_values_str = match[1]
                values = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', array_values_str)
                array_values = [re.sub(r'^["\']|["\']$', '', v.strip()) for v in values]
                # Assume pattern: Client Name, IP, MAC, Lease
                for j in range(0, len(array_values), 4):
                    device = {
                        'Client Name': clean_text(array_values[j]) if j < len(array_values) else 'Not Found',
                        'IP Address': clean_text(array_values[j + 1]) if j + 1 < len(array_values) else 'Not Found',
                        'MAC Address': clean_text(array_values[j + 2]) if j + 2 < len(array_values) else 'Not Found',
                        'Lease Time': clean_text(array_values[j + 3]) if j + 3 < len(array_values) else 'Not Found'
                    }
                    valid_count = sum(1 for value in device.values() if value not in ['Not Found', ''])
                    if valid_count > 1 or (valid_count == 1 and any(value not in ['0', 'Not Found'] for value in device.values())):
                        router_info['Connected Devices'].append(device)

        # Print router information
        print("<DOCUMENT>")
        for section, data in router_info.items():
            print(f"\n{section}")
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f" {key}: {value}")
            elif isinstance(data, list) and section == 'Connected Devices':
                if data:
                    for i, device in enumerate(data, 1):
                        print(f" {i}. Client Name: {device.get('Client Name', 'Not Found')}")
                        print(f"  IP Address: {device.get('IP Address', 'Not Found')}")
                        print(f"  MAC Address: {device.get('MAC Address', 'Not Found')}")
                        print(f"  Lease Time: {device.get('Lease Time', 'Not Found')}")
                else:
                    print(" No connected devices found")
        print("</DOCUMENT>")

        return router_info

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error scraping HTML content: {str(e)}", exc_info=True)
        return None

def get_wr720n_info(status_url, dhcp_url):
    scrape_wr720n_info(status_url, dhcp_url)

# TL-WR802N Functions
def scrape_wr802n_info(status_url, dhcp_url):
    """
    Scrapes router information from a TP-Link TL-WR802N emulator's status and DHCP client list pages.
    """
    try:
        # Validate URLs
        for url in [status_url, dhcp_url]:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.error(f"Invalid URL provided: {url}")
                return None

        # Fetch status HTML content dynamically
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response_status = requests.get(status_url, headers=headers, timeout=10)
        response_status.raise_for_status()
        html_status = response_status.text

        # Save raw status HTML for debugging
        with open("fetched_status.html", "w", encoding="utf-8") as f:
            f.write(html_status)
        logger.info(f"Fetched status HTML saved to fetched_status.html (length: {len(html_status)} bytes)")

        # Fetch DHCP client list HTML content dynamically
        response_dhcp = requests.get(dhcp_url, headers=headers, timeout=10)
        response_dhcp.raise_for_status()
        html_dhcp = response_dhcp.text

        # Save raw DHCP HTML for debugging
        with open("fetched_dhcp.html", "w", encoding="utf-8") as f:
            f.write(html_dhcp)
        logger.info(f"Fetched DHCP HTML saved to fetched_dhcp.html (length: {len(html_dhcp)} bytes)")

        # Extract JavaScript arrays from status page
        scripts_status = re.findall(r'var\s+(\w+Para)\s*=\s*new\s+Array\s*\((.*?)\);', html_status, re.DOTALL)

        data_arrays = {}
        for match in scripts_status:
            array_name = match[0]
            array_values_str = match[1]
            values = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', array_values_str)
            array_values = [re.sub(r'^["\']|["\']$', '', v.strip()) for v in values]
            data_arrays[array_name] = [clean_text(val) for val in array_values]
        logger.info(f"Extracted arrays from status page: {list(data_arrays.keys())}")

        # Initialize dictionary with router model name in Internet section
        router_info = {
            'Internet': {'Model': 'TP-LINK TL-WR802N'},
            'LAN': {},
            'Wireless': {},
            'Connected Devices': []
        }

        # Map data to sections based on array indices from status page
        if 'statusPara' in data_arrays and len(data_arrays['statusPara']) > 6:
            status_data = data_arrays['statusPara']
            router_info['Internet']['Firmware Version'] = status_data[5]
            router_info['Internet']['Hardware Version'] = status_data[6]

        if 'lanPara' in data_arrays and len(data_arrays['lanPara']) > 2:
            lan_data = data_arrays['lanPara']
            router_info['LAN']['MAC Address'] = lan_data[0]
            router_info['LAN']['IP Address'] = lan_data[1]
            router_info['LAN']['Subnet Mask'] = lan_data[2]

        if 'wlanPara' in data_arrays and len(data_arrays['wlanPara']) > 11:
            wlan_data = data_arrays['wlanPara']
            router_info['Wireless']['Wireless Radio'] = 'Disabled' if wlan_data[0] == '0' else 'Enabled'
            router_info['Wireless']['Name (SSID)'] = wlan_data[1]
            router_info['Wireless']['Channel'] = 'Auto (Current channel 0)' if wlan_data[2] == '0' else wlan_data[2]
            router_info['Wireless']['Mode'] = '11bgn mixed' if wlan_data[3] == '5' else 'Not Found'
            router_info['Wireless']['Channel Width'] = 'Automatic'
            router_info['Wireless']['MAC Address'] = wlan_data[4]
            router_info['Wireless']['WDS Status'] = 'Disabled' if wlan_data[10] == '0' else 'Enabled'

        # Parse DHCP client list for Connected Devices
        soup_dhcp = BeautifulSoup(html_dhcp, 'html.parser')
        tables = soup_dhcp.find_all('table')
        logger.info(f"Found {len(tables)} tables in DHCP page")

        if tables:
            for table in tables:
                rows = table.find_all('tr')
                logger.info(f"Found {len(rows)} rows in a DHCP table")
                # Try to detect header to determine column order
                header_row = rows[0] if rows and rows[0].find_all('th') else None
                headers = [clean_text(th.text) for th in header_row.find_all('th')] if header_row else []
                logger.info(f"Detected headers: {headers}")

                for i, row in enumerate(rows[1:], 1):  # Skip header row, start from 1
                    cells = row.find_all('td')
                    if len(cells) >= 4:  # Expecting at least Client Name, IP, MAC, Lease Time
                        # Adjust indexing based on observed pattern: [Client Name, IP, MAC, Lease]
                        device = {
                            'Device Name': clean_text(cells[0].text) if len(cells) > 0 else 'Not Found',
                            'IP Address': clean_text(cells[1].text) if len(cells) > 1 else 'Not Found',
                            'MAC Address': clean_text(cells[2].text) if len(cells) > 2 else 'Not Found',
                            'Lease Time': clean_text(cells[3].text) if len(cells) > 3 else 'Not Found'
                        }
                        # Filter out devices with all fields as Not Found or invalid
                        if not all(value in ['Not Found', ''] for value in device.values()):
                            router_info['Connected Devices'].append(device)

        # Fallback to JS arrays in DHCP page if table parsing fails
        dhcp_scripts = re.findall(r'var\s+(\w+List|dhcpPara)\s*=\s*new\s+Array\s*\((.*?)\);', html_dhcp, re.DOTALL)
        if dhcp_scripts and not router_info['Connected Devices']:
            logger.info(f"Found DHCP JS arrays: {dhcp_scripts[0][0] if dhcp_scripts else 'None'}")
            for match in dhcp_scripts:
                array_name = match[0]
                array_values_str = match[1]
                values = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', array_values_str)
                array_values = [re.sub(r'^["\']|["\']$', '', v.strip()) for v in values]
                # Assume pattern: Client Name, IP, MAC, Lease
                for j in range(0, len(array_values), 4):
                    device = {
                        'Device Name': clean_text(array_values[j]) if j < len(array_values) else 'Not Found',
                        'IP Address': clean_text(array_values[j + 1]) if j + 1 < len(array_values) else 'Not Found',
                        'MAC Address': clean_text(array_values[j + 2]) if j + 2 < len(array_values) else 'Not Found',
                        'Lease Time': clean_text(array_values[j + 3]) if j + 3 < len(array_values) else 'Not Found'
                    }
                    if not all(value in ['Not Found', ''] for value in device.values()):
                        router_info['Connected Devices'].append(device)

        # Print router information
        for section, data in router_info.items():
            if isinstance(data, dict):
                print(f"\n**{section}**")
                for key, value in data.items():
                    print(f"{key}: {value}")
            elif isinstance(data, list) and section == 'Connected Devices':
                print(f"\n**{section}**")
                if data:
                    for i, device in enumerate(data, 1):
                        print(f"{i}. Client name: {device.get('Device Name', 'Unknown')}")
                        print(f"   MAC Address: {device.get('MAC Address', 'Not Found')}")
                        print(f"   IP Address: {device.get('IP Address', 'Not Found')}")
                        print(f"   Lease Time: {device.get('Lease Time', 'Not Found')}")
                else:
                    print("No connected devices found")

        return router_info

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error scraping HTML content: {str(e)}", exc_info=True)
        return None

def get_wr802n_info(status_url, dhcp_url):
    scrape_wr802n_info(status_url, dhcp_url)

# TL-WR3002X Functions
def fetch_wr3002x_info(url, output_file="wr3002x_router_status.json"):
    """Fetch connected devices, router status, and product info from the JSON endpoint for AX1500."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Check for HTTP errors
        data = response.json().get("data", {})  # Access the nested data
        
        # Extract connected devices
        devices = data.get("access_devices_wired", []) or data.get("connected_devices", [])  # Fallback key
        
        # Extract router status, mapping JSON keys to meaningful labels
        # WAN Section
        wan_status = {
            "MAC Address": data.get("wan_macaddr", "N/A"),
            "IP Address": data.get("wan_ipv4_ipaddr", "N/A"),
            "Subnet Mask": data.get("wan_ipv4_netmask", "N/A"),
            "Default Gateway": data.get("wan_ipv4_gateway", "N/A"),
            "Primary DNS": data.get("wan_ipv4_pridns", "N/A"),
            "Secondary DNS": data.get("wan_ipv4_snddns", "N/A"),
            "Connection Type": "Dynamic IP" if data.get("wan_ipv4_conntype") == "dhcp" else data.get("wan_ipv4_conntype", "N/A")
        }
        
        # LAN Section
        lan_status = {
            "MAC Address": data.get("lan_macaddr", "N/A"),
            "IP Address": data.get("lan_ipv4_ipaddr", "N/A"),
            "Subnet Mask": data.get("lan_ipv4_netmask", "N/A"),
            "DHCP": "On" if data.get("lan_ipv4_dhcp_enable") == "On" else "Off"
        }
         
        # Wireless 2.4GHz Section 
        wireless_2g_status = {
            "Network Name (SSID)": data.get("wireless_2g_ssid", "N/A"),
            "Wireless Radio": "On" if data.get("wireless_2g_enable") == "on" else "Off",
            "Mode": data.get("wireless_2g_hwmode", "N/A").replace("bgn", "802.11b/g/n mixed").replace("ax", "802.11ax"),  # Adjust for Wi-Fi 6
            "Channel Width": data.get("wireless_2g_htmode", "N/A").capitalize(),
            "Channel": f"{data.get('wireless_2g_channel', 'N/A')} (Current Channel {data.get('wireless_2g_current_channel', 'N/A')})" if data.get("wireless_2g_current_channel") else data.get("wireless_2g_channel", "N/A"),
            "MAC Address": data.get("wireless_2g_macaddr", "N/A"),
            "WDS Status": "Disabled" if data.get("wireless_2g_wds_status") == "disable" else "Enabled"
        }
        
        # Wireless 5GHz Section 
        wireless_5g_status = {
            "Network Name (SSID)": data.get("wireless_5g_ssid", "N/A"),
            "Wireless Radio": "On" if data.get("wireless_5g_enable") == "on" else "Off",
            "Mode": data.get("wireless_5g_hwmode", "N/A").replace("ac", "802.11ac").replace("ax", "802.11ax"),
            "Channel Width": data.get("wireless_5g_htmode", "N/A").capitalize(),
            "Channel": f"{data.get('wireless_5g_channel', 'N/A')} (Current Channel {data.get('wireless_5g_current_channel', 'N/A')})" if data.get("wireless_5g_current_channel") else data.get("wireless_5g_channel", "N/A"),
            "MAC Address": data.get("wireless_5g_macaddr", "N/A"),
            "WDS Status": "Disabled" if data.get("wireless_5g_wds_status") == "disable" else "Enabled" 
        }
        
        # Guest Network 2.4GHz Section
        guest_2g_status = {
            "Network Name (SSID)": data.get("guest_2g_ssid", "N/A"),
            "Hide SSID": "Off" if data.get("guest_2g_hidden") == "off" else "On",
            "Wireless Radio": "Off" if data.get("guest_2g_enable") == "off" else "On",
            "Allow guests to see each other": "Off" if data.get("guest_isolate") == "off" else "On"
        }
        
        # Guest Network 5GHz Section
        guest_5g_status = {
            "Network Name (SSID)": data.get("guest_5g_ssid", "N/A"),
            "Hide SSID": "Off" if data.get("guest_5g_hidden") == "off" else "On",
            "Wireless Radio": "Off" if data.get("guest_5g_enable") == "off" else "On",
            "Allow guests to see each other": "Off" if data.get("guest_isolate") == "off" else "On"
        }
        
        # Product Info Section
        product_status = {
            "Firmware Version": data.get("firmware_version", "N/A"),
            "Hardware Version": data.get("hardware_version", "TL-WR1502X v1.0")
        }
        
        # Structure output  
        output_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "devices": devices,
            "router_status": {
                "WAN": wan_status,
                "LAN": lan_status,
                "Wireless 2.4GHz": wireless_2g_status,
                "Wireless 5GHz": wireless_5g_status,
                "Guest Network 2.4GHz": guest_2g_status,
                "Guest Network 5GHz": guest_5g_status,
                "Product Info": product_status
            }
        }
        
        # Print connected devices
        print("Connected Devices:")
        print(f"Total connected devices: {len(devices)}")
        for idx, device in enumerate(devices, 1):
            print(f"{idx}. Details:")
            print(f"   Wire Type: {device.get('wire_type', 'N/A')}")
            print(f"   MAC Address: {device.get('macaddr', 'N/A')}")
            print(f"   IP Address: {device.get('ipaddr', 'N/A')}")
            print(f"   Hostname: {device.get('hostname', 'N/A')}")
        
        # Print router info
        print("\nRouter Information:")
        print("  WAN:")
        for key, value in wan_status.items():
            print(f"    {key}: {value}")
        
        print("  LAN:")
        for key, value in lan_status.items():
            print(f"    {key}: {value}")
        
        print("  Wireless 2.4GHz:")
        for key, value in wireless_2g_status.items():
            print(f"    {key}: {value}")
        
        print("  Wireless 5GHz:")
        for key, value in wireless_5g_status.items():
            print(f"    {key}: {value}")
        
        print("  Guest Network 2.4GHz:")
        for key, value in guest_2g_status.items():
            print(f"    {key}: {value}")
        
        print("  Guest Network 5GHz:")
        for key, value in guest_5g_status.items():
            print(f"    {key}: {value}")
        
        print("  Product Info:")
        for key, value in product_status.items():
            print(f"    {key}: {value}")
        
        # Save to JSON file
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=4)
        print(f"\n***Output saved to {output_file}***")
        
        return output_data
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"Error parsing JSON: {e}")
        return None

def get_wr3002x_info(url):
    fetch_wr3002x_info(url)

# Main Function
def main(router_url=None, username="admin", password="admin"):
    if not router_url:
        print("Error: No router URL provided. Usage: python index.py <router_url> [<username> [<password>]]")
        print("Supported formats:")
        print("- TL-WR941HP: e.g., http://192.168.1.1")
        print("- Archer C6: e.g., https://emulator.tp-link.com/c6-eu-v2/data/status.json")
        print("- Archer C54 (Network Status): e.g., https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus")
        print("- Archer C54 (Client List): e.g., https://emulator.tp-link.com/c54-v1-eu-re/index.html#networkMap")
        print("- TL-WR720N (Status): e.g., https://emulator.tp-link.com/TL-WR720N_V2/userRpm/StatusRpm.htm")
        print("- TL-WR720N (DHCP): e.g., https://emulator.tp-link.com/TL-WR720N/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh")
        print("- TL-WR802N (Status): e.g., https://emulator.tp-link.com/TL-WR802N_V1/userRpm/StatusRpm.htm")
        print("- TL-WR802N (DHCP): e.g., https://emulator.tp-link.com/TL-WR802N_V1/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh")
        print("- TL-WR3002X: e.g., https://emulator.tp-link.com/TL-WR1502Xv1-router_mode_US/data/status.json")
        return
    
    # Default URLs for Archer C54
    default_c54_urls = {
        'network_status_url': 'https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus',
        'network_map_url': 'https://emulator.tp-link.com/c54-v1-eu-re/index.html#networkMap'
    }
    # Default URLs for TL-WR720N
    default_wr720n_urls = {
        'status_url': 'https://emulator.tp-link.com/TL-WR720N_V2/userRpm/StatusRpm.htm',
        'dhcp_url': 'https://emulator.tp-link.com/TL-WR720N/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh'
    }
    # Default URLs for TL-WR802N
    default_wr802n_urls = {
        'status_url': 'https://emulator.tp-link.com/TL-WR802N_V1/userRpm/StatusRpm.htm',
        'dhcp_url': 'https://emulator.tp-link.com/TL-WR802N_V1/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh'
    }
    # Default URL for TL-WR3002X
    default_wr3002x_url = 'https://emulator.tp-link.com/TL-WR1502Xv1-router_mode_US/data/status.json'
    
    # Determine router type based on URL
    if router_url.startswith('http://192.168'):
        print(f"\nFetching info for {router_url} (TL-WR941HP)...")
        get_wr941hp_info(router_url, username, password)
    elif router_url.endswith('status.json'):
        if 'c6' in router_url.lower():
            print(f"\nFetching info for {router_url} (TP-Link Archer C6)...")
            get_archer_c6_info(router_url)
        elif 'wr1502x' in router_url.lower():
            print(f"\nFetching info for {router_url} (TP-Link TL-WR3002X)...")
            get_wr3002x_info(router_url)
        else:
            print(f"Error: Unrecognized JSON endpoint: {router_url}")
    elif router_url.endswith('#networkStatus'):
        print(f"\nFetching info for TP-Link Archer C54 (Network Status: {router_url}, Client List: {default_c54_urls['network_map_url']})...")
        get_archer_c54_info(router_url, default_c54_urls['network_map_url'])
    elif router_url.endswith('#networkMap'):
        print(f"\nFetching info for TP-Link Archer C54 (Network Status: {default_c54_urls['network_status_url']}, Client List: {router_url})...")
        get_archer_c54_info(default_c54_urls['network_status_url'], router_url)
    elif router_url.endswith('StatusRpm.htm'):
        if 'wr720n' in router_url.lower():
            print(f"\nFetching info for TP-Link TL-WR720N (Status: {router_url}, DHCP: {default_wr720n_urls['dhcp_url']})...")
            get_wr720n_info(router_url, default_wr720n_urls['dhcp_url'])
        elif 'wr802n' in router_url.lower():
            print(f"\nFetching info for TP-Link TL-WR802N (Status: {router_url}, DHCP: {default_wr802n_urls['dhcp_url']})...")
            get_wr802n_info(router_url, default_wr802n_urls['dhcp_url'])
        else:
            print(f"Error: Unrecognized StatusRpm.htm URL: {router_url}")
    elif router_url.endswith('AssignedIpAddrListRpm.htm?Refresh=Refresh'):
        if 'wr720n' in router_url.lower():
            print(f"\nFetching info for TP-Link TL-WR720N (DHCP: {router_url}, Status: {default_wr720n_urls['status_url']})...")
            get_wr720n_info(default_wr720n_urls['status_url'], router_url)
        elif 'wr802n' in router_url.lower():
            print(f"\nFetching info for TP-Link TL-WR802N (DHCP: {router_url}, Status: {default_wr802n_urls['status_url']})...")
            get_wr802n_info(default_wr802n_urls['status_url'], router_url)
        else:
            print(f"Error: Unrecognized AssignedIpAddrListRpm.htm URL: {router_url}")
    else:
        print(f"Error: Invalid router URL provided: {router_url}")
        print("Supported formats:")
        print("- TL-WR941HP: e.g., http://192.168.1.1")
        print("- Archer C6: e.g., https://emulator.tp-link.com/c6-eu-v2/data/status.json")
        print("- Archer C54 (Network Status): e.g., https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus")
        print("- Archer C54 (Client List): e.g., https://emulator.tp-link.com/c54-v1-eu-re/index.html#networkMap")
        print("- TL-WR720N (Status): e.g., https://emulator.tp-link.com/TL-WR720N_V2/userRpm/StatusRpm.htm")
        print("- TL-WR720N (DHCP): e.g., https://emulator.tp-link.com/TL-WR720N/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh")
        print("- TL-WR802N (Status): e.g., https://emulator.tp-link.com/TL-WR802N_V1/userRpm/StatusRpm.htm")
        print("- TL-WR802N (DHCP): e.g., https://emulator.tp-link.com/TL-WR802N_V1/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh")
        print("- TL-WR3002X: e.g., https://emulator.tp-link.com/TL-WR1502Xv1-router_mode_US/data/status.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch TP-Link router information.")
    parser.add_argument("router_url", nargs='?', default=None, help="URL of the router (e.g., http://192.168.1.1, https://emulator.tp-link.com/c6-eu-v2/data/status.json, etc.)")
    parser.add_argument("username", nargs='?', default="admin", help="Username for TL-WR941HP authentication (default: admin)")
    parser.add_argument("password", nargs='?', default="admin", help="Password for TL-WR941HP authentication (default: admin)")
    args = parser.parse_args()
    main(args.router_url, args.username, args.password)

# python index.py "http://192.168.0.1" "admin" "admin"                                        **FOR TL-WR941HP**
# python index.py "https://emulator.tp-link.com/c6-eu-v2/data/status.json"                    **FOR ARCHER C6**
# python index.py "https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus"     **FOR ARCHER C54 (Network Status)**
# python index.py "https://emulator.tp-link.com/c54-v1-eu-re/index.html#networkMap"           **FOR ARCHER C54 (Client List)**
# python index.py "https://emulator.tp-link.com/TL-WR720N_V2/userRpm/StatusRpm.htm"          **FOR TL-WR720N (Status)**
# python index.py "https://emulator.tp-link.com/TL-WR720N/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh" **FOR TL-WR720N (DHCP)**
# python index.py "https://emulator.tp-link.com/TL-WR802N_V1/userRpm/StatusRpm.htm"          **FOR TL-WR802N (Status)**
# python index.py "https://emulator.tp-link.com/TL-WR802N_V1/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh" **FOR TL-WR802N (DHCP)**
# python index.py "https://emulator.tp-link.com/TL-WR1502Xv1-router_mode_US/data/status.json" **FOR TL-WR3002X**