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
from dotenv import load_dotenv

# Load environment variables for credentials
load_dotenv()
USERNAME = os.getenv("ROUTER_USERNAME", "admin")
PASSWORD = os.getenv("ROUTER_PASSWORD", "admin")

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

def login_wr941hp(router_url="http://192.168.100.108", login_path="/userRpm/LoginRpm.htm"):
    session = requests.Session()
    auth_cookie = get_auth_cookie(USERNAME, PASSWORD, use_md5=True)
    session.cookies.set("Authorization", auth_cookie, path="/", domain="192.168.100.108")
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

def get_wr941hp_info():
    router_url = "http://192.168.100.108"
    output_file = "wr941hp_status.json"
    session, final_url, resp_text = login_wr941hp(router_url)
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
def fetch_c6_info(url="https://emulator.tp-link.com/c6-eu-v2/data/status.json", output_file="archer_c6_status.json"):
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

def get_archer_c6_info():
    fetch_c6_info()

# Archer C54 Functions
def clean_text(text):
    return text.strip().replace('\n', '').replace('\t', '') if text else 'Not Found'

def scrape_c54_info(network_status_url="https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus", 
                    network_map_url="https://emulator.tp-link.com/c54-v1-eu-re/index.html#networkMap"):
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
            username_field.send_keys(USERNAME)
            password_field.send_keys(PASSWORD)
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

def get_archer_c54_info():
    scrape_c54_info()

# Main Menu
def main():
    while True:
        print("\nTP-Link Router Information Viewer")
        print("Select a model:")
        print("1. TL-WR941HP")
        print("2. TP-Link Archer C6")
        print("3. TP-Link Archer C54")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            print("\nFetching info for TL-WR941HP...")
            get_wr941hp_info()
        elif choice == '2':
            print("\nFetching info for Archer C6...")
            get_archer_c6_info()
        elif choice == '3':
            print("\nFetching info for Archer C54...")
            get_archer_c54_info()
        elif choice == '4':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()