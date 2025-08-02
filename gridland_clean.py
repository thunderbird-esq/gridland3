#!/usr/bin/env python3
"""
GRIDLAND - Real Security Scanner
Clean implementation based on proven CamXploit.py functionality
"""

import socket
import threading
import requests
import ipaddress
import time
import json
import warnings
import click
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.auth import HTTPBasicAuth

# Suppress SSL warnings for embedded devices
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

@dataclass
class ScanTarget:
    ip: str
    open_ports: List[int] = None
    device_type: Optional[str] = None
    brand: Optional[str] = None
    credentials: Dict[str, str] = None
    streams: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.credentials is None:
            self.credentials = {}
        if self.streams is None:
            self.streams = []

class GridlandScanner:
    """Real scanner based on CamXploit.py proven functionality"""
    
    # Comprehensive camera port list from CamXploit.py
    CAMERA_PORTS = [
        80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
        8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
        554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
        1935, 1936, 1937, 1938, 1939,
        37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
        37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800,
        3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
        5000, 5001, 5002, 5003, 5004, 5005, 6000, 6001, 6002, 6003, 6004, 6005,
        7000, 7001, 7002, 7003, 7004, 7005, 9000, 9001, 9002, 9003, 9004, 9005,
        8888, 8889, 8890, 8891, 8892, 8893, 9999, 9998, 9997, 9996, 9995, 9994
    ]
    
    # Default credentials from CamXploit.py
    DEFAULT_CREDENTIALS = {
        "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default"],
        "root": ["root", "toor", "1234", "pass", "root123"],
        "user": ["user", "user123", "password"],
        "guest": ["guest", "guest123"],
        "operator": ["operator", "operator123"],
    }
    
    # Camera brand detection patterns from CamXploit.py
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
    
    def __init__(self, max_threads=100, timeout=1.5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.http_timeout = 5
        self._stop_scanning = False
        self.headers = {'User-Agent': 'Mozilla/5.0 Security Scanner'}
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """Port scanning based on CamXploit.py check_ports()"""
        if ports is None:
            ports = self.CAMERA_PORTS
            
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
        
        return sorted(open_ports)
    
    def detect_camera(self, ip: str, ports: List[int]) -> Tuple[Optional[str], Optional[str]]:
        """Camera detection based on CamXploit.py check_if_camera()"""
        print(f"[📷] Analyzing {ip} for camera indicators")
        
        for port in ports:
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{ip}:{port}"
            
            try:
                response = requests.get(base_url, headers=self.headers, 
                                      timeout=self.http_timeout, verify=False)
                
                server_header = response.headers.get('Server', '').lower()
                content = response.text.lower()
                
                # Check for camera brand indicators
                for brand, keywords in self.CAMERA_BRANDS.items():
                    if any(keyword in server_header for keyword in keywords) or \
                       any(keyword in content for keyword in keywords):
                        print(f"    ✅ {brand.upper()} Camera Detected!")
                        return "camera", brand
                
            except Exception as e:
                continue
        
        return None, None
    
    def test_credentials(self, ip: str, ports: List[int]) -> Dict[str, str]:
        """Credential testing based on CamXploit.py test_default_passwords()"""
        print(f"[🔑] Testing credentials on {ip}")
        
        successful_creds = {}
        
        for port in ports:
            if port not in [80, 443, 8080, 8443]:
                continue
                
            protocol = "https" if port in [443, 8443] else "http"
            
            endpoints = [
                f"{protocol}://{ip}:{port}/",
                f"{protocol}://{ip}:{port}/login",
                f"{protocol}://{ip}:{port}/admin",
                f"{protocol}://{ip}:{port}/cgi-bin/"
            ]
            
            for endpoint in endpoints:
                for username, passwords in self.DEFAULT_CREDENTIALS.items():
                    for password in passwords:
                        try:
                            response = requests.get(endpoint, auth=(username, password),
                                                  headers=self.headers, timeout=self.http_timeout, 
                                                  verify=False)
                            
                            if response.status_code == 200:
                                cred_key = f"{port}_{username}"
                                successful_creds[cred_key] = f"{username}:{password}"
                                print(f"    🔥 SUCCESS: {username}:{password} @ {endpoint}")
                                return successful_creds  # Found credentials, stop testing
                                
                        except Exception:
                            continue
        
        return successful_creds
    
    def discover_streams(self, ip: str, ports: List[int]) -> List[str]:
        """Stream discovery based on CamXploit.py detect_live_streams()"""
        print(f"[🎥] Checking for streams on {ip}")
        
        streams = []
        
        # RTSP stream paths
        rtsp_paths = ['/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub']
        
        # HTTP stream paths
        http_paths = ['/video', '/stream', '/mjpg/video.mjpg', '/snapshot.jpg']
        
        for port in ports:
            # Check RTSP streams
            if port in [554, 8554]:
                for path in rtsp_paths:
                    stream_url = f"rtsp://{ip}:{port}{path}"
                    if self._test_rtsp_stream(ip, port):
                        streams.append(stream_url)
                        print(f"    ✅ RTSP Stream: {stream_url}")
                        break
            
            # Check HTTP streams
            elif port in [80, 443, 8080, 8443]:
                protocol = "https" if port in [443, 8443] else "http"
                for path in http_paths:
                    stream_url = f"{protocol}://{ip}:{port}{path}"
                    if self._test_http_stream(stream_url):
                        streams.append(stream_url)
                        print(f"    ✅ HTTP Stream: {stream_url}")
        
        return streams
    
    def _test_rtsp_stream(self, ip: str, port: int) -> bool:
        """Test RTSP stream availability"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.http_timeout)
                sock.connect((ip, port))
                return True
        except:
            return False
    
    def _test_http_stream(self, url: str) -> bool:
        """Test HTTP stream availability"""
        try:
            response = requests.head(url, timeout=self.http_timeout, verify=False)
            content_type = response.headers.get('Content-Type', '').lower()
            
            if any(x in content_type for x in ['video', 'image', 'mjpeg', 'stream']):
                return True
            
            return response.status_code == 200
                
        except:
            return False
    
    def scan_target(self, ip: str, aggressive: bool = True) -> ScanTarget:
        """Complete scan of single target"""
        print(f"\n[🎯] Scanning {ip}")
        
        target = ScanTarget(ip=ip)
        
        # Step 1: Port scan
        target.open_ports = self.scan_ports(ip)
        
        if not target.open_ports:
            print(f"[❌] No open ports found")
            return target
        
        # Step 2: Device detection
        device_type, brand = self.detect_camera(ip, target.open_ports)
        target.device_type = device_type
        target.brand = brand
        
        if aggressive:
            # Step 3: Credential testing
            target.credentials = self.test_credentials(ip, target.open_ports)
            
            # Step 4: Stream discovery
            target.streams = self.discover_streams(ip, target.open_ports)
        
        print(f"[✅] Scan complete for {ip}")
        return target
    
    def scan_network(self, network_range: str, aggressive: bool = True) -> List[ScanTarget]:
        """Scan entire network range"""
        print(f"\n[🌐] Scanning network: {network_range}")
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            print(f"[❌] Invalid network range")
            return []
        
        targets = []
        for ip in network.hosts():
            if self._stop_scanning:
                break
            
            target = self.scan_target(str(ip), aggressive)
            if target.open_ports:
                targets.append(target)
        
        return targets
    
    def stop(self):
        self._stop_scanning = True

# CLI Implementation
@click.group()
def gridland():
    """GRIDLAND - Real Network Security Scanner"""
    pass

@gridland.command()
@click.argument('target')
@click.option('--aggressive', '-a', is_flag=True, help='Enable credential testing and stream discovery')
@click.option('--threads', '-t', default=100, help='Number of threads')
@click.option('--output', '-o', help='Output JSON file')
def scan(target, aggressive, threads, output):
    """Scan single IP or network range"""
    
    scanner = GridlandScanner(max_threads=threads)
    
    try:
        if '/' in target:
            results = scanner.scan_network(target, aggressive)
            print(f"\n[📊] Found {len(results)} devices with open ports")
        else:
            result = scanner.scan_target(target, aggressive)
            results = [result] if result.open_ports else []
        
        # Display results
        for result in results:
            print(f"\n🎯 {result.ip}")
            print(f"   📡 Open Ports: {', '.join(map(str, result.open_ports))}")
            
            if result.device_type:
                print(f"   📷 Device: {result.device_type} ({result.brand})")
            
            if result.credentials:
                print(f"   🔑 CREDENTIALS FOUND:")
                for k, v in result.credentials.items():
                    print(f"      🔥 {v}")
            
            if result.streams:
                print(f"   🎥 STREAMS FOUND:")
                for stream in result.streams:
                    print(f"      📺 {stream}")
        
        # Save to file if requested
        if output and results:
            data = []
            for result in results:
                data.append({
                    'ip': result.ip,
                    'open_ports': result.open_ports,
                    'device_type': result.device_type,
                    'brand': result.brand,
                    'credentials': result.credentials,
                    'streams': result.streams,
                    'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            with open(output, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"\n[📄] Results saved to {output}")
    
    except KeyboardInterrupt:
        print("\n[⏹️] Scan stopped by user")
        scanner.stop()

@gridland.command()
@click.argument('target')
def quick(target):
    """Quick aggressive scan"""
    scanner = GridlandScanner()
    result = scanner.scan_target(target, aggressive=True)
    
    if result.open_ports:
        print(f"\n🎯 {result.ip} - {len(result.open_ports)} open ports")
        if result.credentials:
            print(f"🔥 CREDENTIALS: {list(result.credentials.values())}")
        if result.streams:
            print(f"📺 STREAMS: {len(result.streams)} found")
    else:
        print(f"❌ No open ports on {target}")

if __name__ == '__main__':
    gridland()