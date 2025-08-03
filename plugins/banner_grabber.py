"""
Banner Grabber Plugin for Gridland
Advanced service fingerprinting and version detection for security assessment
"""
import socket
import requests
import ssl
import re
from typing import List, Dict, Optional, Tuple
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget


class BannerGrabberPlugin(ScannerPlugin):
    """
    Advanced banner grabbing and service fingerprinting plugin.
    Extracts detailed version information, SSL certificates, and service details.
    """
    
    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has any open ports for banner grabbing"""
        return len(target.open_ports) > 0

    # Service-specific probes and patterns
    SERVICE_PROBES = {
        # HTTP/HTTPS probes
        "http": {
            "probe": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 Banner Scanner\r\n\r\n",
            "patterns": {
                "server": r"Server:\s*([^\r\n]+)",
                "version": r"(\d+\.\d+(?:\.\d+)?)",
                "camera_model": r"(IP Camera|Network Camera|Web Camera|DVR|NVR)",
                "framework": r"(nginx|apache|lighttpd|iis|jetty|tomcat)"
            }
        },
        
        # RTSP probes
        "rtsp": {
            "probe": b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Banner Scanner\r\n\r\n",
            "patterns": {
                "server": r"Server:\s*([^\r\n]+)",
                "version": r"RTSP/(\d+\.\d+)",
                "camera_info": r"(Hikvision|Dahua|Axis|Sony|Bosch|Panasonic)"
            }
        },
        
        # SSH probes
        "ssh": {
            "probe": b"SSH-2.0-BannerScanner\r\n",
            "patterns": {
                "version": r"SSH-(\d+\.\d+)",
                "software": r"SSH-\d+\.\d+-([^\r\n\s]+)"
            }
        },
        
        # FTP probes
        "ftp": {
            "probe": b"",  # FTP sends banner immediately
            "patterns": {
                "software": r"220[- ]([^\r\n]+)",
                "version": r"(\d+\.\d+(?:\.\d+)?)"
            }
        },
        
        # Telnet probes
        "telnet": {
            "probe": b"",  # Telnet often sends banner immediately
            "patterns": {
                "system": r"([Ll]inux|[Bb]usybox|[Vv]xWorks)",
                "device": r"(IP Camera|DVR|NVR|Network Camera)"
            }
        }
    }

    # Known vulnerable software versions
    VULNERABLE_VERSIONS = {
        "hikvision": {
            "5.2.0": ["CVE-2017-7921", "Authentication bypass"],
            "5.3.0": ["CVE-2017-7921", "Authentication bypass"],
            "5.4.0": ["CVE-2017-7921", "Authentication bypass"]
        },
        "dahua": {
            "2.420": ["CVE-2013-6117", "Authentication bypass"],
            "2.608": ["CVE-2013-6117", "Authentication bypass"]
        },
        "axis": {
            "5.50": ["CVE-2018-10658", "Directory traversal"],
            "6.50": ["CVE-2018-10658", "Directory traversal"]
        }
    }

    def scan(self, target: ScanTarget) -> List[Finding]:
        """Perform comprehensive banner grabbing and fingerprinting"""
        findings = []
        
        for port_result in target.open_ports:
            port = port_result.port
            
            # HTTP/HTTPS banner grabbing
            if port in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]:
                findings.extend(self._grab_http_banner(target.ip, port))
                
            # RTSP banner grabbing
            elif port in [554, 8554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554]:
                findings.extend(self._grab_rtsp_banner(target.ip, port))
                
            # SSH banner grabbing
            elif port == 22:
                findings.extend(self._grab_ssh_banner(target.ip, port))
                
            # FTP banner grabbing
            elif port == 21:
                findings.extend(self._grab_ftp_banner(target.ip, port))
                
            # Telnet banner grabbing
            elif port == 23:
                findings.extend(self._grab_telnet_banner(target.ip, port))
                
            # Generic TCP banner grab for unknown services
            else:
                findings.extend(self._grab_generic_banner(target.ip, port))
        
        return findings

    def _grab_http_banner(self, ip: str, port: int) -> List[Finding]:
        """Grab HTTP/HTTPS banners and extract detailed information"""
        findings = []
        
        protocols = ["https"] if port in [443, 8443] else ["http", "https"]
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{ip}:{port}"
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 Banner Scanner'}
                )
                
                # Extract server information
                server_header = response.headers.get('Server', '')
                if server_header:
                    finding = Finding(
                        category="banner",
                        description=f"HTTP Server: {server_header}",
                        severity="low",
                        port=port,
                        data={
                            "service": "http",
                            "server": server_header,
                            "status_code": response.status_code,
                            "headers": dict(response.headers)
                        }
                    )
                    findings.append(finding)
                    
                    # Check for vulnerable versions
                    vuln_findings = self._check_vulnerable_version(server_header, port)
                    findings.extend(vuln_findings)
                
                # Extract additional fingerprinting information
                content = response.text[:1000]  # First 1KB for analysis
                fingerprint_data = self._analyze_http_content(content, response.headers)
                
                if fingerprint_data:
                    finding = Finding(
                        category="fingerprint",
                        description=f"HTTP Service fingerprint: {fingerprint_data.get('technology', 'Unknown')}",
                        severity="low",
                        port=port,
                        data=fingerprint_data
                    )
                    findings.append(finding)
                
                # SSL/TLS certificate analysis for HTTPS
                if protocol == "https":
                    cert_findings = self._analyze_ssl_certificate(ip, port)
                    findings.extend(cert_findings)
                    
                break  # Use first successful protocol
                
            except requests.RequestException:
                continue
                
        return findings

    def _grab_rtsp_banner(self, ip: str, port: int) -> List[Finding]:
        """Grab RTSP service banners"""
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # Send RTSP OPTIONS request
            request = f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Banner Scanner\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if response:
                # Extract server information
                server_match = re.search(r"Server:\s*([^\r\n]+)", response, re.IGNORECASE)
                if server_match:
                    server_info = server_match.group(1)
                    
                    finding = Finding(
                        category="banner",
                        description=f"RTSP Server: {server_info}",
                        severity="low",
                        port=port,
                        data={
                            "service": "rtsp",
                            "server": server_info,
                            "full_response": response
                        }
                    )
                    findings.append(finding)
                    
        except (socket.error, UnicodeDecodeError):
            pass
            
        return findings

    def _grab_ssh_banner(self, ip: str, port: int) -> List[Finding]:
        """Grab SSH service banners"""
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # SSH server sends banner first
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner.startswith('SSH-'):
                finding = Finding(
                    category="banner",
                    description=f"SSH Banner: {banner}",
                    severity="low",
                    port=port,
                    data={
                        "service": "ssh",
                        "banner": banner,
                        "version": self._extract_ssh_version(banner)
                    }
                )
                findings.append(finding)
                
        except (socket.error, UnicodeDecodeError):
            pass
            
        return findings

    def _grab_ftp_banner(self, ip: str, port: int) -> List[Finding]:
        """Grab FTP service banners"""
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # FTP server sends banner immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner.startswith('220'):
                finding = Finding(
                    category="banner",
                    description=f"FTP Banner: {banner}",
                    severity="low",
                    port=port,
                    data={
                        "service": "ftp",
                        "banner": banner
                    }
                )
                findings.append(finding)
                
        except (socket.error, UnicodeDecodeError):
            pass
            
        return findings

    def _grab_telnet_banner(self, ip: str, port: int) -> List[Finding]:
        """Grab Telnet service banners"""
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # Telnet may send banner immediately or after negotiation
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner and len(banner) > 5:  # Meaningful banner
                finding = Finding(
                    category="banner",
                    description=f"Telnet Banner: {banner[:100]}...",
                    severity="low",
                    port=port,
                    data={
                        "service": "telnet",
                        "banner": banner
                    }
                )
                findings.append(finding)
                
        except (socket.error, UnicodeDecodeError):
            pass
            
        return findings

    def _grab_generic_banner(self, ip: str, port: int) -> List[Finding]:
        """Grab banners from unknown services"""
        findings = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Try to receive banner
            banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner and len(banner) > 5:  # Meaningful banner
                finding = Finding(
                    category="banner",
                    description=f"Service Banner on port {port}: {banner[:50]}...",
                    severity="low",
                    port=port,
                    data={
                        "service": "unknown",
                        "banner": banner
                    }
                )
                findings.append(finding)
                
        except (socket.error, UnicodeDecodeError):
            pass
            
        return findings

    def _analyze_http_content(self, content: str, headers: Dict[str, str]) -> Dict[str, str]:
        """Analyze HTTP content for technology fingerprinting"""
        fingerprint = {}
        
        content_lower = content.lower()
        
        # Detect web technologies
        if 'jquery' in content_lower:
            fingerprint['javascript'] = 'jQuery'
        if 'angular' in content_lower:
            fingerprint['javascript'] = 'AngularJS'
        if 'react' in content_lower:
            fingerprint['javascript'] = 'React'
        
        # Detect camera-specific interfaces
        if any(x in content_lower for x in ['webcamxp', 'webcam', 'ipcamera']):
            fingerprint['technology'] = 'WebcamXP/IP Camera'
        if 'hikvision' in content_lower:
            fingerprint['technology'] = 'Hikvision Camera'
        if 'dahua' in content_lower:
            fingerprint['technology'] = 'Dahua Camera'
        
        # Extract framework information from headers
        if 'X-Powered-By' in headers:
            fingerprint['framework'] = headers['X-Powered-By']
            
        return fingerprint

    def _analyze_ssl_certificate(self, ip: str, port: int) -> List[Finding]:
        """Analyze SSL/TLS certificates for security information"""
        findings = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Extract certificate information
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        
                        cert_info = {
                            'subject': subject,
                            'issuer': issuer,
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_after': cert.get('notAfter'),
                            'not_before': cert.get('notBefore')
                        }
                        
                        finding = Finding(
                            category="ssl_certificate",
                            description=f"SSL Certificate: {subject.get('commonName', 'Unknown CN')}",
                            severity="low",
                            port=port,
                            data=cert_info
                        )
                        findings.append(finding)
                        
        except (socket.error, ssl.SSLError):
            pass
            
        return findings

    def _check_vulnerable_version(self, server_header: str, port: int) -> List[Finding]:
        """Check if server version is known to be vulnerable"""
        findings = []
        
        server_lower = server_header.lower()
        
        for vendor, versions in self.VULNERABLE_VERSIONS.items():
            if vendor in server_lower:
                for version, cves in versions.items():
                    if version in server_lower:
                        for cve in cves:
                            finding = Finding(
                                category="vulnerability",
                                description=f"Vulnerable software version detected: {cve}",
                                severity="high",
                                port=port,
                                data={
                                    "vendor": vendor,
                                    "version": version,
                                    "cve": cve,
                                    "server_header": server_header
                                }
                            )
                            findings.append(finding)
                            
        return findings

    def _extract_ssh_version(self, banner: str) -> Optional[str]:
        """Extract SSH version from banner"""
        match = re.search(r"SSH-(\d+\.\d+)", banner)
        return match.group(1) if match else None

    def get_description(self) -> str:
        """Get plugin description"""
        return "Advanced banner grabbing and service fingerprinting scanner"