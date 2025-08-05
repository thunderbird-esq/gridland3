"""
Fingerprint Scanner Plugin for Gridland
Core intelligence component for identifying target services and technologies.
"""
import socket
import requests
import ssl
import re
from typing import List, Dict, Optional, Tuple
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os

class FingerprintScannerPlugin(ScannerPlugin):
    """
    Performs deep fingerprinting of services to identify vendor, product, and version.
    This is the core intelligence gathering plugin.
    """

    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has any open ports for fingerprinting."""
        return len(target.open_ports) > 0

    def get_description(self) -> str:
        """Get plugin description."""
        return "Core intelligence plugin for service and technology fingerprinting."

    def scan(self, target: ScanTarget) -> List[Finding]:
        """
        Perform comprehensive fingerprinting, calculate confidence, and return a single finding.
        """
        proxy_url = os.environ.get('PROXY_URL')
        all_indicators = []
        port_info = {}

        for port_result in target.open_ports:
            port = port_result.port
            indicators = []
            service_name = "unknown"

            if port in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]:
                indicators = self._grab_http_banner(target.ip, port, proxy_url)
                service_name = "http"
            elif port in [554, 8554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554]:
                indicators = self._grab_rtsp_banner(target.ip, port)
                service_name = "rtsp"
            elif port == 22:
                indicators = self._grab_ssh_banner(target.ip, port)
                service_name = "ssh"
            elif port == 21:
                indicators = self._grab_ftp_banner(target.ip, port)
                service_name = "ftp"
            elif port == 23:
                indicators = self._grab_telnet_banner(target.ip, port)
                service_name = "telnet"
            else:
                # Generic banner grabbing can be added here if needed
                pass

            if indicators:
                all_indicators.extend(indicators)
                # Store vendors found on this port
                port_info[port] = {"service": service_name, "vendors": list(set([ind[1] for ind in indicators]))}

        if not all_indicators:
            return []

        # Step 2: Calculate confidence
        vendor, product, version, confidence, evidence = self._calculate_confidence(all_indicators)

        # Step 3: Create a single, high-confidence finding
        if vendor:
            finding = Finding(
                category="fingerprint",
                description=f"Device fingerprint identified: {vendor} (Confidence: {confidence})",
                severity="info",
                port=next(iter(port_info), None),
                data={
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    "confidence": confidence,
                    "evidence": evidence,
                    "ports": port_info
                }
            )
            return [finding]

        return []

    def _calculate_confidence(self, indicators: List[Tuple[str, str, str]]) -> Tuple[Optional[str], Optional[str], Optional[str], int, List[Dict]]:
        """
        Calculates confidence scores for vendors based on a list of indicators.
        Returns the top vendor, its details, confidence score, and the evidence log.
        """
        scores = {}
        evidence_log = []

        confidence_map = {
            'header': 3,
            'rtsp_header': 3,
            'ssh_banner': 3,
            'ftp_banner': 2, # Lower confidence than specific App headers
            'html_specific': 2,
            'telnet_banner': 1,
            'html_generic': 1,
        }

        for ind_type, ind_value, ind_source in indicators:
            score = confidence_map.get(ind_type, 0)
            scores[ind_value] = scores.get(ind_value, 0) + score
            evidence_log.append({
                "vendor": ind_value,
                "type": ind_type,
                "score": score,
                "source": ind_source
            })

        if not scores:
            return None, None, None, 0, []

        highest_vendor = max(scores, key=scores.get)
        highest_score = scores[highest_vendor]

        # Product/version extraction is simplified for now. Can be enhanced to use evidence.
        return highest_vendor, None, None, highest_score, evidence_log

    def _grab_http_banner(self, ip: str, port: int, proxy_url: Optional[str] = None) -> List[Tuple[str, str, str]]:
        """Grab HTTP/HTTPS banners and return a list of indicators."""
        protocols = ["https"] if port in [443, 8443] else ["http", "https"]
        for protocol in protocols:
            try:
                url = f"{protocol}://{ip}:{port}"
                response = requests.get(
                    url, timeout=5, verify=False, headers=get_request_headers(), proxies=get_proxies(proxy_url)
                )
                return self._analyze_http_response(response)
            except requests.RequestException:
                continue
        return []

    def _analyze_http_response(self, response: requests.Response) -> List[Tuple[str, str, str]]:
        """
        Analyzes an HTTP response to find all potential vendor indicators.
        Returns a list of (type, value, source) tuples.
        """
        indicators = []
        headers = response.headers
        content = response.text
        url = str(response.url)

        server_header = headers.get('Server', '')
        if server_header:
            known_headers = {
                'Dahua': 'Dahua',
                'Hikvision-Webs': 'Hikvision',
                'Hikvision': 'Hikvision',
                'Axis': 'Axis',
                'Apache': 'Apache',
            }
            for key, vendor in known_headers.items():
                if key in server_header:
                    indicators.append(('header', vendor, f"Server: {server_header} on {url}"))
                    break

        indicators.extend(self._analyze_content_for_vendor(content, url))
        return indicators

    def _analyze_content_for_vendor(self, content: str, source: str) -> List[Tuple[str, str, str]]:
        """
        Analyzes HTML or banner content to find all potential vendor indicators.
        Returns a list of (type, value, source) tuples.
        """
        indicators = []
        content_lower = content.lower()

        if 'dahua' in content_lower or ('web-service' in content_lower and 'login' in content_lower):
            indicators.append(('html_specific', 'Dahua', f"Found 'Dahua' keyword/pattern in content from {source}"))
        if 'hikvision' in content_lower:
            indicators.append(('html_specific', 'Hikvision', f"Found 'Hikvision' keyword in content from {source}"))
        if 'axis' in content_lower:
            indicators.append(('html_specific', 'Axis', f"Found 'Axis' keyword in content from {source}"))
        if 'sony' in content_lower:
            indicators.append(('html_specific', 'Sony', f"Found 'Sony' keyword in content from {source}"))
        if 'panasonic' in content_lower:
            indicators.append(('html_specific', 'Panasonic', f"Found 'Panasonic' keyword in content from {source}"))
        if 'bosch' in content_lower:
            indicators.append(('html_specific', 'Bosch', f"Found 'Bosch' keyword in content from {source}"))

        if 'ip camera' in content_lower or 'network camera' in content_lower:
            indicators.append(('html_generic', 'Generic Camera', f"Found generic camera keyword in content from {source}"))

        return indicators

    def _grab_rtsp_banner(self, ip: str, port: int) -> List[Tuple[str, str, str]]:
        """Grab RTSP service banners and return a list of indicators."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                request = f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Gridland Scanner\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                server_match = re.search(r"Server:\s*([^\r\n]+)", response, re.IGNORECASE)
                if server_match:
                    server_info = server_match.group(1).strip()
                    vendor, _, _ = self._parse_server_string(server_info)
                    if vendor:
                        return [('rtsp_header', vendor, f"RTSP Server: {server_info} on {ip}:{port}")]
        except (socket.error, UnicodeDecodeError):
            pass
        return []

    def _grab_ssh_banner(self, ip: str, port: int) -> List[Tuple[str, str, str]]:
        """Grab SSH service banners and return a list of indicators."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner.startswith('SSH-'):
                    match = re.search(r"SSH-[\d.]+-(?P<software>[^\s\r\n]*)", banner)
                    if match:
                        software = match.group('software')
                        vendor = self._vendor_from_software(software)
                        if vendor:
                            return [('ssh_banner', vendor, f"SSH Banner: {banner} on {ip}:{port}")]
        except (socket.error, UnicodeDecodeError):
            pass
        return []

    def _grab_ftp_banner(self, ip: str, port: int) -> List[Tuple[str, str, str]]:
        """Grab FTP service banners and return a list of indicators."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner.startswith('220'):
                    match = re.search(r'220[ -](?P<product>[^\s]+)\s*server', banner, re.IGNORECASE)
                    if match:
                        product = match.group('product')
                        return [('ftp_banner', product, f"FTP Banner: {banner} on {ip}:{port}")]
        except (socket.error, UnicodeDecodeError):
            pass
        return []

    def _grab_telnet_banner(self, ip: str, port: int) -> List[Tuple[str, str, str]]:
        """Grab Telnet service banners and return a list of indicators."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner and len(banner) > 5:
                    return self._analyze_content_for_vendor(banner, f"Telnet banner on {ip}:{port}")
        except (socket.error, UnicodeDecodeError):
            pass
        return []

    def _parse_server_string(self, server_string: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parses a server string to extract vendor, product, and version."""
        match = re.match(r'([\w-]+)/([\d.]+)', server_string)
        if match:
            product, version = match.groups()
            vendor = product.split('-')[0]
            return vendor, product, version
        if "rtsp" in server_string.lower():
            return "Generic", "RTSP Server", server_string.split('/')[-1]
        return None, server_string, None

    def _vendor_from_software(self, software: str) -> Optional[str]:
        """Infers vendor from SSH software string."""
        if 'dropbear' in software.lower():
            return 'Dropbear'
        if 'openssh' in software.lower():
            return 'OpenSSH'
        return None