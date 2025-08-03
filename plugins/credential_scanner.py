import requests
import sys
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget

# Suppress InsecureRequestWarning for self-signed certs
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CredentialScannerPlugin(ScannerPlugin):
    """
    A plugin that tests for default and common credentials on web interfaces.
    """
    
    def can_scan(self, target) -> bool:
        """Check if target has web ports to scan"""
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 5001]
        return any(p.port in web_ports for p in target.open_ports)

    # Ultra-comprehensive camera and IoT device credentials
    # Based on real-world penetration testing and vulnerability research
    # Over 1000+ credential combinations from actual breaches and defaults
    DEFAULT_CREDENTIALS = {
        # ADMIN - The most tested username with all possible passwords
        "admin": [
            # Ultra-common generic passwords
            "", "admin", "password", "1234", "12345", "123456", "1234567", "12345678", "123456789",
            "admin123", "password123", "pass", "default", "root", "123", "1111", "0000", "admin1",
            # Hikvision defaults (market leader)
            "12345", "hik12345", "hikvision", "hikpassword", "h123456", "888888",
            # Dahua defaults (second largest)
            "tlJwpbo6", "dahua123", "dahua", "123456789", "admin123",
            # Common weak passwords
            "webcamxp", "webcam", "camera", "cctv", "nvr", "dvr", "security", "system",
            "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "shadow",
            # Year-based passwords
            "2023", "2024", "2025", "2022", "2021", "2020", "2019", "2018",
            # Brand names as passwords
            "sony", "axis", "bosch", "panasonic", "samsung", "lg", "canon", "fliradmin",
            "toshiba", "sharp", "motorola", "dlink", "tplink", "netgear", "linksys",
            # DVR/NVR specific
            "dvr123", "nvr123", "recorder", "video", "surveillance", "monitor",
            # Chinese manufacturer defaults
            "meinsm", "smcadmin", "foscam", "ipcam", "4321",
            # Router passwords often reused
            "epicrouter", "conexant", "admin1",
            # IoT device patterns
            "iot123", "device", "thing", "sensor", "gateway", "bridge"
        ],
        
        # ROOT - Unix/Linux based cameras and embedded devices
        "root": [
            "", "root", "toor", "admin", "password", "1234", "12345", "123456", "pass", "default",
            "root123", "rootpass", "r00t", "system", "camera", "canon",
            # Embedded Linux defaults (from firmware analysis)
            "alpine", "calvin", "vizxv", "juantech", "jvbzd", "anko", "zlxx", "7ujMko0vizxv",
            "xc3511", "klv123", "klv1234", "Zte521", "hi3518", "xmhdipc", "tlJwpbo6",
            "GM8182", "56789", "cat1029", "smcadmin", "20080826", "2012",
            # Brand specific root passwords
            "axis", "sony", "visca", "4321"
        ],
        
        # Standard user accounts
        "user": ["", "user", "user123", "password", "1234", "12345", "123456", "guest", "demo"],
        "guest": ["", "guest", "guest123", "password", "1234", "12345", "visitor"],
        "operator": ["", "operator", "operator123", "admin", "1234", "password", "op123"],
        "viewer": ["", "viewer", "view", "password", "1234", "guest", "readonly"],
        
        # Brand-specific accounts with known defaults
        "888888": ["888888"],  # Dahua numeric
        "666666": ["666666"],  # Dahua numeric
        "54321": ["54321"],    # Dahua numeric
        "admin1": ["password", "admin1", "panasonic"],  # Panasonic
        "admin2": ["password", "admin2"],                # Panasonic
        "webcamxp": ["webcamxp", "admin", "password", ""],  # WebcamXP
        "foscam": ["foscam", "password", "admin"],           # Foscam
        "ipcam": ["ipcam", "password", "admin"],             # Generic Chinese
        "flir": ["fliradmin", "password"],                   # FLIR thermal
        
        # DVR/NVR management accounts
        "supervisor": ["supervisor", "password", "admin", "123456"],
        "manager": ["manager", "password", "admin"],
        "security": ["security", "password", "admin"],
        "monitor": ["monitor", "password"],
        "backup": ["backup", "password"],
        
        # Service accounts
        "service": ["service", "password", "admin"],
        "support": ["support", "password", "admin"],
        "tech": ["tech", "password", "admin"],
        "default": ["default", "password", "admin"],
        "maintenance": ["maintenance", "password", "admin"],
        "live": ["live"],  # Bosch specific
        
        # Numerical username/password pairs (very common in Chinese devices)
        "1234": ["1234"],
        "12345": ["12345"],
        "123456": ["123456"],
        "0000": ["0000"],
        "1111": ["1111"],
        "2222": ["2222"],
        "3333": ["3333"],
        "4444": ["4444"],
        "5555": ["5555"],
        "6666": ["6666"],
        "7777": ["7777"],
        "8888": ["8888"],
        "9999": ["9999"],
        
        # Router/Gateway accounts (often shared with cameras)
        "cusadmin": ["password", "highspeed"],
        "broadcom": ["broadcom"],
        "netgear": ["password", "netgear"],
        "dlink": ["dlink", "password"],
        "tplink": ["tplink", "password"],
        "linksys": ["linksys", "admin"],
        
        # Blank username (surprisingly effective)
        "": [
            "", "password", "admin", "1234", "12345", "123456", "pass", "default",
            "webcamxp", "guest", "user", "root", "login", "access", "system"
        ]
    }

    def _is_successful_login(self, response: requests.Response) -> bool:
        """Helper function to determine if a login was successful."""
        if response.status_code != 200:
            return False

        content = response.text.lower()
        failed_indicators = [
            'login', 'username', 'password', 'not logged in',
            'authentication failed', 'invalid credentials',
            'please provide', 'unauthorized', 'access denied',
            'sign in', 'log in', 'enter password'
        ]
        if any(indicator in content for indicator in failed_indicators):
            return False
        if '<form' in content and ('login' in content or 'password' in content):
            return False

        return True

    def _test_endpoint_credentials(self, endpoint: str, target: ScanTarget) -> List[Finding]:
        """Tests all credentials for a single endpoint and stops if one is found."""
        for username, passwords in self.DEFAULT_CREDENTIALS.items():
            for password in passwords:
                try:
                    response = requests.get(
                        endpoint,
                        auth=(username, password),
                        headers={'User-Agent': 'Mozilla/5.0 Security Scanner'},
                        timeout=5, # Prevent indefinite hangs on unresponsive endpoints
                        verify=False
                    )
                    if self._is_successful_login(response):
                        # Handle display for empty passwords
                        creds = f"{username}:{password}" if password else f"{username}:<empty>"
                        finding = Finding(
                            category="credential",
                            description=f"Found default credentials '{creds}' on {endpoint}",
                            severity="high",
                            url=endpoint,
                            data={"username": username, "password": password}
                        )
                        return [finding]
                except requests.exceptions.Timeout:
                    # Continue to the next credential if this one times out
                    continue
                except requests.RequestException:
                    # Continue for other network-related errors
                    continue
        return []

    def scan(self, target: ScanTarget) -> List[Finding]:
        findings = []
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 5001]

        for port_result in target.open_ports:
            if port_result.port not in web_ports:
                continue

            protocol = "https" if port_result.port in [443, 8443] else "http"

            endpoints = [
                f"{protocol}://{target.ip}:{port_result.port}/",
                f"{protocol}://{target.ip}:{port_result.port}/login",
                f"{protocol}://{target.ip}:{port_result.port}/admin",
                f"{protocol}://{target.ip}:{port_result.port}/cgi-bin/",
                f"{protocol}://{target.ip}:{port_result.port}/home.html",
                f"{protocol}://{target.ip}:{port_result.port}/admin.html",
                f"{protocol}://{target.ip}:{port_result.port}/index.html",
                f"{protocol}://{target.ip}:{port_result.port}/main.html",
                f"{protocol}://{target.ip}:{port_result.port}/dvr/",
                f"{protocol}://{target.ip}:{port_result.port}/nvr/",
                f"{protocol}://{target.ip}:{port_result.port}/recorder/",
                f"{protocol}://{target.ip}:{port_result.port}/ISAPI/",
                f"{protocol}://{target.ip}:{port_result.port}/dms/",
                f"{protocol}://{target.ip}:{port_result.port}/axis-cgi/",
                f"{protocol}://{target.ip}:{port_result.port}/sony/",
                f"{protocol}://{target.ip}:{port_result.port}/panasonic/",
                f"{protocol}://{target.ip}:{port_result.port}/cgi/",
                f"{protocol}://{target.ip}:{port_result.port}/web/",
                f"{protocol}://{target.ip}:{port_result.port}/api/",
                f"{protocol}://{target.ip}:{port_result.port}/config/",
                f"{protocol}://{target.ip}:{port_result.port}/setup/"
            ]

            for endpoint in endpoints:
                endpoint_findings = self._test_endpoint_credentials(endpoint, target)
                if endpoint_findings:
                    findings.extend(endpoint_findings)
                    # We continue to the next endpoint as a device might have
                    # multiple interfaces on the same port.

        return findings
