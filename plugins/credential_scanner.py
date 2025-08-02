import requests
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget

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

    def scan(self, target: ScanTarget, progress_callback=None) -> List[Finding]:
        findings = []

        web_ports = [p.port for p in target.open_ports if p.port in [80, 443, 8080, 8443]]
        if not web_ports:
            return []

        # Calculate total number of checks for progress reporting
        total_creds = sum(len(p) for p in self.DEFAULT_CREDENTIALS.values())
        # Estimate endpoints per port. This is not perfect but good for progress.
        # A better approach might be to generate all endpoints first.
        estimated_endpoints_per_port = 21
        total_checks = total_creds * estimated_endpoints_per_port * len(web_ports)
        checks_done = 0

        for port in web_ports:
            protocol = "https" if port in [443, 8443] else "http"
            endpoints = [
                f"{protocol}://{target.ip}:{port}/", f"{protocol}://{target.ip}:{port}/login",
                f"{protocol}://{target.ip}:{port}/admin", f"{protocol}://{target.ip}:{port}/cgi-bin/",
                f"{protocol}://{target.ip}:{port}/home.html", f"{protocol}://{target.ip}:{port}/admin.html",
                f"{protocol}://{target.ip}:{port}/index.html", f"{protocol}://{target.ip}:{port}/main.html",
                f"{protocol}://{target.ip}:{port}/dvr/", f"{protocol}://{target.ip}:{port}/nvr/",
                f"{protocol}://{target.ip}:{port}/recorder/", f"{protocol}://{target.ip}:{port}/ISAPI/",
                f"{protocol}://{target.ip}:{port}/dms/", f"{protocol}://{target.ip}:{port}/axis-cgi/",
                f"{protocol}://{target.ip}:{port}/sony/", f"{protocol}://{target.ip}:{port}/panasonic/",
                f"{protocol}://{target.ip}:{port}/cgi/", f"{protocol}://{target.ip}:{port}/web/",
                f"{protocol}://{target.ip}:{port}/api/", f"{protocol}://{target.ip}:{port}/config/",
                f"{protocol}://{target.ip}:{port}/setup/"
            ]

            for endpoint in endpoints:
                found_creds_for_endpoint = False
                for username, passwords in self.DEFAULT_CREDENTIALS.items():
                    if found_creds_for_endpoint:
                        break
                    for password in passwords:
                        checks_done += 1
                        if progress_callback:
                            progress = (checks_done / total_checks) * 100
                            progress_callback(self.name, progress, f"Testing {username}:{password} on {endpoint}")

                        try:
                            response = requests.get(endpoint, auth=(username, password),
                                                  headers={'User-Agent': 'Mozilla/5.0 Security Scanner'},
                                                  timeout=3, verify=False)
                            
                            if response.status_code == 200:
                                content = response.text.lower()
                                failed_indicators = [
                                    'login', 'username', 'password', 'not logged in',
                                    'authentication failed', 'invalid credentials',
                                    'please provide', 'unauthorized', 'access denied',
                                    'sign in', 'log in', 'enter password'
                                ]
                                if any(indicator in content for indicator in failed_indicators):
                                    continue
                                if '<form' in content and ('login' in content or 'password' in content):
                                    continue
                                
                                creds = f"{username}:{password}"
                                finding = Finding(
                                    category="credential",
                                    description=f"Found default credentials {creds} on {endpoint}",
                                    severity="high",
                                    url=endpoint,
                                    data={"username": username, "password": password}
                                )
                                findings.append(finding)
                                found_creds_for_endpoint = True
                                break
                        except requests.RequestException:
                            continue
        return findings
