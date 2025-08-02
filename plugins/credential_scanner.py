import requests
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget

class CredentialScannerPlugin(ScannerPlugin):
    """
    A plugin that tests for default and common credentials on web interfaces.
    """
    @property
    def name(self) -> str:
        return "credential_scanner"

    # This data was originally in gridland_clean.py
    DEFAULT_CREDENTIALS = {
        "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default"],
        "root": ["root", "toor", "1234", "pass", "root123"],
        "user": ["user", "user123", "password"],
        "guest": ["guest", "guest123"],
        "operator": ["operator", "operator123"],
    }

    def scan(self, target: ScanTarget) -> List[Finding]:
        findings = []
        for port_result in target.open_ports:
            if port_result.port not in [80, 443, 8080, 8443]:
                continue

            protocol = "https" if port_result.port in [443, 8443] else "http"

            endpoints = [
                f"{protocol}://{target.ip}:{port_result.port}/",
                f"{protocol}://{target.ip}:{port_result.port}/login",
                f"{protocol}://{target.ip}:{port_result.port}/admin",
                f"{protocol}://{target.ip}:{port_result.port}/cgi-bin/"
            ]

            for endpoint in endpoints:
                for username, passwords in self.DEFAULT_CREDENTIALS.items():
                    for password in passwords:
                        try:
                            response = requests.get(endpoint, auth=(username, password),
                                                  headers={'User-Agent': 'Mozilla/5.0 Security Scanner'},
                                                  timeout=5, verify=False)
                            if response.status_code == 200:
                                creds = f"{username}:{password}"
                                finding = Finding(
                                    category="Default Credentials",
                                    description=f"Found default credentials {creds} on {endpoint}",
                                    confidence=1.0,
                                    raw_evidence=creds
                                )
                                findings.append(finding)
                                # Found creds for this endpoint, no need to test more
                                return findings
                        except requests.RequestException:
                            continue
        return findings
