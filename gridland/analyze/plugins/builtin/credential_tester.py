"""
Credential Tester Plugin for GRIDLAND v3.0

This plugin tests default credentials on IP camera authentication endpoints through
multi-threaded brute force testing. Supports Basic, Digest, and Form-based authentication.

100% feature parity with CamXploit.py test_default_passwords() (lines 1201-1283).
"""

import json
import threading
from typing import Any, Dict, List, Optional
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import urllib3

from gridland.analyze.memory import get_memory_pool
from gridland.analyze.plugins.manager import PluginMetadata, VulnerabilityPlugin
from gridland.core.logger import get_logger

# Disable SSL warnings for camera endpoints
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)


class CredentialTester(VulnerabilityPlugin):
    """
    Default credential testing plugin for IP camera systems.

    Tests common default credentials using multi-threaded authentication attempts.
    Supports Basic, Digest, and Form-based authentication mechanisms.

    Attributes:
        credentials (Dict[str, List[str]]): Username to password list mapping.
        max_concurrent_threads (int): Maximum concurrent test threads (default: 20).
        timeout (int): HTTP request timeout in seconds (default: 5).
    """

    def __init__(self):
        """Initialize the Credential Tester plugin."""
        super().__init__()
        self.credentials = self._load_credentials()
        self.max_concurrent_threads = 20  # From CamXploit.py line 1248 (lower for credential testing)
        self.timeout = 5  # From CamXploit.py TIMEOUT constant line 797
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.memory_pool = get_memory_pool()

    def _load_credentials(self) -> Dict[str, List[str]]:
        """
        Load default credentials from default_credentials.json.

        Returns:
            Dict[str, List[str]]: Username to password list mapping.
        """
        try:
            # Get path to default_credentials.json
            data_dir = Path(__file__).parent.parent.parent.parent / "data"
            creds_file = data_dir / "default_credentials.json"

            with open(creds_file, encoding="utf-8") as f:
                creds_data = json.load(f)

            return creds_data.get("credentials", {})

        except Exception as e:
            logger.error(f"Failed to load default credentials: {e}")
            # Fallback to CamXploit.py DEFAULT_CREDENTIALS (lines 784-790)
            return {
                "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default"],
                "root": ["root", "toor", "1234", "pass", "root123"],
                "user": ["user", "user123", "password"],
                "guest": ["guest", "guest123"],
                "operator": ["operator", "operator123"],
            }

    def get_metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.

        Returns:
            PluginMetadata: Plugin information and configuration.
        """
        return PluginMetadata(
            name="Credential Tester",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="Tests default credentials on IP camera authentication endpoints",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=list(range(1, 65536)),
            requires_auth=False,
            performance_impact="HIGH",
            priority=60,
        )

    async def scan_vulnerabilities(
        self, target_ip: str, target_port: int, service: str = "", banner: str = ""
    ) -> List[Any]:
        """
        Test credentials on a single port.

        This method is called by the plugin framework for individual port analysis.
        For multi-port testing, use test_default_credentials() directly.

        Args:
            target_ip: Target IP address.
            target_port: Target port number.
            service: Detected service type (unused).
            banner: Service banner (unused).

        Returns:
            List of VulnerabilityResult objects for successful authentication.
        """
        # Test single port
        results = self.test_default_credentials(target_ip, [target_port])
        return self._convert_to_vulnerability_results(target_ip, results)

    def test_default_credentials(
        self,
        ip: str,
        open_ports: List[int],
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Test default credentials across multiple ports.

        100% feature parity with CamXploit.py test_default_passwords() (lines 1201-1283).

        Args:
            ip: Target IP address.
            open_ports: List of open ports to test.
            progress_callback: Optional callback(current, total) for progress updates.

        Returns:
            Dict containing:
                - 'success': Boolean indicating if credentials were found
                - 'credentials': Dict with 'username', 'password', 'url' if found
                - 'auth_type': Authentication type used ('basic', 'form', 'digest')
        """
        found = [False]  # Mutable flag for threading
        credentials_found = {}
        lock = threading.Lock()

        # CamXploit.py lines 1254-1259: test these endpoints per port
        test_endpoints = [
            ("/", "basic"),
            ("/login", "form"),
            ("/admin/login", "form"),
            ("/cgi-bin/login", "form"),
        ]

        def test_credentials(protocol: str, port: int, path: str, auth_type: str):
            """Test credentials on a single endpoint."""
            # Early termination if credentials already found (CamXploit.py lines 1208-1209)
            if found[0]:
                return False

            url = f"{protocol}://{ip}:{port}{path}"

            for username, passwords in self.credentials.items():
                # Check for early termination (CamXploit.py line 1213-1214)
                if found[0]:
                    return False

                for password in passwords:
                    # Check for early termination (CamXploit.py line 1216-1217)
                    if found[0]:
                        return False

                    try:
                        success = False

                        # Test based on authentication type
                        if auth_type == "basic":
                            success = self._test_basic_auth(url, username, password)
                        elif auth_type == "form":
                            success = self._test_form_auth(url, username, password)
                        elif auth_type == "digest":
                            success = self._test_digest_auth(url, username, password)

                        # CamXploit.py lines 1236-1241: successful authentication
                        if success:
                            with lock:
                                # Double-check to avoid duplicate detection (CamXploit.py line 1238)
                                if not found[0]:
                                    found[0] = True
                                    credentials_found.update(
                                        {
                                            "username": username,
                                            "password": password,
                                            "url": url,
                                            "auth_type": auth_type,
                                        }
                                    )
                                    logger.info(
                                        f"Success! {username}:{password} @ {url} ({auth_type})"
                                    )
                            return True

                    except Exception:
                        # Silent failure as in CamXploit.py line 1242-1243
                        pass

            return False

        # Test endpoints with threading (CamXploit.py lines 1246-1279)
        threads = []

        for port in open_ports:
            # Early termination (CamXploit.py lines 1251-1252)
            if found[0]:
                break

            protocol = self._get_protocol(port)

            for path, auth_type in test_endpoints:
                # Early termination (CamXploit.py lines 1262-1263)
                if found[0]:
                    break

                thread = threading.Thread(
                    target=test_credentials, args=(protocol, port, path, auth_type)
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()

                # Limit concurrent threads (CamXploit.py lines 1272-1275)
                if len(threads) >= self.max_concurrent_threads:
                    for t in threads:
                        t.join()
                    threads = []

        # Wait for remaining threads (CamXploit.py lines 1278-1279)
        for thread in threads:
            thread.join()

        return {
            "success": found[0],
            "credentials": credentials_found if found[0] else None,
        }

    def _get_protocol(self, port: int) -> str:
        """
        Determine protocol (http/https) based on port number.

        Args:
            port: Port number.

        Returns:
            'https' for SSL ports, 'http' otherwise.
        """
        # From CamXploit.py lines 793, 926-927
        https_ports = [443, 8443, 8444]
        return "https" if port in https_ports else "http"

    def _test_basic_auth(self, url: str, username: str, password: str) -> bool:
        """
        Test Basic authentication.

        CamXploit.py lines 1220-1226.

        Args:
            url: Target URL.
            username: Username to test.
            password: Password to test.

        Returns:
            True if authentication successful (200 response), False otherwise.
        """
        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            # CamXploit.py line 1236: success is status_code == 200
            return response.status_code == 200
        except Exception:
            return False

    def _test_form_auth(self, url: str, username: str, password: str) -> bool:
        """
        Test Form-based authentication.

        CamXploit.py lines 1228-1234.

        Args:
            url: Target URL.
            username: Username to test.
            password: Password to test.

        Returns:
            True if authentication successful (200 response), False otherwise.
        """
        try:
            response = requests.post(
                url,
                data={"username": username, "password": password},
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            # CamXploit.py line 1236: success is status_code == 200
            return response.status_code == 200
        except Exception:
            return False

    def _test_digest_auth(self, url: str, username: str, password: str) -> bool:
        """
        Test Digest authentication.

        Not explicitly in CamXploit.py but follows same pattern as Basic auth.

        Args:
            url: Target URL.
            username: Username to test.
            password: Password to test.

        Returns:
            True if authentication successful (200 response), False otherwise.
        """
        try:
            response = requests.get(
                url,
                auth=HTTPDigestAuth(username, password),
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
            return response.status_code == 200
        except Exception:
            return False

    def _convert_to_vulnerability_results(
        self, ip: str, test_results: Dict[str, Any]
    ) -> List[Any]:
        """
        Convert test results to VulnerabilityResult objects.

        Args:
            ip: Target IP address.
            test_results: Results from test_default_credentials().

        Returns:
            List of VulnerabilityResult objects (empty if no credentials found).
        """
        results = []

        if test_results["success"] and test_results["credentials"]:
            creds = test_results["credentials"]
            vuln = self.memory_pool.acquire_vulnerability_result()
            vuln.ip = ip

            # Extract port from URL
            url_parts = creds["url"].split(":")
            if len(url_parts) >= 3:
                port_str = url_parts[2].split("/")[0]
                vuln.port = int(port_str)
            else:
                vuln.port = 80

            vuln.service = "http"
            vuln.vulnerability_id = "DEFAULT-CREDENTIALS"
            vuln.severity = "CRITICAL"
            vuln.confidence = 100
            vuln.description = (
                f"Default credentials found: {creds['username']}:{creds['password']}"
            )
            vuln.exploit_available = True

            # Add details
            details = {
                "username": creds["username"],
                "password": creds["password"],
                "url": creds["url"],
                "auth_type": creds["auth_type"],
                "plugin": "credential_tester",
            }
            vuln.details = json.dumps(details)

            results.append(vuln)

        return results


# Plugin instance for automatic discovery
credential_tester = CredentialTester()
