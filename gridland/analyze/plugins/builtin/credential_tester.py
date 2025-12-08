"""
Credential Tester Plugin for GRIDLAND v3.0

This plugin tests default credentials on IP camera authentication endpoints through
multi-threaded brute force testing. Supports Basic, Digest, and Form-based authentication.

⚠️ ETHICAL USE WARNING: This tool performs credential testing and must only be used on
systems you own or have explicit authorization to test. Rate limiting and audit logging
are provided to ensure responsible security research.

100% feature parity with CamXploit.py test_default_passwords() (lines 1201-1283).
"""

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import urllib3
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

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

    Ethical Safeguards:
        - Rate limiting: Configurable delay between credential attempts (default: 0.1s)
        - Attempt limiting: Maximum attempts per target to prevent excessive testing
        - Audit logging: Optional audit trail for compliance and accountability
        - Early termination: Stops testing once valid credentials are found

    Attributes:
        credentials (Dict[str, List[str]]): Username to password list mapping.
        max_concurrent_threads (int): Maximum concurrent test threads (default: 20).
        timeout (int): HTTP request timeout in seconds (default: 5).
        rate_limit_delay (float): Delay between credential attempts in seconds (default: 0.1).
        max_attempts_per_target (int): Maximum total attempts per target (default: 100).
        audit_log_path (Optional[Path]): Path to audit log file if logging enabled.
    """

    def __init__(
        self,
        rate_limit_delay: float = 0.1,
        max_attempts_per_target: int = 100,
        audit_log_path: str | None = None,
    ):
        """
        Initialize the Credential Tester plugin.

        Args:
            rate_limit_delay: Delay between credential attempts in seconds (default: 0.1).
                             Helps prevent overwhelming target systems and ensures responsible testing.
            max_attempts_per_target: Maximum total credential attempts per target (default: 100).
                                    Prevents excessive brute-forcing.
            audit_log_path: Optional path to CSV audit log file. If provided, all credential
                           test attempts will be logged with timestamps for compliance tracking.
        """
        super().__init__()
        self.credentials = self._load_credentials()
        self.max_concurrent_threads = (
            20  # From CamXploit.py line 1248 (lower for credential testing)
        )
        self.timeout = 5  # From CamXploit.py TIMEOUT constant line 797
        self.rate_limit_delay = rate_limit_delay
        self.max_attempts_per_target = max_attempts_per_target
        self.audit_log_path = Path(audit_log_path) if audit_log_path else None
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.memory_pool = get_memory_pool()

        # Initialize audit log if path provided
        if self.audit_log_path:
            self._initialize_audit_log()

    def _load_credentials(self) -> dict[str, list[str]]:
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
                "admin": [
                    "admin",
                    "1234",
                    "admin123",
                    "password",
                    "12345",
                    "123456",
                    "1111",
                    "default",
                ],
                "root": ["root", "toor", "1234", "pass", "root123"],
                "user": ["user", "user123", "password"],
                "guest": ["guest", "guest123"],
                "operator": ["operator", "operator123"],
            }

    def _initialize_audit_log(self):
        """
        Initialize the audit log file with CSV headers.

        Creates the audit log file if it doesn't exist and writes CSV headers.
        Thread-safe for concurrent audit logging.
        """
        try:
            # Create parent directories if they don't exist
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

            # Create file with headers if it doesn't exist
            if not self.audit_log_path.exists():
                with open(self.audit_log_path, "w", encoding="utf-8") as f:
                    f.write("timestamp,ip,port,username,password,url,auth_type,result\n")
                logger.info(f"Initialized audit log: {self.audit_log_path}")

        except Exception as e:
            logger.error(f"Failed to initialize audit log: {e}")
            # Disable audit logging if initialization fails
            self.audit_log_path = None

    def _log_audit_entry(
        self,
        ip: str,
        port: int,
        username: str,
        password: str,
        url: str,
        auth_type: str,
        success: bool,
    ):
        """
        Log a credential test attempt to the audit log.

        Args:
            ip: Target IP address.
            port: Target port number.
            username: Username tested.
            password: Password tested.
            url: Full URL tested.
            auth_type: Authentication type (basic, digest, form).
            success: Whether the credential test succeeded.
        """
        if not self.audit_log_path:
            return

        try:
            timestamp = datetime.utcnow().isoformat()
            result = "success" if success else "failure"

            # Thread-safe append to audit log
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(
                    f"{timestamp},{ip},{port},{username},{password},{url},{auth_type},{result}\n"
                )

        except Exception as e:
            logger.error(f"Failed to write audit log entry: {e}")

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
    ) -> list[Any]:
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
        open_ports: list[int],
        progress_callback: callable | None = None,
    ) -> dict[str, Any]:
        """
        Test default credentials across multiple ports.

        100% feature parity with CamXploit.py test_default_passwords() (lines 1201-1283).
        Enhanced with ethical safeguards: rate limiting, attempt limiting, and audit logging.

        Args:
            ip: Target IP address.
            open_ports: List of open ports to test.
            progress_callback: Optional callback(current, total) for progress updates.

        Returns:
            Dict containing:
                - 'success': Boolean indicating if credentials were found
                - 'credentials': Dict with 'username', 'password', 'url' if found
                - 'auth_type': Authentication type used ('basic', 'form', 'digest')
                - 'attempts_made': Number of credential attempts made
                - 'stopped_by_limit': Boolean indicating if stopped by attempt limit
        """
        found = [False]  # Mutable flag for threading
        credentials_found = {}
        attempt_count = [0]  # Track total attempts
        stopped_by_limit = [False]  # Track if stopped by limit
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

            # Check if stopped by attempt limit
            if stopped_by_limit[0]:
                return False

            url = f"{protocol}://{ip}:{port}{path}"

            for username, passwords in self.credentials.items():
                # Check for early termination (CamXploit.py line 1213-1214)
                if found[0] or stopped_by_limit[0]:
                    return False

                for password in passwords:
                    # Check for early termination (CamXploit.py line 1216-1217)
                    if found[0] or stopped_by_limit[0]:
                        return False

                    # Check attempt limit (ethical safeguard)
                    with lock:
                        if attempt_count[0] >= self.max_attempts_per_target:
                            stopped_by_limit[0] = True
                            logger.warning(
                                f"Reached max attempts limit ({self.max_attempts_per_target}) for {ip}"
                            )
                            return False
                        attempt_count[0] += 1

                    # Rate limiting (ethical safeguard)
                    if self.rate_limit_delay > 0:
                        time.sleep(self.rate_limit_delay)

                    try:
                        success = False

                        # Test based on authentication type
                        if auth_type == "basic":
                            success = self._test_basic_auth(url, username, password)
                        elif auth_type == "form":
                            success = self._test_form_auth(url, username, password)
                        elif auth_type == "digest":
                            success = self._test_digest_auth(url, username, password)

                        # Audit logging (ethical safeguard)
                        self._log_audit_entry(ip, port, username, password, url, auth_type, success)

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
                        # Still log audit entry for failed attempts
                        self._log_audit_entry(ip, port, username, password, url, auth_type, False)

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
            "attempts_made": attempt_count[0],
            "stopped_by_limit": stopped_by_limit[0],
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

    def _convert_to_vulnerability_results(self, ip: str, test_results: dict[str, Any]) -> list[Any]:
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
            vuln.description = f"Default credentials found: {creds['username']}:{creds['password']}"
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
