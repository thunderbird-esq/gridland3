"""
Login Page Scanner Plugin for GRIDLAND v3.0

This plugin detects authentication endpoints on IP camera systems through multi-threaded
HTTP probing. It checks common login paths and identifies authentication mechanisms
(Basic, Digest, Form-based).

100% feature parity with CamXploit.py check_login_pages() (lines 1155-1199).
"""

import json
import threading
from typing import Any, Dict, List, Optional
from pathlib import Path

import requests
import urllib3

from gridland.analyze.memory import get_memory_pool
from gridland.analyze.plugins.manager import PluginMetadata, VulnerabilityPlugin
from gridland.core.logger import get_logger

# Disable SSL warnings for camera endpoints
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)


class LoginPageScanner(VulnerabilityPlugin):
    """
    Login page detection plugin for IP camera systems.

    Scans for authentication endpoints using multi-threaded HTTP probing.
    Supports detection of Basic, Digest, and Form-based authentication.

    Attributes:
        login_paths (List[str]): List of paths to check for login pages.
        max_concurrent_threads (int): Maximum concurrent scan threads (default: 50).
        timeout (int): HTTP request timeout in seconds (default: 5).
    """

    def __init__(self):
        """Initialize the Login Page Scanner plugin."""
        super().__init__()
        self.login_paths = self._load_login_paths()
        self.max_concurrent_threads = 50  # From CamXploit.py line 1176
        self.timeout = 5  # From CamXploit.py TIMEOUT constant line 797
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.memory_pool = get_memory_pool()

    def _load_login_paths(self) -> List[str]:
        """
        Load login paths from login_paths.json.

        Returns:
            List[str]: List of unique login paths from all brands.
        """
        try:
            # Get path to login_paths.json
            data_dir = Path(__file__).parent.parent.parent.parent / "data"
            login_file = data_dir / "login_paths.json"

            with open(login_file, encoding="utf-8") as f:
                login_data = json.load(f)

            # Extract all paths from all brand categories
            paths = set()
            for brand_paths in login_data["categories"].values():
                for path_info in brand_paths:
                    paths.add(path_info["path"])

            return sorted(list(paths))

        except Exception as e:
            logger.error(f"Failed to load login paths: {e}")
            # Fallback to CamXploit.py COMMON_PATHS (lines 763-781)
            return [
                "/",
                "/admin",
                "/login",
                "/viewer",
                "/webadmin",
                "/video",
                "/stream",
                "/live",
                "/snapshot",
                "/onvif-http/snapshot",
                "/system.ini",
                "/config",
                "/setup",
                "/cgi-bin/",
                "/api/",
                "/camera",
                "/img/main.cgi",
            ]

    def get_metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.

        Returns:
            PluginMetadata: Plugin information and configuration.
        """
        return PluginMetadata(
            name="Login Page Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="Detects authentication endpoints on IP camera systems",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=list(range(1, 65536)),
            requires_auth=False,
            performance_impact="MEDIUM",
            priority=50,
        )

    async def scan_vulnerabilities(
        self, target_ip: str, target_port: int, service: str = "", banner: str = ""
    ) -> List[Any]:
        """
        Scan for login pages on a single port.

        This method is called by the plugin framework for individual port analysis.
        For multi-port scanning, use scan_login_pages() directly.

        Args:
            target_ip: Target IP address.
            target_port: Target port number.
            service: Detected service type (unused).
            banner: Service banner (unused).

        Returns:
            List of VulnerabilityResult objects for found login pages.
        """
        # Scan single port
        results = self.scan_login_pages(target_ip, [target_port])
        return self._convert_to_vulnerability_results(target_ip, results)

    def scan_login_pages(
        self, ip: str, open_ports: List[int], progress_callback: Optional[callable] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan for authentication pages across multiple ports.

        100% feature parity with CamXploit.py check_login_pages() (lines 1155-1199).

        Args:
            ip: Target IP address.
            open_ports: List of open ports to scan.
            progress_callback: Optional callback(checked, total) for progress updates.

        Returns:
            Dict containing:
                - 'login_pages': List of dicts with 'url', 'status_code', 'auth_type'
                - 'total_found': Total number of login pages found
        """
        found_urls = []
        lock = threading.Lock()
        checked_count = [0]  # Mutable counter for threading
        total_checks = len(open_ports) * len(self.login_paths)

        def check_endpoint(port: int, path: str):
            """Check a single endpoint for login page indicators."""
            protocol = self._get_protocol(port)
            url = f"{protocol}://{ip}:{port}{path}"

            try:
                response = requests.head(
                    url, headers=self.headers, timeout=self.timeout, verify=False
                )

                # CamXploit.py line 1165: success codes are 200, 401, 403
                if response.status_code in [200, 401, 403]:
                    # Detect authentication type
                    auth_type = self._detect_auth_type(response)

                    with lock:
                        found_urls.append(
                            {
                                "url": url,
                                "status_code": response.status_code,
                                "auth_type": auth_type,
                            }
                        )
                        logger.info(
                            f"Found login page: {url} (HTTP {response.status_code}, {auth_type})"
                        )

            except Exception:
                # Silent failure as in CamXploit.py line 1170-1171
                pass
            finally:
                with lock:
                    checked_count[0] += 1
                    if progress_callback:
                        progress_callback(checked_count[0], total_checks)

        # Use threading for faster checking (CamXploit.py lines 1174-1193)
        threads = []

        for port in open_ports:
            for path in self.login_paths:
                thread = threading.Thread(target=check_endpoint, args=(port, path))
                thread.daemon = True
                threads.append(thread)
                thread.start()

                # Limit concurrent threads to avoid overwhelming
                # CamXploit.py lines 1186-1189
                if len(threads) >= self.max_concurrent_threads:
                    for t in threads:
                        t.join()
                    threads = []

        # Wait for remaining threads (CamXploit.py lines 1192-1193)
        for thread in threads:
            thread.join()

        return {"login_pages": found_urls, "total_found": len(found_urls)}

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

    def _detect_auth_type(self, response: requests.Response) -> str:
        """
        Detect authentication type from HTTP response.

        Analyzes WWW-Authenticate header and response body to determine
        authentication mechanism.

        Args:
            response: HTTP response object.

        Returns:
            Authentication type: 'basic', 'digest', 'form', or 'unknown'.
        """
        # Check WWW-Authenticate header for Basic/Digest
        www_auth = response.headers.get("WWW-Authenticate", "")
        if "Basic" in www_auth:
            return "basic"
        elif "Digest" in www_auth:
            return "digest"

        # For 200 responses, check if it's a login form
        if response.status_code == 200:
            try:
                # Do a GET to fetch body content
                full_response = requests.get(
                    response.url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,
                )
                if self._has_login_form(full_response.text):
                    return "form"
            except Exception:
                pass

        return "unknown"

    def _has_login_form(self, html: str) -> bool:
        """
        Check if HTML contains login form indicators.

        Args:
            html: HTML content to analyze.

        Returns:
            True if login form detected, False otherwise.
        """
        html_lower = html.lower()

        # Look for common form field indicators
        form_indicators = [
            "type=\"password\"",
            "type='password'",
            'name="username"',
            'name="password"',
            'name="login"',
            "type=\"submit\"",
            "<form",
        ]

        # Need at least a form and password field
        has_form = "<form" in html_lower
        has_password = any(
            ind in html_lower
            for ind in ["type=\"password\"", "type='password'"]
        )

        return has_form and has_password

    def _convert_to_vulnerability_results(
        self, ip: str, scan_results: Dict[str, Any]
    ) -> List[Any]:
        """
        Convert scan results to VulnerabilityResult objects.

        Args:
            ip: Target IP address.
            scan_results: Results from scan_login_pages().

        Returns:
            List of VulnerabilityResult objects.
        """
        results = []

        for login_page in scan_results["login_pages"]:
            vuln = self.memory_pool.acquire_vulnerability_result()
            vuln.ip = ip
            # Extract port from URL
            url_parts = login_page["url"].split(":")
            if len(url_parts) >= 3:
                port_str = url_parts[2].split("/")[0]
                vuln.port = int(port_str)
            else:
                vuln.port = 80

            vuln.service = "http"
            vuln.vulnerability_id = "LOGIN-PAGE-DETECTED"
            vuln.severity = "INFO"
            vuln.confidence = 95
            vuln.description = f"Login page detected: {login_page['auth_type']} authentication"
            vuln.exploit_available = False

            # Add details
            details = {
                "url": login_page["url"],
                "status_code": login_page["status_code"],
                "auth_type": login_page["auth_type"],
                "plugin": "login_scanner",
            }
            vuln.details = json.dumps(details)

            results.append(vuln)

        return results


# Plugin instance for automatic discovery
login_scanner = LoginPageScanner()
