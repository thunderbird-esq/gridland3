"""
Credential Bruteforcing Plugin for GRIDLAND

This plugin tests for weak or default credentials on discovered services,
supporting both HTTP Basic Auth and form-based authentication.
"""

import asyncio
import aiohttp
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata, VulnerabilityResult

class CredentialBruteforcingScanner(VulnerabilityPlugin):
    """Tests for weak or default credentials."""

    def __init__(self):
        from gridland.analyze.memory import get_memory_pool
        from gridland.core.logger import get_logger
        super().__init__()
        self.metadata = PluginMetadata(
            name="Credential Bruteforcing Scanner",
            version="1.1.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=[80, 443, 8080, 8000, 8443, 8888, 9000],
            description="Tests for weak or default credentials using HTTP Basic Auth and form submission."
        )
        self.memory_pool = get_memory_pool()
        self.logger = get_logger(__name__)
        self.default_credentials = self._load_default_credentials()
        self.session: aiohttp.ClientSession | None = None
        self.form_field_variants = [
            ('username', 'password'),
            ('user', 'pass'),
            ('login', 'password'),
            ('user_id', 'user_pass'),
        ]
        self.login_endpoints = ['/login', '/admin', '/login.html', '/admin/login', '/']


    def _load_default_credentials(self) -> List[Tuple[str, str]]:
        """Load default credentials from the centralized JSON file."""
        creds_list = []
        try:
            # Correctly reference the data file relative to this plugin's location
            creds_path = Path(__file__).parent.parent.parent.parent / 'data' / 'default_credentials.json'
            with open(creds_path, 'r') as f:
                data = json.load(f)
                creds_dict = data.get("credentials", {})
                for username, passwords in creds_dict.items():
                    for password in passwords:
                        creds_list.append((username, password))
            self.logger.info(f"Successfully loaded {len(creds_list)} default credentials.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to load default credentials: {e}. Using a minimal list.")
            return [('admin', 'admin')]
        return creds_list

    async def _init_session(self):
        if not self.session or self.session.closed:
            # Disable SSL verification for testing self-signed certs on cameras
            connector = aiohttp.TCPConnector(ssl=False)
            self.session = aiohttp.ClientSession(connector=connector)

    async def _cleanup_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    def _is_successful_login(self, status: int, content: str) -> bool:
        """Check for indicators of a successful login to avoid false positives."""
        if status != 200:
            return False

        content_lower = content.lower()
        # Positive indicators of being logged in
        success_keywords = ['logout', 'dashboard', 'system status', 'device settings', 'welcome admin']
        # Negative indicators (still on the login page)
        failure_keywords = ['invalid username or password', 'login failed', 'please log in']

        if any(keyword in content_lower for keyword in failure_keywords):
            return False

        return any(keyword in content_lower for keyword in success_keywords)

    async def _test_basic_auth(self, base_url: str, username: str, password: str) -> bool:
        """Test credentials using HTTP Basic Auth."""
        try:
            auth = aiohttp.BasicAuth(username, password)
            self.logger.debug(f"Testing Basic Auth {username}:{password} on {base_url}")
            async with self.session.get(base_url, auth=auth, timeout=5) as response:
                content = await response.text()
                if self._is_successful_login(response.status, content):
                    self.logger.info(f"Successful Basic Auth login with {username}:{password} on {base_url}")
                    return True
        except Exception as e:
            self.logger.debug(f"Basic Auth test for {username}:{password} failed: {e}")
        return False

    async def _test_form_auth(self, base_url: str, username: str, password: str) -> bool:
        """Test credentials using form-based authentication."""
        for endpoint in self.login_endpoints:
            url = f"{base_url}{endpoint}"
            for user_field, pass_field in self.form_field_variants:
                data = {user_field: username, pass_field: password}
                try:
                    self.logger.debug(f"Testing Form Auth {username}:{password} on {url} with fields {user_field}/{pass_field}")
                    async with self.session.post(url, data=data, timeout=5) as response:
                        content = await response.text()
                        if self._is_successful_login(response.status, content):
                            self.logger.info(f"Successful Form Auth login with {username}:{password} on {url}")
                            return True
                except Exception as e:
                    self.logger.debug(f"Form Auth test for {username}:{password} failed on {url}: {e}")
        return False

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                 service: str, banner: str) -> List[VulnerabilityResult]:
        """Scan for weak or default credentials using multiple methods."""
        if service not in ["http", "https"]:
            return []

        await self._init_session()
        base_url = f"{service}://{target_ip}:{target_port}"
        self.logger.info(f"Starting credential bruteforce on {base_url}")

        for username, password in self.default_credentials:
            # Test Basic Auth
            if await self._test_basic_auth(base_url, username, password):
                vuln = self._create_vuln_result(target_ip, target_port, service, username, password, "HTTP Basic Auth")
                await self._cleanup_session()
                return [vuln]

            # Test Form-based Auth
            if await self._test_form_auth(base_url, username, password):
                vuln = self._create_vuln_result(target_ip, target_port, service, username, password, "Form-Based Auth")
                await self._cleanup_session()
                return [vuln]

        await self._cleanup_session()
        return []

    def _create_vuln_result(self, ip: str, port: int, service: str, user: str, passw: str, method: str) -> VulnerabilityResult:
        """Create a new VulnerabilityResult object."""
        vuln = self.memory_pool.acquire_vulnerability_result()
        vuln.ip = ip
        vuln.port = port
        vuln.service = service
        vuln.vulnerability_id = "DEFAULT-CREDENTIALS"
        vuln.severity = "HIGH"
        vuln.confidence = 0.95
        vuln.description = f"Default credentials found via {method}: {user}:{passw}"
        vuln.exploit_available = True
        return vuln
