"""
Credential Bruteforcing Plugin for GRIDLAND

This plugin tests for weak or default credentials on discovered services.
"""

import asyncio
import aiohttp
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata

class CredentialBruteforcingScanner(VulnerabilityPlugin):
    """Tests for weak or default credentials."""

    def __init__(self):
        from gridland.analyze.memory import get_memory_pool
        from gridland.core.logger import get_logger
        super().__init__()
        self.memory_pool = get_memory_pool()
        self.logger = get_logger(__name__)
        self.default_credentials = self._load_default_credentials()
        self.session = None

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="Credential Bruteforcing Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=[80, 443, 8080, 8000, 8443, 8888, 9000],
            description="Tests for weak or default credentials on discovered services."
        )

    def _load_default_credentials(self) -> List[Tuple[str, str]]:
        """Load default credentials from the centralized JSON file."""
        creds_list = []
        try:
            creds_path = Path(__file__).parent.parent.parent.parent / 'data' / 'default_credentials.json'
            with open(creds_path, 'r') as f:
                data = json.load(f)
                creds_dict = data.get("credentials", {})
                for username, passwords in creds_dict.items():
                    for password in passwords:
                        creds_list.append((username, password))
            self.logger.info(f"Successfully loaded {len(creds_list)} default credentials for bruteforcing.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to load default credentials for bruteforcing: {e}.")
            return [('admin', 'admin')]
        return creds_list

    async def _init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))

    async def _cleanup_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                 service: str, banner: str) -> List[Any]:
        """Scan for weak or default credentials."""
        results = []
        if service not in ["http", "https"]:
            return results

        await self._init_session()
        base_url = f"{service}://{target_ip}:{target_port}"
        self.logger.info(f"Starting credential bruteforce on {base_url}")

        for username, password in self.default_credentials:
            try:
                auth = aiohttp.BasicAuth(username, password)
                self.logger.debug(f"Testing {username}:{password} on {base_url}")
                async with self.session.get(base_url, auth=auth, timeout=5) as response:
                    self.logger.debug(f"Response status for {username}:{password} on {base_url}: {response.status}")
                    if response.status == 200:
                        self.logger.info(f"Successful login with {username}:{password} on {base_url}")
                        vuln = self.memory_pool.acquire_vulnerability_result()
                        vuln.ip = target_ip
                        vuln.port = target_port
                        vuln.service = service
                        vuln.vulnerability_id = "DEFAULT-CREDENTIALS"
                        vuln.severity = "HIGH"
                        vuln.confidence = 0.9
                        vuln.description = f"Default credentials found: {username}:{password}"
                        vuln.exploit_available = True
                        results.append(vuln)
                        # Stop after first success
                        await self._cleanup_session()
                        return results
            except Exception as e:
                self.logger.debug(f"Credential test for {username}:{password} failed: {e}")

        await self._cleanup_session()
        return results
