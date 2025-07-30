"""
Shodan Enrichment Plugin for GRIDLAND

This plugin enriches analysis results with contextual data from the Shodan API.
"""

import asyncio
import aiohttp
from typing import List, Dict, Any

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger
from gridland.core.config import get_config

logger = get_logger(__name__)

class ShodanEnrichment(VulnerabilityPlugin):
    """Enriches results with Shodan data."""

    def __init__(self):
        super().__init__()
        self.memory_pool = get_memory_pool()
        self.config = get_config()
        self.session = None

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="Shodan Enrichment",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="enrichment",
            supported_services=[],
            supported_ports=[],
            description="Enriches analysis results with contextual data from the Shodan API."
        )

    async def _init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))

    async def _cleanup_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                 service: str, banner: str) -> List[Any]:
        """Scan for Shodan data."""
        results = []
        if not self.config.has_shodan_api():
            logger.warning("Shodan API key not configured, skipping enrichment.")
            return results

        await self._init_session()

        try:
            api_url = getattr(self.config, 'shodan_api_url', f"https://api.shodan.io/shodan/host/{target_ip}?key={self.config.shodan_api_key}")
            api_url = api_url.format(ip=target_ip, key=self.config.shodan_api_key)
            logger.info(f"Querying Shodan API: {api_url}")
            async with self.session.get(api_url) as response:
                logger.info(f"Shodan API response status: {response.status}")
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Shodan API response data: {data}")
                    description = self._format_shodan_data(data)

                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = 0 # Port is not relevant for this info
                    vuln.service = "global"
                    vuln.vulnerability_id = "SHODAN-ENRICHMENT"
                    vuln.severity = "INFO"
                    vuln.confidence = 0.99
                    vuln.description = description
                    vuln.exploit_available = False
                    results.append(vuln)
        except Exception as e:
            logger.warning(f"Could not fetch Shodan data for {target_ip}: {e}")

        finally:
            await self._cleanup_session()

        return results

    def _format_shodan_data(self, data: Dict[str, Any]) -> str:
        """Format the Shodan data into a readable string."""
        parts = []
        if 'org' in data:
            parts.append(f"Org: {data['org']}")
        if 'os' in data and data['os']:
            parts.append(f"OS: {data['os']}")
        if 'isp' in data:
            parts.append(f"ISP: {data['isp']}")
        if 'hostnames' in data and data['hostnames']:
            parts.append(f"Hostnames: {', '.join(data['hostnames'])}")
        if 'vulns' in data:
            parts.append(f"Vulnerabilities: {', '.join(data['vulns'])}")

        return " | ".join(parts)

# Plugin instance for automatic discovery
shodan_enrichment = ShodanEnrichment()
