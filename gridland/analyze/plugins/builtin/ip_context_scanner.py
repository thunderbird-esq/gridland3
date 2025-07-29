"""
IP Context Enrichment Scanner Plugin

This plugin enriches analysis results with contextual information about the
target IP address, such as geolocation and ISP, using the ipinfo.io API.
"""

import asyncio
import aiohttp
from typing import List, Dict, Any

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class IPContextScanner(VulnerabilityPlugin):
    """Enriches results with IP geolocation and ISP data."""
    
    def __init__(self):
        super().__init__()
        self.memory_pool = get_memory_pool()
        self.session = None
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="IP Context Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="enrichment",  # Custom type for enrichment plugins
            supported_ports=list(range(1, 65536)), # Applicable to all ports
            supported_services=[], # Service agnostic
            description="Adds IP geolocation and ISP context to analysis results."
        )
    
    async def _init_session(self):
        """Initialize HTTP session if not already done."""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=15)
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'GRIDLAND Security Scanner v3.0'}
            )
    
    async def _cleanup_session(self):
        """Clean up HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def scan_vulnerabilities(self, target_ip: str, target_port: int, 
                                 service: str, banner: str) -> List[Any]:
        """
        Fetches context for the target IP and returns it as an INFO vulnerability.
        
        Args:
            target_ip: Target IP address
            target_port: Target port (unused, as context is per-IP)
            service: Service type (unused)
            banner: Service banner (unused)
            
        Returns:
            List containing a single VulnerabilityResult with context, or empty list.
        """
        # This check prevents the plugin from running for the same IP multiple times
        # if the target has multiple ports. A more robust solution would be a global
        # state, but this is a simple and effective approach for now.
        if hasattr(self, f'_context_fetched_{target_ip.replace(".", "_")}'):
            return []

        await self._init_session()
        results = []
        
        try:
            api_url = f"https://ipinfo.io/{target_ip}/json"
            async with self.session.get(api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    description = self._format_context(data)
                    
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = 0 # Port is not relevant for this info
                    vuln.service = "global"
                    vuln.vulnerability_id = "IP-CONTEXT"
                    vuln.severity = "INFO"
                    vuln.confidence = 0.99
                    vuln.description = description
                    vuln.exploit_available = False
                    results.append(vuln)
                    
                    # Mark this IP as fetched
                    setattr(self, f'_context_fetched_{target_ip.replace(".", "_")}', True)

        except Exception as e:
            logger.warning(f"Could not fetch IP context for {target_ip}: {e}")
        
        finally:
            await self._cleanup_session()
        
        return results

    def _format_context(self, data: Dict[str, Any]) -> str:
        """Format the ipinfo.io data into a readable string."""
        parts = []
        if 'org' in data:
            parts.append(f"ISP: {data['org']}")
        if 'city' in data and 'region' in data and 'country' in data:
            parts.append(f"Location: {data['city']}, {data['region']}, {data['country']}")
        if 'loc' in data:
            parts.append(f"Coords: {data['loc']}")
            lat, lon = data['loc'].split(',')
            parts.append(f"Map: https://www.google.com/maps?q={lat},{lon}")
        
        return " | ".join(parts)


# Plugin instance for automatic discovery
ip_context_scanner = IPContextScanner()
