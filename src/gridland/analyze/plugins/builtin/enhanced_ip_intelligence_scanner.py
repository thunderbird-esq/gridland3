"""
Enhanced IP Intelligence Scanner with comprehensive geographic and network analysis.
Implements CamXploit.py IP intelligence (lines 213-248) with multiple data sources.
"""

import asyncio
import aiohttp
import ipaddress
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import socket

from gridland.core.logger import get_logger
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory.pool import get_memory_pool, VulnerabilityResult

logger = get_logger(__name__)

@dataclass
class IPIntelligence:
    """Comprehensive IP intelligence information"""
    ip_address: str
    is_private: bool = False
    organization: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    google_maps_url: Optional[str] = None
    google_earth_url: Optional[str] = None
    confidence: float = 0.0
    data_sources: List[str] = None
    hostname: Optional[str] = None
    hosting_provider: Optional[str] = None
    vpn_proxy_indicators: List[str] = None

class EnhancedIPIntelligenceScanner(VulnerabilityPlugin):
    """Enhanced IP intelligence scanner with comprehensive geographic analysis."""

    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Enhanced IP Intelligence Scanner",
            version="2.0.0",
            author="GRIDLAND Security Team",
            description="Comprehensive IP intelligence with geographic and network analysis",
            plugin_type="enrichment",
            priority=190
        )
        self.memory_pool = get_memory_pool()
        self.intelligence_config = self._load_intelligence_config()

    def _load_intelligence_config(self) -> Dict:
        return {
            "hosting_indicators": ["amazon", "aws", "azure", "google cloud", "digitalocean", "linode"],
            "vpn_indicators": ["vpn", "proxy", "tor", "nordvpn", "expressvpn"]
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int, service: str = "", banner: str = "") -> List[VulnerabilityResult]:
        # Unique check per IP to avoid redundant scans
        if hasattr(self, f'_context_fetched_{target_ip.replace(".", "_")}'):
            return []

        try:
            ip_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            logger.warning(f"Invalid IP address for intelligence scan: {target_ip}")
            return []

        intelligence = await self._gather_ip_intelligence(target_ip, ip_obj)
        if not intelligence:
            return []

        setattr(self, f'_context_fetched_{target_ip.replace(".", "_")}', True)
        return self._generate_intelligence_results(intelligence)

    async def _gather_ip_intelligence(self, target_ip: str, ip_obj: ipaddress.IPv4Address) -> Optional[IPIntelligence]:
        if ip_obj.is_private:
            return IPIntelligence(ip_address=target_ip, is_private=True, organization="Private Network", confidence=1.0)

        tasks = [self._query_ipinfo(target_ip), self._query_ipapi(target_ip), self._analyze_network_context(target_ip)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = [r for r in results if r and not isinstance(r, Exception)]
        if not valid_results:
            return None

        return self._merge_intelligence_data(target_ip, valid_results)

    async def _query_ipinfo(self, ip: str) -> Optional[Dict]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://ipinfo.io/{ip}/json", timeout=5) as response:
                    if response.status == 200:
                        return {"source": "ipinfo", "data": await response.json()}
        except Exception as e:
            logger.debug(f"ipinfo.io query failed for {ip}: {e}")
        return None

    async def _query_ipapi(self, ip: str) -> Optional[Dict]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}", timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            return {"source": "ipapi", "data": data}
        except Exception as e:
            logger.debug(f"ip-api.com query failed for {ip}: {e}")
        return None

    async def _analyze_network_context(self, ip: str) -> Optional[Dict]:
        try:
            hostname, _, _ = await asyncio.get_event_loop().getnameinfo((ip, 0), 0)
            return {"source": "network_analysis", "data": {"hostname": hostname}}
        except socket.gaierror:
            return {"source": "network_analysis", "data": {"hostname": None}}
        except Exception as e:
            logger.debug(f"Network context analysis failed for {ip}: {e}")
        return None

    def _merge_intelligence_data(self, ip: str, results: List[Dict]) -> IPIntelligence:
        intel = IPIntelligence(ip_address=ip, data_sources=[r['source'] for r in results])

        for res in results:
            data = res.get('data', {})
            if res['source'] == 'ipinfo':
                intel.organization = intel.organization or data.get('org')
                intel.city = intel.city or data.get('city')
                intel.region = intel.region or data.get('region')
                intel.country = intel.country or data.get('country')
                intel.timezone = intel.timezone or data.get('timezone')
                if 'loc' in data:
                    lat, lon = data['loc'].split(',')
                    intel.latitude = intel.latitude or float(lat)
                    intel.longitude = intel.longitude or float(lon)
            elif res['source'] == 'ipapi':
                intel.organization = intel.organization or data.get('org')
                intel.isp = intel.isp or data.get('isp')
                intel.asn = intel.asn or data.get('as')
                intel.city = intel.city or data.get('city')
                intel.region = intel.region or data.get('regionName')
                intel.country = intel.country or data.get('country')
                intel.latitude = intel.latitude or data.get('lat')
                intel.longitude = intel.longitude or data.get('lon')
            elif res['source'] == 'network_analysis' and data.get('hostname'):
                intel.hostname = data['hostname']
                h_lower = intel.hostname.lower()
                intel.hosting_provider = next((ind for ind in self.intelligence_config['hosting_indicators'] if ind in h_lower), None)
                intel.vpn_proxy_indicators = [ind for ind in self.intelligence_config['vpn_indicators'] if ind in h_lower]

        if intel.latitude and intel.longitude:
            intel.google_maps_url = f"https://www.google.com/maps?q={intel.latitude},{intel.longitude}"
            intel.google_earth_url = f"https://earth.google.com/web/@{intel.latitude},{intel.longitude},0a,1000d,35y,0h,0t,0r"

        intel.confidence = min(len(intel.data_sources) * 0.35, 0.95)
        return intel

    def _generate_intelligence_results(self, intel: IPIntelligence) -> List[VulnerabilityResult]:
        res = self.memory_pool.acquire_vulnerability_result()
        res.vulnerability_id = "enhanced-ip-intelligence"
        res.severity = "INFO"
        res.confidence = intel.confidence

        loc = next((l for l in [intel.city, intel.region, intel.country] if l), "Unknown Location")
        res.description = f"IP Intelligence for {intel.ip_address}: {intel.organization or 'Unknown Org'} - {loc}"

        res.details = {k: v for k, v in asdict(intel).items() if v}
        return [res]
