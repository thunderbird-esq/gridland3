"""
Enhanced IP Intelligence Scanner with comprehensive geographic and network analysis.
Implements CamXploit.py IP intelligence (lines 213-248) with multiple data sources.
"""

import asyncio
import aiohttp
import ipaddress
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

from gridland.core.logger import get_logger
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool


logger = get_logger(__name__)

@dataclass
class IPIntelligence:
    """Comprehensive IP intelligence information"""
    ip_address: str
    is_private: bool
    organization: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    country: Optional[str]
    country_code: Optional[str]
    region: Optional[str]
    city: Optional[str]
    postal_code: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    timezone: Optional[str]
    threat_indicators: List[str]
    reputation_score: Optional[float]
    hosting_provider: Optional[str]
    vpn_proxy_indicators: List[str]
    google_maps_url: Optional[str]
    google_earth_url: Optional[str]
    confidence: float
    data_sources: List[str]

class EnhancedIPIntelligenceScanner(VulnerabilityPlugin):
    """
    Enhanced IP intelligence scanner with comprehensive geographic analysis.

    Provides detailed IP intelligence including geographic location, network
    ownership, threat indicators, and interactive mapping integration.
    """

    def __init__(self):
        super().__init__()
        self.intelligence_config = self._load_intelligence_config()
        self.memory_pool = get_memory_pool()

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Enhanced IP Intelligence Scanner",
            version="2.0.0",
            author="GRIDLAND Security Team",
            description="Comprehensive IP intelligence with geographic and network analysis",
            plugin_type="enrichment",
            supported_services=[],
            supported_ports=[],
            requires_auth=False,
            performance_impact="LOW",
            priority=190
        )

    def _load_intelligence_config(self) -> Dict:
        """Load IP intelligence configuration and data sources"""
        return {
            "data_sources": {
                "ipinfo": {
                    "url": "https://ipinfo.io/{ip}/json",
                    "rate_limit": 1000,  # per month
                    "fields": ["ip", "org", "city", "region", "country", "loc", "timezone", "postal"]
                },
                "ipapi": {
                    "url": "http://ip-api.com/json/{ip}",
                    "rate_limit": 45,   # per minute
                    "fields": ["query", "org", "city", "regionName", "country", "lat", "lon", "timezone", "zip", "isp", "as"]
                },
                "ipgeolocation": {
                    "url": "https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}",
                    "rate_limit": 1000,  # per day (free tier)
                    "fields": ["ip", "organization", "city", "state_prov", "country_name", "latitude", "longitude", "time_zone", "zipcode", "isp"]
                }
            },
            "threat_sources": {
                "abuseipdb": {
                    "url": "https://api.abuseipdb.com/api/v2/check",
                    "headers": {"Key": "{api_key}", "Accept": "application/json"},
                    "confidence_threshold": 25
                },
                "virustotal": {
                    "url": "https://www.virustotal.com/vtapi/v2/ip-address/report",
                    "params": {"apikey": "{api_key}", "ip": "{ip}"}
                }
            },
            "hosting_indicators": [
                "amazon", "aws", "azure", "google cloud", "digitalocean", "linode",
                "vultr", "ovh", "hetzner", "hostinger", "godaddy", "bluehost"
            ],
            "vpn_indicators": [
                "vpn", "proxy", "tor", "anonymizer", "tunnel", "hide", "private",
                "nordvpn", "expressvpn", "surfshark", "purevpn"
            ]
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                    service: str = "", banner: str = "") -> List:
        """Comprehensive IP intelligence analysis"""

        # This check prevents the plugin from running for the same IP multiple times
        if hasattr(self, f'_context_fetched_{target_ip.replace(".", "_")}'):
            return []

        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            logger.warning(f"Invalid IP address: {target_ip}")
            return []

        # Gather intelligence from multiple sources
        intelligence = await self._gather_ip_intelligence(target_ip, ip_obj)

        if not intelligence:
            return []

        # Mark this IP as fetched
        setattr(self, f'_context_fetched_{target_ip.replace(".", "_")}', True)

        # Generate intelligence results
        return self._generate_intelligence_results(intelligence, target_ip, target_port)

    async def _gather_ip_intelligence(self, target_ip: str, ip_obj) -> Optional[IPIntelligence]:
        """Gather IP intelligence from multiple data sources"""

        is_private = ip_obj.is_private

        # Skip private IPs but provide warning
        if is_private:
            logger.warning(f"Private IP address detected: {target_ip}")
            return IPIntelligence(
                ip_address=target_ip,
                is_private=True,
                organization="Private Network",
                isp=None, asn=None, country=None, country_code=None,
                region=None, city=None, postal_code=None,
                latitude=None, longitude=None, timezone=None,
                threat_indicators=["private_ip_warning"],
                reputation_score=None, hosting_provider=None,
                vpn_proxy_indicators=[], google_maps_url=None,
                google_earth_url=None, confidence=1.0,
                data_sources=["local_analysis"]
            )

        # Gather data from multiple sources concurrently
        tasks = [
            self._query_ipinfo(target_ip),
            self._query_ipapi(target_ip),
            self._analyze_network_context(target_ip)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results from all sources
        merged_intelligence = self._merge_intelligence_data(target_ip, results)

        return merged_intelligence

    async def _query_ipinfo(self, target_ip: str) -> Optional[Dict]:
        """Query ipinfo.io for IP intelligence"""

        try:
            url = f"https://ipinfo.io/{target_ip}/json"

            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {"source": "ipinfo", "data": data}

        except Exception as e:
            logger.debug(f"ipinfo.io query failed: {e}")

        return None

    async def _query_ipapi(self, target_ip: str) -> Optional[Dict]:
        """Query ip-api.com for IP intelligence"""

        try:
            url = f"http://ip-api.com/json/{target_ip}"

            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "success":
                            return {"source": "ipapi", "data": data}

        except Exception as e:
            logger.debug(f"ip-api.com query failed: {e}")

        return None

    async def _analyze_network_context(self, target_ip: str) -> Optional[Dict]:
        """Analyze network context and hosting indicators"""

        try:
            # Reverse DNS lookup
            import socket
            try:
                hostname, _, _ = await asyncio.get_event_loop().getnameinfo((target_ip, 0), 0)
            except socket.gaierror:
                hostname = None

            # Analyze hostname for hosting/VPN indicators
            hosting_indicators = []
            vpn_indicators = []

            if hostname:
                hostname_lower = hostname.lower()

                for indicator in self.intelligence_config["hosting_indicators"]:
                    if indicator in hostname_lower:
                        hosting_indicators.append(indicator)

                for indicator in self.intelligence_config["vpn_indicators"]:
                    if indicator in hostname_lower:
                        vpn_indicators.append(indicator)

            return {
                "source": "network_analysis",
                "data": {
                    "hostname": hostname,
                    "hosting_indicators": hosting_indicators,
                    "vpn_indicators": vpn_indicators
                }
            }

        except Exception as e:
            logger.debug(f"Network context analysis failed: {e}")

        return None

    def _merge_intelligence_data(self, target_ip: str, results: List) -> IPIntelligence:
        """Merge intelligence data from multiple sources"""

        # Initialize with defaults
        intelligence = IPIntelligence(
            ip_address=target_ip,
            is_private=False,
            organization=None, isp=None, asn=None,
            country=None, country_code=None, region=None,
            city=None, postal_code=None, latitude=None,
            longitude=None, timezone=None, threat_indicators=[],
            reputation_score=None, hosting_provider=None,
            vpn_proxy_indicators=[], google_maps_url=None,
            google_earth_url=None, confidence=0.0, data_sources=[]
        )

        # Process results from each source
        for result in results:
            if isinstance(result, dict) and "source" in result:
                source = result["source"]
                data = result["data"]
                if data:
                    intelligence.data_sources.append(source)

                    if source == "ipinfo":
                        self._merge_ipinfo_data(intelligence, data)
                    elif source == "ipapi":
                        self._merge_ipapi_data(intelligence, data)
                    elif source == "network_analysis":
                        self._merge_network_analysis(intelligence, data)

        # Generate mapping URLs if coordinates available
        if intelligence.latitude and intelligence.longitude:
            intelligence.google_maps_url = (
                f"https://www.google.com/maps?q={intelligence.latitude},{intelligence.longitude}"
            )
            intelligence.google_earth_url = (
                f"https://earth.google.com/web/@{intelligence.latitude},{intelligence.longitude},"
                f"0a,1000d,35y,0h,0t,0r"
            )

        # Calculate overall confidence
        intelligence.confidence = min(len(intelligence.data_sources) * 0.3, 0.95)

        return intelligence

    def _merge_ipinfo_data(self, intelligence: IPIntelligence, data: Dict):
        """Merge ipinfo.io data into intelligence object"""

        intelligence.organization = data.get("org")
        intelligence.city = data.get("city")
        intelligence.region = data.get("region")
        intelligence.country = data.get("country")
        intelligence.postal_code = data.get("postal")
        intelligence.timezone = data.get("timezone")

        # Parse coordinates
        if "loc" in data:
            try:
                lat_str, lon_str = data["loc"].split(",")
                intelligence.latitude = float(lat_str)
                intelligence.longitude = float(lon_str)
            except:
                pass

    def _merge_ipapi_data(self, intelligence: IPIntelligence, data: Dict):
        """Merge ip-api.com data into intelligence object"""

        if not intelligence.organization:
            intelligence.organization = data.get("org")

        intelligence.isp = data.get("isp")
        intelligence.asn = data.get("as")

        if not intelligence.city:
            intelligence.city = data.get("city")
        if not intelligence.region:
            intelligence.region = data.get("regionName")
        if not intelligence.country:
            intelligence.country = data.get("country")

        # Coordinates from ip-api
        if not intelligence.latitude and "lat" in data:
            intelligence.latitude = data.get("lat")
        if not intelligence.longitude and "lon" in data:
            intelligence.longitude = data.get("lon")

        if not intelligence.timezone:
            intelligence.timezone = data.get("timezone")

    def _merge_network_analysis(self, intelligence: IPIntelligence, data: Dict):
        """Merge network analysis data into intelligence object"""

        hosting_indicators = data.get("hosting_indicators", [])
        vpn_indicators = data.get("vpn_indicators", [])

        if hosting_indicators:
            intelligence.hosting_provider = hosting_indicators[0]  # Primary indicator
            intelligence.threat_indicators.extend([f"hosting: {ind}" for ind in hosting_indicators])

        if vpn_indicators:
            intelligence.vpn_proxy_indicators = vpn_indicators
            intelligence.threat_indicators.extend([f"vpn: {ind}" for ind in vpn_indicators])

    def _generate_intelligence_results(self, intelligence: IPIntelligence,
                                     target_ip: str, target_port: int) -> List:
        """Generate vulnerability results for IP intelligence"""

        results = []

        # Main intelligence result
        intel_result = self.memory_pool.get_vulnerability_result()
        intel_result.id = "enhanced-ip-intelligence"
        intel_result.severity = "INFO"
        intel_result.confidence = intelligence.confidence
        intel_result.description = self._generate_intelligence_description(intelligence)
        intel_result.exploit_available = False
        intel_result.metadata = {
            "ip_address": intelligence.ip_address,
            "is_private": intelligence.is_private,
            "organization": intelligence.organization,
            "isp": intelligence.isp,
            "asn": intelligence.asn,
            "country": intelligence.country,
            "region": intelligence.region,
            "city": intelligence.city,
            "postal_code": intelligence.postal_code,
            "coordinates": {
                "latitude": intelligence.latitude,
                "longitude": intelligence.longitude
            } if intelligence.latitude else None,
            "timezone": intelligence.timezone,
            "hosting_provider": intelligence.hosting_provider,
            "vpn_proxy_indicators": intelligence.vpn_proxy_indicators,
            "threat_indicators": intelligence.threat_indicators,
            "google_maps_url": intelligence.google_maps_url,
            "google_earth_url": intelligence.google_earth_url,
            "data_sources": intelligence.data_sources
        }
        results.append(intel_result)

        # Generate specific alerts for threats/warnings
        if intelligence.is_private:
            warning_result = self.memory_pool.get_vulnerability_result()
            warning_result.id = "private-ip-warning"
            warning_result.severity = "LOW"
            warning_result.confidence = 1.0
            warning_result.description = "Private IP address detected - tool intended for public IPs only"
            warning_result.exploit_available = False
            warning_result.metadata = {
                "warning_type": "private_ip",
                "ip_address": intelligence.ip_address
            }
            results.append(warning_result)

        if intelligence.vpn_proxy_indicators:
            vpn_result = self.memory_pool.get_vulnerability_result()
            vpn_result.id = "vpn-proxy-detected"
            vpn_result.severity = "INFO"
            vpn_result.confidence = 0.80
            vpn_result.description = f"VPN/Proxy indicators detected: {', '.join(intelligence.vpn_proxy_indicators)}"
            vpn_result.exploit_available = False
            vpn_result.metadata = {
                "detection_type": "vpn_proxy",
                "indicators": intelligence.vpn_proxy_indicators
            }
            results.append(vpn_result)

        if intelligence.hosting_provider:
            hosting_result = self.memory_pool.get_vulnerability_result()
            hosting_result.id = "hosting-provider-detected"
            hosting_result.severity = "INFO"
            hosting_result.confidence = 0.75
            hosting_result.description = f"Cloud/hosting provider detected: {intelligence.hosting_provider}"
            hosting_result.exploit_available = False
            hosting_result.metadata = {
                "detection_type": "hosting_provider",
                "provider": intelligence.hosting_provider
            }
            results.append(hosting_result)

        return results

    def _generate_intelligence_description(self, intelligence: IPIntelligence) -> str:
        """Generate human-readable intelligence description"""

        if intelligence.is_private:
            return f"Private IP address: {intelligence.ip_address} - {intelligence.organization}"

        parts = [f"IP Intelligence for {intelligence.ip_address}"]

        if intelligence.organization:
            parts.append(f"Org: {intelligence.organization}")

        if intelligence.city and intelligence.country:
            location = f"{intelligence.city}, {intelligence.country}"
            if intelligence.region:
                location = f"{intelligence.city}, {intelligence.region}, {intelligence.country}"
            parts.append(f"Location: {location}")

        if intelligence.latitude and intelligence.longitude:
            parts.append(f"Coords: {intelligence.latitude:.4f}, {intelligence.longitude:.4f}")

        if intelligence.timezone:
            parts.append(f"Timezone: {intelligence.timezone}")

        return " | ".join(parts)


# Plugin instance for automatic discovery
enhanced_ip_intelligence_scanner = EnhancedIPIntelligenceScanner()
