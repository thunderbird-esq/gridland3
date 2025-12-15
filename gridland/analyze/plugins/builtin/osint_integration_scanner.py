"""
OSINT Integration Scanner Plugin for GRIDLAND v3.0

This plugin provides comprehensive OSINT (Open Source Intelligence) integration
for camera reconnaissance, including search URL generation for multiple platforms,
Google dorking automation, and API integration (when keys are available).

Key Features:
- Generate search URLs for Shodan, Censys, ZoomEye, BinaryEdge
- Generate Google Dork queries for camera discovery
- Passive DNS lookup integration
- Geolocation lookup with map URL generation
- Graceful degradation without API keys
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from gridland.analyze.core.osint.geo_lookup import GeoLookup
from gridland.analyze.core.osint.url_generator import OSINTURLGenerator
from gridland.analyze.memory import get_memory_pool
from gridland.analyze.plugins.manager import PluginMetadata, VulnerabilityPlugin
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class OSINTIntegrationScanner(VulnerabilityPlugin):
    """
    OSINT Integration Scanner plugin for camera reconnaissance.
    
    Integrates multiple OSINT sources to provide comprehensive intelligence
    about target IP addresses, including search URLs, Google dorks, and
    geolocation data.
    
    Attributes:
        url_generator: OSINTURLGenerator for creating search URLs.
        geo_lookup: GeoLookup for IP geolocation.
        api_keys: Dictionary of available API keys.
    """

    def __init__(self):
        """Initialize the OSINT Integration Scanner plugin."""
        super().__init__()
        self.url_generator = OSINTURLGenerator()
        self.geo_lookup = GeoLookup()
        self.memory_pool = get_memory_pool()
        
        # Load API keys from environment
        self.api_keys = self._load_api_keys()
        
        # Extended Google Dork patterns for cameras
        self.extended_dorks = [
            "inurl:view/view.shtml",
            "inurl:admin.html",
            "inurl:login",
            "intitle:'webcam'",
            "intitle:'IP Camera'",
            "intitle:'Network Camera'",
            "inurl:/cgi-bin/viewer/video.jpg",
            "inurl:CgiStart?page=",
            "inurl:/view.htm?indexpage",
            "inurl:/live.htm?indexpage",
            "inurl:/axis-cgi/mjpg",
            "inurl:ViewerFrame?Mode=",
            "inurl:mjpg/video.mjpg",
        ]

    def _load_api_keys(self) -> dict[str, str | None]:
        """Load API keys from environment variables.
        
        Returns:
            Dictionary of API key names to values (None if not set).
        """
        return {
            "shodan": os.environ.get("SHODAN_API_KEY"),
            "censys_id": os.environ.get("CENSYS_API_ID"),
            "censys_secret": os.environ.get("CENSYS_API_SECRET"),
            "zoomeye": os.environ.get("ZOOMEYE_API_KEY"),
            "binaryedge": os.environ.get("BINARYEDGE_API_KEY"),
        }

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata.
        
        Returns:
            PluginMetadata: Plugin information and configuration.
        """
        return PluginMetadata(
            name="OSINT Integration Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="OSINT platform integration for camera reconnaissance",
            plugin_type="reconnaissance",
            supported_services=["http", "https", "rtsp", "ftp"],
            supported_ports=list(range(1, 65536)),
            requires_auth=False,
            performance_impact="LOW",
            priority=50,  # Run early in scan
        )

    async def scan_vulnerabilities(
        self, target_ip: str, target_port: int, service: str = "", banner: str = ""
    ) -> list[Any]:
        """
        Generate OSINT intelligence for target IP.
        
        Args:
            target_ip: Target IP address.
            target_port: Target port number (used for context).
            service: Detected service type.
            banner: Service banner (not used in OSINT).
            
        Returns:
            List of VulnerabilityResult objects containing OSINT data.
        """
        results = []
        
        try:
            # Generate all OSINT data
            osint_data = await self._generate_osint_report(target_ip)
            
            # Create main OSINT summary result
            vuln = self.memory_pool.acquire_vulnerability_result()
            vuln.ip = target_ip
            vuln.port = target_port
            vuln.service = service or "osint"
            vuln.vulnerability_id = "OSINT-INTELLIGENCE"
            vuln.severity = "INFO"
            vuln.confidence = 100
            vuln.description = f"OSINT intelligence gathered for {target_ip}"
            vuln.exploit_available = False
            vuln.details = json.dumps(osint_data)
            results.append(vuln)
            
        except Exception as e:
            logger.error(f"OSINT scan error for {target_ip}: {e}")
        
        return results

    async def _generate_osint_report(self, ip: str) -> dict[str, Any]:
        """
        Generate comprehensive OSINT report for an IP.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dictionary containing all OSINT data.
        """
        report = {
            "target_ip": ip,
            "search_urls": {},
            "google_dorks": [],
            "extended_dorks": [],
            "geolocation": {},
            "api_results": {},
            "apis_available": [],
        }
        
        # Generate search URLs
        report["search_urls"] = self._generate_all_urls(ip)
        
        # Generate Google Dorks
        report["google_dorks"] = self._generate_all_dorks(ip)
        
        # Generate extended dorks
        report["extended_dorks"] = self._generate_extended_dorks(ip)
        
        # Get geolocation data
        try:
            geo_data = await self.geo_lookup.get_ip_info(ip)
            report["geolocation"] = geo_data
            report["map_urls"] = self.geo_lookup.generate_map_urls(geo_data)
        except Exception as e:
            logger.debug(f"Geolocation lookup failed for {ip}: {e}")
            report["geolocation"] = {"error": str(e)}
        
        # Check which APIs are available
        report["apis_available"] = [
            name for name, key in self.api_keys.items() if key
        ]
        
        return report

    def _generate_all_urls(self, ip: str) -> dict[str, str]:
        """
        Generate search URLs for all OSINT platforms.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dictionary of platform names to search URLs.
        """
        # Use the existing URL generator
        urls = self.url_generator.generate_search_urls(ip)
        
        # Add additional platforms
        urls["binaryedge"] = f"https://app.binaryedge.io/services/query?query={ip}"
        urls["virustotal"] = f"https://www.virustotal.com/gui/ip-address/{ip}"
        urls["ipinfo"] = f"https://ipinfo.io/{ip}"
        urls["greynoise"] = f"https://viz.greynoise.io/ip/{ip}"
        
        return urls

    def _generate_all_dorks(self, ip: str) -> list[dict[str, str]]:
        """
        Generate Google Dork queries using the URL generator.
        
        Args:
            ip: Target IP address.
            
        Returns:
            List of dork dictionaries with query and URL.
        """
        return self.url_generator.generate_google_dorks(ip)

    def _generate_extended_dorks(self, ip: str) -> list[dict[str, str]]:
        """
        Generate extended Google Dork queries for camera discovery.
        
        Args:
            ip: Target IP address.
            
        Returns:
            List of dork dictionaries with query, URL, and engine.
        """
        from urllib.parse import quote_plus
        
        dorks = []
        for pattern in self.extended_dorks:
            query = f"site:{ip} {pattern}"
            dorks.append({
                "engine": "google",
                "query": query,
                "url": f"https://www.google.com/search?q={quote_plus(query)}",
            })
            # Add Bing variant
            dorks.append({
                "engine": "bing",
                "query": query,
                "url": f"https://www.bing.com/search?q={quote_plus(query)}",
            })
        
        return dorks

    def get_available_apis(self) -> list[str]:
        """Get list of APIs with valid keys configured.
        
        Returns:
            List of API names that have keys configured.
        """
        return [name for name, key in self.api_keys.items() if key]

    def has_api_key(self, api_name: str) -> bool:
        """Check if a specific API key is available.
        
        Args:
            api_name: Name of the API (shodan, censys, etc.).
            
        Returns:
            True if the API key is configured.
        """
        return bool(self.api_keys.get(api_name))

    # =========================================================================
    # API Query Methods
    # =========================================================================

    async def query_shodan_api(self, ip: str) -> dict[str, Any]:
        """
        Query Shodan API for IP intelligence.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dict with Shodan results or error.
        """
        import aiohttp
        
        api_key = self.api_keys.get("shodan")
        if not api_key:
            return {"error": "Shodan API key not configured", "available": False}
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "available": True,
                            "ip": data.get("ip_str"),
                            "organization": data.get("org"),
                            "hostnames": data.get("hostnames", []),
                            "ports": data.get("ports", []),
                            "vulns": data.get("vulns", []),
                            "country": data.get("country_name"),
                            "city": data.get("city"),
                            "asn": data.get("asn"),
                            "isp": data.get("isp"),
                            "services": [
                                {
                                    "port": s.get("port"),
                                    "product": s.get("product"),
                                    "version": s.get("version"),
                                }
                                for s in data.get("data", [])[:10]
                            ],
                        }
                    elif response.status == 404:
                        return {"available": True, "no_data": True, "message": "IP not found in Shodan"}
                    else:
                        return {"error": f"Shodan API error: {response.status}", "available": True}
        except Exception as e:
            logger.debug(f"Shodan API query failed for {ip}: {e}")
            return {"error": str(e), "available": True}

    async def query_censys_api(self, ip: str) -> dict[str, Any]:
        """
        Query Censys API for IP intelligence.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dict with Censys results or error.
        """
        import aiohttp
        import base64
        
        api_id = self.api_keys.get("censys_id")
        api_secret = self.api_keys.get("censys_secret")
        
        if not api_id or not api_secret:
            return {"error": "Censys API credentials not configured", "available": False}
        
        # Create Basic Auth header
        credentials = f"{api_id}:{api_secret}"
        auth_header = base64.b64encode(credentials.encode()).decode()
        
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        headers = {"Authorization": f"Basic {auth_header}"}
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = data.get("result", {})
                        return {
                            "available": True,
                            "ip": result.get("ip"),
                            "services": [
                                {
                                    "port": s.get("port"),
                                    "service_name": s.get("service_name"),
                                    "transport_protocol": s.get("transport_protocol"),
                                }
                                for s in result.get("services", [])[:10]
                            ],
                            "location": result.get("location", {}),
                            "autonomous_system": result.get("autonomous_system", {}),
                            "last_updated": result.get("last_updated_at"),
                        }
                    elif response.status == 404:
                        return {"available": True, "no_data": True, "message": "IP not found in Censys"}
                    else:
                        return {"error": f"Censys API error: {response.status}", "available": True}
        except Exception as e:
            logger.debug(f"Censys API query failed for {ip}: {e}")
            return {"error": str(e), "available": True}

    async def query_zoomeye_api(self, ip: str) -> dict[str, Any]:
        """
        Query ZoomEye API for IP intelligence.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dict with ZoomEye results or error.
        """
        import aiohttp
        
        api_key = self.api_keys.get("zoomeye")
        if not api_key:
            return {"error": "ZoomEye API key not configured", "available": False}
        
        url = f"https://api.zoomeye.org/host/search?query=ip:{ip}"
        headers = {"API-KEY": api_key}
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        matches = data.get("matches", [])
                        return {
                            "available": True,
                            "total": data.get("total", 0),
                            "matches": [
                                {
                                    "ip": m.get("ip"),
                                    "port": m.get("portinfo", {}).get("port"),
                                    "service": m.get("portinfo", {}).get("service"),
                                    "app": m.get("portinfo", {}).get("app"),
                                    "device": m.get("portinfo", {}).get("device"),
                                }
                                for m in matches[:10]
                            ],
                        }
                    elif response.status == 404:
                        return {"available": True, "no_data": True, "message": "IP not found in ZoomEye"}
                    else:
                        return {"error": f"ZoomEye API error: {response.status}", "available": True}
        except Exception as e:
            logger.debug(f"ZoomEye API query failed for {ip}: {e}")
            return {"error": str(e), "available": True}

    async def query_passive_dns(self, ip: str) -> dict[str, Any]:
        """
        Query passive DNS sources for IP hostnames.
        
        This uses free public DNS lookup services.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dict with passive DNS results.
        """
        import aiohttp
        
        results = {"available": True, "hostnames": [], "sources": []}
        
        # Try multiple free DNS lookup sources
        dns_sources = [
            f"https://dns.google/resolve?name={ip}&type=PTR",
        ]
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                for source_url in dns_sources:
                    try:
                        async with session.get(source_url) as response:
                            if response.status == 200:
                                data = await response.json()
                                answers = data.get("Answer", [])
                                for answer in answers:
                                    if answer.get("data"):
                                        hostname = answer["data"].rstrip(".")
                                        if hostname not in results["hostnames"]:
                                            results["hostnames"].append(hostname)
                                results["sources"].append("dns.google")
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Passive DNS query failed for {ip}: {e}")
            results["error"] = str(e)
        
        return results

    async def query_all_apis(self, ip: str) -> dict[str, dict[str, Any]]:
        """
        Query all available OSINT APIs concurrently.
        
        Args:
            ip: Target IP address.
            
        Returns:
            Dict mapping API names to their results.
        """
        results = {}
        
        # Build list of queries to run
        queries = []
        
        if self.has_api_key("shodan"):
            queries.append(("shodan", self.query_shodan_api(ip)))
        
        if self.has_api_key("censys_id") and self.has_api_key("censys_secret"):
            queries.append(("censys", self.query_censys_api(ip)))
        
        if self.has_api_key("zoomeye"):
            queries.append(("zoomeye", self.query_zoomeye_api(ip)))
        
        # Always try passive DNS (free)
        queries.append(("passive_dns", self.query_passive_dns(ip)))
        
        # Run all queries concurrently
        if queries:
            import asyncio
            
            names = [q[0] for q in queries]
            coroutines = [q[1] for q in queries]
            
            query_results = await asyncio.gather(*coroutines, return_exceptions=True)
            
            for name, result in zip(names, query_results):
                if isinstance(result, Exception):
                    results[name] = {"error": str(result), "available": True}
                else:
                    results[name] = result
        
        return results


# Plugin instance for automatic discovery
osint_integration_scanner = OSINTIntegrationScanner()

