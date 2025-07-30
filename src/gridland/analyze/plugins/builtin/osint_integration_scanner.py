"""
OSINT Integration Scanner with automated intelligence gathering and correlation.
Implements CamXploit.py OSINT capabilities (lines 195-211) with enhanced automation.
"""

import asyncio
import aiohttp
import json
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib
import base64

from gridland.core.logger import get_logger
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool

logger = get_logger(__name__)

@dataclass
class OSINTResult:
    """OSINT platform search result"""
    platform: str
    query: str
    url: str
    results_found: Optional[int]
    confidence: float
    summary: Optional[str]
    raw_data: Optional[Dict]
    search_timestamp: datetime

class OSINTIntegrationScanner(VulnerabilityPlugin):
    """
    Comprehensive OSINT integration scanner with automated intelligence gathering.

    Integrates with major OSINT platforms to provide automated intelligence
    correlation and verification workflows for discovered camera systems.
    """

    def __init__(self):
        super().__init__()
        self.osint_config = self._load_osint_config()
        self.memory_pool = get_memory_pool()

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="OSINT Integration Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="Automated OSINT platform integration and intelligence correlation",
            plugin_type="enrichment",
            supported_services=[],
            supported_ports=[],
            requires_auth=False,
            performance_impact="LOW",
            priority=200
        )

    def _load_osint_config(self) -> Dict:
        """Load OSINT platform configuration and API settings"""
        return {
            "platforms": {
                "shodan": {
                    "search_url": "https://www.shodan.io/search?query={query}",
                    "api_url": "https://api.shodan.io/shodan/host/{ip}",
                    "api_key_required": True,
                    "rate_limit": 100,  # per month for free tier
                    "confidence": 0.95
                },
                "censys": {
                    "search_url": "https://search.censys.io/hosts/{ip}",
                    "api_url": "https://search.censys.io/api/v2/hosts/{ip}",
                    "api_key_required": True,
                    "rate_limit": 250,  # per month for free tier
                    "confidence": 0.90
                },
                "zoomeye": {
                    "search_url": "https://www.zoomeye.org/searchResult?q={query}",
                    "api_url": "https://api.zoomeye.org/host/search",
                    "api_key_required": True,
                    "rate_limit": 10000,  # per month for free tier
                    "confidence": 0.85
                },
                "binaryedge": {
                    "search_url": "https://app.binaryedge.io/services/query?query={query}",
                    "api_url": "https://api.binaryedge.io/v2/query/ip/{ip}",
                    "api_key_required": True,
                    "rate_limit": 250,  # per month for free tier
                    "confidence": 0.85
                },
                "fofa": {
                    "search_url": "https://fofa.so/result?qbase64={query_b64}",
                    "api_url": "https://fofa.so/api/v1/search/all",
                    "api_key_required": True,
                    "rate_limit": 10000,  # per year for free tier
                    "confidence": 0.80
                }
            },
            "google_dorking": {
                "camera_dorks": [
                    "site:{ip} inurl:view/view.shtml",
                    "site:{ip} inurl:admin.html",
                    "site:{ip} inurl:login",
                    "site:{ip} intitle:webcam",
                    "site:{ip} inurl:cgi-bin",
                    "site:{ip} inurl:axis-cgi",
                    "site:{ip} inurl:ISAPI",
                    "site:{ip} inurl:onvif",
                    "site:{ip} \"IP Camera\"",
                    "site:{ip} \"Network Camera\"",
                    "site:{ip} \"Live View\"",
                    "site:{ip} \"DVR\"",
                    "site:{ip} \"NVR\""
                ],
                "search_engines": {
                    "google": "https://www.google.com/search?q={query}",
                    "bing": "https://www.bing.com/search?q={query}",
                    "duckduckgo": "https://duckduckgo.com/?q={query}"
                }
            },
            "passive_dns": {
                "virustotal": {
                    "url": "https://www.virustotal.com/vtapi/v2/ip-address/report",
                    "api_key_required": True
                },
                "circl": {
                    "url": "https://www.circl.lu/pdns/query/{ip}",
                    "api_key_required": False
                }
            }
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                    service: str = "", banner: str = "") -> List:
        """Comprehensive OSINT analysis and intelligence correlation"""

        # This check prevents the plugin from running for the same IP multiple times
        if hasattr(self, f'_osint_fetched_{target_ip.replace(".", "_")}'):
            return []

        # Generate search URLs for manual verification
        search_urls = self._generate_search_urls(target_ip)

        # Generate Google dorks
        google_dorks = self._generate_google_dorks(target_ip)

        # Attempt automated platform queries (if API keys available)
        platform_results = await self._query_osint_platforms(target_ip)

        # Generate passive DNS queries
        dns_results = await self._query_passive_dns(target_ip)

        # Combine all OSINT intelligence
        all_results = {
            "search_urls": search_urls,
            "google_dorks": google_dorks,
            "platform_results": platform_results,
            "dns_results": dns_results
        }

        # Mark this IP as fetched
        setattr(self, f'_osint_fetched_{target_ip.replace(".", "_")}', True)

        # Generate vulnerability results
        return self._generate_osint_results(all_results, target_ip, target_port)

    def _generate_search_urls(self, target_ip: str) -> Dict[str, str]:
        """Generate search URLs for manual platform verification"""

        search_urls = {}

        for platform, config in self.osint_config["platforms"].items():
            if "{ip}" in config["search_url"]:
                url = config["search_url"].format(ip=target_ip)
            else:
                query = f'ip="{target_ip}"'
                if platform == 'fofa':
                    query_b64 = base64.b64encode(query.encode()).decode()
                    url = config["search_url"].format(query_b64=query_b64)
                else:
                    url = config["search_url"].format(query=urllib.parse.quote_plus(query))

            search_urls[platform] = url

        return search_urls

    def _generate_google_dorks(self, target_ip: str) -> List[Dict[str, str]]:
        """Generate Google dork queries for camera discovery"""

        dorks = []

        for dork_template in self.osint_config["google_dorking"]["camera_dorks"]:
            dork_query = dork_template.format(ip=target_ip)

            for engine, url_template in self.osint_config["google_dorking"]["search_engines"].items():
                encoded_query = urllib.parse.quote_plus(dork_query)
                search_url = url_template.format(query=encoded_query)

                dorks.append({
                    "engine": engine,
                    "query": dork_query,
                    "url": search_url,
                    "description": f"Search for camera interfaces on {target_ip}"
                })

        return dorks

    async def _query_osint_platforms(self, target_ip: str) -> List[OSINTResult]:
        """Query OSINT platforms with API integration"""

        results = []

        # Check for API keys in environment or config
        api_keys = self._get_api_keys()

        # Query platforms concurrently
        tasks = []

        if "shodan" in api_keys:
            tasks.append(self._query_shodan(target_ip, api_keys["shodan"]))

        if "censys_id" in api_keys and "censys_secret" in api_keys:
            tasks.append(self._query_censys(target_ip, api_keys["censys_id"], api_keys["censys_secret"]))

        if "zoomeye" in api_keys:
            tasks.append(self._query_zoomeye(target_ip, api_keys["zoomeye"]))

        if tasks:
            platform_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in platform_results:
                if isinstance(result, OSINTResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.debug(f"OSINT platform query failed: {result}")

        return results

    def _get_api_keys(self) -> Dict[str, str]:
        """Get API keys from environment variables or configuration"""

        import os

        api_keys = {}

        # Check environment variables for API keys
        env_mappings = {
            "shodan": "SHODAN_API_KEY",
            "censys_id": "CENSYS_API_ID",
            "censys_secret": "CENSYS_API_SECRET",
            "zoomeye": "ZOOMEYE_API_KEY",
            "binaryedge": "BINARYEDGE_API_KEY",
            "fofa": "FOFA_API_KEY",
            "virustotal": "VIRUSTOTAL_API_KEY"
        }

        for key, env_var in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                api_keys[key] = value

        return api_keys

    async def _query_shodan(self, target_ip: str, api_key: str) -> Optional[OSINTResult]:
        """Query Shodan API for IP intelligence"""

        try:
            url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"

            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Extract relevant information
                        ports = data.get("ports", [])
                        organization = data.get("org", "Unknown")
                        hostnames = data.get("hostnames", [])
                        vulns = data.get("vulns", [])

                        summary = f"Org: {organization}, Ports: {len(ports)}, Hostnames: {len(hostnames)}, Vulns: {len(vulns)}"

                        return OSINTResult(
                            platform="shodan",
                            query=target_ip,
                            url=f"https://www.shodan.io/host/{target_ip}",
                            results_found=1,
                            confidence=0.95,
                            summary=summary,
                            raw_data=data,
                            search_timestamp=datetime.now()
                        )

                    elif response.status == 404:
                        return OSINTResult(
                            platform="shodan",
                            query=target_ip,
                            url=f"https://www.shodan.io/host/{target_ip}",
                            results_found=0,
                            confidence=0.90,
                            summary="No Shodan data found for this IP",
                            raw_data=None,
                            search_timestamp=datetime.now()
                        )

        except Exception as e:
            logger.debug(f"Shodan query failed: {e}")

        return None

    async def _query_censys(self, target_ip: str, api_id: str, api_secret: str) -> Optional[OSINTResult]:
        """Query Censys API for IP intelligence"""

        try:
            url = f"https://search.censys.io/api/v2/hosts/{target_ip}"

            # Basic authentication for Censys
            auth_string = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
            headers = {"Authorization": f"Basic {auth_string}"}

            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Extract relevant information
                        services = data.get("result", {}).get("services", [])
                        location = data.get("result", {}).get("location", {})
                        autonomous_system = data.get("result", {}).get("autonomous_system", {})

                        summary = f"Services: {len(services)}, ASN: {autonomous_system.get('asn', 'N/A')}, Country: {location.get('country', 'N/A')}"

                        return OSINTResult(
                            platform="censys",
                            query=target_ip,
                            url=f"https://search.censys.io/hosts/{target_ip}",
                            results_found=1,
                            confidence=0.90,
                            summary=summary,
                            raw_data=data,
                            search_timestamp=datetime.now()
                        )

        except Exception as e:
            logger.debug(f"Censys query failed: {e}")

        return None

    async def _query_zoomeye(self, target_ip: str, api_key: str) -> Optional[OSINTResult]:
        """Query ZoomEye API for IP intelligence"""

        try:
            url = f"https://api.zoomeye.org/host/search?query=ip:{target_ip}"
            headers = {"API-KEY": api_key}

            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=15)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()

                        matches = data.get("matches", [])
                        total = data.get("total", 0)

                        if total > 0:
                            # Extract port information
                            ports = set()
                            services = set()

                            for match in matches:
                                if "portinfo" in match:
                                    ports.add(match["portinfo"].get("port"))
                                    services.add(match["portinfo"].get("service", "unknown"))

                            summary = f"Total records: {total}, Ports: {len(ports)}, Services: {len(services)}"

                            return OSINTResult(
                                platform="zoomeye",
                                query=target_ip,
                                url=f"https://www.zoomeye.org/searchResult?q=ip:{target_ip}",
                                results_found=total,
                                confidence=0.85,
                                summary=summary,
                                raw_data=data,
                                search_timestamp=datetime.now()
                            )

        except Exception as e:
            logger.debug(f"ZoomEye query failed: {e}")

        return None

    async def _query_passive_dns(self, target_ip: str) -> List[OSINTResult]:
        """Query passive DNS sources for historical domain associations"""

        results = []

        try:
            # Query CIRCL passive DNS (free)
            url = f"https://www.circl.lu/pdns/query/{target_ip}"

            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data:
                            unique_domains = set()
                            for record in data:
                                if "rrname" in record:
                                    unique_domains.add(record["rrname"])

                            summary = f"Historical domains: {len(unique_domains)}"

                            results.append(OSINTResult(
                                platform="circl_pdns",
                                query=target_ip,
                                url=f"https://www.circl.lu/pdns/query/{target_ip}",
                                results_found=len(data),
                                confidence=0.80,
                                summary=summary,
                                raw_data={"domains": list(unique_domains)},
                                search_timestamp=datetime.now()
                            ))

        except Exception as e:
            logger.debug(f"Passive DNS query failed: {e}")

        return results

    def _generate_osint_results(self, all_results: Dict, target_ip: str, target_port: int) -> List:
        """Generate vulnerability results for OSINT intelligence"""

        results = []

        # Main OSINT summary result
        osint_result = self.memory_pool.get_vulnerability_result()
        osint_result.id = "osint-intelligence-summary"
        osint_result.severity = "INFO"
        osint_result.confidence = 0.95
        osint_result.description = self._generate_osint_description(all_results, target_ip)
        osint_result.exploit_available = False
        osint_result.metadata = {
            "target_ip": target_ip,
            "search_urls": all_results["search_urls"],
            "google_dorks": all_results["google_dorks"][:5],  # Limit for brevity
            "platform_results": len(all_results["platform_results"]),
            "dns_results": len(all_results["dns_results"]),
            "total_osint_sources": (
                len(all_results["search_urls"]) +
                len(all_results["platform_results"]) +
                len(all_results["dns_results"])
            )
        }
        results.append(osint_result)

        # Individual platform results
        for platform_result in all_results["platform_results"]:
            platform_vuln = self.memory_pool.get_vulnerability_result()
            platform_vuln.id = f"osint-{platform_result.platform}-data"
            platform_vuln.severity = "INFO"
            platform_vuln.confidence = platform_result.confidence
            platform_vuln.description = f"{platform_result.platform.title()} intelligence: {platform_result.summary}"
            platform_vuln.exploit_available = False
            platform_vuln.metadata = {
                "platform": platform_result.platform,
                "query": platform_result.query,
                "url": platform_result.url,
                "results_found": platform_result.results_found,
                "summary": platform_result.summary,
                "search_timestamp": platform_result.search_timestamp.isoformat()
            }
            results.append(platform_vuln)

        # Passive DNS results
        for dns_result in all_results["dns_results"]:
            dns_vuln = self.memory_pool.get_vulnerability_result()
            dns_vuln.id = "osint-passive-dns-data"
            dns_vuln.severity = "INFO"
            dns_vuln.confidence = dns_result.confidence
            dns_vuln.description = f"Passive DNS intelligence: {dns_result.summary}"
            dns_vuln.exploit_available = False
            dns_vuln.metadata = {
                "platform": dns_result.platform,
                "results_found": dns_result.results_found,
                "summary": dns_result.summary,
                "domains": dns_result.raw_data.get("domains", []) if dns_result.raw_data else []
            }
            results.append(dns_vuln)

        return results

    def _generate_osint_description(self, all_results: Dict, target_ip: str) -> str:
        """Generate comprehensive OSINT description"""

        parts = [f"OSINT intelligence compiled for {target_ip}"]

        # Platform coverage
        platform_count = len(all_results["platform_results"])
        search_url_count = len(all_results["search_urls"])

        if platform_count > 0:
            parts.append(f"API results: {platform_count} platforms")

        parts.append(f"Manual search URLs: {search_url_count} platforms")

        # Google dork count
        dork_count = len(all_results["google_dorks"])
        parts.append(f"Google dorks: {dork_count} queries")

        # DNS results
        dns_count = len(all_results["dns_results"])
        if dns_count > 0:
            parts.append(f"Passive DNS: {dns_count} sources")

        return " | ".join(parts)
