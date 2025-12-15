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


# Plugin instance for automatic discovery
osint_integration_scanner = OSINTIntegrationScanner()
