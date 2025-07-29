# NECESSARY-WORK-10: OSINT Integration

## Technical Analysis

### Current State Assessment
**GRIDLAND Current**: Zero OSINT integration or automated search capabilities
**CamXploit.py Intelligence**: Comprehensive OSINT automation with direct platform integration (lines 195-211)
**Integration Gap**: 100% missing automated intelligence gathering and verification workflows

### Critical Business Impact
- **Manual Verification Burden**: Analysts must manually search multiple platforms
- **Workflow Inefficiency**: No automated cross-platform intelligence correlation
- **Missing Attribution Intelligence**: Limited ability to correlate discoveries with public data

## CamXploit.py OSINT Intelligence Analysis

### Automated OSINT Platform Integration (Lines 195-211)

#### 1. **Search Platform URL Generation** (Lines 195-200)
```python
def print_search_urls(ip):
    print(f"\n[🌍] {C}Use these URLs to check the camera exposure manually:{W}")
    print(f"  🔹 Shodan: https://www.shodan.io/search?query={ip}")
    print(f"  🔹 Censys: https://search.censys.io/hosts/{ip}")
    print(f"  🔹 Zoomeye: https://www.zoomeye.org/searchResult?q={ip}")
    print(f"  🔹 Google Dorking (Quick Search): https://www.google.com/search?q=site:{ip}+inurl:view/view.shtml+OR+inurl:admin.html+OR+inurl:login")
```
**Rationale**: Pre-built URLs enable immediate manual verification across major OSINT platforms

#### 2. **Google Dorking Automation** (Lines 202-211)
```python
def google_dork_search(ip):
    print(f"\n[🔎] {C}Google Dorking Suggestions:{W}")
    queries = [
        f"site:{ip} inurl:view/view.shtml",
        f"site:{ip} inurl:admin.html", 
        f"site:{ip} inurl:login",
        f"intitle:'webcam' inurl:{ip}",
    ]
    for q in queries:
        print(f"  🔍 Google Dork: https://www.google.com/search?q={q.replace(' ', '+')}")
```
**Rationale**: Automated Google dorking enables discovery of exposed camera interfaces

#### 3. **Multi-Platform Search Strategy** (Lines 195-211)
- **Shodan**: Device discovery and service enumeration
- **Censys**: Certificate and infrastructure intelligence
- **ZoomEye**: Chinese-focused device discovery
- **Google**: Web interface and exposed endpoint discovery

**Rationale**: Different platforms provide complementary intelligence requiring comprehensive coverage

## Technical Implementation Plan

### 1. **OSINT Integration Engine**

**File**: `gridland/analyze/plugins/builtin/osint_integration_scanner.py`
**New Plugin**: Comprehensive OSINT platform integration and automation

```python
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

from ...memory.pool import get_memory_pool
from ..manager import VulnerabilityPlugin, PluginMetadata
from ....core.logger import get_logger

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
        self.metadata = PluginMetadata(
            name="OSINT Integration Scanner",
            version="2.0.0",
            author="GRIDLAND Security Team",
            description="Automated OSINT platform integration and intelligence correlation"
        )
        self.osint_config = self._load_osint_config()
        self.memory_pool = get_memory_pool()
    
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
    
    async def analyze_vulnerabilities(self, target_ip: str, target_port: int,
                                    banner: Optional[str] = None) -> List:
        """Comprehensive OSINT analysis and intelligence correlation"""
        
        osint_results = []
        
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
        
        # Generate vulnerability results
        return self._generate_osint_results(all_results, target_ip, target_port)
    
    def _generate_search_urls(self, target_ip: str) -> Dict[str, str]:
        """Generate search URLs for manual platform verification"""
        
        search_urls = {}
        
        for platform, config in self.osint_config["platforms"].items():
            if "{ip}" in config["search_url"]:
                url = config["search_url"].format(ip=target_ip)
            else:
                url = config["search_url"].format(query=target_ip)
            
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
            
            connector = aiohttp.TCPConnector()
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
            
            connector = aiohttp.TCPConnector()
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
            
            connector = aiohttp.TCPConnector()
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
            
            connector = aiohttp.TCPConnector()
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
```

### 2. **Integration with Plugin System**

**File**: `gridland/analyze/plugins/builtin/__init__.py`
**Enhancement**: Add OSINT integration scanner

```python
from .osint_integration_scanner import OSINTIntegrationScanner

BUILTIN_PLUGINS = [
    hikvision_scanner,
    dahua_scanner, 
    axis_scanner,
    banner_grabber,
    enhanced_stream_scanner,
    enhanced_camera_detector,
    cp_plus_scanner,
    advanced_fingerprinting_scanner,
    cve_correlation_scanner,
    enhanced_credential_scanner,
    multi_protocol_stream_scanner,
    enhanced_ip_intelligence_scanner,
    OSINTIntegrationScanner()  # Add comprehensive OSINT integration
]
```

### 3. **OSINT Configuration Management**

**File**: `gridland/tools/osint_config.py`
**New Tool**: OSINT API key management and configuration

```python
"""
OSINT Configuration Manager for API keys and platform settings.
"""

import os
import json
from pathlib import Path
import argparse

class OSINTConfigManager:
    """Manage OSINT platform API keys and configuration"""
    
    def __init__(self, config_path: Path = None):
        self.config_path = config_path or Path.home() / ".gridland" / "osint_config.json"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load OSINT configuration from file"""
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        return {"api_keys": {}, "preferences": {}}
    
    def set_api_key(self, platform: str, api_key: str):
        """Set API key for platform"""
        
        if "api_keys" not in self.config:
            self.config["api_keys"] = {}
        
        self.config["api_keys"][platform] = api_key
        self._save_config()
        print(f"API key set for {platform}")
    
    def get_api_key(self, platform: str) -> Optional[str]:
        """Get API key for platform"""
        
        # Check config file first
        if platform in self.config.get("api_keys", {}):
            return self.config["api_keys"][platform]
        
        # Check environment variables
        env_mappings = {
            "shodan": "SHODAN_API_KEY",
            "censys": "CENSYS_API_KEY",
            "zoomeye": "ZOOMEYE_API_KEY"
        }
        
        if platform in env_mappings:
            return os.getenv(env_mappings[platform])
        
        return None
    
    def list_api_keys(self):
        """List configured API keys"""
        
        print("Configured API keys:")
        
        for platform, key in self.config.get("api_keys", {}).items():
            masked_key = key[:8] + "..." + key[-4:] if len(key) > 12 else "***"
            print(f"  {platform}: {masked_key}")
    
    def _save_config(self):
        """Save configuration to file"""
        
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT Configuration Manager")
    parser.add_argument("--set-key", nargs=2, metavar=("platform", "key"), help="Set API key for platform")
    parser.add_argument("--list-keys", action="store_true", help="List configured API keys")
    
    args = parser.parse_args()
    
    manager = OSINTConfigManager()
    
    if args.set_key:
        platform, key = args.set_key
        manager.set_api_key(platform, key)
    elif args.list_keys:
        manager.list_api_keys()
    else:
        parser.print_help()
```

## Expected Performance Impact

### OSINT Integration Enhancement
- **Current OSINT**: Zero automated intelligence gathering
- **Enhanced OSINT**: 5+ platform integration with automated queries
- **Workflow Efficiency**: Direct URL generation for immediate verification

### Platform Coverage
- **Shodan**: Primary device discovery and vulnerability intelligence
- **Censys**: Certificate and infrastructure analysis
- **ZoomEye**: Chinese-focused device discovery
- **BinaryEdge**: Internet scanning data
- **Google Dorking**: Web interface discovery automation

## Success Metrics

### Quantitative Measures
- **Platform Integration**: Add 5+ OSINT platforms (new capability)
- **Search Automation**: 10+ Google dork patterns generated automatically
- **API Coverage**: Support for major paid and free OSINT APIs

### Implementation Validation
1. **API Integration**: Test API connectivity and data retrieval
2. **URL Generation**: Verify search URLs work correctly
3. **Intelligence Correlation**: Validate data correlation accuracy

## Risk Assessment

### Technical Risks
- **API Rate Limits**: Free tiers have strict usage limitations
- **API Dependencies**: Platform changes could break integrations
- **Data Privacy**: OSINT queries may reveal analyst intentions

### Mitigation Strategies
- **Rate Limit Management**: Track and respect API limitations
- **Graceful Degradation**: Generate URLs even if APIs unavailable
- **Privacy Considerations**: Clear documentation of data collection

## Conclusion

The OSINT integration enhancement transforms GRIDLAND into a comprehensive intelligence platform that automates the manual verification workflow. By providing direct integration with major OSINT platforms and automated Google dorking, analysts can immediately cross-reference discoveries with public intelligence sources while maintaining operational security through configurable API management.

**Implementation Priority**: LOW - Operational workflow improvement with high analyst value but not critical for core scanning functionality.