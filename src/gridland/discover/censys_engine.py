"""
Censys integration for GRIDLAND discovery operations.

Provides professional-grade internet scanning capabilities using the Censys API
as a backup to ShodanSpider when API credentials are available.
"""

import json
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import base64

import requests

from ..core.config import get_config
from ..core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CensysResult:
    """Result from Censys search operation."""
    ip: str
    port: int
    service: str
    protocol: str = "tcp"
    banner: str = ""
    country: str = ""
    org: str = ""
    timestamp: str = ""
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class CensysEngine:
    """Professional internet scanning using Censys API."""
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.api_id = self.config.censys_api_id
        self.api_secret = self.config.censys_api_secret
        self.base_url = "https://search.censys.io/api/v2"
        self.session = requests.Session()
        
        # Setup authentication
        if self.api_id and self.api_secret:
            credentials = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {credentials}',
                'Content-Type': 'application/json'
            })
        
        # Camera-specific search queries
        self.camera_queries = [
            'services.service_name: "HTTP" and services.http.response.body: "camera"',
            'services.port: 554',  # RTSP
            'services.port: 37777', # Dahua
            'services.port: 8899',  # Hikvision
            'services.service_name: "HTTP" and services.http.response.html_title: "DVR"',
            'services.service_name: "HTTP" and services.http.response.html_title: "NVR"',
            'autonomous_system.description: "hikvision"',
            'autonomous_system.description: "dahua"',
        ]
    
    def is_available(self) -> bool:
        """Check if Censys API credentials are configured."""
        return bool(self.api_id and self.api_secret)
    
    def test_connection(self) -> bool:
        """Test API connection and credentials."""
        if not self.is_available():
            return False
        
        try:
            response = self.session.get(f"{self.base_url}/account")
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Censys connection test failed: {e}")
            return False
    
    def search_hosts(self, query: str, limit: int = 1000) -> List[CensysResult]:
        """
        Search for hosts using Censys API.
        
        Args:
            query: Censys search query
            limit: Maximum results to return
            
        Returns:
            List of CensysResult objects
        """
        if not self.is_available():
            logger.error("Censys API credentials not configured")
            return []
        
        logger.info(f"Searching Censys: {query}")
        
        try:
            results = []
            per_page = min(100, limit)  # Censys max per page
            pages_needed = (limit + per_page - 1) // per_page
            
            for page in range(1, pages_needed + 1):
                page_results = self._search_page(query, page, per_page)
                results.extend(page_results)
                
                if len(results) >= limit:
                    results = results[:limit]
                    break
                
                # Rate limiting
                time.sleep(1)
            
            logger.info(f"Found {len(results)} results from Censys")
            return results
            
        except Exception as e:
            logger.error(f"Censys search failed: {e}")
            return []
    
    def _search_page(self, query: str, page: int, per_page: int) -> List[CensysResult]:
        """Search single page of results."""
        endpoint = f"{self.base_url}/hosts/search"
        
        payload = {
            'q': query,
            'per_page': per_page,
            'cursor': None  # Will be updated for pagination
        }
        
        try:
            response = self.session.post(endpoint, json=payload, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            results = []
            
            for hit in data.get('result', {}).get('hits', []):
                parsed_results = self._parse_host(hit)
                results.extend(parsed_results)
            
            return results
            
        except requests.RequestException as e:
            logger.error(f"Censys API request failed: {e}")
            return []
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse Censys response: {e}")
            return []
    
    def _parse_host(self, host_data: Dict[str, Any]) -> List[CensysResult]:
        """Parse host data into CensysResult objects."""
        results = []
        
        try:
            ip = host_data.get('ip', '')
            if not ip:
                return results
            
            # Extract location info
            location = host_data.get('location', {})
            country = location.get('country', '')
            
            # Extract organization info
            autonomous_system = host_data.get('autonomous_system', {})
            org = autonomous_system.get('description', '')
            
            # Extract timestamp
            timestamp = host_data.get('last_updated_at', '')
            
            # Process each service
            for service in host_data.get('services', []):
                port = service.get('port', 0)
                if port == 0:
                    continue
                
                service_name = service.get('service_name', 'unknown')
                transport_protocol = service.get('transport_protocol', 'tcp')
                
                # Extract banner information
                banner = self._extract_banner(service)
                
                # Extract tags
                tags = service.get('software', [])
                
                results.append(CensysResult(
                    ip=ip,
                    port=port,
                    service=service_name,
                    protocol=transport_protocol,
                    banner=banner,
                    country=country,
                    org=org,
                    timestamp=timestamp,
                    tags=tags
                ))
        
        except (KeyError, TypeError) as e:
            logger.debug(f"Failed to parse host data: {e}")
        
        return results
    
    def _extract_banner(self, service: Dict[str, Any]) -> str:
        """Extract banner/response data from service."""
        banner_parts = []
        
        # HTTP response
        if 'http' in service:
            http_data = service['http']
            if 'response' in http_data:
                response = http_data['response']
                
                # HTML title
                if 'html_title' in response:
                    banner_parts.append(f"Title: {response['html_title']}")
                
                # Server header
                if 'headers' in response:
                    server = response['headers'].get('server', '')
                    if server:
                        banner_parts.append(f"Server: {server}")
        
        # Raw banner
        if 'banner' in service:
            banner_parts.append(service['banner'])
        
        return ' | '.join(banner_parts)
    
    def search_cameras(self, limit: int = 1000) -> List[CensysResult]:
        """Search for camera devices using multiple queries."""
        all_results = []
        seen_hosts = set()
        
        queries_to_use = self.camera_queries[:3]  # Use first 3 queries to stay within limits
        limit_per_query = limit // len(queries_to_use)
        
        for query in queries_to_use:
            logger.info(f"Executing Censys camera query: {query}")
            
            try:
                results = self.search_hosts(query, limit_per_query)
                
                # Deduplicate by IP:port
                for result in results:
                    host_key = (result.ip, result.port)
                    if host_key not in seen_hosts:
                        all_results.append(result)
                        seen_hosts.add(host_key)
                
                # Rate limiting between queries
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Camera query failed: {e}")
                continue
        
        return all_results
    
    def search_by_country(self, country_code: str, limit: int = 500) -> List[CensysResult]:
        """Search for cameras in specific country."""
        query = f'location.country: "{country_code}" and (services.port: 554 or services.port: 80)'
        return self.search_hosts(query, limit)
    
    def search_by_org(self, organization: str, limit: int = 500) -> List[CensysResult]:
        """Search for cameras by organization."""
        query = f'autonomous_system.description: "{organization}" and services.port: (80 or 554 or 8080)'
        return self.search_hosts(query, limit)
    
    def get_camera_candidates(self, results: List[CensysResult]) -> List[CensysResult]:
        """Filter results for likely camera candidates."""
        camera_keywords = [
            'camera', 'webcam', 'dvr', 'nvr', 'cctv', 'surveillance',
            'hikvision', 'dahua', 'axis', 'bosch', 'sony'
        ]
        
        camera_ports = {80, 443, 554, 8080, 8081, 8000, 8443, 8888, 9000,
                       37777, 37778, 8899, 4567, 5000, 5001}
        
        candidates = []
        
        for result in results:
            # Check port
            if result.port in camera_ports:
                candidates.append(result)
                continue
            
            # Check service/banner for camera keywords
            search_text = f"{result.service} {result.banner}".lower()
            if any(keyword in search_text for keyword in camera_keywords):
                candidates.append(result)
        
        return candidates
    
    def results_to_dict(self, results: List[CensysResult]) -> List[Dict]:
        """Convert results to dictionary format for JSON output."""
        return [
            {
                'ip': r.ip,
                'port': r.port,
                'service': r.service,
                'protocol': r.protocol,
                'banner': r.banner,
                'country': r.country,
                'org': r.org,
                'timestamp': r.timestamp,
                'tags': r.tags
            }
            for r in results
        ]
    
    def get_account_info(self) -> Optional[Dict[str, Any]]:
        """Get Censys account information and quota status."""
        if not self.is_available():
            return None
        
        try:
            response = self.session.get(f"{self.base_url}/account")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"Failed to get account info: {e}")
        
        return None