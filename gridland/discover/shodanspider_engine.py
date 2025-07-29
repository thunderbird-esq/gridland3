"""
ShodanSpider v2 integration for GRIDLAND discovery operations.

Provides free access to Shodan-style device discovery without API limitations,
using the ShodanSpider v2 tool for CVE searching and device enumeration.
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from urllib.parse import quote_plus

import requests

from ..core.config import get_config
from ..core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ShodanSpiderResult:
    """Result from ShodanSpider v2 operation."""
    ip: str
    port: int
    service: str
    banner: str = ""
    country: str = ""
    org: str = ""
    timestamp: str = ""
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class ShodanSpiderEngine:
    """Free Shodan alternative using ShodanSpider v2."""
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.shodanspider_path = self._find_shodanspider()
        self.temp_dir = self.config.temp_dir
        
        # Camera-specific search queries
        self.camera_queries = [
            'camera',
            'webcam', 
            'dvr',
            'nvr',
            'cctv',
            'surveillance',
            'hikvision',
            'dahua',
            'axis',
            'onvif',
            'rtsp',
            'title:"camera"',
            'title:"dvr"',
            'title:"surveillance"',
            'port:554',  # RTSP port
            'port:37777', # Dahua
            'port:8899',  # Hikvision
        ]
    
    def _find_shodanspider(self) -> Optional[str]:
        """Locate ShodanSpider v2 executable."""
        common_paths = [
            '/usr/local/bin/shodanspider',
            '/usr/bin/shodanspider',
            '../ShodanSpider/shodanspider.sh',  # Local installation
            './ShodanSpider/shodanspider.sh',   # Local installation
            './shodanspider.sh',
            'shodanspider'  # In PATH
        ]
        
        for path in common_paths:
            try:
                # Check if file exists and is executable
                if os.path.exists(path) and os.access(path, os.X_OK):
                    logger.debug(f"Found ShodanSpider at: {path}")
                    return path
                    
                # Also try running it to check
                result = subprocess.run([path, '-h'], 
                                      capture_output=True, text=True, timeout=5)
                if 'ShodanSpider' in result.stderr or 'shodanspider' in result.stderr.lower():
                    logger.debug(f"Found ShodanSpider at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        logger.warning("ShodanSpider v2 not found. Install from: https://github.com/shubhamrooter/ShodanSpider")
        return None
    
    def is_available(self) -> bool:
        """Check if ShodanSpider v2 is available."""
        return self.shodanspider_path is not None
    
    def search_cameras(self, query: str = "camera", limit: int = 1000, 
                      country: Optional[str] = None) -> List[ShodanSpiderResult]:
        """
        Search for camera devices using ShodanSpider v2.
        
        Args:
            query: Search query (default: "camera")
            limit: Maximum results to return
            country: Filter by country code (e.g., "US", "CN")
            
        Returns:
            List of ShodanSpiderResult objects
        """
        if not self.is_available():
            logger.error("ShodanSpider v2 not available")
            return []
        
        # Build search query
        full_query = query
        if country:
            full_query += f" country:{country}"
        
        logger.info(f"Searching ShodanSpider for: {full_query}")
        
        try:
            results = self._execute_search(full_query, limit)
            logger.info(f"Found {len(results)} results from ShodanSpider")
            return results
        
        except Exception as e:
            logger.error(f"ShodanSpider search failed: {e}")
            return []
    
    def search_by_cve(self, cve_id: str, limit: int = 500) -> List[ShodanSpiderResult]:
        """
        Search for devices vulnerable to specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-36260")
            limit: Maximum results to return
            
        Returns:
            List of vulnerable devices
        """
        if not self.is_available():
            logger.error("ShodanSpider v2 not available")
            return []
        
        logger.info(f"Searching for devices vulnerable to {cve_id}")
        
        try:
            # ShodanSpider v2 supports direct CVE searching
            results = self._execute_cve_search(cve_id, limit)
            logger.info(f"Found {len(results)} devices vulnerable to {cve_id}")
            return results
        
        except Exception as e:
            logger.error(f"CVE search failed: {e}")
            return []
    
    def search_camera_brands(self, brands: List[str], limit: int = 1000) -> List[ShodanSpiderResult]:
        """
        Search for specific camera brands.
        
        Args:
            brands: List of brand names (e.g., ["hikvision", "dahua"])
            limit: Maximum results per brand
            
        Returns:
            Combined results for all brands
        """
        all_results = []
        
        for brand in brands:
            logger.info(f"Searching for {brand} cameras")
            
            # Build brand-specific query
            query = f"{brand} camera"
            results = self.search_cameras(query, limit // len(brands))
            all_results.extend(results)
            
            # Rate limiting to be respectful
            time.sleep(1)
        
        return all_results
    
    def search_by_port(self, port: int, service: str = "", limit: int = 1000) -> List[ShodanSpiderResult]:
        """
        Search for devices with specific port open.
        
        Args:
            port: Port number to search for
            service: Optional service filter
            limit: Maximum results to return
            
        Returns:
            List of devices with port open
        """
        query = f"port:{port}"
        if service:
            query += f" {service}"
        
        return self.search_cameras(query, limit)
    
    def _execute_search(self, query: str, limit: int) -> List[ShodanSpiderResult]:
        """Execute ShodanSpider search command."""
        output_file = self.temp_dir / f"shodanspider_{int(time.time())}.txt"
        
        try:
            # Build command - ShodanSpider v2 uses different syntax
            cmd = [
                self.shodanspider_path,
                '-q', query,
                '-o', str(output_file)
            ]
            
            # Execute with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                check=False
            )
            
            if result.returncode != 0:
                logger.warning(f"ShodanSpider returned code {result.returncode}")
                if result.stderr:
                    logger.debug(f"ShodanSpider stderr: {result.stderr}")
            
            # Parse results from text output
            return self._parse_text_results(output_file)
        
        except subprocess.TimeoutExpired:
            logger.error("ShodanSpider search timed out")
            return []
        except Exception as e:
            logger.error(f"ShodanSpider execution failed: {e}")
            return []
        finally:
            # Cleanup
            if output_file.exists():
                output_file.unlink()
    
    def _execute_cve_search(self, cve_id: str, limit: int) -> List[ShodanSpiderResult]:
        """Execute CVE-specific search."""
        output_file = self.temp_dir / f"shodanspider_cve_{int(time.time())}.txt"
        
        try:
            cmd = [
                self.shodanspider_path,
                '-cve', cve_id,
                '-o', str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False
            )
            
            return self._parse_text_results(output_file)
        
        except Exception as e:
            logger.error(f"CVE search execution failed: {e}")
            return []
        finally:
            if output_file.exists():
                output_file.unlink()
    
    def _parse_results(self, output_file: Path) -> List[ShodanSpiderResult]:
        """Parse ShodanSpider JSON output."""
        results = []
        
        if not output_file.exists():
            logger.warning("ShodanSpider output file not found")
            return results
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Handle different output formats
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = data.get('results', [data])
            else:
                logger.warning("Unexpected ShodanSpider output format")
                return results
            
            for entry in entries:
                try:
                    result = self._parse_entry(entry)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Failed to parse entry: {e}")
                    continue
        
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to parse ShodanSpider output: {e}")
        
        return results
    
    def _parse_text_results(self, output_file: Path) -> List[ShodanSpiderResult]:
        """Parse ShodanSpider text output format."""
        results = []
        
        if not output_file.exists():
            logger.warning("ShodanSpider output file not found")
            return results
        
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            
            # ShodanSpider v2 outputs plain text - usually just IP addresses
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Check for IP:port pattern first
                if ':' in line and len(line.split(':')) == 2:
                    try:
                        parts = line.split(':')
                        ip = parts[0].strip()
                        port = int(parts[1].strip())
                        
                        if self._is_valid_ip(ip):
                            results.append(ShodanSpiderResult(
                                ip=ip,
                                port=port,
                                service="unknown",
                                banner="",
                                country="",
                                org="",
                                timestamp=str(int(time.time())),
                                vulnerabilities=[]
                            ))
                    except (ValueError, IndexError):
                        continue
                
                # Otherwise treat as just an IP address
                elif self._is_valid_ip(line):
                    # Use common camera ports for IP-only results
                    common_ports = [80, 443, 554, 8080]
                    for port in common_ports:
                        results.append(ShodanSpiderResult(
                            ip=line,
                            port=port,
                            service="http" if port in [80, 8080] else "https" if port == 443 else "rtsp" if port == 554 else "unknown",
                            banner="",
                            country="",
                            org="",
                            timestamp=str(int(time.time())),
                            vulnerabilities=[]
                        ))
        
        except IOError as e:
            logger.error(f"Failed to read ShodanSpider output: {e}")
        
        return results
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def _parse_entry(self, entry: Dict[str, Any]) -> Optional[ShodanSpiderResult]:
        """Parse single result entry."""
        try:
            # Extract required fields
            ip = entry.get('ip', entry.get('ip_str', ''))
            port = entry.get('port', 0)
            
            if not ip or not port:
                return None
            
            # Extract optional fields
            service = entry.get('service', entry.get('product', ''))
            banner = entry.get('banner', entry.get('data', ''))
            country = entry.get('country', entry.get('location', {}).get('country_name', ''))
            org = entry.get('org', entry.get('organization', ''))
            timestamp = entry.get('timestamp', str(int(time.time())))
            
            # Extract vulnerabilities if present
            vulns = []
            if 'vulns' in entry:
                vulns = list(entry['vulns'].keys()) if isinstance(entry['vulns'], dict) else entry['vulns']
            elif 'cves' in entry:
                vulns = entry['cves']
            
            return ShodanSpiderResult(
                ip=ip,
                port=int(port),
                service=service,
                banner=banner,
                country=country,
                org=org,
                timestamp=timestamp,
                vulnerabilities=vulns
            )
        
        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Failed to parse entry: {e}")
            return None
    
    def get_camera_candidates(self, results: List[ShodanSpiderResult]) -> List[ShodanSpiderResult]:
        """Filter results for likely camera candidates."""
        camera_keywords = [
            'camera', 'webcam', 'dvr', 'nvr', 'cctv', 'surveillance',
            'hikvision', 'dahua', 'axis', 'bosch', 'sony', 'panasonic',
            'vivotek', 'onvif', 'rtsp', 'mjpeg'
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
    
    def results_to_dict(self, results: List[ShodanSpiderResult]) -> List[Dict]:
        """Convert results to dictionary format for JSON output."""
        return [
            {
                'ip': r.ip,
                'port': r.port,
                'service': r.service,
                'banner': r.banner,
                'country': r.country,
                'org': r.org,
                'timestamp': r.timestamp,
                'vulnerabilities': r.vulnerabilities
            }
            for r in results
        ]
    
    def search_multiple_queries(self, queries: List[str], limit_per_query: int = 100) -> List[ShodanSpiderResult]:
        """Execute multiple search queries and combine results."""
        all_results = []
        seen_ips = set()
        
        for query in queries:
            logger.info(f"Executing query: {query}")
            
            try:
                results = self.search_cameras(query, limit_per_query)
                
                # Deduplicate by IP
                for result in results:
                    if result.ip not in seen_ips:
                        all_results.append(result)
                        seen_ips.add(result.ip)
                
                # Rate limiting
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Query failed: {query} - {e}")
                continue
        
        return all_results
    
    def get_default_camera_search(self, limit: int = 1000) -> List[ShodanSpiderResult]:
        """Execute default camera search using multiple queries."""
        selected_queries = self.camera_queries[:5]  # Use first 5 queries
        limit_per_query = limit // len(selected_queries)
        
        return self.search_multiple_queries(selected_queries, limit_per_query)