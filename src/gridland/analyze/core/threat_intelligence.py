# -*- coding: utf-8 -*-
"""
Real-Time Threat Intelligence Integration for GRIDLAND v3.0

This module provides real-time threat intelligence integration capabilities,
combining external threat feeds with local vulnerability analysis for enhanced
security reconnaissance and threat correlation.

Author: GRIDLAND Development Team
Date: July 29, 2025
"""

import asyncio
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp
import requests
from gridland.core.logger import get_logger
from gridland.core.config import get_config

logger = get_logger(__name__)


@dataclass
class ThreatIntelligenceResult:
    """Result from threat intelligence analysis."""
    target_ip: str
    target_port: int
    threat_indicators: List[Dict[str, Any]] = field(default_factory=list)
    cve_correlations: List[Dict[str, Any]] = field(default_factory=list)
    reputation_scores: Dict[str, float] = field(default_factory=dict)
    risk_assessment: str = "unknown"
    confidence_score: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    sources: List[str] = field(default_factory=list)


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration."""
    name: str
    url: str
    api_key: Optional[str] = None
    update_interval: int = 3600  # seconds
    enabled: bool = True
    last_update: Optional[datetime] = None
    cache_duration: int = 1800  # seconds


class ThreatIntelligenceCache:
    """High-performance cache for threat intelligence data."""
    
    def __init__(self, max_size: int = 10000, ttl: int = 1800):
        self.max_size = max_size
        self.ttl = ttl
        self.cache = {}
        self.access_times = {}
        self.logger = get_logger(__name__)
    
    def _generate_key(self, ip: str, port: int = None) -> str:
        """Generate cache key for IP/port combination."""
        if port:
            return f"{ip}:{port}"
        return ip
    
    def get(self, ip: str, port: int = None) -> Optional[ThreatIntelligenceResult]:
        """Retrieve cached threat intelligence result."""
        key = self._generate_key(ip, port)
        
        if key not in self.cache:
            return None
        
        # Check TTL
        if time.time() - self.access_times[key] > self.ttl:
            self._evict(key)
            return None
        
        # Update access time
        self.access_times[key] = time.time()
        return self.cache[key]
    
    def set(self, ip: str, result: ThreatIntelligenceResult, port: int = None):
        """Cache threat intelligence result."""
        key = self._generate_key(ip, port)
        
        # Evict oldest if at capacity
        if len(self.cache) >= self.max_size:
            self._evict_oldest()
        
        self.cache[key] = result
        self.access_times[key] = time.time()
    
    def _evict(self, key: str):
        """Evict specific cache entry."""
        if key in self.cache:
            del self.cache[key]
        if key in self.access_times:
            del self.access_times[key]
    
    def _evict_oldest(self):
        """Evict oldest cache entry based on access time."""
        if not self.access_times:
            return
        
        oldest_key = min(self.access_times, key=self.access_times.get)
        self._evict(oldest_key)
    
    def clear_expired(self):
        """Clear all expired cache entries."""
        current_time = time.time()
        expired_keys = [
            key for key, access_time in self.access_times.items()
            if current_time - access_time > self.ttl
        ]
        
        for key in expired_keys:
            self._evict(key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'ttl': self.ttl,
            'hit_ratio': getattr(self, '_hits', 0) / max(getattr(self, '_requests', 1), 1)
        }


class CVEDatabase:
    """CVE database integration for vulnerability correlation."""
    
    def __init__(self):
        self.cve_cache = {}
        self.last_update = None
        self.logger = get_logger(__name__)
        
        # CVE API endpoints
        self.cve_sources = {
            'nist': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'mitre': 'https://cveawg.mitre.org/api/cve',
            'circl': 'https://cve.circl.lu/api/cve'
        }
    
    async def correlate_cves(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate target information with known CVEs."""
        correlations = []
        
        # Extract relevant identifiers
        software_info = target_info.get('software', {})
        service_info = target_info.get('service', {})
        banner_info = target_info.get('banner', '')
        
        # Search for CVEs based on software versions
        for software, version in software_info.items():
            cves = await self._search_cves_by_software(software, version)
            correlations.extend(cves)
        
        # Search for CVEs based on service information
        if service_info:
            service_cves = await self._search_cves_by_service(service_info)
            correlations.extend(service_cves)
        
        # Search for CVEs based on banner patterns
        if banner_info:
            banner_cves = await self._search_cves_by_banner(banner_info)
            correlations.extend(banner_cves)
        
        # Deduplicate and sort by severity
        unique_cves = self._deduplicate_cves(correlations)
        return sorted(unique_cves, key=lambda x: x.get('cvss_score', 0), reverse=True)
    
    async def _search_cves_by_software(self, software: str, version: str) -> List[Dict[str, Any]]:
        """Search CVEs by software name and version."""
        cves = []
        
        try:
            # Use NIST NVD API for comprehensive CVE search
            async with aiohttp.ClientSession() as session:
                params = {
                    'keywordSearch': f"{software} {version}",
                    'resultsPerPage': 20
                }
                
                async with session.get(self.cve_sources['nist'], params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        for vulnerability in data.get('vulnerabilities', []):
                            cve_data = vulnerability.get('cve', {})
                            cves.append(self._parse_nist_cve(cve_data))
        except Exception as e:
            self.logger.debug(f"CVE search failed for {software} {version}: {e}")
        
        return cves
    
    async def _search_cves_by_service(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search CVEs by service information."""
        cves = []
        service_name = service_info.get('name', '')
        service_version = service_info.get('version', '')
        
        if service_name:
            search_term = f"{service_name}"
            if service_version:
                search_term += f" {service_version}"
            
            cves = await self._search_cves_by_software(service_name, service_version)
        
        return cves
    
    async def _search_cves_by_banner(self, banner: str) -> List[Dict[str, Any]]:
        """Search CVEs by banner information."""
        cves = []
        
        # Extract potential software names from banner
        software_patterns = [
            r'Apache[/\s]+(\d+\.[\d\.]+)',
            r'nginx[/\s]+(\d+\.[\d\.]+)',
            r'Microsoft-IIS[/\s]+(\d+\.[\d\.]+)',
            r'OpenSSH[_\s]+(\d+\.[\d\.]+)',
            r'(\w+)[/\s]+(\d+\.[\d\.]+)'
        ]
        
        import re
        for pattern in software_patterns:
            matches = re.findall(pattern, banner, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    software, version = match[0], match[1] if len(match) > 1 else ''
                else:
                    software, version = match, ''
                
                software_cves = await self._search_cves_by_software(software, version)
                cves.extend(software_cves)
        
        return cves
    
    def _parse_nist_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NIST CVE data into standardized format."""
        cve_id = cve_data.get('id', '')
        
        # Extract CVSS score
        cvss_score = 0.0
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0.0)
        elif 'cvssMetricV30' in metrics:
            cvss_score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0.0)
        elif 'cvssMetricV2' in metrics:
            cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0.0)
        
        # Extract description
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'description': description,
            'published_date': cve_data.get('published', ''),
            'last_modified': cve_data.get('lastModified', ''),
            'source': 'nist'
        }
    
    def _deduplicate_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate CVEs based on CVE ID."""
        seen_cves = set()
        unique_cves = []
        
        for cve in cves:
            cve_id = cve.get('cve_id', '')
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_cves.append(cve)
        
        return unique_cves


class ReputationEngine:
    """IP reputation scoring engine with multiple sources."""
    
    def __init__(self):
        self.reputation_sources = {
            'abuseipdb': {
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'api_key_env': 'ABUSEIPDB_API_KEY'
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
                'api_key_env': 'VIRUSTOTAL_API_KEY'
            }
        }
        self.logger = get_logger(__name__)
    
    async def get_reputation_score(self, ip: str) -> Dict[str, float]:
        """Get reputation scores from multiple sources."""
        scores = {}
        
        # Check each reputation source
        for source_name, source_config in self.reputation_sources.items():
            try:
                score = await self._query_reputation_source(ip, source_name, source_config)
                if score is not None:
                    scores[source_name] = score
            except Exception as e:
                self.logger.debug(f"Reputation query failed for {source_name}: {e}")
        
        # Calculate aggregate reputation score
        if scores:
            aggregate_score = sum(scores.values()) / len(scores)
            scores['aggregate'] = aggregate_score
        
        return scores
    
    async def _query_reputation_source(self, ip: str, source_name: str, source_config: Dict[str, Any]) -> Optional[float]:
        """Query individual reputation source."""
        import os
        
        api_key = os.getenv(source_config.get('api_key_env', ''))
        if not api_key:
            self.logger.debug(f"No API key configured for {source_name}")
            return None
        
        if source_name == 'abuseipdb':
            return await self._query_abuseipdb(ip, api_key)
        elif source_name == 'virustotal':
            return await self._query_virustotal(ip, api_key)
        
        return None
    
    async def _query_abuseipdb(self, ip: str, api_key: str) -> Optional[float]:
        """Query AbuseIPDB for reputation score."""
        try:
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
                        # Convert abuse confidence to reputation score (inverted)
                        return max(0.0, 1.0 - (abuse_confidence / 100.0))
        except Exception as e:
            self.logger.debug(f"AbuseIPDB query failed: {e}")
        
        return None
    
    async def _query_virustotal(self, ip: str, api_key: str) -> Optional[float]:
        """Query VirusTotal for reputation score."""
        try:
            params = {
                'apikey': api_key,
                'ip': ip
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://www.virustotal.com/vtapi/v2/ip-address/report',
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('response_code') == 1:
                            detected_urls = data.get('detected_urls', [])
                            total_urls = len(detected_urls)
                            if total_urls > 0:
                                # Calculate reputation based on detection ratio
                                detected_count = sum(1 for url in detected_urls if url.get('positives', 0) > 0)
                                reputation = max(0.0, 1.0 - (detected_count / total_urls))
                                return reputation
                            else:
                                return 1.0  # No URLs detected = good reputation
        except Exception as e:
            self.logger.debug(f"VirusTotal query failed: {e}")
        
        return None


class RealTimeThreatIntelligence:
    """Real-time threat intelligence integration system for GRIDLAND v3.0."""
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.logger = get_logger(__name__)
        
        # Initialize components
        self.cache = ThreatIntelligenceCache(
            max_size=self.config.threat_intel_cache_size,
            ttl=self.config.threat_intel_cache_ttl
        )
        self.cve_database = CVEDatabase()
        self.reputation_engine = ReputationEngine()
        
        # Threat feed configuration
        self.threat_feeds = self._initialize_threat_feeds()
        
        # Statistics
        self.stats = {
            'queries_processed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'threat_indicators_found': 0,
            'cve_correlations_found': 0
        }
    
    def _initialize_threat_feeds(self) -> List[ThreatFeed]:
        """Initialize threat intelligence feeds."""
        feeds = []
        
        # Default threat feeds (can be configured via environment)
        default_feeds = [
            ThreatFeed(
                name='abuse_ch_malware',
                url='https://feodotracker.abuse.ch/downloads/ipblocklist.json',
                update_interval=3600
            ),
            ThreatFeed(
                name='emergingthreats_compromised',
                url='https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                update_interval=1800
            ),
            ThreatFeed(
                name='alienvault_reputation',
                url='https://reputation.alienvault.com/reputation.generic',
                update_interval=3600
            )
        ]
        
        feeds.extend(default_feeds)
        return feeds
    
    async def analyze_threat_intelligence(self, target_ip: str, target_port: int, 
                                        target_info: Dict[str, Any]) -> ThreatIntelligenceResult:
        """Perform comprehensive threat intelligence analysis."""
        self.stats['queries_processed'] += 1
        
        # Check cache first
        cached_result = self.cache.get(target_ip, target_port)
        if cached_result:
            self.stats['cache_hits'] += 1
            self.logger.debug(f"Threat intelligence cache hit for {target_ip}:{target_port}")
            return cached_result
        
        self.stats['cache_misses'] += 1
        
        # Perform comprehensive analysis
        result = ThreatIntelligenceResult(
            target_ip=target_ip,
            target_port=target_port
        )
        
        # Get reputation scores
        reputation_scores = await self.reputation_engine.get_reputation_score(target_ip)
        result.reputation_scores = reputation_scores
        
        # Correlate with CVE database
        cve_correlations = await self.cve_database.correlate_cves(target_info)
        result.cve_correlations = cve_correlations
        self.stats['cve_correlations_found'] += len(cve_correlations)
        
        # Check threat feeds
        threat_indicators = await self._check_threat_feeds(target_ip)
        result.threat_indicators = threat_indicators
        self.stats['threat_indicators_found'] += len(threat_indicators)
        
        # Calculate risk assessment
        result.risk_assessment = self._calculate_risk_assessment(
            reputation_scores, cve_correlations, threat_indicators
        )
        
        # Calculate confidence score
        result.confidence_score = self._calculate_confidence_score(
            reputation_scores, cve_correlations, threat_indicators
        )
        
        # Set sources
        result.sources = list(reputation_scores.keys()) + ['nist_cve'] + [feed.name for feed in self.threat_feeds]
        
        # Cache the result
        self.cache.set(target_ip, result, target_port)
        
        return result
    
    async def _check_threat_feeds(self, target_ip: str) -> List[Dict[str, Any]]:
        """Check target IP against threat intelligence feeds."""
        indicators = []
        
        for feed in self.threat_feeds:
            if not feed.enabled:
                continue
            
            try:
                feed_indicators = await self._query_threat_feed(target_ip, feed)
                indicators.extend(feed_indicators)
            except Exception as e:
                self.logger.debug(f"Threat feed query failed for {feed.name}: {e}")
        
        return indicators
    
    async def _query_threat_feed(self, target_ip: str, feed: ThreatFeed) -> List[Dict[str, Any]]:
        """Query individual threat feed."""
        indicators = []
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {}
                if feed.api_key:
                    headers['Authorization'] = f'Bearer {feed.api_key}'
                
                async with session.get(feed.url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse different feed formats
                        if feed.url.endswith('.json'):
                            data = json.loads(content)
                            indicators.extend(self._parse_json_feed(target_ip, data, feed.name))
                        else:
                            # Assume text-based feed
                            indicators.extend(self._parse_text_feed(target_ip, content, feed.name))
                        
                        feed.last_update = datetime.now()
        except Exception as e:
            self.logger.debug(f"Failed to query threat feed {feed.name}: {e}")
        
        return indicators
    
    def _parse_json_feed(self, target_ip: str, data: Any, feed_name: str) -> List[Dict[str, Any]]:
        """Parse JSON-based threat feed."""
        indicators = []
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ip = item.get('ip', item.get('address', ''))
                    if ip == target_ip:
                        indicators.append({
                            'type': 'malicious_ip',
                            'source': feed_name,
                            'details': item,
                            'severity': item.get('threat_level', 'medium')
                        })
        elif isinstance(data, dict):
            # Handle various JSON structures
            ips = data.get('ips', data.get('addresses', []))
            for ip_entry in ips:
                if isinstance(ip_entry, str) and ip_entry == target_ip:
                    indicators.append({
                        'type': 'malicious_ip',
                        'source': feed_name,
                        'details': {'ip': ip_entry},
                        'severity': 'medium'
                    })
                elif isinstance(ip_entry, dict):
                    ip = ip_entry.get('ip', ip_entry.get('address', ''))
                    if ip == target_ip:
                        indicators.append({
                            'type': 'malicious_ip',
                            'source': feed_name,
                            'details': ip_entry,
                            'severity': ip_entry.get('threat_level', 'medium')
                        })
        
        return indicators
    
    def _parse_text_feed(self, target_ip: str, content: str, feed_name: str) -> List[Dict[str, Any]]:
        """Parse text-based threat feed."""
        indicators = []
        
        lines = content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Extract IP from line (handle various formats)
            import re
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match and ip_match.group(1) == target_ip:
                indicators.append({
                    'type': 'malicious_ip',
                    'source': feed_name,
                    'details': {'raw_line': line},
                    'severity': 'medium'
                })
        
        return indicators
    
    def _calculate_risk_assessment(self, reputation_scores: Dict[str, float], 
                                 cve_correlations: List[Dict[str, Any]], 
                                 threat_indicators: List[Dict[str, Any]]) -> str:
        """Calculate overall risk assessment."""
        risk_factors = []
        
        # Reputation-based risk
        if reputation_scores:
            avg_reputation = reputation_scores.get('aggregate', 1.0)
            if avg_reputation < 0.3:
                risk_factors.append('high_malicious_reputation')
            elif avg_reputation < 0.7:
                risk_factors.append('medium_malicious_reputation')
        
        # CVE-based risk
        high_severity_cves = [cve for cve in cve_correlations if cve.get('cvss_score', 0) >= 7.0]
        if high_severity_cves:
            risk_factors.append('high_severity_vulnerabilities')
        elif cve_correlations:
            risk_factors.append('known_vulnerabilities')
        
        # Threat indicator-based risk
        if threat_indicators:
            high_severity_indicators = [ind for ind in threat_indicators if ind.get('severity') == 'high']
            if high_severity_indicators:
                risk_factors.append('active_threat_indicators')
            else:
                risk_factors.append('threat_indicators_present')
        
        # Determine overall risk level
        if any(factor in risk_factors for factor in ['high_malicious_reputation', 'high_severity_vulnerabilities', 'active_threat_indicators']):
            return 'high'
        elif any(factor in risk_factors for factor in ['medium_malicious_reputation', 'known_vulnerabilities', 'threat_indicators_present']):
            return 'medium'
        elif risk_factors:
            return 'low'
        else:
            return 'minimal'
    
    def _calculate_confidence_score(self, reputation_scores: Dict[str, float], 
                                  cve_correlations: List[Dict[str, Any]], 
                                  threat_indicators: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for the threat assessment."""
        confidence_factors = []
        
        # Reputation source confidence
        if reputation_scores:
            source_count = len([k for k in reputation_scores.keys() if k != 'aggregate'])
            confidence_factors.append(min(0.4, source_count * 0.2))  # Max 0.4 from reputation
        
        # CVE correlation confidence
        if cve_correlations:
            cve_confidence = min(0.3, len(cve_correlations) * 0.1)  # Max 0.3 from CVEs
            confidence_factors.append(cve_confidence)
        
        # Threat indicator confidence
        if threat_indicators:
            indicator_confidence = min(0.3, len(threat_indicators) * 0.15)  # Max 0.3 from indicators
            confidence_factors.append(indicator_confidence)
        
        return min(1.0, sum(confidence_factors))
    
    async def update_threat_feeds(self):
        """Update all threat intelligence feeds."""
        for feed in self.threat_feeds:
            if not feed.enabled:
                continue
            
            # Check if update is needed
            if feed.last_update and (datetime.now() - feed.last_update).seconds < feed.update_interval:
                continue
            
            try:
                self.logger.info(f"Updating threat feed: {feed.name}")
                # Trigger feed update by querying with a dummy IP
                await self._query_threat_feed('127.0.0.1', feed)
            except Exception as e:
                self.logger.error(f"Failed to update threat feed {feed.name}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        cache_stats = self.cache.get_stats()
        
        return {
            **self.stats,
            'cache_stats': cache_stats,
            'active_feeds': len([f for f in self.threat_feeds if f.enabled]),
            'total_feeds': len(self.threat_feeds)
        }
    
    def clear_cache(self):
        """Clear threat intelligence cache."""
        self.cache.cache.clear()
        self.cache.access_times.clear()
        self.logger.info("Threat intelligence cache cleared")


# Global threat intelligence instance
_threat_intelligence_instance = None


def get_threat_intelligence() -> RealTimeThreatIntelligence:
    """Get global threat intelligence instance."""
    global _threat_intelligence_instance
    if _threat_intelligence_instance is None:
        _threat_intelligence_instance = RealTimeThreatIntelligence()
    return _threat_intelligence_instance


# Configuration additions for threat intelligence
def extend_config_with_threat_intel():
    """Extend GRIDLAND configuration with threat intelligence settings."""
    from gridland.core.config import GridlandConfig
    
    # Add threat intelligence configuration attributes
    if not hasattr(GridlandConfig, 'threat_intel_cache_size'):
        GridlandConfig.threat_intel_cache_size = 10000
    if not hasattr(GridlandConfig, 'threat_intel_cache_ttl'):
        GridlandConfig.threat_intel_cache_ttl = 1800
    if not hasattr(GridlandConfig, 'threat_intel_enabled'):
        GridlandConfig.threat_intel_enabled = True


# Initialize configuration extensions
extend_config_with_threat_intel()