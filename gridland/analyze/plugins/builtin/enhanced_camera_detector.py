"""
Enhanced Camera Detection Plugin with multi-method analysis.
Implements CamXploit.py detection logic (lines 313-442) with architectural improvements.
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import json
from pathlib import Path

from gridland.analyze.memory.pool import get_memory_pool, VulnerabilityResult
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.core.logger import get_logger
from gridland.core.database_manager import db_manager

logger = get_logger(__name__)

@dataclass
class CameraIndicator:
    """Camera detection indicator with confidence scoring"""
    indicator_type: str  # "server_header", "content_type", "keyword", "endpoint", "title", "form"
    value: str
    confidence: float
    brand: Optional[str] = None

class DetectionOptimizer:
    """Optimize detection method execution order"""

    def __init__(self):
        self.method_effectiveness = {
            'server_header': 0.85,      # Fast, reliable
            'content_type': 0.90,       # Fast, very reliable
            'content_keyword': 0.70,    # Medium speed, good reliability
            'camera_endpoint': 0.75,    # Slow, good reliability
            'page_title': 0.80,         # Fast, reliable
            'login_form': 0.65          # Fast, moderate reliability
        }

    def should_continue_detection(self, current_indicators: List[CameraIndicator]) -> bool:
        """Determine if additional detection methods needed"""

        if not current_indicators:
            return True

        # Calculate current confidence
        confidence = sum(ind.confidence for ind in current_indicators) / len(current_indicators)

        # Stop if high confidence achieved
        if confidence >= 0.85 and len(current_indicators) >= 2:
            return False

        return True

class EnhancedCameraDetector(VulnerabilityPlugin):
    """
    Advanced camera detection using multi-method analysis.

    Implements sophisticated detection logic from CamXploit.py (lines 313-442)
    with enhanced confidence scoring and brand identification.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Enhanced Camera Detector",
            version="2.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=[80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8888, 9999],
            description="Multi-method camera detection with advanced heuristics and confidence scoring"
        )

    def __init__(self):
        super().__init__()
        self.detection_database = self._load_detection_database()
        self.memory_pool = get_memory_pool()
        self.optimizer = DetectionOptimizer()

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                banner: Optional[str] = None) -> List:
        return await analyze_vulnerabilities(self, target_ip, target_port, banner)

    def _analyze_server_header(self, header: str) -> list:
        """Analyzes the Server header for known camera signatures."""
        indicators = []
        header_lower = header.lower()

        server_patterns = self.detection_database.get('server_keywords', {})

        # --- THIS IS THE FIX ---
        # We track if a specific brand was found.
        found_specific_brand = False
        for brand, patterns in server_patterns.items():
            for pattern in patterns:
                if pattern in header_lower:
                    if brand != 'generic':
                        indicators.append(CameraIndicator(
                            indicator_type="SERVER_HEADER",
                            value=pattern,
                            brand=brand,
                            confidence=0.9
                        ))
                        found_specific_brand = True

        # If no specific brand matched, create a generic indicator from the header.
        if not found_specific_brand:
            generic_value = header_lower.split('server:')[-1].strip()
            if generic_value:
                indicators.append(CameraIndicator(
                    indicator_type="SERVER_HEADER",
                    value=generic_value,
                    brand="generic", # Explicitly label as generic
                    confidence=0.5
                ))
        # --- END OF FIX ---

        return indicators

    def _analyze_content_keywords(self, content: str) -> list:
        """Analyzes HTML content for camera-specific keywords."""
        indicators = []
        content_lower = content.lower()

        keyword_patterns = self.detection_database.get('content_keywords', {})

        for category, patterns in keyword_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    indicators.append(CameraIndicator(
                        indicator_type="CONTENT_KEYWORD",
                        value=f"{category}: {pattern}",
                        brand="generic", # Keywords are usually generic
                        confidence=0.6 if category == 'device_type' else 0.75
                    ))
        return indicators

    def _load_detection_database(self) -> Dict:
        """Load comprehensive camera detection patterns"""
        return {
            "server_keywords": {
                'hikvision': ['hikvision', 'dvr', 'nvr', 'webcam'],
                'dahua': ['dahua', 'dvr', 'nvr'],
                'axis': ['axis', 'axis communications'],
                'sony': ['sony', 'ipela'],
                'bosch': ['bosch', 'security systems'],
                'samsung': ['samsung', 'samsung techwin'],
                'panasonic': ['panasonic', 'network camera'],
                'vivotek': ['vivotek', 'network camera'],
                'cp_plus': ['cp plus', 'cp-plus', 'cpplus', 'cp_plus'],
                'generic': ['camera', 'webcam', 'surveillance', 'ip camera', 'dvr', 'nvr']
            },
            "content_types": {
                'video_stream': ['video/mpeg', 'video/mp4', 'video/h264', 'video/quicktime'],
                'image_stream': ['image/jpeg', 'image/mjpeg', 'multipart/x-mixed-replace'],
                'streaming': ['application/x-mpegURL', 'video/MP2T', 'application/octet-stream']
            },
            "content_keywords": {
                'device_types': ['camera', 'webcam', 'surveillance', 'cctv', 'dvr', 'nvr', 'recorder'],
                'functionality': ['stream', 'video', 'snapshot', 'live', 'monitoring', 'security'],
                'interface': ['login', 'admin', 'viewer', 'configuration', 'settings']
            },
            "camera_endpoints": [
                '/video', '/stream', '/snapshot', '/live', '/cgi-bin', '/admin',
                '/viewer', '/login', '/camera', '/mjpg', '/axis-cgi', '/ISAPI',
                '/onvif', '/api/camera', '/api/video', '/api/stream'
            ],
            "title_indicators": [
                'dvr', 'nvr', 'recorder', 'surveillance', 'cctv', 'camera',
                'webcam', 'ip camera', 'network camera', 'security camera',
                'video surveillance', 'monitoring system'
            ],
            "form_indicators": [
                'username', 'password', 'login', 'admin', 'user', 'pass',
                'authentication', 'signin', 'logon'
            ]
        }

async def analyze_vulnerabilities(self, target_ip: str, target_port: int,
                                banner: Optional[str] = None) -> List:
    if target_port not in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8888, 9999]:
        return []

    indicators = []
    protocol = "https" if target_port in [443, 8443] else "http"
    base_url = f"{protocol}://{target_ip}:{target_port}"

    # Method 1: Server header analysis from initial banner
    if banner:
        indicators.extend(self._analyze_server_header(banner))

    # Methods 2-6: Deep HTTP response analysis
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(base_url) as response:
                content_type = response.headers.get('Content-Type', '')
                server_header = response.headers.get('Server', '')

                # Method 2: Content-Type analysis
                indicators.extend(self._analyze_content_type(content_type))

                # Method 3: Server header analysis (from live response)
                if server_header and not banner:
                    indicators.extend(self._analyze_server_header(server_header))

                if response.status == 200:
                    content = await response.text()
                    # Method 4: Content keyword analysis
                    indicators.extend(self._analyze_content_keywords(content))
                    # Method 5: Page title analysis
                    indicators.extend(self._analyze_page_title(content))
                    # Method 6: Form field analysis
                    indicators.extend(self._analyze_form_fields(content))

            # Method 7: Endpoint probing
            indicators.extend(await self._analyze_camera_endpoints(session, base_url))

    except Exception as e:
        logger.debug(f"HTTP analysis failed for {base_url}: {e}")

    return self._generate_detection_results(indicators, target_ip, target_port)

    def _analyze_server_header(self, server_header: str) -> List[CameraIndicator]:
        """Analyze server header for camera brand indicators"""

        indicators = []
        server_lower = server_header.lower()

        for brand, keywords in self.detection_database["server_keywords"].items():
            for keyword in keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', server_lower):
                    confidence = 0.85 if brand != 'generic' else 0.60
                    indicators.append(CameraIndicator(
                        indicator_type="server_header",
                        value=f"{keyword} (in: {server_header})",
                        confidence=confidence,
                        brand=brand if brand != 'generic' else None
                    ))

        return indicators

    def _generate_detection_results(self, indicators: List[CameraIndicator],
                                  target_ip: str, target_port: int) -> List[VulnerabilityResult]:
        """Generate vulnerability results based on detection indicators"""

        if not indicators:
            return []

        # Calculate overall confidence using weighted average
        total_weight = sum(indicator.confidence for indicator in indicators)
        weighted_confidence = total_weight / len(indicators) if indicators else 0

        # Boost confidence if multiple methods agree
        method_types = set(indicator.indicator_type for indicator in indicators)
        if len(method_types) >= 3:
            weighted_confidence = min(weighted_confidence * 1.2, 0.95)

        # Determine detected brand
        brand_votes = {}
        for indicator in indicators:
            if indicator.brand:
                brand_votes[indicator.brand] = brand_votes.get(indicator.brand, 0) + indicator.confidence

        detected_brand = max(brand_votes, key=brand_votes.get) if brand_votes else None

        # Only report as camera if confidence exceeds threshold
        if weighted_confidence < 0.50:
            return []

        # Generate vulnerability result
        vuln_result = self.memory_pool.acquire_vulnerability_result()
        vuln_result.vulnerability_id = "enhanced-camera-detection"
        vuln_result.severity = "INFO"
        vuln_result.confidence = weighted_confidence
        vuln_result.description = self._generate_detection_description(indicators, detected_brand)
        vuln_result.ip = target_ip
        vuln_result.port = target_port

        details = {
            "detected_brand": detected_brand,
            "detection_methods": len(method_types),
            "total_indicators": len(indicators),
            "indicator_details": [
                {
                    "type": ind.indicator_type,
                    "value": ind.value,
                    "confidence": ind.confidence,
                    "brand": ind.brand
                } for ind in indicators
            ]
        }

        return [vuln_result]

    def _generate_detection_description(self, indicators: List[CameraIndicator],
                                      detected_brand: Optional[str]) -> str:
        """Generate human-readable detection description"""

        description_parts = ["Camera device detected using multi-method analysis:"]

        # Add brand information
        if detected_brand:
            brand_name = detected_brand.replace('_', ' ').title()
            description_parts.append(f"Brand: {brand_name}")

        # Summarize detection methods
        method_summary = {}
        for indicator in indicators:
            method = indicator.indicator_type.replace('_', ' ').title()
            if method not in method_summary:
                method_summary[method] = 0
            method_summary[method] += 1

        method_descriptions = [f"{method} ({count})" for method, count in method_summary.items()]
        description_parts.append(f"Detection methods: {', '.join(method_descriptions)}")

        # Add high-confidence indicators
        high_conf_indicators = [ind for ind in indicators if ind.confidence >= 0.80]
        if high_conf_indicators:
            high_conf_values = [ind.value.split(' (')[0] for ind in high_conf_indicators[:3]]
            description_parts.append(f"High-confidence indicators: {', '.join(high_conf_values)}")

        return " | ".join(description_parts)

    def _analyze_content_type(self, content_type: str) -> List[CameraIndicator]:
        """Analyze Content-Type header for video/image streams"""

        indicators = []
        content_type_lower = content_type.lower()

        for category, types in self.detection_database["content_types"].items():
            for ct in types:
                if ct in content_type_lower:
                    confidence = 0.90 if category == 'video_stream' else 0.75
                    indicators.append(CameraIndicator(
                        indicator_type="content_type",
                        value=f"{ct} ({category})",
                        confidence=confidence
                    ))

        return indicators

    def _analyze_content_keywords(self, content: str) -> List[CameraIndicator]:
        """Analyze page content for camera-related keywords"""

        indicators = []
        content_lower = content.lower()

        for category, keywords in self.detection_database["content_keywords"].items():
            found_keywords = [kw for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', content_lower)]

            if found_keywords:
                # Calculate confidence based on keyword relevance and count
                base_confidence = 0.70 if category == 'device_types' else 0.50
                keyword_bonus = min(len(found_keywords) * 0.05, 0.20)
                confidence = min(base_confidence + keyword_bonus, 0.85)

                indicators.append(CameraIndicator(
                    indicator_type="content_keyword",
                    value=f"{category}: {', '.join(found_keywords[:5])}",  # Limit display
                    confidence=confidence
                ))

        return indicators

    def _analyze_page_title(self, content: str) -> List[CameraIndicator]:
        """Extract and analyze HTML page title for camera indicators"""

        indicators = []

        # Extract title using regex
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        if not title_match:
            return indicators

        title = title_match.group(1).strip().lower()

        for indicator in self.detection_database["title_indicators"]:
            if indicator in title:
                confidence = 0.80  # Page titles are quite reliable
                indicators.append(CameraIndicator(
                    indicator_type="page_title",
                    value=f"'{indicator}' in title: '{title[:50]}...'",
                    confidence=confidence
                ))

        return indicators

    def _analyze_form_fields(self, content: str) -> List[CameraIndicator]:
        """Analyze HTML form fields for authentication interfaces"""

        indicators = []
        content_lower = content.lower()

        # Look for input fields and form elements
        form_patterns = [
            r'<input[^>]*name=["\']?({})'.format('|'.join(self.detection_database["form_indicators"])),
            r'<input[^>]*id=["\']?({})'.format('|'.join(self.detection_database["form_indicators"])),
            r'placeholder=["\']?[^"\']*({})'.format('|'.join(self.detection_database["form_indicators"]))
        ]

        found_indicators = set()
        for pattern in form_patterns:
            matches = re.findall(pattern, content_lower, re.IGNORECASE)
            found_indicators.update(matches)

        if found_indicators:
            confidence = 0.65  # Login forms common but not definitive
            indicators.append(CameraIndicator(
                indicator_type="login_form",
                value=f"Authentication form fields: {', '.join(list(found_indicators)[:3])}",
                confidence=confidence
            ))

        return indicators

    async def _analyze_camera_endpoints(self, session: aiohttp.ClientSession,
                                      base_url: str) -> List[CameraIndicator]:
        """Probe common camera endpoints for accessibility"""

        indicators = []
        endpoint_results = []

        # Test endpoints concurrently with limited concurrency
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

        async def test_endpoint(endpoint: str):
            async with semaphore:
                try:
                    url = f"{base_url}{endpoint}"
                    async with session.head(url, timeout=aiohttp.ClientTimeout(total=3)) as response:
                        if response.status in [200, 401, 403]:
                            confidence = 0.75 if response.status == 200 else 0.60
                            return CameraIndicator(
                                indicator_type="camera_endpoint",
                                value=f"{endpoint} (HTTP {response.status})",
                                confidence=confidence
                            )
                except Exception:
                    pass
                return None

        # Test all endpoints concurrently
        tasks = [test_endpoint(endpoint) for endpoint in self.detection_database["camera_endpoints"]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect valid indicators
        for result in results:
            if isinstance(result, CameraIndicator):
                indicators.append(result)

        return indicators
