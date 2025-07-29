"""
Enhanced Stream Scanner with comprehensive protocol and path support.
Implements intelligence from CamXploit.py stream detection (lines 818-1057).
This is a new plugin that does not replace existing functionality.
"""

import asyncio
import aiohttp
import socket
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import json
from pathlib import Path

from ...memory.pool import get_memory_pool
from ..manager import StreamPlugin, PluginMetadata
from ....core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class StreamEndpoint:
    """Enhanced stream endpoint with protocol and brand information"""
    url: str
    protocol: str
    brand: Optional[str]
    content_type: Optional[str]
    response_size: Optional[int]
    authentication_required: bool
    confidence: float

class EnhancedStreamScannerPlus(StreamPlugin):
    """
    Comprehensive stream detection with multi-protocol support.

    Based on CamXploit.py stream detection patterns (lines 836-938)
    with enhanced protocol awareness and brand-specific path testing.
    """

    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Enhanced Stream Scanner Plus",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="Comprehensive multi-protocol stream detection with brand intelligence"
        )
        self.stream_database = self._load_stream_database()
        self.memory_pool = get_memory_pool()

    def _load_stream_database(self) -> Dict:
        """Load comprehensive stream path database"""
        try:
            db_path = Path(__file__).parent.parent.parent.parent / "data" / "stream_paths_plus.json"
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load enhanced stream database: {e}, using defaults")
            return self._get_default_database()

    def _get_default_database(self) -> Dict:
        """Fallback stream database with essential paths"""
        return {
            "protocols": {
                "rtsp": {
                    "generic": ["/live.sdp", "/h264.sdp", "/stream1", "/video"],
                    "onvif": ["/onvif/streaming/channels/1"],
                    "hikvision": ["/Streaming/Channels/1"],
                    "dahua": ["/cam/realmonitor?channel=1&subtype=0"],
                    "axis": ["/axis-media/media.amp"]
                },
                "http": {
                    "snapshots": ["/snapshot.jpg", "/img/snapshot.cgi"],
                    "mjpeg_streams": ["/mjpg/video.mjpg", "/cgi-bin/mjpg/video.cgi"]
                }
            }
        }

    async def analyze_streams(self, target_ip: str, target_port: int,
                            banner: Optional[str] = None) -> List:
        """Enhanced stream analysis with comprehensive protocol testing"""

        detected_streams = []
        brand = self._detect_brand_from_banner(banner) if banner else None

        # Test RTSP streams if appropriate port
        if target_port in [554, 8554, 10554] + list(range(1554, 9555, 1000)):
            rtsp_streams = await self._test_rtsp_streams(target_ip, target_port, brand)
            detected_streams.extend(rtsp_streams)

        # Test HTTP-based streams
        if target_port in [80, 443, 8080, 8443, 8000, 8001]:
            http_streams = await self._test_http_streams(target_ip, target_port, brand)
            detected_streams.extend(http_streams)

        # Test RTMP streams if appropriate port
        if target_port in [1935, 1936, 1937]:
            rtmp_streams = await self._test_rtmp_streams(target_ip, target_port)
            detected_streams.extend(rtmp_streams)

        # Convert to memory pool objects
        stream_results = []
        for stream in detected_streams:
            stream_result = self.memory_pool.get_stream_result()
            stream_result.url = stream.url
            stream_result.protocol = stream.protocol
            stream_result.status = "accessible" if not stream.authentication_required else "auth_required"
            stream_result.confidence = stream.confidence
            stream_result.metadata = {
                "brand": stream.brand,
                "content_type": stream.content_type,
                "response_size": stream.response_size,
                "authentication_required": stream.authentication_required
            }
            stream_results.append(stream_result)

        return stream_results

    async def _test_rtsp_streams(self, target_ip: str, target_port: int,
                               brand: Optional[str]) -> List[StreamEndpoint]:
        """Test RTSP stream endpoints with brand-specific paths"""

        streams = []
        rtsp_paths = self._get_rtsp_paths_for_brand(brand)

        # Use raw socket for RTSP testing (like CamXploit.py line 967-968)
        for path in rtsp_paths:
            stream_url = f"rtsp://{target_ip}:{target_port}{path}"

            try:
                # Test RTSP OPTIONS request
                accessible, auth_required = await self._test_rtsp_endpoint(target_ip, target_port, path)

                if accessible:
                    confidence = 0.95 if brand and brand in path else 0.85

                    stream = StreamEndpoint(
                        url=stream_url,
                        protocol="rtsp",
                        brand=brand,
                        content_type="video/h264",  # Most common for RTSP
                        response_size=None,
                        authentication_required=auth_required,
                        confidence=confidence
                    )
                    streams.append(stream)

            except Exception as e:
                logger.debug(f"RTSP test failed for {stream_url}: {e}")

        return streams

    async def _test_http_streams(self, target_ip: str, target_port: int,
                               brand: Optional[str]) -> List[StreamEndpoint]:
        """Test HTTP stream endpoints with comprehensive path testing"""

        streams = []
        protocol = "https" if target_port in [443, 8443] else "http"
        http_paths = self._get_http_paths_for_brand(brand)

        # Use aiohttp for HTTP testing with proper stream detection
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=5)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for path in http_paths:
                stream_url = f"{protocol}://{target_ip}:{target_port}{path}"

                try:
                    async with session.get(stream_url) as response:
                        if response.status == 200:
                            content_type = response.headers.get('Content-Type', '').lower()
                            content_length = response.headers.get('Content-Length', '0')

                            # Check if it's actually a video/image stream
                            if self._is_stream_content_type(content_type):
                                confidence = self._calculate_stream_confidence(content_type, path, brand)

                                stream = StreamEndpoint(
                                    url=stream_url,
                                    protocol="http",
                                    brand=brand,
                                    content_type=content_type,
                                    response_size=int(content_length) if content_length.isdigit() else None,
                                    authentication_required=False,
                                    confidence=confidence
                                )
                                streams.append(stream)

                        elif response.status == 401:
                            # Authentication required but endpoint exists
                            stream = StreamEndpoint(
                                url=stream_url,
                                protocol="http",
                                brand=brand,
                                content_type=None,
                                response_size=None,
                                authentication_required=True,
                                confidence=0.80
                            )
                            streams.append(stream)

                except Exception as e:
                    logger.debug(f"HTTP stream test failed for {stream_url}: {e}")

        return streams

    async def _test_rtsp_endpoint(self, target_ip: str, target_port: int, path: str) -> Tuple[bool, bool]:
        """Test RTSP endpoint using raw socket (CamXploit.py methodology)"""

        try:
            # Create RTSP OPTIONS request
            rtsp_request = (
                f"OPTIONS rtsp://{target_ip}:{target_port}{path} RTSP/1.0\\r\\n"
                f"CSeq: 1\\r\\n"
                f"User-Agent: GRIDLAND-StreamScanner/2.0\\r\\n"
                f"\\r\\n"
            )

            # Connect with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, target_port))
            sock.send(rtsp_request.encode())

            # Read response
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            # Parse RTSP response
            if "RTSP/1.0" in response:
                if "200 OK" in response:
                    return True, False  # Accessible, no auth required
                elif "401 Unauthorized" in response:
                    return True, True   # Accessible, auth required

            return False, False

        except Exception:
            return False, False

    def _get_rtsp_paths_for_brand(self, brand: Optional[str]) -> List[str]:
        """Get RTSP paths prioritized by brand"""

        paths = []
        rtsp_db = self.stream_database.get("protocols", {}).get("rtsp", {})

        # Add brand-specific paths first
        if brand and brand.lower() in rtsp_db:
            paths.extend(rtsp_db[brand.lower()])

        # Add ONVIF paths (widely supported)
        if "onvif" in rtsp_db:
            paths.extend(rtsp_db["onvif"])

        # Add generic paths
        if "generic" in rtsp_db:
            paths.extend(rtsp_db["generic"])

        return list(dict.fromkeys(paths))  # Remove duplicates, preserve order

    def _get_http_paths_for_brand(self, brand: Optional[str]) -> List[str]:
        """Get HTTP paths prioritized by brand and type"""

        paths = []
        http_db = self.stream_database.get("protocols", {}).get("http", {})

        # Prioritize snapshots (faster to test)
        if "snapshots" in http_db:
            paths.extend(http_db["snapshots"])

        # Add MJPEG streams
        if "mjpeg_streams" in http_db:
            paths.extend(http_db["mjpeg_streams"])

        # Add API endpoints (modern cameras)
        if "api_endpoints" in http_db:
            paths.extend(http_db["api_endpoints"])

        return paths

    def _is_stream_content_type(self, content_type: str) -> bool:
        """Check if content type indicates video/image stream"""

        stream_indicators = [
            'video/', 'image/', 'multipart/x-mixed-replace',
            'application/x-mpegurl', 'application/octet-stream'
        ]

        return any(indicator in content_type for indicator in stream_indicators)

    def _calculate_stream_confidence(self, content_type: str, path: str, brand: Optional[str]) -> float:
        """Calculate confidence score for stream detection"""

        confidence = 0.70  # Base confidence

        # Content type indicators
        if 'video/' in content_type:
            confidence += 0.20
        elif 'image/jpeg' in content_type:
            confidence += 0.15
        elif 'multipart/x-mixed-replace' in content_type:
            confidence += 0.25  # MJPEG stream

        # Path indicators
        if any(indicator in path.lower() for indicator in ['stream', 'video', 'live']):
            confidence += 0.10

        # Brand match
        if brand and brand.lower() in path.lower():
            confidence += 0.15

        return min(confidence, 0.98)  # Cap at 98%

    def _detect_brand_from_banner(self, banner: str) -> Optional[str]:
        """Detect camera brand from banner for path prioritization"""

        if not banner:
            return None

        banner_lower = banner.lower()

        if 'hikvision' in banner_lower:
            return 'hikvision'
        elif 'dahua' in banner_lower:
            return 'dahua'
        elif 'axis' in banner_lower:
            return 'axis'
        elif any(cp in banner_lower for cp in ['cp plus', 'cp-plus', 'cpplus']):
            return 'cp_plus'

        return None

    async def _test_rtmp_streams(self, target_ip: str, target_port: int) -> List[StreamEndpoint]:
        """Test RTMP streams"""
        # This is a placeholder for the actual implementation
        return []
