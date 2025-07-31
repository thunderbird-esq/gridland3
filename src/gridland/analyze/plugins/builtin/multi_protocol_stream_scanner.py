"""
Multi-Protocol Stream Scanner with comprehensive validation and intelligence.
Implements CamXploit.py stream detection methods (lines 818-1057) with enhanced capabilities.
"""

import asyncio
import aiohttp
import socket
import struct
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import json
import re
import os

from gridland.analyze.memory.pool import get_memory_pool, StreamResult
from gridland.analyze.plugins.manager import StreamPlugin, PluginMetadata
from gridland.core.logger import get_logger

logger = get_logger(__name__)

class StreamProtocol(Enum):
    """Supported streaming protocols"""
    RTSP = "rtsp"
    RTMP = "rtmp"
    HTTP = "http"
    HTTPS = "https"
    MMS = "mms"
    ONVIF = "onvif"
    HLS = "hls"
    MPEG_TS = "mpeg-ts"

@dataclass
class StreamDetails:
    """Comprehensive stream information"""
    url: str
    protocol: StreamProtocol
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    resolution: Optional[str] = None
    frame_rate: Optional[str] = None
    codec: Optional[str] = None
    bitrate: Optional[str] = None
    authentication_required: bool = False
    stream_active: bool = False
    response_headers: Dict[str, str] = None
    confidence: float = 0.0
    validation_method: str = "unknown"

class MultiProtocolStreamScanner(StreamPlugin):
    """
    Comprehensive multi-protocol stream detection and validation.
    """

    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Multi-Protocol Stream Scanner",
            version="2.0.0",
            author="GRIDLAND Security Team",
            plugin_type="stream",
            supported_services=["http", "https", "rtsp", "rtmp", "mms", "onvif"],
            supported_ports=[80, 443, 554, 1935, 1755, 3702, 8080, 8443, 8554, 10554],
            description="Comprehensive multi-protocol stream detection with detailed validation"
        )
        self.protocol_config = self._load_protocol_config()
        self.memory_pool = get_memory_pool()

    def _load_protocol_config(self) -> Dict:
        """Load protocol-specific configuration"""
        return {
            "protocols": {
                StreamProtocol.RTSP: {"default_ports": [554, 8554]},
                StreamProtocol.RTMP: {"default_ports": [1935]},
                StreamProtocol.HTTP: {"default_ports": [80, 8080, 8000]},
                StreamProtocol.HTTPS: {"default_ports": [443, 8443]},
                StreamProtocol.MMS: {"default_ports": [1755]},
                StreamProtocol.ONVIF: {"default_ports": [3702]},
                StreamProtocol.HLS: {"default_ports": [80, 443, 8080]},
            }
        }

    async def analyze_streams(self, target_ip: str, target_port: int,
                            service: str, banner: Optional[str] = None) -> List[StreamResult]:
        """Comprehensive multi-protocol stream analysis"""
        protocols_to_test = self._get_protocols_for_port(target_port)
        if not protocols_to_test:
            return []

        logger.info(f"Testing {len(protocols_to_test)} protocols on {target_ip}:{target_port}")
        tasks = [self._test_protocol_streams(target_ip, target_port, p) for p in protocols_to_test]

        detected_streams = []
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, list):
                detected_streams.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"Protocol test failed: {result}")

        return self._create_stream_results(detected_streams)

    def _get_protocols_for_port(self, port: int) -> List[StreamProtocol]:
        """Determine which protocols to test for a given port"""
        protocols = [p for p, c in self.protocol_config["protocols"].items() if port in c["default_ports"]]
        if port in [80, 8080] and StreamProtocol.HTTP not in protocols:
            protocols.append(StreamProtocol.HTTP)
        if port in [443, 8443] and StreamProtocol.HTTPS not in protocols:
            protocols.append(StreamProtocol.HTTPS)
        return protocols

    def _create_stream_results(self, streams: List[StreamDetails]) -> List[StreamResult]:
        """Convert StreamDetails into StreamResult objects from the memory pool"""
        results = []
        for stream in streams:
            res = self.memory_pool.acquire_stream_result()
            res.stream_url = stream.url
            res.protocol = stream.protocol.value
            res.accessible = stream.stream_active
            res.authenticated = stream.authentication_required
            res.confidence = stream.confidence
            res.details = {k: v for k, v in asdict(stream).items() if k not in ['url', 'protocol', 'stream_active', 'authentication_required', 'confidence']}
            results.append(res)
        if results:
            logger.info(f"Detected {len(results)} potential streams.")
        return results

    async def _test_protocol_streams(self, ip: str, port: int, proto: StreamProtocol) -> List[StreamDetails]:
        """Dispatcher for protocol-specific test functions"""
        if proto == StreamProtocol.RTSP: return await self._test_rtsp_streams(ip, port)
        if proto == StreamProtocol.RTMP: return await self._test_rtmp_streams(ip, port)
        if proto in [StreamProtocol.HTTP, StreamProtocol.HTTPS]: return await self._test_http_streams(ip, port, proto)
        if proto == StreamProtocol.HLS: return await self._test_hls_streams(ip, port)
        # MMS and ONVIF are complex and not implemented in this pass.
        return []

    async def _test_rtsp_streams(self, ip: str, port: int) -> List[StreamDetails]:
        """Test for common RTSP stream paths"""
        paths = ["/live.sdp", "/stream1", "/axis-media/media.amp"]
        streams = []
        for path in paths:
            url = f"rtsp://{ip}:{port}{path}"
            try:
                resp = await self._send_rtsp_options(ip, port, path)
                if resp:
                    streams.append(StreamDetails(
                        url=url, protocol=StreamProtocol.RTSP, stream_active="200 OK" in resp,
                        authentication_required="401" in resp, confidence=0.85,
                        response_headers=self._parse_rtsp_headers(resp), validation_method="rtsp_options"
                    ))
            except Exception as e:
                logger.debug(f"RTSP test for {url} failed: {e}")
        return streams

    async def _send_rtsp_options(self, ip: str, port: int, path: str) -> Optional[str]:
        """Send RTSP OPTIONS request using raw socket"""
        req = f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: GRIDLAND\r\n\r\n".encode()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
            writer.write(req)
            await writer.drain()
            response = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            return response.decode('utf-8', errors='ignore')
        except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror) as e:
            logger.debug(f"RTSP connect to {ip}:{port} failed: {e}")
            return None

    def _parse_rtsp_headers(self, resp: str) -> Dict[str, str]:
        """Parse headers from raw RTSP response"""
        try:
            lines = resp.splitlines()
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            return headers
        except Exception:
            return {}

    async def _test_http_streams(self, ip: str, port: int, proto: StreamProtocol) -> List[StreamDetails]:
        """Test for common HTTP/HTTPS stream paths"""
        paths = ["/video", "/stream.mjpg", "/mjpg/video.mjpg", "/snapshot.jpg"]
        streams = []
        proto_name = "https" if proto == StreamProtocol.HTTPS else "http"
        base_url = f"{proto_name}://{ip}:{port}"

        conn = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            for path in paths:
                url = f"{base_url}{path}"
                try:
                    async with session.head(url, allow_redirects=True) as resp:
                        if resp.status == 200 and self._is_stream_content_type(resp.headers.get('Content-Type', '')):
                            streams.append(StreamDetails(
                                url=url, protocol=proto, stream_active=True, confidence=0.8,
                                content_type=resp.headers.get('Content-Type'),
                                content_length=int(resp.headers.get('Content-Length', 0)),
                                response_headers=dict(resp.headers), validation_method="http_head"
                            ))
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"HTTP HEAD for {url} failed: {e}")
        return streams

    def _is_stream_content_type(self, ctype: str) -> bool:
        """Check if a Content-Type header suggests a video or image stream"""
        return any(indicator in ctype.lower() for indicator in ['video/', 'image/', 'multipart/x-mixed-replace'])

    async def _test_rtmp_streams(self, ip: str, port: int) -> List[StreamDetails]:
        """Test for RTMP streams by attempting a handshake"""
        try:
            accessible = await self._test_rtmp_handshake(ip, port)
            if accessible:
                return [StreamDetails(
                    url=f"rtmp://{ip}:{port}/live", protocol=StreamProtocol.RTMP,
                    stream_active=True, confidence=0.75, validation_method="rtmp_handshake"
                )]
        except Exception as e:
            logger.debug(f"RTMP handshake for {ip}:{port} failed: {e}")
        return []

    async def _test_rtmp_handshake(self, ip: str, port: int) -> bool:
        """Perform a simplified RTMP handshake"""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
            c0 = b'\x03'
            c1 = os.urandom(1536)
            writer.write(c0 + c1)
            await writer.drain()
            s0 = await reader.readexactly(1)
            s1 = await reader.readexactly(1536)
            writer.close()
            await writer.wait_closed()
            return s0 == c0
        except (asyncio.TimeoutError, ConnectionRefusedError, asyncio.IncompleteReadError) as e:
            logger.debug(f"RTMP handshake to {ip}:{port} failed: {e}")
            return False

    async def _test_hls_streams(self, ip: str, port: int) -> List[StreamDetails]:
        """Test for HLS streams by looking for .m3u8 playlists"""
        paths = ["/live.m3u8", "/stream.m3u8", "/playlist.m3u8"]
        streams = []
        proto_name = "https" if port == 443 else "http"
        base_url = f"{proto_name}://{ip}:{port}"

        conn = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            for path in paths:
                url = f"{base_url}{path}"
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            if content.startswith("#EXTM3U"):
                                streams.append(StreamDetails(
                                    url=url, protocol=StreamProtocol.HLS, stream_active=True,
                                    confidence=0.9, content_type=resp.headers.get('Content-Type'),
                                    response_headers=dict(resp.headers), validation_method="hls_playlist"
                                ))
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"HLS GET for {url} failed: {e}")
        return streams
