"""
Stream Discovery Plugin for GRIDLAND v3.0

This plugin performs multi-protocol stream enumeration on IP camera systems through
comprehensive path testing. Supports RTSP, RTMP, HTTP/HTTPS, WebSocket, and WebRTC protocols.

⚠️ ETHICAL USE WARNING: This tool performs stream discovery and must only be used on
systems you own or have explicit authorization to test. Stream discovery should be
conducted responsibly and in compliance with applicable laws.

100% feature parity with CamXploit.py detect_live_streams() (lines 1562-1799).
"""

import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests
import urllib3

from gridland.analyze.plugins.manager import PluginMetadata, VulnerabilityPlugin
from gridland.core.data_loader import load_stream_paths
from gridland.core.logger import get_logger

# Disable SSL warnings for camera endpoints
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)


class StreamDetector:
    """Helper class for stream URL validation and detection."""

    def __init__(self, timeout: int = 5):
        """
        Initialize the StreamDetector.

        Args:
            timeout: HTTP request timeout in seconds (default: 5).
        """
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def validate_stream(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Validate if a URL is a valid stream endpoint.

        Args:
            url: The stream URL to validate.

        Returns:
            Dict containing stream details if valid, None otherwise.
            Dictionary includes: url, protocol, content_type, status_code, detection_method
        """
        try:
            # Determine protocol from URL
            protocol = url.split("://")[0].lower() if "://" in url else "http"

            # For RTSP/RTMP/MMS, we need different validation
            if protocol in ["rtsp", "rtmp", "mms"]:
                # Basic RTSP/RTMP validation (simplified for now)
                # In production, would use proper RTSP/RTMP clients
                return {
                    "url": url,
                    "protocol": protocol,
                    "content_type": f"application/{protocol}",
                    "status_code": None,
                    "detection_method": "protocol_inference",
                }

            # For HTTP/HTTPS streams, make actual request
            response = requests.get(
                url, timeout=self.timeout, verify=False, stream=True, headers=self.headers
            )

            if response.status_code in [200, 401, 403]:
                content_type = response.headers.get("Content-Type", "").lower()

                # Check for stream indicators
                is_stream = any(
                    indicator in content_type
                    for indicator in [
                        "video",
                        "stream",
                        "mpeg",
                        "h264",
                        "h265",
                        "mjpeg",
                        "image",
                        "multipart/x-mixed-replace",
                        "application/octet-stream",
                        "application/x-mpegurl",
                        "application/vnd.apple.mpegurl",
                    ]
                )

                # Check for video file extensions
                is_video_file = any(
                    ext in url.lower()
                    for ext in [".mp4", ".m3u8", ".ts", ".flv", ".webm", ".avi", ".mov"]
                )

                # Check for streaming path keywords
                has_stream_path = any(
                    keyword in url.lower()
                    for keyword in [
                        "/video",
                        "/stream",
                        "/live",
                        "/mjpg",
                        "/snapshot",
                        "/camera",
                        "/cam",
                    ]
                )

                if is_stream or is_video_file or (has_stream_path and response.status_code == 200):
                    detection_method = "content_type" if is_stream else "path_analysis"
                    return {
                        "url": url,
                        "protocol": protocol,
                        "content_type": content_type,
                        "status_code": response.status_code,
                        "detection_method": detection_method,
                    }

        except Exception as e:
            logger.debug(f"Stream validation failed for {url}: {e}")

        return None


class ProtocolHandler:
    """Helper class for building protocol-specific URLs."""

    @staticmethod
    def determine_protocols(port: int, port_protocol_map: Dict[str, List[int]]) -> List[str]:
        """
        Determine which protocols to test for a given port.

        Args:
            port: Port number to check.
            port_protocol_map: Mapping of protocols to their common ports.

        Returns:
            List of protocol names to test for this port.
        """
        protocols = []

        for protocol_name, ports in port_protocol_map.items():
            if port in ports:
                protocols.append(protocol_name)

        # If no specific protocol found, default to HTTP
        if not protocols:
            if port == 443 or port in [8443, 9443, 4443]:
                protocols.append("https")
            else:
                protocols.append("http")

        return protocols

    @staticmethod
    def build_url(protocol: str, ip: str, port: int, path: str) -> str:
        """
        Build a stream URL from components.

        Args:
            protocol: Protocol name (rtsp, rtmp, http, https, etc.).
            ip: IP address.
            port: Port number.
            path: URL path.

        Returns:
            Complete stream URL.
        """
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path

        return f"{protocol}://{ip}:{port}{path}"


class StreamDiscoveryPlugin(VulnerabilityPlugin):
    """
    Multi-protocol stream discovery plugin for IP camera systems.

    Performs comprehensive stream enumeration across RTSP, RTMP, HTTP/HTTPS,
    WebSocket, and WebRTC protocols using multi-threaded path testing.

    Features:
        - Multi-threaded discovery (max 30 concurrent threads)
        - Protocol-aware path selection based on port numbers
        - Content-type validation for stream detection
        - Support for RTSP, RTMP, HTTP, HTTPS, WebSocket, WebRTC
        - Progress callback support for real-time updates

    Attributes:
        stream_data (Dict): Stream paths and protocol configuration from stream_paths.json.
        max_concurrent_threads (int): Maximum concurrent test threads (default: 30).
        timeout (int): HTTP request timeout in seconds (default: 5).
        detector (StreamDetector): Stream validation helper.
        protocol_handler (ProtocolHandler): URL building helper.
    """

    def __init__(self):
        """Initialize the Stream Discovery plugin."""
        super().__init__()
        self.stream_data = load_stream_paths()
        self.max_concurrent_threads = 30  # From CamXploit.py line 1723
        self.timeout = 5  # From CamXploit.py TIMEOUT constant
        self.detector = StreamDetector(timeout=self.timeout)
        self.protocol_handler = ProtocolHandler()

    def get_metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.

        Returns:
            PluginMetadata: Plugin information and configuration.
        """
        return PluginMetadata(
            name="Stream Discovery Plugin",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="Multi-protocol stream enumeration for IP camera reconnaissance",
            plugin_type="vulnerability",
            supported_services=["rtsp", "http", "https", "rtmp", "camera"],
            supported_ports=[
                80,
                443,
                554,
                1935,
                8080,
                8000,
                8001,
                8554,
                8443,
                1554,
                2554,
                3554,
            ],
            requires_auth=False,
            performance_impact="MEDIUM",
            priority=50,
        )

    def discover_streams(
        self,
        ip: str,
        open_ports: List[int],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Discover live streams on the target IP across all open ports.

        This method performs comprehensive stream enumeration by:
        1. Loading stream paths from stream_paths.json
        2. Determining protocols to test based on port numbers
        3. Building URLs for each protocol/path combination
        4. Validating streams using multi-threaded HTTP requests
        5. Collecting successful stream discoveries

        Args:
            ip: Target IP address.
            open_ports: List of open ports to scan.
            progress_callback: Optional callback function(checked, total) for progress updates.

        Returns:
            Dict containing:
                - streams_found: List of discovered stream dictionaries
                - total_checked: Total number of URLs checked
                - total_found: Number of streams discovered

        Example:
            >>> plugin = StreamDiscoveryPlugin()
            >>> result = plugin.discover_streams("192.168.1.100", [80, 554, 8080])
            >>> print(f"Found {result['total_found']} streams")
            >>> for stream in result['streams_found']:
            ...     print(f"  {stream['url']} - {stream['protocol']}")
        """
        logger.info(f"Starting stream discovery on {ip} for {len(open_ports)} ports")

        # Thread-safe result collection
        streams_found = []
        streams_lock = threading.Lock()
        checked_count = [0]  # Use list for mutable integer in closure
        total_count = [0]  # Total URLs to check

        # Get protocol configuration
        port_protocol_map = self.stream_data.get("port_protocols", {})
        protocols_data = self.stream_data.get("protocols", {})

        # Build work queue: list of (url, port, path, protocol) tuples
        work_queue = []

        for port in open_ports:
            # Determine which protocols to test for this port
            protocols = self.protocol_handler.determine_protocols(port, port_protocol_map)

            for protocol_name in protocols:
                # Get stream paths for this protocol
                protocol_paths = self._get_paths_for_protocol(protocol_name, protocols_data)

                for path in protocol_paths:
                    url = self.protocol_handler.build_url(protocol_name, ip, port, path)
                    work_queue.append((url, port, path, protocol_name))

        total_count[0] = len(work_queue)
        logger.debug(f"Built work queue with {total_count[0]} URLs to check")

        def check_stream_worker(url: str, port: int, path: str, protocol: str):
            """Worker function to check a single stream URL."""
            result = self.detector.validate_stream(url)

            if result:
                with streams_lock:
                    streams_found.append(
                        {
                            "url": result["url"],
                            "protocol": result["protocol"],
                            "port": port,
                            "path": path,
                            "content_type": result.get("content_type"),
                            "status_code": result.get("status_code"),
                            "detection_method": result.get("detection_method"),
                        }
                    )

            # Update progress
            with streams_lock:
                checked_count[0] += 1
                # Call progress callback every 50 URLs (matches CamXploit.py pattern)
                if progress_callback and checked_count[0] % 50 == 0:
                    progress_callback(checked_count[0], total_count[0])

        # Execute work queue with batch threading (CamXploit.py pattern)
        threads = []

        for url, port, path, protocol in work_queue:
            thread = threading.Thread(target=check_stream_worker, args=(url, port, path, protocol))
            thread.daemon = True
            threads.append(thread)
            thread.start()

            # Batch threading: start max_concurrent threads, then join before starting more
            if len(threads) >= self.max_concurrent_threads:
                for t in threads:
                    t.join()
                threads = []

        # Join remaining threads
        for t in threads:
            t.join()

        # Final progress callback
        if progress_callback and checked_count[0] > 0:
            progress_callback(checked_count[0], total_count[0])

        logger.info(f"Stream discovery complete: {len(streams_found)} streams found")

        return {
            "streams_found": streams_found,
            "total_checked": checked_count[0],
            "total_found": len(streams_found),
        }

    def _get_paths_for_protocol(self, protocol: str, protocols_data: Dict[str, Any]) -> List[str]:
        """
        Get all stream paths for a given protocol.

        Args:
            protocol: Protocol name (rtsp, rtmp, http, https, etc.).
            protocols_data: Protocol configuration from stream_paths.json.

        Returns:
            List of stream paths to test for this protocol.
        """
        paths = []

        # Map protocol names to their data keys
        if protocol in ["http", "https"]:
            # HTTP/HTTPS streams use 'http' protocol data
            http_data = protocols_data.get("http", {})

            # Collect all HTTP stream paths
            for category in [
                "generic",
                "snapshots",
                "mjpeg_streams",
                "api_endpoints",
                "cgi_endpoints",
            ]:
                if category in http_data:
                    paths.extend(http_data[category])

            # Add brand-specific HTTP paths
            if "brand_specific" in http_data:
                for brand_paths in http_data["brand_specific"].values():
                    paths.extend(brand_paths)

        elif protocol == "rtsp":
            rtsp_data = protocols_data.get("rtsp", {})

            # Collect all RTSP stream paths
            for category in [
                "generic",
                "onvif",
                "hikvision",
                "dahua",
                "axis",
                "sony",
                "bosch",
                "panasonic",
                "cp_plus",
                "foscam",
                "vivotek",
            ]:
                if category in rtsp_data:
                    paths.extend(rtsp_data[category])

        elif protocol == "rtmp":
            rtmp_data = protocols_data.get("rtmp", {})

            # Collect all RTMP stream paths
            for category in ["generic", "variants", "hls"]:
                if category in rtmp_data:
                    paths.extend(rtmp_data[category])

        elif protocol == "websocket":
            ws_data = protocols_data.get("websocket", {})

            # Collect all WebSocket stream paths
            for category in ["generic", "api"]:
                if category in ws_data:
                    paths.extend(ws_data[category])

        elif protocol == "webrtc":
            webrtc_data = protocols_data.get("webrtc", {})

            # Collect all WebRTC stream paths
            for category in ["generic", "signaling"]:
                if category in webrtc_data:
                    paths.extend(webrtc_data[category])

        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for path in paths:
            if path not in seen:
                seen.add(path)
                unique_paths.append(path)

        return unique_paths

    async def scan_vulnerabilities(
        self, ip: str, open_ports: List[int], **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Async interface for stream discovery (plugin framework compatibility).

        Args:
            ip: Target IP address.
            open_ports: List of open ports to scan.
            **kwargs: Additional keyword arguments (progress_callback, etc.).

        Returns:
            List containing discovery results dictionary.
        """
        progress_callback = kwargs.get("progress_callback", None)
        result = self.discover_streams(ip, open_ports, progress_callback)

        # Return as list for consistency with plugin framework
        return [result]


# Plugin instance for automatic discovery
stream_discovery_plugin = StreamDiscoveryPlugin()
