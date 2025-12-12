"""Stream Detection module for GRIDLAND.

This module provides stream URL detection and validation capabilities by analyzing
HTTP responses, content types, URL patterns, and protocols. Detection logic is
ported from CamXploit.py lines 1502-1559 for 100% feature parity.

Stream details and quality detection capabilities added for Phase 7 (TASKS 255-260)
based on CamXploit.py lines 1685-1720.
"""

import re
import warnings
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

# Suppress SSL warnings for camera devices
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except (ImportError, AttributeError):
    pass


class StreamDetector:
    """Detect and validate camera stream URLs.

    This class implements multi-phase stream detection using HEAD/GET requests,
    content-type validation, URL pattern matching, protocol detection, and
    response content analysis. Detection logic matches CamXploit.py for compatibility.

    Detection Methods:
        - content_type: Validates video/stream MIME types
        - url_pattern: Matches video file extensions
        - protocol: Detects streaming protocols (rtsp, rtmp, mms, rtp)
        - path_pattern: Matches common camera stream paths
        - response_content: Analyzes response body for stream indicators

    Example:
        >>> detector = StreamDetector()
        >>> result = detector.check_stream_url("http://192.168.1.100/video.mp4")
        >>> if result['is_stream']:
        ...     print(f"Stream detected via {result['detection_method']}")
        ...     print(f"Content-Type: {result['details']['content_type']}")
        Stream detected via url_pattern
        Content-Type: video/mp4
    """

    # Content-type indicators for streams (CamXploit.py line 1512, 1529)
    CONTENT_TYPE_INDICATORS = ["video", "stream", "mpeg", "h264", "mjpeg", "rtsp", "rtmp", "image"]

    # Video file extensions (CamXploit.py line 1516, 1535)
    VIDEO_EXTENSIONS = [".mp4", ".m3u8", ".ts", ".flv", ".webm", ".avi", ".mov"]

    # Streaming protocols (CamXploit.py line 1519, 1540)
    STREAMING_PROTOCOLS = ["rtsp://", "rtmp://", "mms://", "rtp://"]

    # Camera stream path patterns (CamXploit.py line 1552)
    STREAM_PATH_PATTERNS = ["/video", "/stream", "/live", "/mjpg", "/snapshot"]

    # Response content indicators (CamXploit.py line 1546)
    CONTENT_INDICATORS = ["stream", "video", "live", "camera", "mjpg", "mpeg"]

    # Codec detection patterns (Phase 7 - TASKS 255-260)
    CODEC_PATTERNS = {
        "h264": ["h264", "h.264", "avc"],
        "h265": ["h265", "h.265", "hevc"],
        "mpeg4": ["mpeg4", "mpeg-4", "mp4v"],
        "mjpeg": ["mjpeg", "mjpg", "motion-jpeg"],
        "vp8": ["vp8", "webm"],
        "vp9": ["vp9"],
    }

    # Resolution detection patterns (Phase 7 - TASKS 255-260)
    RESOLUTION_PATTERNS = {
        # Format: pattern -> (width, height)
        r"4k|uhd|2160p": (3840, 2160),
        r"1440p|qhd": (2560, 1440),
        r"1080p|fhd|fullhd": (1920, 1080),
        r"720p|hd": (1280, 720),
        r"480p|sd": (640, 480),
        r"360p": (640, 360),
        r"240p": (352, 240),
        # Explicit width x height patterns will be parsed separately
    }

    def __init__(self) -> None:
        """Initialize StreamDetector."""
        pass

    def check_stream_url(self, url: str, timeout: float = 5) -> Dict[str, Any]:
        """Check if a URL is a valid stream endpoint.

        This method implements a multi-phase detection strategy:
        1. HEAD request to check headers and URL patterns
        2. GET request for deeper content analysis
        3. Path pattern matching for camera-specific endpoints

        Args:
            url: The URL to check for stream indicators
            timeout: Request timeout in seconds (default: 5)

        Returns:
            Dictionary containing:
                - is_stream (bool): True if stream detected, False otherwise
                - detection_method (str): Method used for detection
                  ('content_type', 'url_pattern', 'protocol', 'path_pattern',
                   'response_content', or None)
                - details (dict): Additional detection details
                    - content_type (str): Content-Type header value
                    - status_code (int): HTTP status code
                    - protocol (str, optional): Detected streaming protocol
                    - extension (str, optional): Detected video extension
                    - path_pattern (str, optional): Matched path pattern
                    - content_match (str, optional): Matched content indicator

        Example:
            >>> detector = StreamDetector()
            >>> result = detector.check_stream_url("http://camera.local/video.mp4")
            >>> result['is_stream']
            True
            >>> result['detection_method']
            'url_pattern'
            >>> result['details']['extension']
            '.mp4'

        Note:
            SSL certificate verification is disabled (verify=False) as camera
            devices often use self-signed certificates.
        """
        url_lower = url.lower()

        # Phase 1: Protocol detection (fast, no network request needed)
        for protocol in self.STREAMING_PROTOCOLS:
            if protocol in url_lower:
                return {
                    "is_stream": True,
                    "detection_method": "protocol",
                    "details": {
                        "protocol": protocol.rstrip("://"),
                        "content_type": None,
                        "status_code": None,
                    },
                }

        # Phase 2: Try HEAD request first (lightweight)
        try:
            response = requests.head(url, timeout=timeout, verify=False)

            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "").lower()

                # Check content type for video/stream indicators
                for indicator in self.CONTENT_TYPE_INDICATORS:
                    if indicator in content_type:
                        return {
                            "is_stream": True,
                            "detection_method": "content_type",
                            "details": {
                                "content_type": content_type,
                                "status_code": response.status_code,
                                "indicator": indicator,
                            },
                        }

                # Check for video file extensions in URL
                for extension in self.VIDEO_EXTENSIONS:
                    if extension in url_lower:
                        return {
                            "is_stream": True,
                            "detection_method": "url_pattern",
                            "details": {
                                "content_type": content_type,
                                "status_code": response.status_code,
                                "extension": extension,
                            },
                        }

        except requests.exceptions.RequestException:
            # HEAD request failed, continue to GET request
            pass
        except Exception:
            # Unexpected error, continue to GET request
            pass

        # Phase 3: Try GET request for better detection
        try:
            response = requests.get(url, timeout=timeout, verify=False, stream=True)

            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "").lower()

                # Check content type
                for indicator in self.CONTENT_TYPE_INDICATORS:
                    if indicator in content_type:
                        return {
                            "is_stream": True,
                            "detection_method": "content_type",
                            "details": {
                                "content_type": content_type,
                                "status_code": response.status_code,
                                "indicator": indicator,
                            },
                        }

                # Check for video file extensions in URL
                for extension in self.VIDEO_EXTENSIONS:
                    if extension in url_lower:
                        return {
                            "is_stream": True,
                            "detection_method": "url_pattern",
                            "details": {
                                "content_type": content_type,
                                "status_code": response.status_code,
                                "extension": extension,
                            },
                        }

                # Check response content for stream indicators
                try:
                    # Read first 8KB of content to avoid large downloads
                    content_chunk = next(response.iter_content(chunk_size=8192), b"")
                    content = content_chunk.decode("utf-8", errors="ignore").lower()

                    for indicator in self.CONTENT_INDICATORS:
                        if indicator in content:
                            return {
                                "is_stream": True,
                                "detection_method": "response_content",
                                "details": {
                                    "content_type": content_type,
                                    "status_code": response.status_code,
                                    "content_match": indicator,
                                },
                            }
                except Exception:
                    # Content reading failed, continue
                    pass

        except requests.exceptions.RequestException:
            # GET request failed, continue to path pattern matching
            pass
        except Exception:
            # Unexpected error, continue to path pattern matching
            pass

        # Phase 4: Check for specific camera stream path patterns
        for pattern in self.STREAM_PATH_PATTERNS:
            if pattern in url_lower:
                return {
                    "is_stream": True,
                    "detection_method": "path_pattern",
                    "details": {"content_type": None, "status_code": None, "path_pattern": pattern},
                }

        # No stream detected
        return {
            "is_stream": False,
            "detection_method": None,
            "details": {"content_type": None, "status_code": None},
        }

    def validate_stream_url(self, url: str, timeout: float = 5) -> bool:
        """Simple boolean check if URL is a valid stream.

        This is a convenience method that wraps check_stream_url() and returns
        only the boolean result for compatibility with CamXploit.py check_stream().

        Args:
            url: The URL to check for stream indicators
            timeout: Request timeout in seconds (default: 5)

        Returns:
            True if stream detected, False otherwise

        Example:
            >>> detector = StreamDetector()
            >>> detector.validate_stream_url("rtsp://camera.local/stream")
            True
            >>> detector.validate_stream_url("http://example.com/index.html")
            False
        """
        result = self.check_stream_url(url, timeout)
        return result["is_stream"]

    def get_stream_details(self, url: str, timeout: float = 5) -> Dict[str, Any]:
        """Get detailed information about a stream URL.

        Analyzes a stream URL to extract comprehensive details including
        content type, codec, resolution, and stream category. Uses HTTP
        HEAD/GET requests for HTTP(S) URLs and URL analysis for streaming
        protocols.

        Based on CamXploit.py check_stream_with_details() (lines 1685-1720).

        Args:
            url: Stream URL to analyze (HTTP, HTTPS, RTSP, RTMP, etc.)
            timeout: Request timeout in seconds (default: 5)

        Returns:
            Dict[str, Any]: Stream details containing:
                - url (str): Original URL
                - content_type (Optional[str]): Content-Type header value or None
                - content_length (str): Content-Length header value or "0"
                - resolution (Optional[Tuple[int, int]]): Resolution as (width, height) or None
                - codec (str): Detected codec string or "unknown"
                - category (str): Stream category (live/recorded/snapshot/unknown)
                - protocol (str): Protocol scheme (http/https/rtsp/rtmp/mms/rtp)
                - is_valid_stream (bool): Whether URL appears to be a valid stream

        Example:
            >>> detector = StreamDetector()
            >>> details = detector.get_stream_details("http://192.168.1.100:80/live/h264")
            >>> print(details['codec'])
            'h264'
            >>> print(details['category'])
            'live'
            >>> print(details['is_valid_stream'])
            True

        Note:
            - For streaming protocols (RTSP, RTMP, MMS, RTP), only URL-based analysis is performed
            - For HTTP(S) URLs, attempts to fetch headers without downloading full stream
            - Returns sensible defaults (None, "unknown", etc.) when data is unavailable
        """
        # Parse URL to extract protocol
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme.lower() if parsed_url.scheme else "unknown"

        # Initialize result dictionary
        result = {
            "url": url,
            "content_type": None,
            "content_length": "0",
            "resolution": None,
            "codec": "unknown",
            "category": "unknown",
            "protocol": protocol,
            "is_valid_stream": False,
        }

        # Detect category from URL (live/snapshot/recorded)
        result["category"] = self._detect_category(url)

        # Detect resolution from URL patterns
        result["resolution"] = self._detect_resolution(url)

        # Detect codec from URL patterns
        detected_codec = self._detect_codec_from_url(url)
        if detected_codec:
            result["codec"] = detected_codec

        # For streaming protocols (RTSP, RTMP, MMS, RTP), use URL-based detection only
        if any(url.lower().startswith(proto) for proto in self.STREAMING_PROTOCOLS):
            result["is_valid_stream"] = True
            return result

        # For HTTP(S) URLs, attempt to fetch headers
        if protocol in ["http", "https"]:
            try:
                # Try HEAD request first (faster, doesn't download content)
                response = requests.head(url, timeout=timeout, verify=False, allow_redirects=True)

                # If HEAD fails or returns 4xx/5xx, try GET with stream=True
                if response.status_code >= 400:
                    response = requests.get(
                        url, timeout=timeout, verify=False, stream=True, allow_redirects=True
                    )
                    # Don't download full stream, close immediately
                    response.close()

                # Extract headers if request was successful
                if response.status_code == 200:
                    result["content_type"] = response.headers.get("Content-Type", None)
                    result["content_length"] = response.headers.get("Content-Length", "0")

                    # Detect codec from content-type if not already detected from URL
                    if result["codec"] == "unknown" and result["content_type"]:
                        codec_from_content = self._detect_codec_from_content_type(
                            result["content_type"]
                        )
                        if codec_from_content:
                            result["codec"] = codec_from_content

                    # Validate if it's a stream based on content-type
                    # (CamXploit.py lines 1694-1696)
                    result["is_valid_stream"] = self._is_valid_stream_content(
                        result["content_type"], url
                    )

            except requests.exceptions.RequestException:
                # Request failed, but URL might still be valid
                # Use URL-based heuristics
                result["is_valid_stream"] = self._is_stream_url(url)

        return result

    def _detect_category(self, url: str) -> str:
        """Detect stream category from URL patterns.

        Categorizes streams as live, snapshot, recorded, or unknown based on
        URL path indicators.

        Args:
            url: Stream URL to categorize

        Returns:
            str: Category (live/snapshot/recorded/unknown)
        """
        url_lower = url.lower()

        # Live stream indicators
        if any(
            indicator in url_lower for indicator in ["/live", "/stream", "/realtime", "/real-time"]
        ):
            return "live"

        # Snapshot indicators
        elif any(
            indicator in url_lower
            for indicator in ["/snapshot", "/image", "/snap", "/picture", "/jpg"]
        ):
            return "snapshot"

        # Recorded indicators
        elif any(
            indicator in url_lower for indicator in ["/playback", "/record", "/replay", "/archive"]
        ):
            return "recorded"

        else:
            return "unknown"

    def _detect_resolution(self, url: str) -> Optional[Tuple[int, int]]:
        """Detect video resolution from URL patterns.

        Searches for resolution indicators in the URL such as "720p", "1080p",
        "4K", or explicit "1920x1080" patterns.

        Args:
            url: Stream URL to analyze

        Returns:
            Optional[Tuple[int, int]]: Resolution as (width, height) or None
        """
        url_lower = url.lower()

        # Check for explicit width x height patterns first (e.g., "1920x1080", "640×480")
        explicit_pattern = re.search(r"(\d{3,4})\s*[x×]\s*(\d{3,4})", url_lower)
        if explicit_pattern:
            width = int(explicit_pattern.group(1))
            height = int(explicit_pattern.group(2))
            # Validate reasonable resolution values (QCIF to 8K)
            if 176 <= width <= 7680 and 144 <= height <= 4320:
                return (width, height)

        # Check for standard resolution patterns (720p, 1080p, 4K, etc.)
        for pattern, resolution in self.RESOLUTION_PATTERNS.items():
            if re.search(pattern, url_lower):
                return resolution

        return None

    def _detect_codec_from_url(self, url: str) -> Optional[str]:
        """Detect video codec from URL patterns.

        Searches for codec indicators in the URL path or query string.

        Args:
            url: Stream URL to analyze

        Returns:
            Optional[str]: Detected codec or None
        """
        url_lower = url.lower()

        for codec, patterns in self.CODEC_PATTERNS.items():
            if any(pattern in url_lower for pattern in patterns):
                return codec

        return None

    def _detect_codec_from_content_type(self, content_type: str) -> Optional[str]:
        """Detect video codec from Content-Type header.

        Parses the Content-Type header to identify the video codec.

        Args:
            content_type: Content-Type header value

        Returns:
            Optional[str]: Detected codec or None
        """
        if not content_type:
            return None

        content_type_lower = content_type.lower()

        for codec, patterns in self.CODEC_PATTERNS.items():
            if any(pattern in content_type_lower for pattern in patterns):
                return codec

        return None

    def _is_valid_stream_content(self, content_type: Optional[str], url: str) -> bool:
        """Check if content type indicates a valid stream.

        Validates whether the content type or URL indicates a valid video
        stream based on CamXploit.py detection logic (lines 1694-1716).

        Args:
            content_type: Content-Type header value
            url: Stream URL

        Returns:
            bool: True if valid stream, False otherwise
        """
        # Check content type (CamXploit.py lines 1694-1696)
        if content_type:
            content_type_lower = content_type.lower()
            if any(indicator in content_type_lower for indicator in self.CONTENT_TYPE_INDICATORS):
                return True

        # Check URL for video file extensions (CamXploit.py lines 1702-1707)
        url_lower = url.lower()
        if any(ext in url_lower for ext in self.VIDEO_EXTENSIONS):
            return True

        # Check URL for stream path indicators (CamXploit.py lines 1712-1716)
        if any(pattern in url_lower for pattern in self.STREAM_PATH_PATTERNS):
            return True

        return False

    def _is_stream_url(self, url: str) -> bool:
        """Check if URL appears to be a stream based on heuristics.

        Uses URL-based heuristics when HTTP requests fail.

        Args:
            url: Stream URL to check

        Returns:
            bool: True if URL appears to be a stream
        """
        url_lower = url.lower()

        # Check for streaming protocols
        if any(url_lower.startswith(proto) for proto in self.STREAMING_PROTOCOLS):
            return True

        # Check for video file extensions
        if any(ext in url_lower for ext in self.VIDEO_EXTENSIONS):
            return True

        # Check for stream path indicators
        if any(pattern in url_lower for pattern in self.STREAM_PATH_PATTERNS):
            return True

        return False
