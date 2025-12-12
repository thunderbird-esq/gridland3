"""Stream detection and analysis module for GRIDLAND.

This module provides stream URL detection, validation, and analysis capabilities
for camera reconnaissance. Implements multi-phase detection strategies including
content-type validation, URL pattern matching, protocol detection, and response
content analysis.

Classes:
    StreamDetector: Main stream detection and validation class
    RTSPHandler: RTSP protocol handler
    RTMPHandler: RTMP protocol handler
    HTTPHandler: HTTP/HTTPS protocol handler
    MMSHandler: MMS protocol handler
    ONVIFHandler: ONVIF protocol handler

Example:
    >>> from gridland.analyze.core.stream import StreamDetector, RTSPHandler
    >>> detector = StreamDetector()
    >>> result = detector.check_stream_url("http://camera.local/video.mp4")
    >>> if result['is_stream']:
    ...     print(f"Stream detected: {result['detection_method']}")
    >>>
    >>> # Using protocol handlers
    >>> rtsp_ports = RTSPHandler.get_ports()
    >>> url = RTSPHandler.build_url("192.168.1.100", 554, "/live.sdp")
"""

from gridland.analyze.core.stream.protocol_handlers import (
    PORT_PROTOCOL_MAP,
    PROTOCOL_PORT_MAP,
    HTTPHandler,
    MMSHandler,
    ONVIFHandler,
    RTMPHandler,
    RTSPHandler,
    get_all_handlers,
    get_handler_for_port,
    get_handler_for_protocol,
)
from gridland.analyze.core.stream.stream_detector import StreamDetector

__all__ = [
    "StreamDetector",
    "RTSPHandler",
    "RTMPHandler",
    "HTTPHandler",
    "MMSHandler",
    "ONVIFHandler",
    "PROTOCOL_PORT_MAP",
    "PORT_PROTOCOL_MAP",
    "get_handler_for_protocol",
    "get_handler_for_port",
    "get_all_handlers",
]
