"""Protocol Handlers module for GRIDLAND Stream Discovery.

This module provides protocol-specific handlers for camera stream detection,
including RTSP, RTMP, HTTP/HTTPS, MMS, and ONVIF protocols. Each handler
manages port lists, URL construction, and stream path enumeration.

Ported from CamXploit.py lines 1568-1683 for 100% feature parity.
"""

from typing import Dict, List, Optional


class RTSPHandler:
    """Handler for RTSP (Real Time Streaming Protocol) streams.

    RTSP is the primary protocol for IP camera streaming, typically running
    on port 554 but may use alternative ports (8554, 10554, etc.). This
    handler provides RTSP-specific URL construction and path enumeration.

    Example:
        >>> ports = RTSPHandler.get_ports()
        >>> print(ports)
        [554, 8554, 10554]
        >>> url = RTSPHandler.build_url("192.168.1.100", 554, "/live.sdp")
        >>> print(url)
        rtsp://192.168.1.100:554/live.sdp
        >>> paths = RTSPHandler.get_stream_paths()
        >>> print(len(paths))
        36
    """

    # Default RTSP ports from CamXploit.py line 1569
    PORTS = [554, 8554, 10554]

    # RTSP stream paths from CamXploit.py lines 1580-1617
    STREAM_PATHS = [
        # Generic paths
        "/live.sdp",
        "/h264.sdp",
        "/stream1",
        "/stream2",
        "/main",
        "/sub",
        "/video",
        "/cam/realmonitor",
        "/Streaming/Channels/1",
        "/Streaming/Channels/101",
        # ONVIF paths
        "/onvif/streaming/channels/1",
        "/live/0/onvif.sdp",
        "/live/1/onvif.sdp",
        # Brand-specific paths
        "/axis-media/media.amp",
        "/axis-cgi/mjpg/video.cgi",
        "/cgi-bin/mjpg/video.cgi",
        "/cgi-bin/hi3510/snap.cgi",
        "/cgi-bin/snapshot.cgi",
        "/cgi-bin/viewer/video.jpg",
        "/img/snapshot.cgi",
        "/snapshot.jpg",
        "/video/mjpg.cgi",
        "/video.cgi",
        "/videostream.cgi",
        "/mjpg/video.mjpg",
        "/mjpg.cgi",
        "/stream.cgi",
        "/live.cgi",
        # Live stream variants
        "/live/0/h264.sdp",
        "/live/0/mpeg4.sdp",
        "/live/0/audio.sdp",
        "/live/1/h264.sdp",
        "/live/1/mpeg4.sdp",
        "/live/1/audio.sdp",
    ]

    @staticmethod
    def get_ports() -> List[int]:
        """Get list of default RTSP ports.

        Returns:
            List of RTSP port numbers (554, 8554, 10554).
        """
        return RTSPHandler.PORTS.copy()

    @staticmethod
    def get_protocol() -> str:
        """Get protocol identifier string.

        Returns:
            Protocol string: "rtsp".
        """
        return "rtsp"

    @staticmethod
    def get_stream_paths() -> List[str]:
        """Get list of common RTSP stream paths.

        Returns:
            List of RTSP stream paths for enumeration.
        """
        return RTSPHandler.STREAM_PATHS.copy()

    @staticmethod
    def build_url(ip: str, port: int, path: str) -> str:
        """Build full RTSP URL from components.

        Args:
            ip: Target IP address or hostname.
            port: Target port number.
            path: Stream path (must start with '/').

        Returns:
            Full RTSP URL string (e.g., "rtsp://192.168.1.100:554/live.sdp").

        Example:
            >>> RTSPHandler.build_url("192.168.1.100", 554, "/live.sdp")
            'rtsp://192.168.1.100:554/live.sdp'
        """
        if not path.startswith('/'):
            path = '/' + path
        return f"rtsp://{ip}:{port}{path}"


class RTMPHandler:
    """Handler for RTMP (Real Time Messaging Protocol) streams.

    RTMP is commonly used for streaming media servers and some IP cameras,
    typically running on port 1935. This handler provides RTMP-specific URL
    construction and path enumeration.

    Example:
        >>> ports = RTMPHandler.get_ports()
        >>> print(ports)
        [1935, 1936]
        >>> url = RTMPHandler.build_url("192.168.1.100", 1935, "/live")
        >>> print(url)
        rtmp://192.168.1.100:1935/live
    """

    # Default RTMP ports from CamXploit.py line 1570
    PORTS = [1935, 1936]

    # RTMP stream paths from CamXploit.py lines 1618-1634
    STREAM_PATHS = [
        "/live",
        "/stream",
        "/hls",
        "/flv",
        "/rtmp",
        "/live/stream",
        "/live/stream1",
        "/live/stream2",
        "/live/main",
        "/live/sub",
        "/live/video",
        "/live/audio",
        "/live/av",
        "/live/rtmp",
        "/live/rtmps",
    ]

    @staticmethod
    def get_ports() -> List[int]:
        """Get list of default RTMP ports.

        Returns:
            List of RTMP port numbers (1935, 1936).
        """
        return RTMPHandler.PORTS.copy()

    @staticmethod
    def get_protocol() -> str:
        """Get protocol identifier string.

        Returns:
            Protocol string: "rtmp".
        """
        return "rtmp"

    @staticmethod
    def get_stream_paths() -> List[str]:
        """Get list of common RTMP stream paths.

        Returns:
            List of RTMP stream paths for enumeration.
        """
        return RTMPHandler.STREAM_PATHS.copy()

    @staticmethod
    def build_url(ip: str, port: int, path: str) -> str:
        """Build full RTMP URL from components.

        Args:
            ip: Target IP address or hostname.
            port: Target port number.
            path: Stream path (must start with '/').

        Returns:
            Full RTMP URL string (e.g., "rtmp://192.168.1.100:1935/live").

        Example:
            >>> RTMPHandler.build_url("192.168.1.100", 1935, "/live")
            'rtmp://192.168.1.100:1935/live'
        """
        if not path.startswith('/'):
            path = '/' + path
        return f"rtmp://{ip}:{port}{path}"


class HTTPHandler:
    """Handler for HTTP/HTTPS camera streams and snapshots.

    HTTP/HTTPS are commonly used for camera web interfaces, MJPEG streams,
    and snapshot APIs. This handler manages both HTTP and HTTPS protocols
    with automatic protocol selection based on port number.

    Example:
        >>> ports = HTTPHandler.get_ports()
        >>> print(ports)
        [80, 8080, 8000, 8001, 443, 8443, 8444]
        >>> url = HTTPHandler.build_url("192.168.1.100", 443, "/snapshot.jpg")
        >>> print(url)
        https://192.168.1.100:443/snapshot.jpg
        >>> url = HTTPHandler.build_url("192.168.1.100", 80, "/mjpg/video.mjpg")
        >>> print(url)
        http://192.168.1.100:80/mjpg/video.mjpg
    """

    # Default HTTP/HTTPS ports from CamXploit.py lines 1571-1572
    HTTP_PORTS = [80, 8080, 8000, 8001]
    HTTPS_PORTS = [443, 8443, 8444]
    PORTS = HTTP_PORTS + HTTPS_PORTS

    # HTTP stream paths from CamXploit.py lines 1635-1682
    STREAM_PATHS = [
        # Generic paths
        "/video",
        "/stream",
        "/mjpg/video.mjpg",
        "/cgi-bin/mjpg/video.cgi",
        "/axis-cgi/mjpg/video.cgi",
        "/cgi-bin/viewer/video.jpg",
        "/snapshot.jpg",
        "/img/snapshot.cgi",
        # ONVIF paths
        "/onvif/device_service",
        "/onvif/streaming",
        # Brand-specific CGI paths
        "/axis-cgi/com/ptz.cgi",
        "/axis-cgi/param.cgi",
        "/cgi-bin/snapshot.cgi",
        "/cgi-bin/hi3510/snap.cgi",
        "/cgi-bin/viewer/video.jpg",
        "/video/mjpg.cgi",
        "/video.cgi",
        "/videostream.cgi",
        "/mjpg.cgi",
        "/stream.cgi",
        "/live.cgi",
        # API endpoints
        "/api/video",
        "/api/stream",
        "/api/live",
        "/api/video/live",
        "/api/stream/live",
        "/api/camera/live",
        "/api/camera/stream",
        "/api/camera/video",
        "/api/camera/snapshot",
        "/api/camera/image",
        "/api/camera/feed",
        "/api/camera/feed/live",
        "/api/camera/feed/stream",
        "/api/camera/feed/video",
        # CP Plus specific paths
        "/cgi-bin/video.cgi",
        "/cgi-bin/stream.cgi",
        "/cgi-bin/live.cgi",
    ]

    @staticmethod
    def get_ports() -> List[int]:
        """Get list of default HTTP/HTTPS ports.

        Returns:
            List of HTTP/HTTPS port numbers.
        """
        return HTTPHandler.PORTS.copy()

    @staticmethod
    def get_protocol() -> str:
        """Get protocol identifier string.

        Returns:
            Protocol string: "http" (protocol auto-selected in build_url).
        """
        return "http"

    @staticmethod
    def get_stream_paths() -> List[str]:
        """Get list of common HTTP/HTTPS stream paths.

        Returns:
            List of HTTP stream paths for enumeration.
        """
        return HTTPHandler.STREAM_PATHS.copy()

    @staticmethod
    def build_url(ip: str, port: int, path: str) -> str:
        """Build full HTTP/HTTPS URL from components.

        Automatically selects HTTPS for secure ports (443, 8443, 8444) and
        HTTP for standard ports (80, 8080, 8000, 8001).

        Args:
            ip: Target IP address or hostname.
            port: Target port number.
            path: Stream path (must start with '/').

        Returns:
            Full HTTP/HTTPS URL string.

        Example:
            >>> HTTPHandler.build_url("192.168.1.100", 443, "/snapshot.jpg")
            'https://192.168.1.100:443/snapshot.jpg'
            >>> HTTPHandler.build_url("192.168.1.100", 80, "/video.cgi")
            'http://192.168.1.100:80/video.cgi'
        """
        if not path.startswith('/'):
            path = '/' + path

        # Auto-select protocol based on port
        protocol = "https" if port in HTTPHandler.HTTPS_PORTS else "http"
        return f"{protocol}://{ip}:{port}{path}"


class MMSHandler:
    """Handler for MMS (Microsoft Media Server) streams.

    MMS is a legacy protocol used by some older IP cameras and Windows Media
    servers, typically running on port 1755. This handler provides MMS-specific
    URL construction.

    Example:
        >>> ports = MMSHandler.get_ports()
        >>> print(ports)
        [1755]
        >>> url = MMSHandler.build_url("192.168.1.100", 1755, "/stream")
        >>> print(url)
        mms://192.168.1.100:1755/stream
    """

    # Default MMS port from CamXploit.py line 1573
    PORTS = [1755]

    # MMS typically uses generic paths
    STREAM_PATHS = [
        "/",
        "/stream",
        "/video",
        "/live",
    ]

    @staticmethod
    def get_ports() -> List[int]:
        """Get list of default MMS ports.

        Returns:
            List of MMS port numbers (1755).
        """
        return MMSHandler.PORTS.copy()

    @staticmethod
    def get_protocol() -> str:
        """Get protocol identifier string.

        Returns:
            Protocol string: "mms".
        """
        return "mms"

    @staticmethod
    def get_stream_paths() -> List[str]:
        """Get list of common MMS stream paths.

        Returns:
            List of MMS stream paths for enumeration.
        """
        return MMSHandler.STREAM_PATHS.copy()

    @staticmethod
    def build_url(ip: str, port: int, path: str) -> str:
        """Build full MMS URL from components.

        Args:
            ip: Target IP address or hostname.
            port: Target port number.
            path: Stream path (must start with '/').

        Returns:
            Full MMS URL string (e.g., "mms://192.168.1.100:1755/stream").

        Example:
            >>> MMSHandler.build_url("192.168.1.100", 1755, "/stream")
            'mms://192.168.1.100:1755/stream'
        """
        if not path.startswith('/'):
            path = '/' + path
        return f"mms://{ip}:{port}{path}"


class ONVIFHandler:
    """Handler for ONVIF (Open Network Video Interface Forum) protocol.

    ONVIF is a standardized protocol for IP cameras, typically using HTTP/HTTPS
    on ports 80, 443, or dedicated port 3702 for WS-Discovery. This handler
    provides ONVIF-specific endpoint enumeration.

    Example:
        >>> ports = ONVIFHandler.get_ports()
        >>> print(ports)
        [3702, 80, 443]
        >>> url = ONVIFHandler.build_url("192.168.1.100", 80, "/onvif/device_service")
        >>> print(url)
        http://192.168.1.100:80/onvif/device_service
    """

    # Default ONVIF ports from CamXploit.py line 1574
    PORTS = [3702, 80, 443]

    # ONVIF-specific paths
    STREAM_PATHS = [
        "/onvif/device_service",
        "/onvif/streaming",
        "/onvif/media",
        "/onvif/ptz",
        "/onvif/events",
        "/onvif/imaging",
        "/onvif/analytics",
    ]

    @staticmethod
    def get_ports() -> List[int]:
        """Get list of default ONVIF ports.

        Returns:
            List of ONVIF port numbers (3702, 80, 443).
        """
        return ONVIFHandler.PORTS.copy()

    @staticmethod
    def get_protocol() -> str:
        """Get protocol identifier string.

        Returns:
            Protocol string: "onvif".
        """
        return "onvif"

    @staticmethod
    def get_stream_paths() -> List[str]:
        """Get list of ONVIF service endpoints.

        Returns:
            List of ONVIF endpoint paths for enumeration.
        """
        return ONVIFHandler.STREAM_PATHS.copy()

    @staticmethod
    def build_url(ip: str, port: int, path: str) -> str:
        """Build full ONVIF URL from components.

        ONVIF uses HTTP/HTTPS transport. Auto-selects HTTPS for port 443,
        HTTP for other ports.

        Args:
            ip: Target IP address or hostname.
            port: Target port number.
            path: ONVIF service path (must start with '/').

        Returns:
            Full ONVIF URL string (HTTP/HTTPS based on port).

        Example:
            >>> ONVIFHandler.build_url("192.168.1.100", 80, "/onvif/device_service")
            'http://192.168.1.100:80/onvif/device_service'
            >>> ONVIFHandler.build_url("192.168.1.100", 443, "/onvif/streaming")
            'https://192.168.1.100:443/onvif/streaming'
        """
        if not path.startswith('/'):
            path = '/' + path

        # Auto-select protocol based on port
        protocol = "https" if port == 443 else "http"
        return f"{protocol}://{ip}:{port}{path}"


# Protocol-to-ports mapping (from CamXploit.py lines 1568-1576)
PROTOCOL_PORT_MAP: Dict[str, List[int]] = {
    "rtsp": RTSPHandler.PORTS,
    "rtmp": RTMPHandler.PORTS,
    "http": HTTPHandler.HTTP_PORTS,
    "https": HTTPHandler.HTTPS_PORTS,
    "mms": MMSHandler.PORTS,
    "onvif": ONVIFHandler.PORTS,
}

# Reverse mapping: port-to-protocol(s)
# Note: Some ports may support multiple protocols (e.g., 80 for HTTP and ONVIF)
PORT_PROTOCOL_MAP: Dict[int, List[str]] = {}
for protocol, ports in PROTOCOL_PORT_MAP.items():
    for port in ports:
        if port not in PORT_PROTOCOL_MAP:
            PORT_PROTOCOL_MAP[port] = []
        PORT_PROTOCOL_MAP[port].append(protocol)


def get_handler_for_protocol(protocol: str) -> Optional[type]:
    """Get handler class for specified protocol.

    Args:
        protocol: Protocol name (rtsp, rtmp, http, https, mms, onvif).

    Returns:
        Handler class or None if protocol not found.

    Example:
        >>> handler = get_handler_for_protocol("rtsp")
        >>> print(handler.get_protocol())
        rtsp
    """
    protocol = protocol.lower()
    handlers = {
        "rtsp": RTSPHandler,
        "rtmp": RTMPHandler,
        "http": HTTPHandler,
        "https": HTTPHandler,  # HTTPHandler handles both
        "mms": MMSHandler,
        "onvif": ONVIFHandler,
    }
    return handlers.get(protocol)


def get_handler_for_port(port: int) -> Optional[type]:
    """Get primary handler class for specified port.

    For ports that support multiple protocols, returns the most common
    handler (e.g., RTSP for 554, HTTP for 80).

    Args:
        port: Port number.

    Returns:
        Handler class or None if port not recognized.

    Example:
        >>> handler = get_handler_for_port(554)
        >>> print(handler.get_protocol())
        rtsp
        >>> handler = get_handler_for_port(80)
        >>> print(handler.get_protocol())
        http
    """
    # Primary protocol mappings for common ports
    primary_mappings = {
        554: RTSPHandler,
        8554: RTSPHandler,
        10554: RTSPHandler,
        1935: RTMPHandler,
        1936: RTMPHandler,
        80: HTTPHandler,
        8080: HTTPHandler,
        8000: HTTPHandler,
        8001: HTTPHandler,
        443: HTTPHandler,
        8443: HTTPHandler,
        8444: HTTPHandler,
        1755: MMSHandler,
        3702: ONVIFHandler,
    }
    return primary_mappings.get(port)


def get_all_handlers() -> List[type]:
    """Get list of all available protocol handlers.

    Returns:
        List of handler classes.

    Example:
        >>> handlers = get_all_handlers()
        >>> print(len(handlers))
        5
        >>> protocols = [h.get_protocol() for h in handlers]
        >>> print(protocols)
        ['rtsp', 'rtmp', 'http', 'mms', 'onvif']
    """
    return [
        RTSPHandler,
        RTMPHandler,
        HTTPHandler,
        MMSHandler,
        ONVIFHandler,
    ]
