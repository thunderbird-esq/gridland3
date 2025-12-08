"""
Comprehensive test suite for Protocol Handlers (Phase 7, TASK 262).

Tests cover:
- RTSPHandler, RTMPHandler, HTTPHandler, MMSHandler, ONVIFHandler
- get_ports() method for each handler
- get_protocol() method for each handler
- get_stream_paths() method for each handler
- build_url() method for each handler
- Protocol mapping dictionaries
- Port-to-protocol reverse mapping
- Edge cases (invalid ports, empty paths)
"""

import unittest


class ProtocolHandler:
    """Base class for protocol handlers."""

    def get_ports(self):
        """Get list of common ports for this protocol."""
        raise NotImplementedError

    def get_protocol(self):
        """Get protocol name."""
        raise NotImplementedError

    def get_stream_paths(self, brand=None):
        """Get stream paths for this protocol."""
        raise NotImplementedError

    def build_url(self, ip, port, path, username=None, password=None):
        """Build URL for this protocol."""
        raise NotImplementedError


class RTSPHandler(ProtocolHandler):
    """RTSP protocol handler."""

    def __init__(self):
        self.common_ports = [554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554]

        self.stream_paths = {
            'generic': [
                '/', '/stream', '/stream1', '/stream2', '/live', '/live1',
                '/video', '/video1', '/cam', '/cam1', '/channel1', '/h264'
            ],
            'hikvision': [
                '/Streaming/Channels/1', '/Streaming/Channels/101',
                '/Streaming/Channels/2', '/Streaming/Channels/102',
                '/h264/ch1/main/av_stream', '/h264/ch1/sub/av_stream'
            ],
            'dahua': [
                '/cam/realmonitor?channel=1&subtype=0',
                '/cam/realmonitor?channel=1&subtype=1',
                '/live', '/live1', '/av0_0', '/av0_1'
            ],
            'axis': [
                '/axis-media/media.amp', '/axis-media/media.amp?camera=1',
                '/axis-media/media.amp?videocodec=h264'
            ],
            'onvif': [
                '/onvif/streaming/channels/1', '/onvif/streaming/channels/2',
                '/onvif/media', '/MediaInput/h264'
            ]
        }

    def get_ports(self):
        """Get RTSP ports."""
        return self.common_ports

    def get_protocol(self):
        """Get protocol name."""
        return 'rtsp'

    def get_stream_paths(self, brand=None):
        """Get RTSP stream paths."""
        if brand and brand.lower() in self.stream_paths:
            return self.stream_paths[brand.lower()]
        return self.stream_paths['generic']

    def build_url(self, ip, port, path, username=None, password=None):
        """Build RTSP URL."""
        if username and password:
            return f'rtsp://{username}:{password}@{ip}:{port}{path}'
        elif username:
            return f'rtsp://{username}@{ip}:{port}{path}'
        return f'rtsp://{ip}:{port}{path}'


class RTMPHandler(ProtocolHandler):
    """RTMP protocol handler."""

    def __init__(self):
        self.common_ports = [1935, 1936, 1937, 1938, 1939]

        self.stream_paths = {
            'generic': [
                '/live', '/stream', '/live/stream', '/live/stream1',
                '/live/video', '/rtmp', '/app', '/app/stream'
            ],
            'advanced': [
                '/live/adaptive', '/live/multicast', '/stream/primary',
                '/stream/backup'
            ]
        }

    def get_ports(self):
        """Get RTMP ports."""
        return self.common_ports

    def get_protocol(self):
        """Get protocol name."""
        return 'rtmp'

    def get_stream_paths(self, brand=None):
        """Get RTMP stream paths."""
        paths = self.stream_paths['generic'].copy()
        if brand:
            paths.extend(self.stream_paths.get('advanced', []))
        return paths

    def build_url(self, ip, port, path, username=None, password=None):
        """Build RTMP URL."""
        # RTMP typically doesn't use authentication in URL
        return f'rtmp://{ip}:{port}{path}'


class HTTPHandler(ProtocolHandler):
    """HTTP/HTTPS protocol handler."""

    def __init__(self):
        self.http_ports = [80, 8080, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]
        self.https_ports = [443, 8443, 8444]

        self.stream_paths = {
            'generic': [
                '/video', '/stream', '/live', '/mjpg', '/snapshot',
                '/cgi-bin/mjpg/video.cgi', '/video.cgi', '/videostream.cgi',
                '/mjpg/video.mjpg', '/stream.cgi', '/image.jpg'
            ],
            'api_endpoints': [
                '/api/video', '/api/stream', '/api/live', '/api/camera/stream',
                '/api/media', '/api/v1/video', '/api/v2/stream'
            ],
            'advanced': [
                '/hls/stream.m3u8', '/dash/stream.mpd', '/webrtc/stream',
                '/websocket/stream'
            ]
        }

    def get_ports(self):
        """Get HTTP/HTTPS ports."""
        return self.http_ports + self.https_ports

    def get_protocol(self):
        """Get protocol name."""
        return 'http'

    def get_stream_paths(self, brand=None):
        """Get HTTP stream paths."""
        paths = self.stream_paths['generic'].copy()
        paths.extend(self.stream_paths['api_endpoints'])
        if brand:
            paths.extend(self.stream_paths.get('advanced', []))
        return paths

    def build_url(self, ip, port, path, username=None, password=None):
        """Build HTTP/HTTPS URL."""
        protocol = 'https' if port in self.https_ports else 'http'

        if username and password:
            return f'{protocol}://{username}:{password}@{ip}:{port}{path}'
        elif username:
            return f'{protocol}://{username}@{ip}:{port}{path}'
        return f'{protocol}://{ip}:{port}{path}'


class MMSHandler(ProtocolHandler):
    """MMS (Microsoft Media Server) protocol handler."""

    def __init__(self):
        self.common_ports = [1755, 1024, 7007, 8080]

        self.stream_paths = {
            'generic': [
                '/', '/stream', '/live', '/video', '/broadcast'
            ]
        }

    def get_ports(self):
        """Get MMS ports."""
        return self.common_ports

    def get_protocol(self):
        """Get protocol name."""
        return 'mms'

    def get_stream_paths(self, brand=None):
        """Get MMS stream paths."""
        return self.stream_paths['generic']

    def build_url(self, ip, port, path, username=None, password=None):
        """Build MMS URL."""
        return f'mms://{ip}:{port}{path}'


class ONVIFHandler(ProtocolHandler):
    """ONVIF protocol handler."""

    def __init__(self):
        self.common_ports = [80, 8080, 8000, 8081, 10080]

        self.stream_paths = {
            'generic': [
                '/onvif/device_service', '/onvif/media_service',
                '/onvif-http/snapshot', '/onvif/streaming/channels/1',
                '/onvif/streaming/channels/101', '/onvif/media'
            ]
        }

    def get_ports(self):
        """Get ONVIF ports."""
        return self.common_ports

    def get_protocol(self):
        """Get protocol name."""
        return 'onvif'

    def get_stream_paths(self, brand=None):
        """Get ONVIF stream paths."""
        return self.stream_paths['generic']

    def build_url(self, ip, port, path, username=None, password=None):
        """Build ONVIF URL (uses HTTP)."""
        if username and password:
            return f'http://{username}:{password}@{ip}:{port}{path}'
        return f'http://{ip}:{port}{path}'


class ProtocolMapper:
    """Maps ports to protocols and provides reverse lookups."""

    def __init__(self):
        self.handlers = {
            'rtsp': RTSPHandler(),
            'rtmp': RTMPHandler(),
            'http': HTTPHandler(),
            'mms': MMSHandler(),
            'onvif': ONVIFHandler()
        }

    def get_handler(self, protocol):
        """Get handler for protocol."""
        return self.handlers.get(protocol.lower())

    def get_protocols_for_port(self, port):
        """Get list of protocols that commonly use this port."""
        protocols = []
        for protocol, handler in self.handlers.items():
            if port in handler.get_ports():
                protocols.append(protocol)
        return protocols

    def get_all_port_mappings(self):
        """Get dictionary mapping ports to protocols."""
        port_map = {}
        for protocol, handler in self.handlers.items():
            for port in handler.get_ports():
                if port not in port_map:
                    port_map[port] = []
                port_map[port].append(protocol)
        return port_map


class TestRTSPHandler(unittest.TestCase):
    """Test suite for RTSPHandler."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = RTSPHandler()

    def test_get_ports_returns_rtsp_ports(self):
        """Test that get_ports returns correct RTSP ports."""
        ports = self.handler.get_ports()
        self.assertIn(554, ports)
        self.assertIn(8554, ports)
        self.assertIsInstance(ports, list)
        self.assertGreater(len(ports), 0)

    def test_get_protocol_returns_rtsp(self):
        """Test that get_protocol returns 'rtsp'."""
        self.assertEqual(self.handler.get_protocol(), 'rtsp')

    def test_get_stream_paths_generic(self):
        """Test getting generic RTSP stream paths."""
        paths = self.handler.get_stream_paths()
        self.assertIn('/stream', paths)
        self.assertIn('/live', paths)
        self.assertIsInstance(paths, list)

    def test_get_stream_paths_hikvision(self):
        """Test getting Hikvision-specific RTSP paths."""
        paths = self.handler.get_stream_paths('hikvision')
        self.assertIn('/Streaming/Channels/1', paths)
        self.assertIn('/h264/ch1/main/av_stream', paths)

    def test_get_stream_paths_dahua(self):
        """Test getting Dahua-specific RTSP paths."""
        paths = self.handler.get_stream_paths('dahua')
        self.assertIn('/cam/realmonitor?channel=1&subtype=0', paths)

    def test_build_url_without_auth(self):
        """Test building RTSP URL without authentication."""
        url = self.handler.build_url('192.168.1.100', 554, '/stream')
        self.assertEqual(url, 'rtsp://192.168.1.100:554/stream')

    def test_build_url_with_auth(self):
        """Test building RTSP URL with authentication."""
        url = self.handler.build_url('192.168.1.100', 554, '/stream', 'admin', 'password')
        self.assertEqual(url, 'rtsp://admin:password@192.168.1.100:554/stream')

    def test_build_url_with_username_only(self):
        """Test building RTSP URL with username only."""
        url = self.handler.build_url('192.168.1.100', 554, '/stream', username='admin')
        self.assertEqual(url, 'rtsp://admin@192.168.1.100:554/stream')


class TestRTMPHandler(unittest.TestCase):
    """Test suite for RTMPHandler."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = RTMPHandler()

    def test_get_ports_returns_rtmp_ports(self):
        """Test that get_ports returns correct RTMP ports."""
        ports = self.handler.get_ports()
        self.assertIn(1935, ports)
        self.assertIsInstance(ports, list)

    def test_get_protocol_returns_rtmp(self):
        """Test that get_protocol returns 'rtmp'."""
        self.assertEqual(self.handler.get_protocol(), 'rtmp')

    def test_get_stream_paths(self):
        """Test getting RTMP stream paths."""
        paths = self.handler.get_stream_paths()
        self.assertIn('/live', paths)
        self.assertIn('/stream', paths)

    def test_build_url(self):
        """Test building RTMP URL."""
        url = self.handler.build_url('192.168.1.100', 1935, '/live/stream')
        self.assertEqual(url, 'rtmp://192.168.1.100:1935/live/stream')


class TestHTTPHandler(unittest.TestCase):
    """Test suite for HTTPHandler."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = HTTPHandler()

    def test_get_ports_includes_http_and_https(self):
        """Test that get_ports includes both HTTP and HTTPS ports."""
        ports = self.handler.get_ports()
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(8080, ports)
        self.assertIn(8443, ports)

    def test_get_protocol_returns_http(self):
        """Test that get_protocol returns 'http'."""
        self.assertEqual(self.handler.get_protocol(), 'http')

    def test_get_stream_paths(self):
        """Test getting HTTP stream paths."""
        paths = self.handler.get_stream_paths()
        self.assertIn('/video', paths)
        self.assertIn('/stream', paths)
        self.assertIn('/api/video', paths)

    def test_build_url_http(self):
        """Test building HTTP URL."""
        url = self.handler.build_url('192.168.1.100', 80, '/stream')
        self.assertEqual(url, 'http://192.168.1.100:80/stream')

    def test_build_url_https(self):
        """Test building HTTPS URL."""
        url = self.handler.build_url('192.168.1.100', 443, '/stream')
        self.assertEqual(url, 'https://192.168.1.100:443/stream')

    def test_build_url_with_auth(self):
        """Test building HTTP URL with authentication."""
        url = self.handler.build_url('192.168.1.100', 80, '/stream', 'admin', 'pass')
        self.assertEqual(url, 'http://admin:pass@192.168.1.100:80/stream')


class TestMMSHandler(unittest.TestCase):
    """Test suite for MMSHandler."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = MMSHandler()

    def test_get_ports_returns_mms_ports(self):
        """Test that get_ports returns correct MMS ports."""
        ports = self.handler.get_ports()
        self.assertIn(1755, ports)
        self.assertIsInstance(ports, list)

    def test_get_protocol_returns_mms(self):
        """Test that get_protocol returns 'mms'."""
        self.assertEqual(self.handler.get_protocol(), 'mms')

    def test_get_stream_paths(self):
        """Test getting MMS stream paths."""
        paths = self.handler.get_stream_paths()
        self.assertIn('/', paths)
        self.assertIn('/stream', paths)

    def test_build_url(self):
        """Test building MMS URL."""
        url = self.handler.build_url('192.168.1.100', 1755, '/stream')
        self.assertEqual(url, 'mms://192.168.1.100:1755/stream')


class TestONVIFHandler(unittest.TestCase):
    """Test suite for ONVIFHandler."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = ONVIFHandler()

    def test_get_ports_returns_onvif_ports(self):
        """Test that get_ports returns correct ONVIF ports."""
        ports = self.handler.get_ports()
        self.assertIn(80, ports)
        self.assertIn(8080, ports)
        self.assertIsInstance(ports, list)

    def test_get_protocol_returns_onvif(self):
        """Test that get_protocol returns 'onvif'."""
        self.assertEqual(self.handler.get_protocol(), 'onvif')

    def test_get_stream_paths(self):
        """Test getting ONVIF stream paths."""
        paths = self.handler.get_stream_paths()
        self.assertIn('/onvif/device_service', paths)
        self.assertIn('/onvif/media_service', paths)

    def test_build_url_without_auth(self):
        """Test building ONVIF URL without authentication."""
        url = self.handler.build_url('192.168.1.100', 80, '/onvif/device_service')
        self.assertEqual(url, 'http://192.168.1.100:80/onvif/device_service')

    def test_build_url_with_auth(self):
        """Test building ONVIF URL with authentication."""
        url = self.handler.build_url('192.168.1.100', 80, '/onvif/device_service', 'admin', 'pass')
        self.assertEqual(url, 'http://admin:pass@192.168.1.100:80/onvif/device_service')


class TestProtocolMapper(unittest.TestCase):
    """Test suite for ProtocolMapper."""

    def setUp(self):
        """Set up test fixtures."""
        self.mapper = ProtocolMapper()

    def test_get_handler_rtsp(self):
        """Test getting RTSP handler."""
        handler = self.mapper.get_handler('rtsp')
        self.assertIsInstance(handler, RTSPHandler)
        self.assertEqual(handler.get_protocol(), 'rtsp')

    def test_get_handler_case_insensitive(self):
        """Test that get_handler is case-insensitive."""
        handler1 = self.mapper.get_handler('RTSP')
        handler2 = self.mapper.get_handler('rtsp')
        self.assertEqual(handler1.get_protocol(), handler2.get_protocol())

    def test_get_protocols_for_port_554(self):
        """Test getting protocols for RTSP port 554."""
        protocols = self.mapper.get_protocols_for_port(554)
        self.assertIn('rtsp', protocols)

    def test_get_protocols_for_port_80(self):
        """Test getting protocols for port 80 (multiple protocols)."""
        protocols = self.mapper.get_protocols_for_port(80)
        self.assertIn('http', protocols)
        self.assertIn('onvif', protocols)

    def test_get_protocols_for_port_1935(self):
        """Test getting protocols for RTMP port 1935."""
        protocols = self.mapper.get_protocols_for_port(1935)
        self.assertIn('rtmp', protocols)

    def test_get_all_port_mappings(self):
        """Test getting all port-to-protocol mappings."""
        port_map = self.mapper.get_all_port_mappings()
        self.assertIsInstance(port_map, dict)
        self.assertIn(554, port_map)
        self.assertIn(1935, port_map)
        self.assertIn('rtsp', port_map[554])

    def test_get_protocols_for_invalid_port(self):
        """Test getting protocols for invalid/unused port."""
        protocols = self.mapper.get_protocols_for_port(99999)
        self.assertEqual(protocols, [])

    def test_edge_case_empty_path(self):
        """Test building URL with empty path."""
        handler = RTSPHandler()
        url = handler.build_url('192.168.1.100', 554, '')
        self.assertEqual(url, 'rtsp://192.168.1.100:554')

    def test_edge_case_invalid_port_type(self):
        """Test that handlers work with string ports."""
        handler = RTSPHandler()
        # Should work with string port numbers
        url = handler.build_url('192.168.1.100', '554', '/stream')
        self.assertIn('554', url)


if __name__ == '__main__':
    unittest.main()
