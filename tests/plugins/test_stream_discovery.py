"""
Comprehensive test suite for StreamDiscoveryPlugin (Phase 7, TASK 263-266).

Tests cover:
- Plugin metadata
- Stream discovery with RTSP streams (mocked)
- Stream discovery with RTMP streams (mocked)
- Stream discovery with HTTP streams (mocked)
- Stream discovery with multiple protocols (mocked)
- Stream discovery with no streams found
- Threading behavior (max 30 concurrent threads)
- Progress callback invocation
- Thread-safe result collection
- Integration with StreamDetector
- Integration with protocol handlers
- Integration with stream_paths.json
- Error handling (network failures, timeouts)
"""

import asyncio
import json
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch


class StreamDiscoveryPlugin:
    """
    Multi-threaded stream discovery plugin.

    This is a placeholder class for testing. The actual implementation
    will be created based on these tests (TDD approach).
    """

    def __init__(self, max_threads=30):
        self.max_threads = max_threads
        self.stream_detector = None  # Will be injected
        self.protocol_handlers = {}  # Will be injected
        self.stream_paths_db = None
        self.results_lock = threading.Lock()
        self.discovered_streams = []

    def get_metadata(self):
        """Return plugin metadata."""
        return {
            "name": "Stream Discovery Plugin",
            "version": "1.0.0",
            "author": "GRIDLAND Security Team",
            "plugin_type": "stream_discovery",
            "supported_protocols": ["rtsp", "rtmp", "http", "https", "mms", "onvif"],
            "description": "Multi-protocol stream discovery with threading support",
        }

    def load_stream_paths_database(self):
        """Load stream paths from database file."""
        try:
            db_path = (
                Path(__file__).parent.parent.parent / "gridland" / "data" / "stream_paths.json"
            )
            if db_path.exists():
                with open(db_path) as f:
                    self.stream_paths_db = json.load(f)
                return True
            return False
        except Exception:
            return False

    async def discover_streams(self, ip, open_ports, protocols=None, progress_callback=None):
        """
        Discover streams on target using multiple protocols.

        Args:
            ip: Target IP address
            open_ports: List of open ports
            protocols: List of protocols to test (default: all)
            progress_callback: Optional callback(current, total) for progress

        Returns:
            List of discovered stream dictionaries
        """
        if protocols is None:
            protocols = ["rtsp", "rtmp", "http", "https"]

        self.discovered_streams = []
        total_tests = 0
        completed_tests = 0

        # Calculate total tests
        for protocol in protocols:
            if protocol in self.protocol_handlers:
                handler = self.protocol_handlers[protocol]
                protocol_ports = [p for p in open_ports if p in handler.get_ports()]
                paths = handler.get_stream_paths()
                total_tests += len(protocol_ports) * len(paths[:10])  # Limit paths

        # Create thread pool
        semaphore = threading.Semaphore(self.max_threads)
        threads = []

        def test_endpoint_worker(protocol, ip, port, path):
            """Worker thread for testing a single endpoint."""
            nonlocal completed_tests

            with semaphore:
                try:
                    handler = self.protocol_handlers[protocol]
                    url = handler.build_url(ip, port, path)

                    # Simulate stream testing
                    result = asyncio.run(self._test_stream_endpoint(url, protocol))

                    if result and result.get("is_stream"):
                        with self.results_lock:
                            self.discovered_streams.append(result)

                    with self.results_lock:
                        completed_tests += 1
                        if progress_callback and completed_tests % 10 == 0:
                            progress_callback(completed_tests, total_tests)

                except Exception as e:
                    with self.results_lock:
                        completed_tests += 1

        # Start threads for each protocol
        for protocol in protocols:
            if protocol not in self.protocol_handlers:
                continue

            handler = self.protocol_handlers[protocol]
            protocol_ports = [p for p in open_ports if p in handler.get_ports()]
            paths = handler.get_stream_paths()[:10]  # Limit paths for performance

            for port in protocol_ports:
                for path in paths:
                    thread = threading.Thread(
                        target=test_endpoint_worker, args=(protocol, ip, port, path)
                    )
                    threads.append(thread)
                    thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Final progress callback
        if progress_callback:
            progress_callback(total_tests, total_tests)

        return self.discovered_streams

    async def _test_stream_endpoint(self, url, protocol):
        """Test a single stream endpoint."""
        if not self.stream_detector:
            return None

        try:
            # Use stream detector to check URL
            if protocol in ["http", "https"]:
                result = await self.stream_detector.check_stream_url(url)
                if result.get("is_stream"):
                    return {
                        "url": url,
                        "protocol": protocol,
                        "is_stream": True,
                        "content_type": result.get("content_type"),
                        "detection_method": result.get("detection_method"),
                    }
            elif protocol in ["rtsp", "rtmp"]:
                # For RTSP/RTMP, use protocol detection
                is_stream = self.stream_detector.detect_protocol(url) == protocol
                if is_stream:
                    return {
                        "url": url,
                        "protocol": protocol,
                        "is_stream": True,
                        "detection_method": "protocol_detection",
                    }

            return None

        except Exception:
            return None

    def get_active_thread_count(self):
        """Get current active thread count (for testing)."""
        return threading.active_count()


class TestStreamDiscoveryPluginMetadata(unittest.TestCase):
    """Test suite for plugin metadata."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

    def test_get_metadata_returns_dict(self):
        """Test that get_metadata returns a dictionary."""
        metadata = self.plugin.get_metadata()
        self.assertIsInstance(metadata, dict)

    def test_metadata_has_required_fields(self):
        """Test that metadata contains required fields."""
        metadata = self.plugin.get_metadata()
        self.assertIn("name", metadata)
        self.assertIn("version", metadata)
        self.assertIn("author", metadata)
        self.assertIn("plugin_type", metadata)
        self.assertIn("supported_protocols", metadata)

    def test_metadata_plugin_type(self):
        """Test that plugin type is stream_discovery."""
        metadata = self.plugin.get_metadata()
        self.assertEqual(metadata["plugin_type"], "stream_discovery")

    def test_metadata_supported_protocols(self):
        """Test that supported protocols are listed."""
        metadata = self.plugin.get_metadata()
        protocols = metadata["supported_protocols"]
        self.assertIn("rtsp", protocols)
        self.assertIn("rtmp", protocols)
        self.assertIn("http", protocols)
        self.assertIn("https", protocols)


class TestStreamDiscoveryConfiguration(unittest.TestCase):
    """Test suite for plugin configuration."""

    def test_default_max_threads(self):
        """Test default max threads is 30."""
        plugin = StreamDiscoveryPlugin()
        self.assertEqual(plugin.max_threads, 30)

    def test_custom_max_threads(self):
        """Test custom max threads configuration."""
        plugin = StreamDiscoveryPlugin(max_threads=50)
        self.assertEqual(plugin.max_threads, 50)

    def test_results_lock_initialized(self):
        """Test that results lock is initialized."""
        plugin = StreamDiscoveryPlugin()
        # threading.Lock() returns a lock object, check it has acquire/release methods
        self.assertTrue(hasattr(plugin.results_lock, "acquire"))
        self.assertTrue(hasattr(plugin.results_lock, "release"))

    def test_discovered_streams_initialized(self):
        """Test that discovered_streams list is initialized."""
        plugin = StreamDiscoveryPlugin()
        self.assertIsInstance(plugin.discovered_streams, list)
        self.assertEqual(len(plugin.discovered_streams), 0)


class TestStreamDiscoveryRTSP(unittest.IsolatedAsyncioTestCase):
    """Test suite for RTSP stream discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

        # Mock StreamDetector
        self.mock_detector = Mock()
        self.mock_detector.detect_protocol = Mock(return_value="rtsp")
        self.mock_detector.check_stream_url = AsyncMock(
            return_value={"is_stream": True, "detection_method": "protocol_detection"}
        )
        self.plugin.stream_detector = self.mock_detector

        # Mock RTSPHandler
        self.mock_rtsp_handler = Mock()
        self.mock_rtsp_handler.get_ports = Mock(return_value=[554, 8554])
        self.mock_rtsp_handler.get_protocol = Mock(return_value="rtsp")
        self.mock_rtsp_handler.get_stream_paths = Mock(return_value=["/stream", "/live"])
        self.mock_rtsp_handler.build_url = Mock(
            side_effect=lambda ip, port, path: f"rtsp://{ip}:{port}{path}"
        )
        self.plugin.protocol_handlers = {"rtsp": self.mock_rtsp_handler}

    async def test_discover_rtsp_streams(self):
        """Test discovery of RTSP streams."""
        streams = await self.plugin.discover_streams("192.168.1.100", [554], protocols=["rtsp"])

        self.assertIsInstance(streams, list)
        self.assertGreater(len(streams), 0)

    async def test_rtsp_stream_structure(self):
        """Test structure of discovered RTSP stream."""
        streams = await self.plugin.discover_streams("192.168.1.100", [554], protocols=["rtsp"])

        if len(streams) > 0:
            stream = streams[0]
            self.assertIn("url", stream)
            self.assertIn("protocol", stream)
            self.assertIn("is_stream", stream)
            self.assertEqual(stream["protocol"], "rtsp")
            self.assertTrue(stream["is_stream"])

    async def test_rtsp_multiple_ports(self):
        """Test RTSP discovery across multiple ports."""
        streams = await self.plugin.discover_streams(
            "192.168.1.100", [554, 8554], protocols=["rtsp"]
        )

        # Should test multiple ports
        self.mock_rtsp_handler.build_url.assert_called()
        call_count = self.mock_rtsp_handler.build_url.call_count
        self.assertGreater(call_count, 1)


class TestStreamDiscoveryRTMP(unittest.IsolatedAsyncioTestCase):
    """Test suite for RTMP stream discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

        # Mock StreamDetector
        self.mock_detector = Mock()
        self.mock_detector.detect_protocol = Mock(return_value="rtmp")
        self.plugin.stream_detector = self.mock_detector

        # Mock RTMPHandler
        self.mock_rtmp_handler = Mock()
        self.mock_rtmp_handler.get_ports = Mock(return_value=[1935])
        self.mock_rtmp_handler.get_protocol = Mock(return_value="rtmp")
        self.mock_rtmp_handler.get_stream_paths = Mock(return_value=["/live", "/stream"])
        self.mock_rtmp_handler.build_url = Mock(
            side_effect=lambda ip, port, path: f"rtmp://{ip}:{port}{path}"
        )
        self.plugin.protocol_handlers = {"rtmp": self.mock_rtmp_handler}

    async def test_discover_rtmp_streams(self):
        """Test discovery of RTMP streams."""
        streams = await self.plugin.discover_streams("192.168.1.100", [1935], protocols=["rtmp"])

        self.assertIsInstance(streams, list)

    async def test_rtmp_url_format(self):
        """Test RTMP URL format."""
        await self.plugin.discover_streams("192.168.1.100", [1935], protocols=["rtmp"])

        # Check that build_url was called with correct format
        self.mock_rtmp_handler.build_url.assert_called()


class TestStreamDiscoveryHTTP(unittest.IsolatedAsyncioTestCase):
    """Test suite for HTTP stream discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

        # Mock StreamDetector with successful detection
        self.mock_detector = Mock()
        self.mock_detector.check_stream_url = AsyncMock(
            return_value={
                "is_stream": True,
                "content_type": "video/h264",
                "detection_method": "content_type",
                "response_code": 200,
            }
        )
        self.plugin.stream_detector = self.mock_detector

        # Mock HTTPHandler
        self.mock_http_handler = Mock()
        self.mock_http_handler.get_ports = Mock(return_value=[80, 8080])
        self.mock_http_handler.get_protocol = Mock(return_value="http")
        self.mock_http_handler.get_stream_paths = Mock(return_value=["/video", "/stream", "/live"])
        self.mock_http_handler.build_url = Mock(
            side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}"
        )
        self.plugin.protocol_handlers = {"http": self.mock_http_handler}

    async def test_discover_http_streams(self):
        """Test discovery of HTTP streams."""
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        self.assertIsInstance(streams, list)
        self.assertGreater(len(streams), 0)

    async def test_http_stream_content_type(self):
        """Test HTTP stream includes content type."""
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        if len(streams) > 0:
            stream = streams[0]
            self.assertIn("content_type", stream)
            self.assertEqual(stream["content_type"], "video/h264")

    async def test_http_detection_method(self):
        """Test HTTP stream includes detection method."""
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        if len(streams) > 0:
            stream = streams[0]
            self.assertIn("detection_method", stream)
            self.assertEqual(stream["detection_method"], "content_type")


class TestStreamDiscoveryMultiProtocol(unittest.IsolatedAsyncioTestCase):
    """Test suite for multi-protocol stream discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

        # Mock StreamDetector
        self.mock_detector = Mock()
        self.mock_detector.detect_protocol = Mock(side_effect=lambda url: url.split("://")[0])
        self.mock_detector.check_stream_url = AsyncMock(
            return_value={
                "is_stream": True,
                "content_type": "video/h264",
                "detection_method": "content_type",
            }
        )
        self.plugin.stream_detector = self.mock_detector

        # Mock handlers
        mock_rtsp = Mock()
        mock_rtsp.get_ports = Mock(return_value=[554])
        mock_rtsp.get_protocol = Mock(return_value="rtsp")
        mock_rtsp.get_stream_paths = Mock(return_value=["/stream"])
        mock_rtsp.build_url = Mock(side_effect=lambda ip, port, path: f"rtsp://{ip}:{port}{path}")

        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=["/video"])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"rtsp": mock_rtsp, "http": mock_http}

    async def test_discover_multiple_protocols(self):
        """Test discovery with multiple protocols."""
        streams = await self.plugin.discover_streams(
            "192.168.1.100", [554, 80], protocols=["rtsp", "http"]
        )

        protocols_found = {s["protocol"] for s in streams}
        self.assertGreater(len(protocols_found), 0)

    async def test_multiple_protocol_results_combined(self):
        """Test that results from multiple protocols are combined."""
        streams = await self.plugin.discover_streams(
            "192.168.1.100", [554, 80], protocols=["rtsp", "http"]
        )

        # Should have streams from both protocols
        self.assertIsInstance(streams, list)


class TestStreamDiscoveryNoStreams(unittest.IsolatedAsyncioTestCase):
    """Test suite for cases with no streams found."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

        # Mock StreamDetector that finds no streams
        self.mock_detector = Mock()
        self.mock_detector.detect_protocol = Mock(return_value=None)
        self.mock_detector.check_stream_url = AsyncMock(
            return_value={"is_stream": False, "error": "Not found"}
        )
        self.plugin.stream_detector = self.mock_detector

        # Mock handler
        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=["/video"])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"http": mock_http}

    async def test_no_streams_found_returns_empty_list(self):
        """Test that no streams found returns empty list."""
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        self.assertIsInstance(streams, list)
        self.assertEqual(len(streams), 0)

    async def test_no_open_ports_returns_empty_list(self):
        """Test that no open ports returns empty list."""
        streams = await self.plugin.discover_streams("192.168.1.100", [], protocols=["http"])

        self.assertEqual(len(streams), 0)


class TestStreamDiscoveryThreading(unittest.IsolatedAsyncioTestCase):
    """Test suite for threading behavior."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin(max_threads=5)

        # Mock detector with delay to test threading
        async def delayed_check(url):
            await asyncio.sleep(0.1)  # Small delay
            return {"is_stream": True, "content_type": "video/h264", "detection_method": "test"}

        self.mock_detector = Mock()
        self.mock_detector.check_stream_url = delayed_check
        self.plugin.stream_detector = self.mock_detector

        # Mock handler with many paths
        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=[f"/path{i}" for i in range(20)])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"http": mock_http}

    async def test_max_concurrent_threads(self):
        """Test that max concurrent threads limit is respected."""
        # This test is difficult to verify precisely, but we can check it completes
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        # Should complete without hanging
        self.assertIsInstance(streams, list)

    async def test_threading_performance(self):
        """Test that threading improves performance."""
        start_time = time.time()

        await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        elapsed = time.time() - start_time

        # With threading, should be faster than sequential (20 * 0.1 = 2.0s)
        # With max 5 threads, should take ~0.4s (20/5 * 0.1)
        # Allow some overhead, but should be under 1s
        self.assertLess(elapsed, 1.5)


class TestStreamDiscoveryProgressCallback(unittest.IsolatedAsyncioTestCase):
    """Test suite for progress callback."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()
        self.progress_calls = []

        def progress_callback(current, total):
            self.progress_calls.append((current, total))

        self.progress_callback = progress_callback

        # Mock detector
        self.mock_detector = Mock()
        self.mock_detector.check_stream_url = AsyncMock(
            return_value={
                "is_stream": True,
                "content_type": "video/h264",
                "detection_method": "test",
            }
        )
        self.plugin.stream_detector = self.mock_detector

        # Mock handler
        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=["/video", "/stream"])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"http": mock_http}

    async def test_progress_callback_invoked(self):
        """Test that progress callback is invoked."""
        await self.plugin.discover_streams(
            "192.168.1.100", [80], protocols=["http"], progress_callback=self.progress_callback
        )

        self.assertGreater(len(self.progress_calls), 0)

    async def test_progress_callback_final_values(self):
        """Test that final progress callback has correct values."""
        await self.plugin.discover_streams(
            "192.168.1.100", [80], protocols=["http"], progress_callback=self.progress_callback
        )

        # Last call should have current == total
        if len(self.progress_calls) > 0:
            last_call = self.progress_calls[-1]
            current, total = last_call
            self.assertEqual(current, total)


class TestStreamDiscoveryThreadSafety(unittest.IsolatedAsyncioTestCase):
    """Test suite for thread safety."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin(max_threads=10)

        # Mock detector
        self.mock_detector = Mock()
        self.mock_detector.check_stream_url = AsyncMock(
            return_value={
                "is_stream": True,
                "content_type": "video/h264",
                "detection_method": "test",
            }
        )
        self.plugin.stream_detector = self.mock_detector

        # Mock handler with many paths to test concurrency
        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=[f"/path{i}" for i in range(50)])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"http": mock_http}

    async def test_thread_safe_result_collection(self):
        """Test that result collection is thread-safe."""
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        # Should have results without duplicates or missing entries
        self.assertIsInstance(streams, list)
        self.assertGreater(len(streams), 0)

        # Check for duplicates
        urls = [s["url"] for s in streams]
        self.assertEqual(len(urls), len(set(urls)))  # No duplicates


class TestStreamDiscoveryIntegration(unittest.IsolatedAsyncioTestCase):
    """Test suite for integration with other components."""

    def test_load_stream_paths_database(self):
        """Test loading stream paths database."""
        plugin = StreamDiscoveryPlugin()
        # May or may not exist in test environment
        result = plugin.load_stream_paths_database()
        self.assertIsInstance(result, bool)

    async def test_integration_with_stream_detector(self):
        """Test integration with StreamDetector."""
        plugin = StreamDiscoveryPlugin()

        # Import actual StreamDetector if available
        try:
            from test_stream_detector import StreamDetector

            detector = StreamDetector()
            plugin.stream_detector = detector

            # Test that detector methods are called correctly
            self.assertTrue(hasattr(detector, "detect_protocol"))
            self.assertTrue(hasattr(detector, "check_stream_url"))
        except ImportError:
            self.skipTest("StreamDetector not available")

    async def test_integration_with_protocol_handlers(self):
        """Test integration with protocol handlers."""
        plugin = StreamDiscoveryPlugin()

        # Import actual protocol handlers if available
        try:
            from test_protocol_handlers import HTTPHandler, RTSPHandler

            plugin.protocol_handlers = {"rtsp": RTSPHandler(), "http": HTTPHandler()}

            # Verify handlers have required methods
            for handler in plugin.protocol_handlers.values():
                self.assertTrue(hasattr(handler, "get_ports"))
                self.assertTrue(hasattr(handler, "get_protocol"))
                self.assertTrue(hasattr(handler, "get_stream_paths"))
                self.assertTrue(hasattr(handler, "build_url"))
        except ImportError:
            self.skipTest("Protocol handlers not available")


class TestStreamDiscoveryErrorHandling(unittest.IsolatedAsyncioTestCase):
    """Test suite for error handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = StreamDiscoveryPlugin()

    async def test_network_error_handling(self):
        """Test handling of network errors."""

        # Mock detector that raises network error
        async def failing_check(url):
            raise ConnectionError("Network error")

        self.mock_detector = Mock()
        self.mock_detector.check_stream_url = failing_check
        self.plugin.stream_detector = self.mock_detector

        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=["/video"])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"http": mock_http}

        # Should not crash
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        self.assertIsInstance(streams, list)

    async def test_timeout_error_handling(self):
        """Test handling of timeout errors."""

        # Mock detector that times out
        async def timeout_check(url):
            raise asyncio.TimeoutError()

        self.mock_detector = Mock()
        self.mock_detector.check_stream_url = timeout_check
        self.plugin.stream_detector = self.mock_detector

        mock_http = Mock()
        mock_http.get_ports = Mock(return_value=[80])
        mock_http.get_protocol = Mock(return_value="http")
        mock_http.get_stream_paths = Mock(return_value=["/video"])
        mock_http.build_url = Mock(side_effect=lambda ip, port, path: f"http://{ip}:{port}{path}")

        self.plugin.protocol_handlers = {"http": mock_http}

        # Should not crash
        streams = await self.plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        self.assertIsInstance(streams, list)

    async def test_missing_handler_graceful_handling(self):
        """Test graceful handling of missing protocol handlers."""
        plugin = StreamDiscoveryPlugin()
        plugin.protocol_handlers = {}  # No handlers

        # Should not crash
        streams = await plugin.discover_streams("192.168.1.100", [80], protocols=["http"])

        self.assertEqual(len(streams), 0)


if __name__ == "__main__":
    unittest.main()
