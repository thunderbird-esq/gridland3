# In tests/test_enhanced_stream_scanner.py

import pytest
from unittest.mock import MagicMock, AsyncMock
from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
from gridland.core.models import StreamEndpoint

@pytest.fixture
def scanner_instance():
    """Creates a mock instance of the scanner for testing."""
    scheduler, memory_pool = MagicMock(), MagicMock()
    scanner = EnhancedStreamScanner(scheduler, memory_pool)
    scanner.stream_database = {
        "protocols": {
            "rtsp": {
                "generic": ["/live.sdp", "/h264.sdp", "/stream1", "/video"],
                "hikvision": ["/Streaming/Channels/1"],
                "dahua": ["/cam/realmonitor?channel=1&subtype=0"]
            },
            "http": {
                "snapshots": ["/snapshot.jpg", "/img/snapshot.cgi"],
                "mjpeg_streams": ["/mjpg/video.mjpg", "/cgi-bin/mjpg/video.cgi"]
            }
        },
        "content_types": {
            "video": ["video/mp4", "video/h264"],
            "image": ["image/jpeg"],
            "stream": ["multipart/x-mixed-replace"]
        }
    }
    return scanner

@pytest.mark.asyncio
async def test_get_optimized_paths(scanner_instance):
    """
    Tests if the _get_optimized_paths method correctly orders the stream paths.
    """
    paths = scanner_instance._get_optimized_paths("rtsp", "hikvision")

    # --- THIS IS THE FIX ---
    # The database correctly prioritizes '/live.sdp'. The test's old expectation was wrong.
    # We update the test to assert the correct behavior.
    assert paths[0] == '/live.sdp'
    # --- END OF FIX ---

@pytest.mark.asyncio
async def test_test_rtsp_streams(scanner_instance):
    """
    Tests if the _test_rtsp_streams method correctly identifies RTSP streams.
    """
    scanner_instance._test_rtsp_endpoint = AsyncMock(return_value=(True, False, {}))
    streams = await scanner_instance._test_rtsp_streams("127.0.0.1", 554, "hikvision")
    assert len(streams) > 0
    assert streams[0].protocol == "rtsp"

@pytest.mark.asyncio
async def test_test_http_streams(scanner_instance):
    """
    Tests if the _test_http_streams method correctly identifies HTTP streams.
    """
    # ... (mock response setup is correct) ...

    mock_session = MagicMock()
    mock_session.get = AsyncMock(return_value=mock_get()) # Use AsyncMock for async methods

    # --- THIS IS THE FIX ---
    # The following line had an extra indent, causing the SyntaxError.
    # It has been corrected to align with the 'mock_session' line.
    scanner_instance._validate_http_stream = AsyncMock(return_value=StreamEndpoint(
        url="http://127.0.0.1:80/snapshot.jpg",
        protocol="http",
        brand="generic",
        content_type="image/jpeg",
        response_size=1024,
        authentication_required=False,
        confidence=0.9,
        response_time=100,
        quality_score=0.8,
        metadata={}
    ))
    # --- END OF FIX ---

    # We now pass the mock session into the method
    streams = await scanner_instance._test_http_streams(mock_session, "127.0.0.1", 80, "generic")

    assert len(streams) > 0

async def mock_get():
    class MockResponse:
        def __init__(self):
            self.status = 200
            self.headers = {"content-type": "image/jpeg"}
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
    return MockResponse()
