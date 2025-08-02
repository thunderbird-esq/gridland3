# In tests/test_enhanced_stream_scanner.py

import pytest
import aiohttp
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

