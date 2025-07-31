import pytest
import asyncio
from unittest.mock import patch, MagicMock
import ffmpeg

from gridland.analyze.plugins.builtin.rtsp_stream_scanner import RTSPStreamScanner
from gridland.core.config import get_config

@pytest.fixture
def scanner():
    """Provides a fresh scanner instance for each test."""
    return RTSPStreamScanner()

@pytest.mark.asyncio
@patch('ffmpeg.run')
async def test_capture_stream_clip_success(mock_ffmpeg_run, scanner):
    """
    Test that _capture_stream_clip successfully calls ffmpeg and returns a path.
    """
    # --- Arrange ---
    test_url = "rtsp://test:test@1.2.3.4:554/stream1"
    target_ip = "1.2.3.4"
    target_port = 554

    # --- Act ---
    result_path = await scanner._capture_stream_clip(test_url, target_ip, target_port)

    # --- Assert ---
    mock_ffmpeg_run.assert_called_once()
    assert result_path is not None
    assert "recordings" in result_path
    assert f"{target_ip.replace('.', '_')}_{target_port}" in result_path
    assert result_path.endswith('.mp4')

@pytest.mark.asyncio
@patch('ffmpeg.run')
async def test_capture_stream_clip_failure(mock_ffmpeg_run, scanner):
    """
    Test that _capture_stream_clip handles ffmpeg errors gracefully.
    """
    # --- Arrange ---
    test_url = "rtsp://invalid.stream"
    target_ip = "1.1.1.1"
    target_port = 554

    # Configure the mock to raise an ffmpeg.Error when called
    mock_ffmpeg_run.side_effect = ffmpeg.Error('ffmpeg', stdout=None, stderr=b'Invalid data')

    # --- Act ---
    result_path = await scanner._capture_stream_clip(test_url, target_ip, target_port)

    # --- Assert ---
    mock_ffmpeg_run.assert_called_once()
    assert result_path is None # Should return None on failure
