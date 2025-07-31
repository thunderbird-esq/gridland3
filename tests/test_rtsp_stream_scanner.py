import pytest
from unittest.mock import patch, MagicMock
import ffmpeg

from gridland.analyze.plugins.builtin.rtsp_stream_scanner import RTSPStreamScanner

@pytest.fixture
def scanner():
    return RTSPStreamScanner()

@pytest.mark.asyncio
@patch('ffmpeg.input')
async def test_capture_stream_clip_success(mock_ffmpeg_input, scanner):
    mock_stream = MagicMock()
    mock_ffmpeg_input.return_value = mock_stream
    result_path = await scanner._capture_stream_clip("rtsp://test", "1.2.3.4", 554)
    mock_ffmpeg_input.assert_called_once()
    mock_stream.output.return_value.overwrite_output.return_value.run.assert_called_once()
    assert result_path is not None

@pytest.mark.asyncio
@patch('ffmpeg.input')
async def test_capture_stream_clip_failure(mock_ffmpeg_input, scanner):
    mock_stream = MagicMock()
    mock_ffmpeg_input.return_value = mock_stream
    mock_stream.output.return_value.overwrite_output.return_value.run.side_effect = ffmpeg.Error(
        'ffmpeg', stdout=None, stderr=b'Error'
    )
    result_path = await scanner._capture_stream_clip("rtsp://invalid", "1.1.1.1", 554)
    mock_stream.output.return_value.overwrite_output.return_value.run.assert_called_once()
    assert result_path is None
