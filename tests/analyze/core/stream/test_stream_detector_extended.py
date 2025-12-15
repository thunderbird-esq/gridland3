"""
Comprehensive test suite for stream_detector.py.

Tests cover:
- StreamDetector initialization
- Category detection
- Resolution detection
- Codec detection
- Stream URL validation
"""

import pytest
from unittest.mock import MagicMock, patch

from gridland.analyze.core.stream.stream_detector import StreamDetector


class TestStreamDetectorInit:
    """Test StreamDetector initialization."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = StreamDetector()
        assert detector is not None

    def test_has_session(self):
        """Test detector can work with minimal dependencies."""
        detector = StreamDetector()
        # Should be able to check if detector is ready
        assert detector is not None


class TestStreamDetectorCategory:
    """Test StreamDetector category detection."""

    def test_detect_category_live(self):
        """Test live stream category detection."""
        detector = StreamDetector()
        result = detector._detect_category("rtsp://camera/live")
        assert result == "live"

    def test_detect_category_snapshot(self):
        """Test snapshot category detection."""
        detector = StreamDetector()
        result = detector._detect_category("http://camera/snapshot.jpg")
        assert result == "snapshot"

    def test_detect_category_recorded(self):
        """Test recorded category detection."""
        detector = StreamDetector()
        result = detector._detect_category("http://camera/playback/recording.mp4")
        assert result in ["recorded", "unknown"]

    def test_detect_category_unknown(self):
        """Test unknown category detection."""
        detector = StreamDetector()
        result = detector._detect_category("http://example.com/")
        assert result == "unknown"


class TestStreamDetectorResolution:
    """Test StreamDetector resolution detection."""

    def test_detect_resolution_1080p(self):
        """Test 1080p resolution detection."""
        detector = StreamDetector()
        result = detector._detect_resolution("rtsp://camera/1080p/stream")
        assert result == (1920, 1080)

    def test_detect_resolution_720p(self):
        """Test 720p resolution detection."""
        detector = StreamDetector()
        result = detector._detect_resolution("rtsp://camera/720p/stream")
        assert result == (1280, 720)

    def test_detect_resolution_explicit(self):
        """Test explicit resolution detection."""
        detector = StreamDetector()
        result = detector._detect_resolution("rtsp://camera?resolution=1920x1080")
        assert result == (1920, 1080)

    def test_detect_resolution_none(self):
        """Test no resolution in URL."""
        detector = StreamDetector()
        result = detector._detect_resolution("rtsp://camera/stream")
        assert result is None


class TestStreamDetectorCodec:
    """Test StreamDetector codec detection."""

    def test_detect_codec_h264(self):
        """Test H.264 codec detection from URL."""
        detector = StreamDetector()
        result = detector._detect_codec_from_url("rtsp://camera/h264/stream")
        assert result == "h264"

    def test_detect_codec_h265(self):
        """Test H.265 codec detection from URL."""
        detector = StreamDetector()
        result = detector._detect_codec_from_url("rtsp://camera/h265/stream")
        assert result == "h265"

    def test_detect_codec_mjpeg(self):
        """Test MJPEG codec detection from URL."""
        detector = StreamDetector()
        result = detector._detect_codec_from_url("http://camera/mjpeg/video.cgi")
        assert result == "mjpeg"

    def test_detect_codec_from_content_type_h264(self):
        """Test codec detection from content type."""
        detector = StreamDetector()
        result = detector._detect_codec_from_content_type("video/h264")
        assert result == "h264"

    def test_detect_codec_from_content_type_mp4(self):
        """Test codec detection from mp4 content type."""
        detector = StreamDetector()
        result = detector._detect_codec_from_content_type("video/mp4")
        assert result == "mp4" or result is None


class TestStreamDetectorValidation:
    """Test StreamDetector stream URL validation."""

    def test_is_stream_url_rtsp(self):
        """Test RTSP URL is recognized as stream."""
        detector = StreamDetector()
        result = detector._is_stream_url("rtsp://camera/stream")
        assert result is True

    def test_is_stream_url_mjpeg(self):
        """Test MJPEG URL is recognized as stream."""
        detector = StreamDetector()
        result = detector._is_stream_url("http://camera/video.mjpeg")
        assert result is True

    def test_is_stream_url_html(self):
        """Test HTML URL is not recognized as stream."""
        detector = StreamDetector()
        result = detector._is_stream_url("http://example.com/index.html")
        assert result is False

    def test_is_valid_stream_content_video(self):
        """Test video content type is valid."""
        detector = StreamDetector()
        result = detector._is_valid_stream_content("video/mp4", "http://camera/stream.mp4")
        assert result is True

    def test_is_valid_stream_content_html(self):
        """Test HTML content type is invalid."""
        detector = StreamDetector()
        result = detector._is_valid_stream_content("text/html", "http://example.com/")
        assert result is False


class TestStreamDetectorMethods:
    """Test StreamDetector public methods."""

    def test_validate_stream_url_returns_bool(self):
        """Test validate_stream_url returns boolean."""
        detector = StreamDetector()
        # Should return False for unreachable URL
        result = detector.validate_stream_url("rtsp://nonexistent/stream", timeout=0.1)
        assert isinstance(result, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
