"""
Comprehensive test suite for RTSPStreamScanner.

Tests cover:
- Initialization and metadata
- RTSP path definitions
- Stream testing
- Session management
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.plugins.builtin.rtsp_stream_scanner import RTSPStreamScanner


class TestRTSPScannerInit:
    """Test RTSPStreamScanner initialization."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = RTSPStreamScanner()
        assert scanner is not None

    def test_has_memory_pool(self):
        """Test scanner has memory pool."""
        scanner = RTSPStreamScanner()
        assert scanner.memory_pool is not None

    def test_has_rtsp_paths(self):
        """Test scanner has RTSP paths."""
        scanner = RTSPStreamScanner()
        assert hasattr(scanner, 'rtsp_paths') or hasattr(scanner, 'stream_paths')

    def test_has_common_ports(self):
        """Test scanner has common ports."""
        scanner = RTSPStreamScanner()
        assert hasattr(scanner, 'common_ports') or hasattr(scanner, 'rtsp_ports')


class TestRTSPScannerMetadata:
    """Test RTSPStreamScanner metadata."""

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = RTSPStreamScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')

    def test_metadata_has_rtsp_port(self):
        """Test metadata includes RTSP port."""
        scanner = RTSPStreamScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'supported_ports')
        assert 554 in metadata.supported_ports


class TestRTSPScannerSession:
    """Test RTSPStreamScanner session management."""

    @pytest.mark.asyncio
    async def test_init_session(self):
        """Test session initialization."""
        scanner = RTSPStreamScanner()
        await scanner._init_session()
        assert scanner.session is not None
        await scanner._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        scanner = RTSPStreamScanner()
        await scanner._init_session()
        await scanner._cleanup_session()
        assert scanner.session is None


class TestRTSPScannerScan:
    """Test RTSPStreamScanner vulnerability scan."""

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_returns_list(self):
        """Test scan returns list."""
        scanner = RTSPStreamScanner()
        with patch.object(scanner, '_init_session', new_callable=AsyncMock):
            with patch.object(scanner, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(scanner, '_test_rtsp_streams', new_callable=AsyncMock) as mock_test:
                    mock_test.return_value = []
                    results = await scanner.scan_vulnerabilities("192.168.1.1", 554, "rtsp", "")
                    assert isinstance(results, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
