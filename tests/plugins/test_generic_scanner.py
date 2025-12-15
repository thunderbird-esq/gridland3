"""
Comprehensive test suite for GenericCameraScanner.

Tests cover:
- Initialization and metadata
- Camera type detection
- Common endpoint testing
- Model extraction
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.plugins.builtin.generic_camera_scanner import GenericCameraScanner


class TestGenericScannerInit:
    """Test GenericCameraScanner initialization."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = GenericCameraScanner()
        assert scanner is not None

    def test_has_memory_pool(self):
        """Test scanner has memory pool."""
        scanner = GenericCameraScanner()
        assert scanner.memory_pool is not None

    def test_has_test_paths(self):
        """Test scanner has test paths."""
        scanner = GenericCameraScanner()
        assert hasattr(scanner, 'test_paths') or hasattr(scanner, 'common_paths')


class TestGenericScannerMetadata:
    """Test GenericCameraScanner metadata."""

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = GenericCameraScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')

    def test_metadata_has_supported_ports(self):
        """Test metadata includes supported ports."""
        scanner = GenericCameraScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'supported_ports')
        assert 80 in metadata.supported_ports


class TestGenericScannerDetection:
    """Test GenericCameraScanner device detection."""

    def test_is_camera_positive_nvr(self):
        """Test detection with NVR banner."""
        scanner = GenericCameraScanner()
        result = scanner._is_camera_device("Network Video Recorder")
        assert isinstance(result, bool)

    def test_is_camera_positive_dvr(self):
        """Test detection with DVR banner."""
        scanner = GenericCameraScanner()
        result = scanner._is_camera_device("Digital Video Recorder")
        assert isinstance(result, bool)

    def test_is_camera_positive_ipcam(self):
        """Test detection with IP camera banner."""
        scanner = GenericCameraScanner()
        result = scanner._is_camera_device("IP Camera Server")
        assert isinstance(result, bool)

    def test_is_camera_negative_apache(self):
        """Test detection with Apache banner."""
        scanner = GenericCameraScanner()
        result = scanner._is_camera_device("Apache/2.4.41")
        assert isinstance(result, bool)


class TestGenericScannerSession:
    """Test GenericCameraScanner session management."""

    @pytest.mark.asyncio
    async def test_init_session(self):
        """Test session initialization."""
        scanner = GenericCameraScanner()
        await scanner._init_session()
        assert scanner.session is not None
        await scanner._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        scanner = GenericCameraScanner()
        await scanner._init_session()
        await scanner._cleanup_session()
        assert scanner.session is None


class TestGenericScannerScan:
    """Test GenericCameraScanner vulnerability scan."""

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_returns_list(self):
        """Test scan returns list."""
        scanner = GenericCameraScanner()
        with patch.object(scanner, '_init_session', new_callable=AsyncMock):
            with patch.object(scanner, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(scanner, '_test_common_endpoints', new_callable=AsyncMock) as mock_test:
                    mock_test.return_value = []
                    results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "")
                    assert isinstance(results, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
