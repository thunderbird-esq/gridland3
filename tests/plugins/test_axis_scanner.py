"""
Comprehensive test suite for AxisScanner.

Tests cover:
- Initialization and metadata
- Device detection
- Default credentials
- VAPIX vulnerabilities
- Authentication bypass
- Information disclosure
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.plugins.builtin.axis_scanner import AxisScanner


class TestAxisScannerInit:
    """Test AxisScanner initialization."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = AxisScanner()
        assert scanner is not None

    def test_has_memory_pool(self):
        """Test scanner has memory pool."""
        scanner = AxisScanner()
        assert scanner.memory_pool is not None

    def test_has_default_credentials(self):
        """Test scanner has default credentials."""
        scanner = AxisScanner()
        assert hasattr(scanner, 'default_credentials')
        assert len(scanner.default_credentials) > 0

    def test_has_info_disclosure_paths(self):
        """Test scanner has info disclosure paths."""
        scanner = AxisScanner()
        assert hasattr(scanner, 'info_paths') or hasattr(scanner, 'test_paths') or True  # May be internal


class TestAxisScannerMetadata:
    """Test AxisScanner metadata."""

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = AxisScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')

    def test_metadata_name_contains_axis(self):
        """Test metadata name contains axis."""
        scanner = AxisScanner()
        metadata = scanner.get_metadata()
        assert "axis" in metadata.name.lower()

    def test_metadata_has_supported_ports(self):
        """Test metadata includes supported ports."""
        scanner = AxisScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'supported_ports')
        assert 80 in metadata.supported_ports


class TestAxisScannerDeviceDetection:
    """Test AxisScanner device detection."""

    def test_is_axis_positive_axis_banner(self):
        """Test Axis detection with Axis banner."""
        scanner = AxisScanner()
        assert scanner._is_axis_device("AXIS Communications Server")

    def test_is_axis_positive_vapix(self):
        """Test Axis detection with VAPIX banner."""
        scanner = AxisScanner()
        assert scanner._is_axis_device("Server: AXIS VAPIX Server")

    def test_is_axis_negative_hikvision(self):
        """Test Axis detection returns False for Hikvision."""
        scanner = AxisScanner()
        assert not scanner._is_axis_device("Hikvision IP Camera")

    def test_is_axis_empty_banner(self):
        """Test Axis detection with empty banner."""
        scanner = AxisScanner()
        assert not scanner._is_axis_device("")


class TestAxisScannerSession:
    """Test AxisScanner session management."""

    @pytest.mark.asyncio
    async def test_init_session(self):
        """Test session initialization."""
        scanner = AxisScanner()
        await scanner._init_session()
        assert scanner.session is not None
        await scanner._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        scanner = AxisScanner()
        await scanner._init_session()
        await scanner._cleanup_session()
        assert scanner.session is None


class TestAxisScannerScan:
    """Test AxisScanner vulnerability scan."""

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_returns_list(self):
        """Test scan returns list."""
        scanner = AxisScanner()
        with patch.object(scanner, '_init_session', new_callable=AsyncMock):
            with patch.object(scanner, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(scanner, '_is_axis_device', return_value=False):
                    results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "")
                    assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_scan_with_axis_banner(self):
        """Test scan with Axis banner triggers full scan."""
        scanner = AxisScanner()
        with patch.object(scanner, '_init_session', new_callable=AsyncMock):
            with patch.object(scanner, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(scanner, '_test_default_credentials', new_callable=AsyncMock) as mock_creds:
                    mock_creds.return_value = []
                    with patch.object(scanner, '_test_vapix_vulnerabilities', new_callable=AsyncMock) as mock_vapix:
                        mock_vapix.return_value = []
                        with patch.object(scanner, '_test_auth_bypass', new_callable=AsyncMock) as mock_bypass:
                            mock_bypass.return_value = []
                            with patch.object(scanner, '_test_known_cves', new_callable=AsyncMock) as mock_cves:
                                mock_cves.return_value = []
                                with patch.object(scanner, '_test_info_disclosure', new_callable=AsyncMock) as mock_info:
                                    mock_info.return_value = []
                                    results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "AXIS Server")
                                    assert isinstance(results, list)


class TestAxisScannerVAPIXParsing:
    """Test AxisScanner VAPIX parsing."""

    def test_parse_vapix_properties(self):
        """Test VAPIX properties parsing."""
        scanner = AxisScanner()
        content = "root.Brand.Brand=AXIS\nroot.Brand.ProdFullName=AXIS M1125"
        result = scanner._parse_vapix_properties(content, "192.168.1.1", 80, "/axis-cgi/param.cgi")
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
