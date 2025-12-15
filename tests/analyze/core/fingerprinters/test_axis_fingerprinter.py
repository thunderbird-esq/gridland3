"""
Comprehensive integration tests for AxisFingerprinter.

Tests cover:
- AxisFingerprint dataclass
- Session management
- fingerprint() method with mocked HTTP
- VAPIX response parsing
- Basic info parsing
- Error handling
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp

from gridland.analyze.core.fingerprinters.axis_fingerprinter import (
    AxisFingerprinter,
    AxisFingerprint,
)


class TestAxisFingerprintDataclass:
    """Test AxisFingerprint dataclass."""

    def test_default_creation(self):
        """Test default dataclass creation."""
        fp = AxisFingerprint()
        assert fp.brand == "axis"
        assert fp.model == ""
        assert fp.confidence == 0.0

    def test_with_values(self):
        """Test dataclass with values."""
        fp = AxisFingerprint(
            model="M1065-LW",
            firmware_version="10.12.206",
            serial_number="ACCC8E123456",
        )
        assert fp.model == "M1065-LW"
        assert fp.firmware_version == "10.12.206"

    def test_vendor_default(self):
        """Test vendor defaults to Axis Communications."""
        fp = AxisFingerprint()
        assert fp.vendor == "Axis Communications"

    def test_detection_methods_list(self):
        """Test detection_methods is a list."""
        fp = AxisFingerprint()
        assert isinstance(fp.detection_methods, list)


class TestAxisFingerprinterInit:
    """Test AxisFingerprinter initialization."""

    def test_initialization(self):
        """Test fingerprinter initialization."""
        fp = AxisFingerprinter()
        assert fp is not None
        assert fp.session is None

    def test_has_vapix_endpoints(self):
        """Test has VAPIX endpoints defined."""
        fp = AxisFingerprinter()
        assert hasattr(fp, 'vapix_endpoints')
        assert len(fp.vapix_endpoints) > 0


class TestAxisFingerprinterSession:
    """Test session management."""

    @pytest.mark.asyncio
    async def test_init_session(self):
        """Test session initialization."""
        fp = AxisFingerprinter()
        await fp._init_session()
        assert fp.session is not None
        await fp._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        fp = AxisFingerprinter()
        await fp._init_session()
        await fp._cleanup_session()
        assert fp.session is None


class TestAxisFingerprinterParsing:
    """Test parsing methods."""

    def test_parse_vapix_response_valid(self):
        """Test parsing valid VAPIX response."""
        fp = AxisFingerprinter()
        content = """root.Brand.Brand=AXIS
root.Brand.ProdFullName=AXIS M1065-LW Network Camera
root.Brand.ProdNbr=M1065-LW
root.Brand.ProdShortName=AXIS M1065-LW
root.Brand.ProdType=Network Camera
root.Brand.WebURL=http://www.axis.com"""
        result = fp._parse_vapix_response(content)
        assert isinstance(result, dict)

    def test_parse_vapix_response_empty(self):
        """Test parsing empty response."""
        fp = AxisFingerprinter()
        result = fp._parse_vapix_response("")
        assert isinstance(result, dict)

    def test_parse_basic_info_response(self):
        """Test parsing basic info response."""
        fp = AxisFingerprinter()
        content = "Model=M1065-LW\nSerialNumber=ACCC8E123456"
        result = fp._parse_basic_info_response(content)
        assert isinstance(result, dict)


class TestAxisFingerprinterFingerprint:
    """Test fingerprint method."""

    @pytest.mark.asyncio
    async def test_fingerprint_returns_dataclass(self):
        """Test fingerprint returns AxisFingerprint."""
        fp = AxisFingerprinter()
        with patch.object(fp, '_init_session', new_callable=AsyncMock):
            with patch.object(fp, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(fp, '_query_vapix_brand', new_callable=AsyncMock) as mock_brand:
                    mock_brand.return_value = {"model": "M1065-LW"}
                    with patch.object(fp, '_query_vapix_properties', new_callable=AsyncMock) as mock_props:
                        mock_props.return_value = {}
                        with patch.object(fp, '_query_basic_device_info', new_callable=AsyncMock) as mock_info:
                            mock_info.return_value = {}
                            result = await fp.fingerprint("192.168.1.1", 80)
                            assert isinstance(result, AxisFingerprint)

    @pytest.mark.asyncio
    async def test_fingerprint_with_auth(self):
        """Test fingerprint with authentication."""
        fp = AxisFingerprinter()
        with patch.object(fp, '_init_session', new_callable=AsyncMock):
            with patch.object(fp, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(fp, '_query_vapix_brand', new_callable=AsyncMock) as mock_brand:
                    mock_brand.return_value = {}
                    with patch.object(fp, '_query_vapix_properties', new_callable=AsyncMock) as mock_props:
                        mock_props.return_value = {}
                        with patch.object(fp, '_query_basic_device_info', new_callable=AsyncMock) as mock_info:
                            mock_info.return_value = {}
                            result = await fp.fingerprint("192.168.1.1", 80, "root", "pass")
                            assert isinstance(result, AxisFingerprint)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
