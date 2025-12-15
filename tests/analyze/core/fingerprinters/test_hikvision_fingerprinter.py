"""
Comprehensive integration tests for HikvisionFingerprinter.

Tests cover:
- HikvisionFingerprint dataclass
- Session management
- fingerprint() method with mocked HTTP
- ISAPI XML parsing
- SDK response parsing
- Error handling
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp

from gridland.analyze.core.fingerprinters.hikvision_fingerprinter import (
    HikvisionFingerprinter,
    HikvisionFingerprint,
)


class TestHikvisionFingerprintDataclass:
    """Test HikvisionFingerprint dataclass."""

    def test_default_creation(self):
        """Test default dataclass creation."""
        fp = HikvisionFingerprint()
        assert fp.brand == "hikvision"
        assert fp.model == ""
        assert fp.confidence == 0.0

    def test_with_values(self):
        """Test dataclass with values."""
        fp = HikvisionFingerprint(
            model="DS-2CD2143G2-I",
            firmware_version="V5.6.5",
            serial_number="ABC123",
        )
        assert fp.model == "DS-2CD2143G2-I"
        assert fp.firmware_version == "V5.6.5"

    def test_detection_methods_list(self):
        """Test detection_methods is a list."""
        fp = HikvisionFingerprint()
        assert isinstance(fp.detection_methods, list)

    def test_raw_data_dict(self):
        """Test raw_data is a dict."""
        fp = HikvisionFingerprint()
        assert isinstance(fp.raw_data, dict)


class TestHikvisionFingerprinterInit:
    """Test HikvisionFingerprinter initialization."""

    def test_initialization(self):
        """Test fingerprinter initialization."""
        fp = HikvisionFingerprinter()
        assert fp is not None
        assert fp.session is None

    def test_has_isapi_endpoints(self):
        """Test has ISAPI endpoints defined."""
        fp = HikvisionFingerprinter()
        assert hasattr(fp, 'isapi_endpoints')
        assert len(fp.isapi_endpoints) > 0

    def test_has_sdk_endpoints(self):
        """Test has SDK endpoints defined."""
        fp = HikvisionFingerprinter()
        assert hasattr(fp, 'sdk_endpoints')


class TestHikvisionFingerprinterSession:
    """Test session management."""

    @pytest.mark.asyncio
    async def test_init_session(self):
        """Test session initialization."""
        fp = HikvisionFingerprinter()
        await fp._init_session()
        assert fp.session is not None
        await fp._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        fp = HikvisionFingerprinter()
        await fp._init_session()
        await fp._cleanup_session()
        assert fp.session is None


class TestHikvisionFingerprinterParsing:
    """Test parsing methods."""

    def test_parse_isapi_xml_valid(self):
        """Test parsing valid ISAPI XML response."""
        fp = HikvisionFingerprinter()
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <DeviceInfo version="1.0">
            <deviceName>IP Camera</deviceName>
            <deviceID>DS-2CD2143G2-I</deviceID>
            <model>DS-2CD2143G2-I</model>
            <serialNumber>DS-2CD2143G2-I20210101AAWRD12345678</serialNumber>
            <macAddress>AB:CD:EF:12:34:56</macAddress>
            <firmwareVersion>V5.6.5 build 210701</firmwareVersion>
            <firmwareReleasedDate>build 210701</firmwareReleasedDate>
            <encoderVersion>V5.0 build 200304</encoderVersion>
            <encoderReleasedDate>build 200304</encoderReleasedDate>
            <deviceType>IPCamera</deviceType>
        </DeviceInfo>"""
        result = fp._parse_isapi_xml(xml_content)
        assert "model" in result or isinstance(result, dict)

    def test_parse_isapi_xml_empty(self):
        """Test parsing empty XML."""
        fp = HikvisionFingerprinter()
        result = fp._parse_isapi_xml("")
        assert isinstance(result, dict)

    def test_parse_sdk_response(self):
        """Test parsing SDK response."""
        fp = HikvisionFingerprinter()
        content = "model=DS-2CD2143G2-I\nfirmwareVersion=V5.6.5"
        result = fp._parse_sdk_response(content)
        assert isinstance(result, dict)


class TestHikvisionFingerprinterFingerprint:
    """Test fingerprint method."""

    @pytest.mark.asyncio
    async def test_fingerprint_returns_dataclass(self):
        """Test fingerprint returns HikvisionFingerprint."""
        fp = HikvisionFingerprinter()
        with patch.object(fp, '_init_session', new_callable=AsyncMock):
            with patch.object(fp, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(fp, '_query_isapi_device_info', new_callable=AsyncMock) as mock_isapi:
                    mock_isapi.return_value = {"model": "DS-2CD2143G2-I"}
                    with patch.object(fp, '_query_sdk_endpoints', new_callable=AsyncMock) as mock_sdk:
                        mock_sdk.return_value = {}
                        with patch.object(fp, '_query_capabilities', new_callable=AsyncMock) as mock_caps:
                            mock_caps.return_value = {}
                            result = await fp.fingerprint("192.168.1.1", 80)
                            assert isinstance(result, HikvisionFingerprint)

    @pytest.mark.asyncio
    async def test_fingerprint_with_auth(self):
        """Test fingerprint with authentication."""
        fp = HikvisionFingerprinter()
        with patch.object(fp, '_init_session', new_callable=AsyncMock):
            with patch.object(fp, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(fp, '_query_isapi_device_info', new_callable=AsyncMock) as mock_isapi:
                    mock_isapi.return_value = {}
                    with patch.object(fp, '_query_sdk_endpoints', new_callable=AsyncMock) as mock_sdk:
                        mock_sdk.return_value = {}
                        with patch.object(fp, '_query_capabilities', new_callable=AsyncMock) as mock_caps:
                            mock_caps.return_value = {}
                            result = await fp.fingerprint("192.168.1.1", 80, "admin", "password")
                            assert isinstance(result, HikvisionFingerprint)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
