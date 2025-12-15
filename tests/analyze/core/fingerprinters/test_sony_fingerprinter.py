"""
Test Suite for Sony Fingerprinter.

Comprehensive tests for Sony camera fingerprinting including:
- Device info dataclass
- Endpoint queries
- Response parsing
- Model/firmware extraction
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gridland.analyze.core.fingerprinters.sony_fingerprinter import (
    SonyDeviceInfo,
    SonyFingerprinter,
    fingerprint_sony,
)


# =============================================================================
# SonyDeviceInfo Tests
# =============================================================================


class TestSonyDeviceInfo:
    """Tests for SonyDeviceInfo dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        info = SonyDeviceInfo()
        assert info.brand == "sony"
        assert info.model is None
        assert info.firmware_version is None
        assert info.confidence == 0.0

    def test_custom_values(self):
        """Test initialization with values."""
        info = SonyDeviceInfo(
            model="SNC-CH120",
            firmware_version="1.2.3",
            serial_number="12345",
            confidence=0.85,
        )
        assert info.model == "SNC-CH120"
        assert info.firmware_version == "1.2.3"
        assert info.serial_number == "12345"
        assert info.confidence == 0.85


# =============================================================================
# SonyFingerprinter Initialization Tests
# =============================================================================


class TestSonyFingerprinterInit:
    """Tests for SonyFingerprinter initialization."""

    def test_default_timeout(self):
        """Test default timeout."""
        fp = SonyFingerprinter()
        assert fp.timeout == 10

    def test_custom_timeout(self):
        """Test custom timeout."""
        fp = SonyFingerprinter(timeout=30)
        assert fp.timeout == 30

    def test_endpoints_defined(self):
        """Test endpoints are defined."""
        fp = SonyFingerprinter()
        assert len(fp.endpoints) >= 5
        assert "/command/inquiry.cgi?inq=system" in fp.endpoints

    def test_model_patterns_defined(self):
        """Test model patterns are defined."""
        fp = SonyFingerprinter()
        assert len(fp.model_patterns) > 0

    def test_known_models_defined(self):
        """Test known models set is populated."""
        fp = SonyFingerprinter()
        assert len(fp.known_models) > 20
        assert "SNC-CH120" in fp.known_models


# =============================================================================
# Response Parsing Tests
# =============================================================================


class TestResponseParsing:
    """Tests for response parsing."""

    @pytest.fixture
    def fingerprinter(self):
        return SonyFingerprinter()

    def test_parse_inquiry_response_basic(self, fingerprinter):
        """Test parsing basic inquiry response."""
        text = "Model=SNC-CH120\nVersion=1.2.3\nSerial=12345"
        result = fingerprinter._parse_inquiry_response(text)
        assert result["Model"] == "SNC-CH120"
        assert result["Version"] == "1.2.3"
        assert result["Serial"] == "12345"

    def test_parse_inquiry_response_with_spaces(self, fingerprinter):
        """Test parsing response with spaces around equals."""
        text = "Model = SNC-CH140\nVersion = 2.0.0"
        result = fingerprinter._parse_inquiry_response(text)
        assert result["Model"] == "SNC-CH140"
        assert result["Version"] == "2.0.0"

    def test_parse_inquiry_response_empty_lines(self, fingerprinter):
        """Test parsing response with empty lines."""
        text = "Model=SNC-DH110\n\nVersion=1.0.0\n"
        result = fingerprinter._parse_inquiry_response(text)
        assert result["Model"] == "SNC-DH110"
        assert result["Version"] == "1.0.0"

    def test_parse_system_response(self, fingerprinter):
        """Test parsing system response into SonyDeviceInfo."""
        data = {
            "Model": "SNC-EB600",
            "FirmwareVersion": "1.5.0",
            "SerialNumber": "ABC123",
            "MacAddress": "00:11:22:33:44:55",
        }
        info = SonyDeviceInfo()
        fingerprinter._parse_system_response(data, info)
        assert info.model == "SNC-EB600"
        assert info.firmware_version == "1.5.0"
        assert info.serial_number == "ABC123"
        assert info.mac_address == "00:11:22:33:44:55"

    def test_parse_camera_response(self, fingerprinter):
        """Test parsing camera response."""
        data = {"CameraModel": "SNC-VB630", "ProductID": "SONY-CAM-001"}
        info = SonyDeviceInfo()
        fingerprinter._parse_camera_response(data, info)
        assert info.model == "SNC-VB630"
        assert info.product_id == "SONY-CAM-001"


# =============================================================================
# Banner Detection Tests
# =============================================================================


class TestBannerDetection:
    """Tests for banner-based detection."""

    @pytest.fixture
    def fingerprinter(self):
        return SonyFingerprinter()

    def test_is_sony_device_positive(self, fingerprinter):
        """Test positive Sony detection."""
        assert fingerprinter.is_sony_device("Server: Sony Network Camera")
        assert fingerprinter.is_sony_device("SNC-CH120 Web Interface")
        assert fingerprinter.is_sony_device("IPELA Camera System")

    def test_is_sony_device_negative(self, fingerprinter):
        """Test negative Sony detection."""
        assert not fingerprinter.is_sony_device("Server: Hikvision")
        assert not fingerprinter.is_sony_device("Dahua DH-IPC")
        assert not fingerprinter.is_sony_device("Generic Web Server")

    def test_is_sony_device_case_insensitive(self, fingerprinter):
        """Test case insensitive detection."""
        assert fingerprinter.is_sony_device("SONY NETWORK CAMERA")
        assert fingerprinter.is_sony_device("Sony network camera")

    def test_extract_model_from_banner(self, fingerprinter):
        """Test model extraction from banner."""
        model = fingerprinter.extract_model_from_banner("Server: SNC-CH120/1.0")
        assert model == "SNC-CH120"

    def test_extract_model_from_banner_not_found(self, fingerprinter):
        """Test model extraction when not found."""
        model = fingerprinter.extract_model_from_banner("Generic Server")
        assert model is None

    def test_extract_firmware_from_banner(self, fingerprinter):
        """Test firmware extraction from banner."""
        fw = fingerprinter.extract_firmware_from_banner("Version: 2.5.1")
        assert fw == "2.5.1"

    def test_extract_firmware_from_banner_not_found(self, fingerprinter):
        """Test firmware extraction when not found."""
        fw = fingerprinter.extract_firmware_from_banner("No version here")
        assert fw is None


# =============================================================================
# Async Fingerprinting Tests
# =============================================================================


class TestAsyncFingerprinting:
    """Tests for async fingerprinting methods."""

    @pytest.fixture
    def fingerprinter(self):
        return SonyFingerprinter()

    @pytest.mark.asyncio
    async def test_fingerprint_with_mocked_responses(self, fingerprinter):
        """Test full fingerprinting with mocked responses."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock system inquiry response
            mock_system_resp = AsyncMock()
            mock_system_resp.status = 200
            mock_system_resp.text = AsyncMock(
                return_value="Model=SNC-CH140\nFirmwareVersion=1.2.0"
            )
            
            # Mock camera inquiry response
            mock_camera_resp = AsyncMock()
            mock_camera_resp.status = 200
            mock_camera_resp.text = AsyncMock(return_value="ProductID=SONY001")
            
            # Mock header response
            mock_head_resp = AsyncMock()
            mock_head_resp.headers = {"Server": "Sony Network Camera"}
            
            mock_session.get.return_value.__aenter__.side_effect = [
                mock_system_resp,
                mock_camera_resp,
            ]
            mock_session.head.return_value.__aenter__.return_value = mock_head_resp
            
            result = await fingerprinter.fingerprint("192.168.1.1", 80)
            
            assert result.brand == "sony"
            # Response parsing should have been called
            assert isinstance(result, SonyDeviceInfo)

    @pytest.mark.asyncio
    async def test_fingerprint_handles_errors_gracefully(self, fingerprinter):
        """Test fingerprinting handles errors without crashing."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            mock_session.get.side_effect = Exception("Connection failed")
            mock_session.head.side_effect = Exception("Connection failed")
            
            result = await fingerprinter.fingerprint("192.168.1.1", 80)
            
            assert result.brand == "sony"
            assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_convenience_function(self):
        """Test fingerprint_sony convenience function."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            mock_session.get.side_effect = Exception("Connection failed")
            mock_session.head.side_effect = Exception("Connection failed")
            
            result = await fingerprint_sony("192.168.1.1")
            
            assert isinstance(result, SonyDeviceInfo)
