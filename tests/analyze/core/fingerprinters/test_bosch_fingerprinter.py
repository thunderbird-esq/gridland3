"""
Test Suite for Bosch Fingerprinter.

Comprehensive tests for Bosch camera fingerprinting including:
- Device info dataclass
- RCP XML parsing
- BVIP response parsing
- Model/firmware extraction
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from gridland.analyze.core.fingerprinters.bosch_fingerprinter import (
    BoschDeviceInfo,
    BoschFingerprinter,
    fingerprint_bosch,
)


# =============================================================================
# BoschDeviceInfo Tests
# =============================================================================


class TestBoschDeviceInfo:
    """Tests for BoschDeviceInfo dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        info = BoschDeviceInfo()
        assert info.brand == "bosch"
        assert info.model is None
        assert info.firmware_version is None
        assert info.confidence == 0.0

    def test_custom_values(self):
        """Test initialization with values."""
        info = BoschDeviceInfo(
            model="NBN-50022-V3",
            firmware_version="6.45.0",
            serial_number="SN123456",
            confidence=0.9,
        )
        assert info.model == "NBN-50022-V3"
        assert info.firmware_version == "6.45.0"
        assert info.serial_number == "SN123456"
        assert info.confidence == 0.9


# =============================================================================
# BoschFingerprinter Initialization Tests
# =============================================================================


class TestBoschFingerprinterInit:
    """Tests for BoschFingerprinter initialization."""

    def test_default_timeout(self):
        """Test default timeout."""
        fp = BoschFingerprinter()
        assert fp.timeout == 10

    def test_custom_timeout(self):
        """Test custom timeout."""
        fp = BoschFingerprinter(timeout=20)
        assert fp.timeout == 20

    def test_rcp_commands_defined(self):
        """Test RCP commands are defined."""
        fp = BoschFingerprinter()
        assert len(fp.rcp_commands) >= 4
        assert fp.rcp_commands["device_info"] == "0x0a10"

    def test_endpoints_defined(self):
        """Test endpoints are defined."""
        fp = BoschFingerprinter()
        assert len(fp.endpoints) >= 4
        assert "/rcp.xml?command=0x0a10" in fp.endpoints

    def test_model_patterns_defined(self):
        """Test model patterns are defined."""
        fp = BoschFingerprinter()
        assert len(fp.model_patterns) > 5

    def test_known_models_defined(self):
        """Test known models set is populated."""
        fp = BoschFingerprinter()
        assert len(fp.known_models) > 15
        assert "NBN-50022-V3" in fp.known_models


# =============================================================================
# RCP XML Parsing Tests
# =============================================================================


class TestRCPXMLParsing:
    """Tests for RCP XML parsing."""

    @pytest.fixture
    def fingerprinter(self):
        return BoschFingerprinter()

    def test_parse_rcp_xml_valid(self, fingerprinter):
        """Test parsing valid RCP XML."""
        xml = """<?xml version="1.0"?>
        <response>
            <model>NBN-50022-V3</model>
            <serial>ABC123</serial>
            <version>6.45.0</version>
        </response>"""
        result = fingerprinter._parse_rcp_xml(xml)
        assert result["model"] == "NBN-50022-V3"
        assert result["serial"] == "ABC123"
        assert result["version"] == "6.45.0"

    def test_parse_rcp_xml_with_attributes(self, fingerprinter):
        """Test parsing XML with attributes."""
        xml = """<response>
            <device type="camera">DINION HD</device>
        </response>"""
        result = fingerprinter._parse_rcp_xml(xml)
        assert "device_type" in result

    def test_regex_extract_from_xml(self, fingerprinter):
        """Test regex fallback extraction."""
        text = "<model>NBN-73013-BA</model><serial>TEST123</serial>"
        result = fingerprinter._regex_extract_from_xml(text)
        assert result["model"] == "NBN-73013-BA"
        assert result["serial"] == "TEST123"


# =============================================================================
# BVIP Response Parsing Tests
# =============================================================================


class TestBVIPParsing:
    """Tests for BVIP response parsing."""

    @pytest.fixture
    def fingerprinter(self):
        return BoschFingerprinter()

    def test_parse_bvip_response_equals(self, fingerprinter):
        """Test parsing BVIP response with equals separator."""
        text = "ProductName=FLEXIDOME IP 5000i\nVersion=6.50.0\nSerial=12345"
        result = fingerprinter._parse_bvip_response(text)
        assert result["ProductName"] == "FLEXIDOME IP 5000i"
        assert result["Version"] == "6.50.0"
        assert result["Serial"] == "12345"

    def test_parse_bvip_response_colon(self, fingerprinter):
        """Test parsing BVIP response with colon separator."""
        text = "ProductName: DINION IP 7000 HD\nVersion: 6.40.0"
        result = fingerprinter._parse_bvip_response(text)
        assert result["ProductName"] == "DINION IP 7000 HD"
        assert result["Version"] == "6.40.0"

    def test_parse_bvip_response_empty_lines(self, fingerprinter):
        """Test parsing with empty lines."""
        text = "ProductName=AUTODOME\n\nVersion=7.0.0\n"
        result = fingerprinter._parse_bvip_response(text)
        assert result["ProductName"] == "AUTODOME"
        assert result["Version"] == "7.0.0"


# =============================================================================
# Device Info Parsing Tests
# =============================================================================


class TestDeviceInfoParsing:
    """Tests for device info parsing."""

    @pytest.fixture
    def fingerprinter(self):
        return BoschFingerprinter()

    def test_parse_rcp_device_info(self, fingerprinter):
        """Test parsing RCP device info."""
        data = {
            "model": "NBN-40012-V3",
            "firmware": "6.30.0",
            "serial": "SN123",
            "mac": "00:11:22:33:44:55",
            "hardware": "1.0",
        }
        info = BoschDeviceInfo()
        fingerprinter._parse_rcp_device_info(data, info)
        assert info.model == "NBN-40012-V3"
        assert info.firmware_version == "6.30.0"
        assert info.serial_number == "SN123"
        assert info.mac_address == "00:11:22:33:44:55"
        assert info.hardware_version == "1.0"

    def test_parse_bvip_info(self, fingerprinter):
        """Test parsing BVIP info."""
        data = {"ProductName": "FLEXIDOME IP 4000i", "DeviceType": "camera"}
        info = BoschDeviceInfo()
        fingerprinter._parse_bvip_info(data, info)
        assert info.product_name == "FLEXIDOME IP 4000i"
        assert info.device_type == "camera"


# =============================================================================
# Banner Detection Tests
# =============================================================================


class TestBannerDetection:
    """Tests for banner-based detection."""

    @pytest.fixture
    def fingerprinter(self):
        return BoschFingerprinter()

    def test_is_bosch_device_positive(self, fingerprinter):
        """Test positive Bosch detection."""
        assert fingerprinter.is_bosch_device("Server: Bosch Video IP")
        assert fingerprinter.is_bosch_device("BVIP Camera System")
        assert fingerprinter.is_bosch_device("FLEXIDOME IP 5000i")
        assert fingerprinter.is_bosch_device("NBN-50022-V3")

    def test_is_bosch_device_negative(self, fingerprinter):
        """Test negative Bosch detection."""
        assert not fingerprinter.is_bosch_device("Server: Hikvision")
        assert not fingerprinter.is_bosch_device("Dahua DH-IPC")
        assert not fingerprinter.is_bosch_device("Generic Web Server")

    def test_is_bosch_device_case_insensitive(self, fingerprinter):
        """Test case insensitive detection."""
        assert fingerprinter.is_bosch_device("BOSCH VIDEO IP")
        assert fingerprinter.is_bosch_device("bosch video ip")

    def test_extract_model_from_banner(self, fingerprinter):
        """Test model extraction from banner."""
        model = fingerprinter.extract_model_from_banner("Server: NBN-50022-V3/6.45")
        assert model is not None
        assert "NBN" in model

    def test_extract_model_from_banner_not_found(self, fingerprinter):
        """Test model extraction when not found."""
        model = fingerprinter.extract_model_from_banner("Generic Server")
        assert model is None

    def test_extract_firmware_from_banner(self, fingerprinter):
        """Test firmware extraction from banner."""
        fw = fingerprinter.extract_firmware_from_banner("FirmwareVersion: 6.45.0")
        assert fw == "6.45.0"


# =============================================================================
# Async Fingerprinting Tests
# =============================================================================


class TestAsyncFingerprinting:
    """Tests for async fingerprinting methods."""

    @pytest.fixture
    def fingerprinter(self):
        return BoschFingerprinter()

    @pytest.mark.asyncio
    async def test_fingerprint_handles_errors_gracefully(self, fingerprinter):
        """Test fingerprinting handles errors without crashing."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            mock_session.get.side_effect = Exception("Connection failed")
            mock_session.head.side_effect = Exception("Connection failed")
            
            result = await fingerprinter.fingerprint("192.168.1.1", 80)
            
            assert result.brand == "bosch"
            assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_convenience_function(self):
        """Test fingerprint_bosch convenience function."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            mock_session.get.side_effect = Exception("Connection failed")
            mock_session.head.side_effect = Exception("Connection failed")
            
            result = await fingerprint_bosch("192.168.1.1")
            
            assert isinstance(result, BoschDeviceInfo)
