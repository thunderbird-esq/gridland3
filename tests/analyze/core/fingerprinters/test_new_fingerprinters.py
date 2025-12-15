"""
Comprehensive test suite for Hikvision, Dahua, and Axis fingerprinters.

Tests cover:
- Fingerprint dataclasses
- Fingerprinter initialization
- Endpoint definitions
- Response parsing methods
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.core.fingerprinters.hikvision_fingerprinter import (
    HikvisionFingerprint,
    HikvisionFingerprinter,
)
from gridland.analyze.core.fingerprinters.dahua_fingerprinter import (
    DahuaFingerprint,
    DahuaFingerprinter,
)
from gridland.analyze.core.fingerprinters.axis_fingerprinter import (
    AxisFingerprint,
    AxisFingerprinter,
)


class TestHikvisionFingerprint:
    """Test HikvisionFingerprint dataclass."""

    def test_default_brand(self):
        """Test default brand is hikvision."""
        fp = HikvisionFingerprint()
        assert fp.brand == "hikvision"

    def test_default_confidence(self):
        """Test default confidence is 0."""
        fp = HikvisionFingerprint()
        assert fp.confidence == 0.0

    def test_default_detection_methods(self):
        """Test default detection methods is empty list."""
        fp = HikvisionFingerprint()
        assert fp.detection_methods == []

    def test_with_values(self):
        """Test fingerprint with values."""
        fp = HikvisionFingerprint(
            model="DS-2CD2142FWD-I",
            firmware_version="V5.5.0",
            serial_number="ABC123",
            confidence=0.95,
        )
        assert fp.model == "DS-2CD2142FWD-I"
        assert fp.firmware_version == "V5.5.0"
        assert fp.confidence == 0.95


class TestHikvisionFingerprinter:
    """Test HikvisionFingerprinter class."""

    def test_initialization(self):
        """Test fingerprinter initialization."""
        fp = HikvisionFingerprinter()
        assert fp is not None
        assert fp.session is None

    def test_has_isapi_endpoints(self):
        """Test ISAPI endpoints are defined."""
        fp = HikvisionFingerprinter()
        assert hasattr(fp, 'isapi_endpoints')
        assert "deviceInfo" in fp.isapi_endpoints
        assert len(fp.isapi_endpoints) > 0

    def test_has_sdk_endpoints(self):
        """Test SDK endpoints are defined."""
        fp = HikvisionFingerprinter()
        assert hasattr(fp, 'sdk_endpoints')
        assert len(fp.sdk_endpoints) > 0

    def test_parse_isapi_xml_valid(self):
        """Test ISAPI XML parsing."""
        fp = HikvisionFingerprinter()
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <DeviceInfo>
            <model>DS-2CD2142FWD-I</model>
            <firmwareVersion>V5.5.0</firmwareVersion>
            <serialNumber>ABC123456</serialNumber>
        </DeviceInfo>"""
        result = fp._parse_isapi_xml(xml)
        assert result.get("model") == "DS-2CD2142FWD-I"
        assert result.get("firmwareVersion") == "V5.5.0"

    def test_parse_sdk_response(self):
        """Test SDK response parsing."""
        fp = HikvisionFingerprinter()
        content = "model=DS-2CD2142\nversion=5.5.0\nserial=ABC123"
        result = fp._parse_sdk_response(content)
        assert "model" in result
        assert "version" in result


class TestDahuaFingerprint:
    """Test DahuaFingerprint dataclass."""

    def test_default_brand(self):
        """Test default brand is dahua."""
        fp = DahuaFingerprint()
        assert fp.brand == "dahua"

    def test_default_vendor(self):
        """Test default vendor."""
        fp = DahuaFingerprint()
        assert fp.vendor == "Dahua Technology"

    def test_with_values(self):
        """Test fingerprint with values."""
        fp = DahuaFingerprint(
            model="IPC-HFW4431R-Z",
            firmware_version="2.680.0000000.0",
            confidence=0.90,
        )
        assert fp.model == "IPC-HFW4431R-Z"
        assert fp.confidence == 0.90


class TestDahuaFingerprinter:
    """Test DahuaFingerprinter class."""

    def test_initialization(self):
        """Test fingerprinter initialization."""
        fp = DahuaFingerprinter()
        assert fp is not None
        assert fp.session is None

    def test_has_rpc2_endpoints(self):
        """Test RPC2 endpoints are defined."""
        fp = DahuaFingerprinter()
        assert hasattr(fp, 'rpc2_endpoints')
        assert "magicBox" in fp.rpc2_endpoints
        assert len(fp.rpc2_endpoints) > 0

    def test_has_jsonrpc_endpoint(self):
        """Test JSON-RPC endpoint is defined."""
        fp = DahuaFingerprinter()
        assert hasattr(fp, 'jsonrpc_endpoint')
        assert "/RPC2" in fp.jsonrpc_endpoint

    def test_parse_rpc2_response(self):
        """Test RPC2 response parsing."""
        fp = DahuaFingerprinter()
        content = "deviceType=IPC-HFW4431R-Z\nsoftwareVersion=2.680"
        result = fp._parse_rpc2_response(content, "magicBox")
        assert result.get("deviceType") == "IPC-HFW4431R-Z"
        assert result.get("softwareVersion") == "2.680"

    def test_parse_legacy_response(self):
        """Test legacy response parsing."""
        fp = DahuaFingerprinter()
        content = "model=DH-IPC\nversion=2.680\nserial=ABC123"
        result = fp._parse_legacy_response(content)
        assert "model" in result
        assert "version" in result


class TestAxisFingerprint:
    """Test AxisFingerprint dataclass."""

    def test_default_brand(self):
        """Test default brand is axis."""
        fp = AxisFingerprint()
        assert fp.brand == "axis"

    def test_default_vendor(self):
        """Test default vendor."""
        fp = AxisFingerprint()
        assert fp.vendor == "Axis Communications"

    def test_with_values(self):
        """Test fingerprint with values."""
        fp = AxisFingerprint(
            model="M1125",
            firmware_version="9.80.1",
            confidence=0.95,
        )
        assert fp.model == "M1125"
        assert fp.confidence == 0.95


class TestAxisFingerprinter:
    """Test AxisFingerprinter class."""

    def test_initialization(self):
        """Test fingerprinter initialization."""
        fp = AxisFingerprinter()
        assert fp is not None
        assert fp.session is None

    def test_has_vapix_endpoints(self):
        """Test VAPIX endpoints are defined."""
        fp = AxisFingerprinter()
        assert hasattr(fp, 'vapix_endpoints')
        assert "brand" in fp.vapix_endpoints
        assert "properties" in fp.vapix_endpoints
        assert len(fp.vapix_endpoints) > 0

    def test_has_acap_endpoints(self):
        """Test ACAP endpoints are defined."""
        fp = AxisFingerprinter()
        assert hasattr(fp, 'acap_endpoints')
        assert len(fp.acap_endpoints) > 0

    def test_parse_vapix_response(self):
        """Test VAPIX response parsing."""
        fp = AxisFingerprinter()
        content = "root.Brand.Brand=AXIS\nroot.Brand.ProdFullName=AXIS M1125"
        result = fp._parse_vapix_response(content)
        assert result.get("Brand") == "AXIS"
        assert result.get("ProdFullName") == "AXIS M1125"

    def test_parse_basic_info_response(self):
        """Test basic info response parsing."""
        fp = AxisFingerprinter()
        content = "Model=M1125\nVersion=9.80.1\nSerial=ACCC12345678"
        result = fp._parse_basic_info_response(content)
        assert result.get("model") == "M1125"
        assert result.get("version") == "9.80.1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
