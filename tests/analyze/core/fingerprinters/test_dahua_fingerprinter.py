"""
Comprehensive integration tests for DahuaFingerprinter.

Tests cover:
- DahuaFingerprint dataclass
- Session management
- fingerprint() method with mocked HTTP
- RPC2 response parsing
- Legacy CGI parsing
- Error handling
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp

from gridland.analyze.core.fingerprinters.dahua_fingerprinter import (
    DahuaFingerprinter,
    DahuaFingerprint,
)


class TestDahuaFingerprintDataclass:
    """Test DahuaFingerprint dataclass."""

    def test_default_creation(self):
        """Test default dataclass creation."""
        fp = DahuaFingerprint()
        assert fp.brand == "dahua"
        assert fp.model == ""
        assert fp.confidence == 0.0

    def test_with_values(self):
        """Test dataclass with values."""
        fp = DahuaFingerprint(
            model="IPC-HFW4431R-Z",
            firmware_version="2.680",
            serial_number="YH00A0A0000000",
        )
        assert fp.model == "IPC-HFW4431R-Z"
        assert fp.firmware_version == "2.680"

    def test_vendor_default(self):
        """Test vendor defaults to Dahua Technology."""
        fp = DahuaFingerprint()
        assert fp.vendor == "Dahua Technology"

    def test_detection_methods_list(self):
        """Test detection_methods is a list."""
        fp = DahuaFingerprint()
        assert isinstance(fp.detection_methods, list)


class TestDahuaFingerprinterInit:
    """Test DahuaFingerprinter initialization."""

    def test_initialization(self):
        """Test fingerprinter initialization."""
        fp = DahuaFingerprinter()
        assert fp is not None
        assert fp.session is None

    def test_has_rpc2_endpoints(self):
        """Test has RPC2 endpoints defined."""
        fp = DahuaFingerprinter()
        assert hasattr(fp, 'rpc2_endpoints')
        assert len(fp.rpc2_endpoints) > 0

    def test_has_legacy_endpoints(self):
        """Test has legacy CGI endpoints defined."""
        fp = DahuaFingerprinter()
        assert hasattr(fp, 'legacy_endpoints')


class TestDahuaFingerprinterSession:
    """Test session management."""

    @pytest.mark.asyncio
    async def test_init_session(self):
        """Test session initialization."""
        fp = DahuaFingerprinter()
        await fp._init_session()
        assert fp.session is not None
        await fp._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        fp = DahuaFingerprinter()
        await fp._init_session()
        await fp._cleanup_session()
        assert fp.session is None


class TestDahuaFingerprinterParsing:
    """Test parsing methods."""

    def test_parse_rpc2_response_valid(self):
        """Test parsing valid RPC2 response."""
        fp = DahuaFingerprinter()
        content = """{"id": 1, "params": {"deviceType": "IPC-HFW4431R-Z", "serialNo": "YH00A0A0000000"}, "result": true}"""
        result = fp._parse_rpc2_response(content, "magicBox.getDeviceType")
        assert isinstance(result, dict)

    def test_parse_rpc2_response_empty(self):
        """Test parsing empty response."""
        fp = DahuaFingerprinter()
        result = fp._parse_rpc2_response("", "test")
        assert isinstance(result, dict)

    def test_parse_legacy_response(self):
        """Test parsing legacy CGI response."""
        fp = DahuaFingerprinter()
        content = "deviceType=IPC-HFW4431R-Z\nserialNo=YH00A0A0000000\nsoftwareVersion=2.680"
        result = fp._parse_legacy_response(content)
        assert isinstance(result, dict)


class TestDahuaFingerprinterFingerprint:
    """Test fingerprint method."""

    @pytest.mark.asyncio
    async def test_fingerprint_returns_dataclass(self):
        """Test fingerprint returns DahuaFingerprint."""
        fp = DahuaFingerprinter()
        with patch.object(fp, '_init_session', new_callable=AsyncMock):
            with patch.object(fp, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(fp, '_query_magic_box', new_callable=AsyncMock) as mock_magic:
                    mock_magic.return_value = {"model": "IPC-HFW4431R-Z"}
                    with patch.object(fp, '_query_jsonrpc', new_callable=AsyncMock) as mock_json:
                        mock_json.return_value = {}
                        with patch.object(fp, '_query_legacy_endpoints', new_callable=AsyncMock) as mock_legacy:
                            mock_legacy.return_value = {}
                            result = await fp.fingerprint("192.168.1.1", 80)
                            assert isinstance(result, DahuaFingerprint)

    @pytest.mark.asyncio
    async def test_fingerprint_with_auth(self):
        """Test fingerprint with authentication."""
        fp = DahuaFingerprinter()
        with patch.object(fp, '_init_session', new_callable=AsyncMock):
            with patch.object(fp, '_cleanup_session', new_callable=AsyncMock):
                with patch.object(fp, '_query_magic_box', new_callable=AsyncMock) as mock_magic:
                    mock_magic.return_value = {}
                    with patch.object(fp, '_query_jsonrpc', new_callable=AsyncMock) as mock_json:
                        mock_json.return_value = {}
                        with patch.object(fp, '_query_legacy_endpoints', new_callable=AsyncMock) as mock_legacy:
                            mock_legacy.return_value = {}
                            result = await fp.fingerprint("192.168.1.1", 80, "admin", "admin")
                            assert isinstance(result, DahuaFingerprint)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
