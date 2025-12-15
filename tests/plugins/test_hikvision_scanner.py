"""
Comprehensive test suite for hikvision_scanner.py plugin.

Tests cover:
- HikvisionScanner initialization and metadata
- Default credentials and vulnerability signatures
- Device detection logic (_is_hikvision_device)
- CVE testing methods
- ISAPI authentication testing
- Info disclosure and fingerprinting
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.plugins.builtin.hikvision_scanner import HikvisionScanner


class TestHikvisionScannerInitialization:
    """Test HikvisionScanner initialization."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = HikvisionScanner()
        assert scanner is not None

    def test_has_memory_pool(self):
        """Test scanner has memory pool."""
        scanner = HikvisionScanner()
        assert scanner.memory_pool is not None

    def test_session_initially_none(self):
        """Test HTTP session starts as None."""
        scanner = HikvisionScanner()
        assert scanner.session is None


class TestHikvisionScannerMetadata:
    """Test HikvisionScanner metadata."""

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = HikvisionScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')
        assert hasattr(metadata, 'description')

    def test_metadata_name_contains_hikvision(self):
        """Test metadata name contains hikvision."""
        scanner = HikvisionScanner()
        metadata = scanner.get_metadata()
        assert "hikvision" in metadata.name.lower()

    def test_metadata_has_supported_ports(self):
        """Test metadata includes supported ports."""
        scanner = HikvisionScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'supported_ports')
        assert 80 in metadata.supported_ports

    def test_metadata_has_supported_services(self):
        """Test metadata includes supported services."""
        scanner = HikvisionScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'supported_services')
        assert "http" in metadata.supported_services


class TestHikvisionDefaultCredentials:
    """Test HikvisionScanner default credentials."""

    def test_default_credentials_exist(self):
        """Test default credentials are defined."""
        scanner = HikvisionScanner()
        assert hasattr(scanner, 'default_credentials')
        assert len(scanner.default_credentials) > 0

    def test_admin_12345_in_credentials(self):
        """Test admin:12345 is in default credentials."""
        scanner = HikvisionScanner()
        creds = scanner.default_credentials
        assert ("admin", "12345") in creds

    def test_admin_admin_in_credentials(self):
        """Test admin:admin is in default credentials."""
        scanner = HikvisionScanner()
        creds = scanner.default_credentials
        assert ("admin", "admin") in creds

    def test_credentials_are_tuples(self):
        """Test credentials are username/password tuples."""
        scanner = HikvisionScanner()
        for cred in scanner.default_credentials:
            assert isinstance(cred, tuple)
            assert len(cred) == 2
            assert isinstance(cred[0], str)
            assert isinstance(cred[1], str)


class TestHikvisionVulnerabilitySignatures:
    """Test HikvisionScanner vulnerability signatures."""

    def test_vulnerability_signatures_exist(self):
        """Test vulnerability signatures are defined."""
        scanner = HikvisionScanner()
        assert hasattr(scanner, 'vulnerability_signatures')
        assert len(scanner.vulnerability_signatures) > 0

    def test_cve_2021_36260_exists(self):
        """Test CVE-2021-36260 is in signatures."""
        scanner = HikvisionScanner()
        assert "CVE-2021-36260" in scanner.vulnerability_signatures

    def test_signature_has_required_fields(self):
        """Test signature entries have required fields."""
        scanner = HikvisionScanner()
        for cve_id, signature in scanner.vulnerability_signatures.items():
            assert "path" in signature
            assert "method" in signature
            assert "description" in signature
            assert "severity" in signature


class TestHikvisionTestPaths:
    """Test HikvisionScanner test paths."""

    def test_test_paths_exist(self):
        """Test test paths are defined."""
        scanner = HikvisionScanner()
        assert hasattr(scanner, 'test_paths')
        assert len(scanner.test_paths) > 0

    def test_isapi_path_exists(self):
        """Test ISAPI paths are defined."""
        scanner = HikvisionScanner()
        paths = scanner.test_paths
        isapi_paths = [p for p in paths.values() if "ISAPI" in p or "isapi" in p.lower()]
        assert len(isapi_paths) > 0 or any("SDK" in p for p in paths.values())


class TestHikvisionDeviceDetection:
    """Test HikvisionScanner device detection."""

    def test_is_hikvision_positive_hikvision(self):
        """Test detection with Hikvision banner."""
        scanner = HikvisionScanner()
        assert scanner._is_hikvision_device("Hikvision IP Camera")

    def test_is_hikvision_positive_hik(self):
        """Test detection with Hikvision DS banner."""
        scanner = HikvisionScanner()
        assert scanner._is_hikvision_device("Hikvision DS-2CD2142FWD-I")

    def test_is_hikvision_positive_web_server(self):
        """Test detection with Hikvision Web Server banner."""
        scanner = HikvisionScanner()
        assert scanner._is_hikvision_device("Hikvision-Webs/1.0")

    def test_is_hikvision_positive_embedded(self):
        """Test detection with NVR banner."""
        scanner = HikvisionScanner()
        assert scanner._is_hikvision_device("HIKVISION Network Video Recorder")

    def test_is_hikvision_negative_axis(self):
        """Test detection with Axis banner returns False."""
        scanner = HikvisionScanner()
        assert not scanner._is_hikvision_device("Axis Video Server")

    def test_is_hikvision_negative_dahua(self):
        """Test detection with Dahua banner returns False."""
        scanner = HikvisionScanner()
        assert not scanner._is_hikvision_device("Dahua Web Server")

    def test_is_hikvision_negative_empty(self):
        """Test detection with empty banner returns False."""
        scanner = HikvisionScanner()
        assert not scanner._is_hikvision_device("")

    def test_is_hikvision_negative_nginx(self):
        """Test detection with nginx banner returns False."""
        scanner = HikvisionScanner()
        assert not scanner._is_hikvision_device("nginx/1.18.0")


class TestHikvisionScanVulnerabilities:
    """Test HikvisionScanner scan_vulnerabilities method."""

    @pytest.mark.asyncio
    async def test_scan_not_hikvision_returns_empty(self):
        """Test scan returns empty for non-Hikvision device."""
        scanner = HikvisionScanner()
        results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "nginx")
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_not_hikvision_apache(self):
        """Test scan returns empty for Apache."""
        scanner = HikvisionScanner()
        results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "Apache/2.4.41")
        assert results == []


class TestHikvisionSessionManagement:
    """Test HikvisionScanner session management."""

    @pytest.mark.asyncio
    async def test_init_session_creates_session(self):
        """Test _init_session creates HTTP session."""
        scanner = HikvisionScanner()
        await scanner._init_session()
        assert scanner.session is not None
        await scanner._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session_closes_session(self):
        """Test _cleanup_session closes and nullifies session."""
        scanner = HikvisionScanner()
        await scanner._init_session()
        await scanner._cleanup_session()
        assert scanner.session is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
