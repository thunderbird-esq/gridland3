"""
Comprehensive test suite for axis_scanner.py and dahua_scanner.py plugins.

Tests cover:
- Plugin initialization and metadata
- Credential lists and vulnerability signatures
- Device detection logic
- Scan vulnerability methods with mocked HTTP
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.plugins.builtin.axis_scanner import AxisScanner
from gridland.analyze.plugins.builtin.dahua_scanner import DahuaScanner


class TestAxisScanner:
    """Test AxisScanner plugin."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = AxisScanner()
        assert scanner is not None

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = AxisScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')
        assert hasattr(metadata, 'description')

    def test_metadata_name(self):
        """Test metadata name field."""
        scanner = AxisScanner()
        metadata = scanner.get_metadata()
        assert "axis" in metadata.name.lower()

    def test_default_credentials_exist(self):
        """Test default credentials are defined."""
        scanner = AxisScanner()
        assert hasattr(scanner, 'default_credentials')
        assert len(scanner.default_credentials) > 0

    def test_default_credentials_contain_common(self):
        """Test default credentials contain common pairs."""
        scanner = AxisScanner()
        creds = scanner.default_credentials
        # Should contain root:pass or admin:admin
        usernames = [c[0] for c in creds]
        assert "root" in usernames or "admin" in usernames

    def test_test_paths_exist(self):
        """Test test paths are defined."""
        scanner = AxisScanner()
        assert hasattr(scanner, 'test_paths')
        assert len(scanner.test_paths) > 0

    def test_test_paths_has_vapix(self):
        """Test paths include VAPIX."""
        scanner = AxisScanner()
        assert "vapix" in scanner.test_paths

    def test_vulnerability_signatures_exist(self):
        """Test vulnerability signatures are defined."""
        scanner = AxisScanner()
        assert hasattr(scanner, 'vulnerability_signatures')
        assert len(scanner.vulnerability_signatures) > 0

    def test_vulnerability_signatures_have_cves(self):
        """Test vulnerability signatures include CVEs."""
        scanner = AxisScanner()
        cve_ids = list(scanner.vulnerability_signatures.keys())
        assert any("CVE" in cve for cve in cve_ids)

    def test_is_axis_device_positive(self):
        """Test Axis device detection with matching banner."""
        scanner = AxisScanner()
        assert scanner._is_axis_device("Axis Video Server")
        assert scanner._is_axis_device("axis-cgi")
        assert scanner._is_axis_device("VAPIX enabled camera")

    def test_is_axis_device_negative(self):
        """Test Axis device detection with non-matching banner."""
        scanner = AxisScanner()
        assert not scanner._is_axis_device("Hikvision Camera")
        assert not scanner._is_axis_device("Apache/2.4.41")
        assert not scanner._is_axis_device("")

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_not_axis(self):
        """Test scan returns empty for non-Axis device."""
        scanner = AxisScanner()
        results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "nginx")
        assert results == []


class TestDahuaScanner:
    """Test DahuaScanner plugin."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = DahuaScanner()
        assert scanner is not None

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = DahuaScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')

    def test_metadata_name(self):
        """Test metadata name field."""
        scanner = DahuaScanner()
        metadata = scanner.get_metadata()
        assert "dahua" in metadata.name.lower()

    def test_default_credentials_exist(self):
        """Test default credentials are defined."""
        scanner = DahuaScanner()
        assert hasattr(scanner, 'default_credentials')
        assert len(scanner.default_credentials) > 0

    def test_default_credentials_contain_admin(self):
        """Test default credentials contain admin."""
        scanner = DahuaScanner()
        creds = scanner.default_credentials
        usernames = [c[0] for c in creds]
        assert "admin" in usernames

    def test_test_paths_exist(self):
        """Test test paths are defined."""
        scanner = DahuaScanner()
        assert hasattr(scanner, 'test_paths')
        assert len(scanner.test_paths) > 0

    def test_vulnerability_signatures_exist(self):
        """Test vulnerability signatures are defined."""
        scanner = DahuaScanner()
        assert hasattr(scanner, 'vulnerability_signatures')
        assert len(scanner.vulnerability_signatures) > 0

    def test_is_dahua_device_positive(self):
        """Test Dahua device detection with matching banner."""
        scanner = DahuaScanner()
        assert scanner._is_dahua_device("Dahua Web Server")
        assert scanner._is_dahua_device("DAHUA RPC")
        assert scanner._is_dahua_device("dahua-nvr")

    def test_is_dahua_device_negative(self):
        """Test Dahua device detection with non-matching banner."""
        scanner = DahuaScanner()
        assert not scanner._is_dahua_device("Axis Camera")
        assert not scanner._is_dahua_device("nginx/1.18.0")
        assert not scanner._is_dahua_device("")

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_not_dahua(self):
        """Test scan returns empty for non-Dahua device."""
        scanner = DahuaScanner()
        results = await scanner.scan_vulnerabilities("192.168.1.1", 80, "http", "apache")
        assert results == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
