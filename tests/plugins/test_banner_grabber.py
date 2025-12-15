"""
Comprehensive test suite for banner_grabber.py plugin.

Tests cover:
- BannerGrabber initialization and metadata
- Service patterns and camera patterns
- Security header analysis
- Info disclosure detection
- Verbose error detection
- Camera brand detection
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.plugins.builtin.banner_grabber import BannerGrabber


class TestBannerGrabberInitialization:
    """Test BannerGrabber initialization."""

    def test_initialization(self):
        """Test grabber initialization."""
        grabber = BannerGrabber()
        assert grabber is not None

    def test_has_memory_pool(self):
        """Test grabber has memory pool."""
        grabber = BannerGrabber()
        assert grabber.memory_pool is not None

    def test_has_service_patterns(self):
        """Test grabber has service patterns."""
        grabber = BannerGrabber()
        assert hasattr(grabber, 'service_patterns')
        assert len(grabber.service_patterns) > 0

    def test_has_camera_patterns(self):
        """Test grabber has camera pattern definitions."""
        grabber = BannerGrabber()
        assert hasattr(grabber, 'camera_patterns')
        assert len(grabber.camera_patterns) > 0

    def test_has_security_headers(self):
        """Test grabber has security headers list."""
        grabber = BannerGrabber()
        assert hasattr(grabber, 'security_headers')
        assert len(grabber.security_headers) > 0


class TestBannerGrabberMetadata:
    """Test BannerGrabber metadata."""

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        grabber = BannerGrabber()
        metadata = grabber.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')

    def test_metadata_name(self):
        """Test metadata name field."""
        grabber = BannerGrabber()
        metadata = grabber.get_metadata()
        assert "banner" in metadata.name.lower()

    def test_metadata_has_supported_ports(self):
        """Test metadata includes supported ports."""
        grabber = BannerGrabber()
        metadata = grabber.get_metadata()
        assert hasattr(metadata, 'supported_ports')


class TestBannerGrabberServicePatterns:
    """Test BannerGrabber service patterns."""

    def test_http_pattern_exists(self):
        """Test HTTP service pattern exists."""
        grabber = BannerGrabber()
        assert "http" in grabber.service_patterns

    def test_ssh_pattern_exists(self):
        """Test SSH service pattern exists."""
        grabber = BannerGrabber()
        assert "ssh" in grabber.service_patterns

    def test_rtsp_pattern_exists(self):
        """Test RTSP service pattern exists."""
        grabber = BannerGrabber()
        assert "rtsp" in grabber.service_patterns

    def test_ftp_pattern_exists(self):
        """Test FTP service pattern exists."""
        grabber = BannerGrabber()
        assert "ftp" in grabber.service_patterns


class TestBannerGrabberCameraPatterns:
    """Test BannerGrabber camera pattern detection."""

    def test_hikvision_pattern_exists(self):
        """Test Hikvision camera patterns exist."""
        grabber = BannerGrabber()
        assert "hikvision" in grabber.camera_patterns

    def test_dahua_pattern_exists(self):
        """Test Dahua camera patterns exist."""
        grabber = BannerGrabber()
        assert "dahua" in grabber.camera_patterns

    def test_axis_pattern_exists(self):
        """Test Axis camera patterns exist."""
        grabber = BannerGrabber()
        assert "axis" in grabber.camera_patterns

    def test_detect_camera_brand_hikvision(self):
        """Test Hikvision brand detection from banner."""
        grabber = BannerGrabber()
        brand = grabber._detect_camera_brand("HIKVISION IP Camera Server")
        assert brand == "hikvision"

    def test_detect_camera_brand_dahua(self):
        """Test Dahua brand detection from banner."""
        grabber = BannerGrabber()
        brand = grabber._detect_camera_brand("DAHUA Web Server DH_WEB")
        assert brand == "dahua"

    def test_detect_camera_brand_axis(self):
        """Test Axis brand detection from banner."""
        grabber = BannerGrabber()
        brand = grabber._detect_camera_brand("AXIS Video Server")
        assert brand == "axis"

    def test_detect_camera_brand_unknown(self):
        """Test unknown brand returns None."""
        grabber = BannerGrabber()
        brand = grabber._detect_camera_brand("nginx/1.18.0")
        assert brand is None


class TestBannerGrabberSecurityHeaders:
    """Test BannerGrabber security header analysis."""

    def test_security_headers_include_csp(self):
        """Test security headers include CSP."""
        grabber = BannerGrabber()
        assert "content-security-policy" in grabber.security_headers

    def test_security_headers_include_x_frame(self):
        """Test security headers include X-Frame-Options."""
        grabber = BannerGrabber()
        assert "x-frame-options" in grabber.security_headers

    def test_check_security_headers_missing_all(self):
        """Test detection of all missing security headers."""
        grabber = BannerGrabber()
        missing = grabber._check_security_headers({})
        assert isinstance(missing, list)
        assert len(missing) == len(grabber.security_headers)

    def test_check_security_headers_has_some(self):
        """Test detection when some headers present."""
        grabber = BannerGrabber()
        headers = {"x-frame-options": "DENY", "content-security-policy": "default-src 'self'"}
        missing = grabber._check_security_headers(headers)
        assert isinstance(missing, list)
        assert "x-frame-options" not in missing
        assert "content-security-policy" not in missing


class TestBannerGrabberInfoDisclosure:
    """Test BannerGrabber info disclosure detection."""

    def test_check_info_disclosure_headers_xpowered(self):
        """Test detection of X-Powered-By header."""
        grabber = BannerGrabber()
        headers = {"x-powered-by": "PHP/7.4.3"}
        disclosures = grabber._check_info_disclosure_headers(headers)
        assert isinstance(disclosures, list)
        assert len(disclosures) > 0

    def test_check_info_disclosure_headers_server(self):
        """Test detection of verbose Server header."""
        grabber = BannerGrabber()
        headers = {"server": "Apache/2.4.41 (Ubuntu)"}
        disclosures = grabber._check_info_disclosure_headers(headers)
        assert isinstance(disclosures, list)
        assert len(disclosures) > 0

    def test_check_info_disclosure_headers_clean(self):
        """Test no disclosure for clean headers."""
        grabber = BannerGrabber()
        headers = {"content-type": "text/html"}
        disclosures = grabber._check_info_disclosure_headers(headers)
        assert isinstance(disclosures, list)
        assert len(disclosures) == 0


class TestBannerGrabberVerboseErrors:
    """Test BannerGrabber verbose error detection."""

    def test_has_verbose_errors_stack_trace(self):
        """Test detection of stack traces."""
        grabber = BannerGrabber()
        banner = "Error: stack trace follows\nTraceback..."
        result = grabber._has_verbose_errors(banner)
        assert result is True

    def test_has_verbose_errors_sql_error(self):
        """Test detection of SQL errors."""
        grabber = BannerGrabber()
        banner = "SQL error: syntax error at line 5"
        result = grabber._has_verbose_errors(banner)
        assert result is True

    def test_has_verbose_errors_exception(self):
        """Test detection of exceptions."""
        grabber = BannerGrabber()
        banner = "Exception: NullPointerException"
        result = grabber._has_verbose_errors(banner)
        assert result is True

    def test_has_verbose_errors_negative(self):
        """Test no detection for clean banner."""
        grabber = BannerGrabber()
        banner = "HTTP/1.1 200 OK"
        result = grabber._has_verbose_errors(banner)
        assert result is False


class TestBannerGrabberSessionManagement:
    """Test BannerGrabber session management."""

    @pytest.mark.asyncio
    async def test_init_session_creates_session(self):
        """Test _init_session creates HTTP session."""
        grabber = BannerGrabber()
        await grabber._init_session()
        assert grabber.session is not None
        await grabber._cleanup_session()

    @pytest.mark.asyncio
    async def test_cleanup_session_closes_session(self):
        """Test _cleanup_session closes session."""
        grabber = BannerGrabber()
        await grabber._init_session()
        await grabber._cleanup_session()
        assert grabber.session is None


class TestBannerGrabberVersionVulnerabilities:
    """Test BannerGrabber version vulnerability detection."""

    def test_check_version_vulnerabilities_apache(self):
        """Test Apache version vulnerability detection."""
        grabber = BannerGrabber()
        vulns = grabber._check_version_vulnerabilities("Apache/2.2.5", "192.168.1.1", 80)
        assert isinstance(vulns, list)

    def test_check_version_vulnerabilities_boa(self):
        """Test Boa version vulnerability detection."""
        grabber = BannerGrabber()
        vulns = grabber._check_version_vulnerabilities("Boa/0.9.9", "192.168.1.1", 80)
        assert isinstance(vulns, list)
        assert len(vulns) > 0  # Boa is known to be vulnerable


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
