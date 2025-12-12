"""
Unit tests for Login Page Scanner plugin.

Tests the LoginPageScanner plugin for IP camera authentication endpoint detection.
"""

import json
import threading
from unittest.mock import MagicMock, Mock, call, patch

import pytest

from gridland.analyze.plugins.builtin.login_scanner import LoginPageScanner


class TestLoginPageScanner:
    """Test suite for LoginPageScanner plugin."""

    @pytest.fixture
    def scanner(self):
        """Create a LoginPageScanner instance for testing."""
        return LoginPageScanner()

    def test_initialization(self, scanner):
        """Test scanner initializes with correct default values."""
        assert scanner.max_concurrent_threads == 50
        assert scanner.timeout == 5
        assert len(scanner.login_paths) > 0
        assert "/" in scanner.login_paths

    def test_get_metadata(self, scanner):
        """Test plugin metadata is correctly defined."""
        metadata = scanner.get_metadata()
        assert metadata.name == "Login Page Scanner"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_type == "vulnerability"
        assert "http" in metadata.supported_services
        assert "https" in metadata.supported_services

    def test_get_protocol_http(self, scanner):
        """Test protocol detection returns http for standard ports."""
        assert scanner._get_protocol(80) == "http"
        assert scanner._get_protocol(8080) == "http"
        assert scanner._get_protocol(8000) == "http"

    def test_get_protocol_https(self, scanner):
        """Test protocol detection returns https for SSL ports."""
        assert scanner._get_protocol(443) == "https"
        assert scanner._get_protocol(8443) == "https"
        assert scanner._get_protocol(8444) == "https"

    def test_detect_auth_type_basic(self, scanner):
        """Test detection of Basic authentication."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {"WWW-Authenticate": 'Basic realm="Camera"'}

        auth_type = scanner._detect_auth_type(mock_response)
        assert auth_type == "basic"

    def test_detect_auth_type_digest(self, scanner):
        """Test detection of Digest authentication."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {"WWW-Authenticate": 'Digest realm="Camera", nonce="abc123"'}

        auth_type = scanner._detect_auth_type(mock_response)
        assert auth_type == "digest"

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.get")
    def test_detect_auth_type_form(self, mock_get, scanner):
        """Test detection of form-based authentication."""
        # Mock HEAD response (200 with no WWW-Authenticate)
        mock_head_response = Mock()
        mock_head_response.status_code = 200
        mock_head_response.headers = {}
        mock_head_response.url = "http://192.168.1.1/login"

        # Mock GET response with login form
        mock_get_response = Mock()
        mock_get_response.text = """
        <html>
            <form method="post" action="/login">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
        </html>
        """
        mock_get.return_value = mock_get_response

        auth_type = scanner._detect_auth_type(mock_head_response)
        assert auth_type == "form"

    def test_detect_auth_type_unknown(self, scanner):
        """Test unknown authentication type detection."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {}

        auth_type = scanner._detect_auth_type(mock_response)
        assert auth_type == "unknown"

    def test_has_login_form_positive(self, scanner):
        """Test login form detection with valid form HTML."""
        html = """
        <html>
            <form action="/login" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </html>
        """
        assert scanner._has_login_form(html) is True

    def test_has_login_form_no_form(self, scanner):
        """Test login form detection with no form tag."""
        html = """
        <html>
            <body>
                <input type="password" name="password">
            </body>
        </html>
        """
        assert scanner._has_login_form(html) is False

    def test_has_login_form_no_password(self, scanner):
        """Test login form detection with form but no password field."""
        html = """
        <html>
            <form action="/search">
                <input type="text" name="query">
                <button type="submit">Search</button>
            </form>
        </html>
        """
        assert scanner._has_login_form(html) is False

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_found_basic_auth(self, mock_head, scanner):
        """Test scanning with Basic authentication detected."""
        # Mock successful response with Basic auth
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {"WWW-Authenticate": 'Basic realm="Camera"'}
        mock_head.return_value = mock_response

        # Scan single port with limited paths for testing
        scanner.login_paths = ["/", "/admin"]
        results = scanner.scan_login_pages("192.168.1.1", [80])

        assert results["total_found"] == 2
        assert len(results["login_pages"]) == 2
        assert all(lp["auth_type"] == "basic" for lp in results["login_pages"])
        assert all(lp["status_code"] == 401 for lp in results["login_pages"])

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_found_forbidden(self, mock_head, scanner):
        """Test scanning with 403 Forbidden response."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_head.return_value = mock_response

        scanner.login_paths = ["/admin"]
        results = scanner.scan_login_pages("192.168.1.1", [80])

        assert results["total_found"] == 1
        assert results["login_pages"][0]["status_code"] == 403

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_not_found(self, mock_head, scanner):
        """Test scanning with no login pages found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_head.return_value = mock_response

        scanner.login_paths = ["/"]
        results = scanner.scan_login_pages("192.168.1.1", [80])

        assert results["total_found"] == 0
        assert len(results["login_pages"]) == 0

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_timeout(self, mock_head, scanner):
        """Test scanning handles timeouts gracefully."""
        mock_head.side_effect = Exception("Connection timeout")

        scanner.login_paths = ["/"]
        results = scanner.scan_login_pages("192.168.1.1", [80])

        # Should not raise exception, just return empty results
        assert results["total_found"] == 0
        assert len(results["login_pages"]) == 0

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_multiple_ports(self, mock_head, scanner):
        """Test scanning across multiple ports."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_head.return_value = mock_response

        scanner.login_paths = ["/"]
        results = scanner.scan_login_pages("192.168.1.1", [80, 8080, 8000])

        assert results["total_found"] == 3
        # Verify different ports in URLs
        urls = [lp["url"] for lp in results["login_pages"]]
        assert any(":80/" in url for url in urls)
        assert any(":8080/" in url for url in urls)
        assert any(":8000/" in url for url in urls)

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_threading(self, mock_head, scanner):
        """Test that threading is used for concurrent scanning."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_head.return_value = mock_response

        # Use many paths to trigger thread pooling
        scanner.login_paths = [f"/path{i}" for i in range(100)]
        scanner.max_concurrent_threads = 10

        results = scanner.scan_login_pages("192.168.1.1", [80])

        # Should find 100 login pages
        assert results["total_found"] == 100
        # All requests should have been made
        assert mock_head.call_count == 100

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_progress_callback(self, mock_head, scanner):
        """Test progress callback is invoked during scanning."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_head.return_value = mock_response

        # Track progress callback invocations
        progress_calls = []

        def progress_callback(checked, total):
            progress_calls.append((checked, total))

        scanner.login_paths = ["/", "/admin", "/login"]
        results = scanner.scan_login_pages("192.168.1.1", [80], progress_callback=progress_callback)

        # Progress callback should have been called
        assert len(progress_calls) > 0
        # Last call should report all checked
        assert progress_calls[-1][0] == progress_calls[-1][1]
        # Total should be paths * ports
        assert progress_calls[-1][1] == 3

    def test_convert_to_vulnerability_results(self, scanner):
        """Test conversion of scan results to vulnerability objects."""
        scan_results = {
            "login_pages": [
                {
                    "url": "http://192.168.1.1:80/login",
                    "status_code": 401,
                    "auth_type": "basic",
                }
            ],
            "total_found": 1,
        }

        results = scanner._convert_to_vulnerability_results("192.168.1.1", scan_results)

        assert len(results) == 1
        vuln = results[0]
        assert vuln.ip == "192.168.1.1"
        assert vuln.port == 80
        assert vuln.vulnerability_id == "LOGIN-PAGE-DETECTED"
        assert vuln.severity == "INFO"
        assert vuln.confidence == 95

        # Check details
        details = json.loads(vuln.details)
        assert details["url"] == "http://192.168.1.1:80/login"
        assert details["auth_type"] == "basic"
        assert details["status_code"] == 401

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_https_protocol(self, mock_head, scanner):
        """Test HTTPS protocol is used for SSL ports."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_head.return_value = mock_response

        scanner.login_paths = ["/"]
        results = scanner.scan_login_pages("192.168.1.1", [443])

        assert results["total_found"] == 1
        assert results["login_pages"][0]["url"].startswith("https://")

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_scan_login_pages_mixed_responses(self, mock_head, scanner):
        """Test scanning with mixed success and failure responses."""

        def side_effect(*args, **kwargs):
            url = args[0]
            mock_resp = Mock()
            # Return 401 for /admin, 404 for others
            if "/admin" in url:
                mock_resp.status_code = 401
                mock_resp.headers = {"WWW-Authenticate": "Basic"}
            else:
                mock_resp.status_code = 404
                mock_resp.headers = {}
            return mock_resp

        mock_head.side_effect = side_effect

        scanner.login_paths = ["/", "/admin", "/login"]
        results = scanner.scan_login_pages("192.168.1.1", [80])

        # Only /admin should be found
        assert results["total_found"] == 1
        assert "/admin" in results["login_pages"][0]["url"]

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_async(self, scanner):
        """Test async scan_vulnerabilities method."""
        with patch.object(scanner, "scan_login_pages") as mock_scan:
            mock_scan.return_value = {
                "login_pages": [
                    {
                        "url": "http://192.168.1.1:80/login",
                        "status_code": 401,
                        "auth_type": "basic",
                    }
                ],
                "total_found": 1,
            }

            results = await scanner.scan_vulnerabilities("192.168.1.1", 80)

            assert len(results) == 1
            assert results[0].vulnerability_id == "LOGIN-PAGE-DETECTED"
            mock_scan.assert_called_once_with("192.168.1.1", [80])

    def test_load_login_paths_fallback(self, scanner):
        """Test fallback to hardcoded paths if JSON file fails to load."""
        # The scanner should have loaded paths from JSON or fallback
        assert len(scanner.login_paths) >= 17  # Minimum from COMMON_PATHS
        # Check some essential paths are present
        assert "/" in scanner.login_paths
        assert "/admin" in scanner.login_paths
        assert "/login" in scanner.login_paths

    @patch("gridland.analyze.plugins.builtin.login_scanner.requests.head")
    def test_thread_safety(self, mock_head, scanner):
        """Test thread-safe result collection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_head.return_value = mock_response

        # Large number of paths to stress test threading
        scanner.login_paths = [f"/path{i}" for i in range(200)]
        scanner.max_concurrent_threads = 50

        results = scanner.scan_login_pages("192.168.1.1", [80])

        # All 200 paths should be found without race conditions
        assert results["total_found"] == 200
        assert len(results["login_pages"]) == 200
