"""
Unit tests for Credential Tester plugin.

Tests the CredentialTester plugin for IP camera default credential testing.
"""

import json
import pytest
from unittest.mock import Mock, MagicMock, patch, call
import threading

from gridland.analyze.plugins.builtin.credential_tester import CredentialTester


class TestCredentialTester:
    """Test suite for CredentialTester plugin."""

    @pytest.fixture
    def tester(self):
        """Create a CredentialTester instance for testing."""
        return CredentialTester()

    def test_initialization(self, tester):
        """Test tester initializes with correct default values."""
        assert tester.max_concurrent_threads == 20
        assert tester.timeout == 5
        assert len(tester.credentials) > 0
        assert "admin" in tester.credentials
        assert "root" in tester.credentials

    def test_get_metadata(self, tester):
        """Test plugin metadata is correctly defined."""
        metadata = tester.get_metadata()
        assert metadata.name == "Credential Tester"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_type == "vulnerability"
        assert "http" in metadata.supported_services
        assert "https" in metadata.supported_services
        assert metadata.performance_impact == "HIGH"

    def test_get_protocol_http(self, tester):
        """Test protocol detection returns http for standard ports."""
        assert tester._get_protocol(80) == "http"
        assert tester._get_protocol(8080) == "http"
        assert tester._get_protocol(8000) == "http"

    def test_get_protocol_https(self, tester):
        """Test protocol detection returns https for SSL ports."""
        assert tester._get_protocol(443) == "https"
        assert tester._get_protocol(8443) == "https"
        assert tester._get_protocol(8444) == "https"

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_test_basic_auth_success(self, mock_get, tester):
        """Test successful Basic authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = tester._test_basic_auth("http://192.168.1.1/", "admin", "admin")

        assert result is True
        mock_get.assert_called_once()
        # Verify HTTPBasicAuth was used
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["auth"] is not None

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_test_basic_auth_failure(self, mock_get, tester):
        """Test failed Basic authentication."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        result = tester._test_basic_auth("http://192.168.1.1/", "admin", "wrong")

        assert result is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_test_basic_auth_exception(self, mock_get, tester):
        """Test Basic authentication handles exceptions gracefully."""
        mock_get.side_effect = Exception("Connection error")

        result = tester._test_basic_auth("http://192.168.1.1/", "admin", "admin")

        assert result is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_form_auth_success(self, mock_post, tester):
        """Test successful Form authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = tester._test_form_auth("http://192.168.1.1/login", "admin", "admin")

        assert result is True
        mock_post.assert_called_once()
        # Verify form data was posted
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["username"] == "admin"
        assert call_kwargs["data"]["password"] == "admin"

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_form_auth_failure(self, mock_post, tester):
        """Test failed Form authentication."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        result = tester._test_form_auth("http://192.168.1.1/login", "admin", "wrong")

        assert result is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_form_auth_exception(self, mock_post, tester):
        """Test Form authentication handles exceptions gracefully."""
        mock_post.side_effect = Exception("Connection error")

        result = tester._test_form_auth("http://192.168.1.1/login", "admin", "admin")

        assert result is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_test_digest_auth_success(self, mock_get, tester):
        """Test successful Digest authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = tester._test_digest_auth("http://192.168.1.1/", "admin", "admin")

        assert result is True
        mock_get.assert_called_once()
        # Verify HTTPDigestAuth was used
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["auth"] is not None

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_test_digest_auth_failure(self, mock_get, tester):
        """Test failed Digest authentication."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        result = tester._test_digest_auth("http://192.168.1.1/", "admin", "wrong")

        assert result is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_test_digest_auth_exception(self, mock_get, tester):
        """Test Digest authentication handles exceptions gracefully."""
        mock_get.side_effect = Exception("Connection error")

        result = tester._test_digest_auth("http://192.168.1.1/", "admin", "admin")

        assert result is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_success(self, mock_post, mock_get, tester):
        """Test successful credential discovery."""
        # Mock successful Basic auth on root path
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get.return_value = mock_get_response

        # Mock failed Form auth
        mock_post_response = Mock()
        mock_post_response.status_code = 401
        mock_post.return_value = mock_post_response

        # Limit credentials for faster test
        tester.credentials = {"admin": ["admin"]}

        results = tester.test_default_credentials("192.168.1.1", [80])

        assert results["success"] is True
        assert results["credentials"] is not None
        assert results["credentials"]["username"] == "admin"
        assert results["credentials"]["password"] == "admin"
        assert results["credentials"]["auth_type"] == "basic"
        assert "192.168.1.1:80" in results["credentials"]["url"]

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_failure(self, mock_post, mock_get, tester):
        """Test credential testing with no valid credentials."""
        # Mock all requests fail
        mock_get_response = Mock()
        mock_get_response.status_code = 401
        mock_get.return_value = mock_get_response

        mock_post_response = Mock()
        mock_post_response.status_code = 401
        mock_post.return_value = mock_post_response

        # Limit credentials for faster test
        tester.credentials = {"admin": ["admin"]}

        results = tester.test_default_credentials("192.168.1.1", [80])

        assert results["success"] is False
        assert results["credentials"] is None

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_early_termination(self, mock_post, mock_get, tester):
        """Test early termination when credentials are found."""
        # Create a flag to track if all combinations were tested
        tested_combinations = []

        def mock_get_side_effect(*args, **kwargs):
            tested_combinations.append(("get", args[0]))
            mock_resp = Mock()
            # Check if auth is HTTPBasicAuth with admin:admin
            auth = kwargs.get("auth")
            if auth and hasattr(auth, "username") and auth.username == "admin" and auth.password == "admin":
                mock_resp.status_code = 200
            else:
                mock_resp.status_code = 401
            return mock_resp

        def mock_post_side_effect(*args, **kwargs):
            tested_combinations.append(("post", args[0]))
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        mock_get.side_effect = mock_get_side_effect
        mock_post.side_effect = mock_post_side_effect

        # Use multiple credentials
        tester.credentials = {
            "admin": ["admin", "1234", "password"],
            "root": ["root", "toor"],
            "user": ["user"],
        }

        results = tester.test_default_credentials("192.168.1.1", [80])

        assert results["success"] is True

        # Should not have tested all possible combinations
        # Total would be 4 endpoints * 6 passwords = 24 if no early termination
        # With early termination, should be much less
        assert len(tested_combinations) < 24

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_multiple_ports(self, mock_post, mock_get, tester):
        """Test credential testing across multiple ports."""
        # Mock success on port 8080 only
        def mock_get_side_effect(*args, **kwargs):
            url = args[0]
            mock_resp = Mock()
            if ":8080/" in url:
                mock_resp.status_code = 200
            else:
                mock_resp.status_code = 401
            return mock_resp

        mock_get.side_effect = mock_get_side_effect
        mock_post.return_value = Mock(status_code=401)

        tester.credentials = {"admin": ["admin"]}

        results = tester.test_default_credentials("192.168.1.1", [80, 8080, 8000])

        assert results["success"] is True
        assert ":8080/" in results["credentials"]["url"]

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_form_auth(self, mock_post, tester):
        """Test credential testing finds Form auth credentials."""
        # Mock successful Form auth on /login endpoint
        def mock_post_side_effect(*args, **kwargs):
            url = args[0]
            mock_resp = Mock()
            if "/login" in url:
                data = kwargs.get("data", {})
                if data.get("username") == "admin" and data.get("password") == "1234":
                    mock_resp.status_code = 200
                else:
                    mock_resp.status_code = 401
            else:
                mock_resp.status_code = 404
            return mock_resp

        mock_post.side_effect = mock_post_side_effect

        tester.credentials = {"admin": ["admin", "1234"]}

        results = tester.test_default_credentials("192.168.1.1", [80])

        assert results["success"] is True
        assert results["credentials"]["username"] == "admin"
        assert results["credentials"]["password"] == "1234"
        assert results["credentials"]["auth_type"] == "form"
        assert "/login" in results["credentials"]["url"]

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_threading(self, mock_post, mock_get, tester):
        """Test that threading is used for concurrent testing."""
        request_count = {"get": 0, "post": 0}
        lock = threading.Lock()

        def count_get(*args, **kwargs):
            with lock:
                request_count["get"] += 1
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        def count_post(*args, **kwargs):
            with lock:
                request_count["post"] += 1
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        mock_get.side_effect = count_get
        mock_post.side_effect = count_post

        # Multiple credentials to trigger threading
        tester.credentials = {
            "admin": ["admin", "1234"],
            "root": ["root"],
        }

        results = tester.test_default_credentials("192.168.1.1", [80])

        # Should have made multiple requests
        total_requests = request_count["get"] + request_count["post"]
        # 4 endpoints * 3 passwords = 12 requests minimum
        # (1 GET for basic on /, 3 POST for form endpoints)
        assert total_requests > 0

    def test_convert_to_vulnerability_results_success(self, tester):
        """Test conversion of successful test to vulnerability objects."""
        test_results = {
            "success": True,
            "credentials": {
                "username": "admin",
                "password": "admin",
                "url": "http://192.168.1.1:80/",
                "auth_type": "basic",
            },
        }

        results = tester._convert_to_vulnerability_results("192.168.1.1", test_results)

        assert len(results) == 1
        vuln = results[0]
        assert vuln.ip == "192.168.1.1"
        assert vuln.port == 80
        assert vuln.vulnerability_id == "DEFAULT-CREDENTIALS"
        assert vuln.severity == "CRITICAL"
        assert vuln.confidence == 100
        assert vuln.exploit_available is True

        # Check details
        details = json.loads(vuln.details)
        assert details["username"] == "admin"
        assert details["password"] == "admin"
        assert details["auth_type"] == "basic"

    def test_convert_to_vulnerability_results_failure(self, tester):
        """Test conversion of failed test returns empty results."""
        test_results = {
            "success": False,
            "credentials": None,
        }

        results = tester._convert_to_vulnerability_results("192.168.1.1", test_results)

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_async(self, tester):
        """Test async scan_vulnerabilities method."""
        with patch.object(tester, "test_default_credentials") as mock_test:
            mock_test.return_value = {
                "success": True,
                "credentials": {
                    "username": "admin",
                    "password": "admin",
                    "url": "http://192.168.1.1:80/",
                    "auth_type": "basic",
                },
            }

            results = await tester.scan_vulnerabilities("192.168.1.1", 80)

            assert len(results) == 1
            assert results[0].vulnerability_id == "DEFAULT-CREDENTIALS"
            mock_test.assert_called_once_with("192.168.1.1", [80])

    def test_load_credentials_fallback(self, tester):
        """Test fallback to hardcoded credentials if JSON file fails."""
        # The tester should have loaded credentials from JSON or fallback
        assert len(tester.credentials) >= 5  # Minimum from DEFAULT_CREDENTIALS
        # Check essential usernames are present
        assert "admin" in tester.credentials
        assert "root" in tester.credentials
        assert "user" in tester.credentials

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_https_protocol(self, mock_post, mock_get, tester):
        """Test HTTPS protocol is used for SSL ports."""
        tested_urls = []

        def capture_get(*args, **kwargs):
            tested_urls.append(args[0])
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        def capture_post(*args, **kwargs):
            tested_urls.append(args[0])
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        mock_get.side_effect = capture_get
        mock_post.side_effect = capture_post

        tester.credentials = {"admin": ["admin"]}

        results = tester.test_default_credentials("192.168.1.1", [443])

        # All URLs should use https://
        assert all(url.startswith("https://") for url in tested_urls)
        assert any(":443/" in url for url in tested_urls)

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_test_default_credentials_all_endpoints(self, mock_post, mock_get, tester):
        """Test that all 4 endpoints are tested."""
        tested_endpoints = set()

        def capture_get(*args, **kwargs):
            url = args[0]
            # Extract path from URL
            path = "/" + "/".join(url.split("/")[3:]) if len(url.split("/")) > 3 else "/"
            tested_endpoints.add(path)
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        def capture_post(*args, **kwargs):
            url = args[0]
            path = "/" + "/".join(url.split("/")[3:]) if len(url.split("/")) > 3 else "/"
            tested_endpoints.add(path)
            mock_resp = Mock()
            mock_resp.status_code = 401
            return mock_resp

        mock_get.side_effect = capture_get
        mock_post.side_effect = capture_post

        tester.credentials = {"admin": ["admin"]}

        results = tester.test_default_credentials("192.168.1.1", [80])

        # Should have tested all 4 endpoints from CamXploit.py lines 1254-1259
        assert "/" in tested_endpoints
        assert "/login" in tested_endpoints
        assert "/admin/login" in tested_endpoints
        assert "/cgi-bin/login" in tested_endpoints

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.post")
    def test_thread_safety(self, mock_post, mock_get, tester):
        """Test thread-safe credential testing."""
        mock_get.return_value = Mock(status_code=401)
        mock_post.return_value = Mock(status_code=401)

        # Many credentials to stress test threading
        tester.credentials = {f"user{i}": [f"pass{i}"] for i in range(50)}
        tester.max_concurrent_threads = 20

        results = tester.test_default_credentials("192.168.1.1", [80])

        # Should complete without race conditions
        assert results["success"] is False

    @patch("gridland.analyze.plugins.builtin.credential_tester.requests.get")
    def test_progress_callback_support(self, mock_get, tester):
        """Test progress callback support (for future enhancement)."""
        mock_get.return_value = Mock(status_code=401)

        tester.credentials = {"admin": ["admin"]}

        # Should not raise error even though progress_callback is not implemented yet
        results = tester.test_default_credentials("192.168.1.1", [80])

        assert results is not None
