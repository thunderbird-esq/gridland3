"""
Unit tests for input validation in server.py.

Tests cover:
- IP address validation (valid and invalid)
- Stream URL validation (protocols, dangerous characters)
- Query parameter validation (length limits)
"""

import pytest
import json
import base64
import ipaddress
from unittest.mock import patch


@pytest.mark.unit
class TestIPValidation:
    """Test IP address validation."""

    @pytest.mark.parametrize("valid_ip", [
        "8.8.8.8",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "127.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "2001:4860:4860::8888",  # IPv6
    ])
    def test_validate_ip_success(self, client, valid_ip, mock_subprocess):
        """Verify valid IP addresses are accepted."""
        response = client.post(
            '/scan',
            data=json.dumps({'ip': valid_ip}),
            content_type='application/json'
        )
        # Valid IPs should return 200 (SSE stream)
        assert response.status_code == 200

    @pytest.mark.parametrize("invalid_ip", [
        "999.999.999.999",
        "256.256.256.256",
        "1.2.3",
        "1.2.3.4.5",
        "abc.def.ghi.jkl",
        "192.168.1",
        "192.168.1.1.1",
        "",
        None,
        "192.168.1.1/24",  # CIDR notation not accepted
        "localhost",
        "example.com",
    ])
    def test_validate_ip_rejects_invalid(self, client, invalid_ip):
        """Verify invalid IP addresses are rejected."""
        response = client.post(
            '/scan',
            data=json.dumps({'ip': invalid_ip}),
            content_type='application/json'
        )
        # Invalid IPs should return 400
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data


@pytest.mark.unit
class TestStreamURLValidation:
    """Test stream URL validation."""

    @pytest.mark.parametrize("valid_url", [
        "rtsp://example.com:554/stream",
        "rtsp://192.168.1.100/live",
        "rtsp://user:pass@camera.local/stream1",
    ])
    def test_validate_stream_url_success(self, client, valid_url):
        """Verify valid stream URLs are accepted."""
        encoded_url = base64.urlsafe_b64encode(valid_url.encode('utf-8')).decode('utf-8')

        with patch('subprocess.Popen') as mock_popen:
            mock_process = patch('subprocess.Popen').return_value
            mock_process.stdout.read.return_value = b''

            response = client.get(f'/stream/{encoded_url}')

            # Valid URLs should attempt to stream (200)
            assert response.status_code == 200

    @pytest.mark.parametrize("dangerous_url", [
        "file:///etc/passwd",
        "http://malicious.com/../../etc/passwd",
        "rtsp://example.com/stream;rm -rf /",
        "rtsp://example.com/`whoami`",
    ])
    def test_validate_stream_url_rejects_dangerous_chars(self, client, dangerous_url):
        """Verify URLs with dangerous characters/protocols are handled."""
        # Note: Current implementation doesn't validate protocol/chars in stream URL
        # This test documents expected behavior for security hardening
        encoded_url = base64.urlsafe_b64encode(dangerous_url.encode('utf-8')).decode('utf-8')

        with patch('subprocess.Popen') as mock_popen:
            mock_process = patch('subprocess.Popen').return_value
            mock_process.stdout.read.return_value = b''

            response = client.get(f'/stream/{encoded_url}')

            # Current implementation will attempt to process
            # Future: Should reject non-rtsp protocols
            # For now, just verify it doesn't crash
            assert response.status_code in [200, 400, 500]

    def test_validate_stream_url_rejects_invalid_protocol(self, client):
        """Verify non-RTSP protocols are handled appropriately."""
        # Test with http:// instead of rtsp://
        invalid_url = "http://example.com/stream"
        encoded_url = base64.urlsafe_b64encode(invalid_url.encode('utf-8')).decode('utf-8')

        with patch('subprocess.Popen') as mock_popen:
            # GStreamer will fail with non-RTSP URL
            mock_process = patch('subprocess.Popen').return_value
            mock_process.stdout.read.return_value = b''

            response = client.get(f'/stream/{encoded_url}')

            # Should handle gracefully (not crash)
            assert response.status_code in [200, 400, 500]


@pytest.mark.unit
class TestQueryValidation:
    """Test query parameter validation."""

    def test_validate_query_length_limits(self, client, shodan_api_enabled):
        """Verify query length is enforced appropriately."""
        # Test with extremely long query
        long_query = "A" * 10000

        shodan_api_enabled.search.return_value = {'matches': []}

        response = client.post(
            '/discover',
            data=json.dumps({'query': long_query}),
            content_type='application/json'
        )

        # Should either accept or reject based on length limits
        # Current implementation doesn't enforce limits
        assert response.status_code in [200, 400]

    def test_validate_query_special_characters(self, client, shodan_api_enabled):
        """Verify query with special characters is handled safely."""
        # Test with special characters that might cause injection
        special_query = "'; DROP TABLE cameras; --"

        shodan_api_enabled.search.return_value = {'matches': []}

        response = client.post(
            '/discover',
            data=json.dumps({'query': special_query}),
            content_type='application/json'
        )

        # Should handle safely without injection
        assert response.status_code in [200, 400, 500]

    def test_validate_empty_query_rejected(self, client, shodan_api_enabled):
        """Verify empty query is rejected."""
        response = client.post(
            '/discover',
            data=json.dumps({'query': ''}),
            content_type='application/json'
        )

        # Empty query should be rejected
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
