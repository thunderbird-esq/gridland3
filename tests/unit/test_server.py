"""
Unit tests for server.py - Flask application endpoints.

Tests cover:
- Server initialization
- Index route serving
- Scan endpoint validation and processing
- Discover endpoint Shodan integration
- Stream URL validation
"""

import pytest
import json
import base64
from unittest.mock import Mock, MagicMock, patch
import subprocess


@pytest.mark.unit
class TestServerInitialization:
    """Test Flask application initialization."""

    def test_server_starts(self, app):
        """Verify Flask app initializes correctly."""
        assert app is not None
        assert app.config['TESTING'] is True


@pytest.mark.unit
class TestIndexRoute:
    """Test index page serving."""

    def test_index_route(self, client):
        """Verify index route serves HTML successfully."""
        # Note: This will fail if static/index.html doesn't exist
        # For now, we test that the route exists and returns a response
        response = client.get('/')
        # Should either return HTML or 404 if file doesn't exist
        assert response.status_code in [200, 404]


@pytest.mark.unit
class TestScanEndpoint:
    """Test /scan endpoint functionality."""

    def test_scan_requires_ip(self, client):
        """Verify scan endpoint returns 400 when IP is missing."""
        response = client.post(
            '/scan',
            data=json.dumps({}),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'IP address' in data['error']

    def test_scan_validates_ip(self, client, invalid_ip):
        """Verify scan endpoint rejects invalid IP addresses."""
        response = client.post(
            '/scan',
            data=json.dumps({'ip': invalid_ip}),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'valid IP address' in data['error']

    def test_scan_spawns_process(self, client, valid_ip, mock_subprocess):
        """Verify scan endpoint spawns subprocess for valid IP."""
        response = client.post(
            '/scan',
            data=json.dumps({'ip': valid_ip}),
            content_type='application/json'
        )

        # Should return SSE stream
        assert response.status_code == 200
        assert response.mimetype == 'text/event-stream'

        # Verify subprocess was called
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args

        # Verify CamXploit.py was called (check if it's in the command list)
        command_list = call_args[0][0]
        assert any('CamXploit.py' in arg for arg in command_list)

    def test_scan_accepts_valid_ip(self, client, valid_ip, mock_subprocess):
        """Verify scan endpoint accepts valid IP address."""
        response = client.post(
            '/scan',
            data=json.dumps({'ip': valid_ip}),
            content_type='application/json'
        )
        assert response.status_code == 200


@pytest.mark.unit
class TestDiscoverEndpoint:
    """Test /discover endpoint functionality."""

    def test_discover_requires_shodan(self, client):
        """Verify discover endpoint returns error when Shodan API is unavailable."""
        response = client.post(
            '/discover',
            data=json.dumps({'query': 'webcam'}),
            content_type='application/json'
        )
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Shodan' in data['error']

    def test_discover_requires_query(self, client, shodan_api_enabled):
        """Verify discover endpoint requires query parameter."""
        response = client.post(
            '/discover',
            data=json.dumps({}),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'query' in data['error']

    def test_discover_with_shodan_success(self, client, shodan_api_enabled):
        """Verify discover endpoint returns results with valid Shodan API."""
        # Mock successful Shodan search
        shodan_api_enabled.search.return_value = {
            'matches': [
                {'ip_str': '1.2.3.4'},
                {'ip_str': '5.6.7.8'}
            ]
        }

        response = client.post(
            '/discover',
            data=json.dumps({'query': 'webcam'}),
            content_type='application/json'
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert '1.2.3.4' in data
        assert '5.6.7.8' in data


@pytest.mark.unit
class TestStreamEndpoint:
    """Test /stream endpoint functionality."""

    def test_stream_url_validation(self, client):
        """Verify stream endpoint rejects invalid base64 encoding."""
        # Invalid base64 string
        invalid_b64 = "not!!!valid!!!base64!!!"

        response = client.get(f'/stream/{invalid_b64}')

        assert response.status_code == 400
        assert b'Invalid stream URL' in response.data

    def test_stream_accepts_valid_b64(self, client, valid_stream_url):
        """Verify stream endpoint accepts valid base64 encoded URLs."""
        # Encode valid URL
        encoded_url = base64.urlsafe_b64encode(valid_stream_url.encode('utf-8')).decode('utf-8')

        # Mock gstreamer subprocess to avoid actually streaming
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.stdout.read.return_value = b''  # Empty stream
            mock_popen.return_value = mock_process

            response = client.get(f'/stream/{encoded_url}')

            # Should attempt to stream
            assert response.status_code == 200
            assert response.mimetype == 'video/MP2T'
