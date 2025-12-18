"""
Tests for GRIDLAND Server OSINT API Endpoints

Tests the /api/osint/* endpoints with proper mocking of the OSINT module.
"""

import pytest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestOsintUrlsEndpoint:
    """Tests for /api/osint/urls/<ip> endpoint."""
    
    def test_osint_urls_valid_ip(self, client):
        """Test OSINT URLs endpoint with valid IP."""
        response = client.get('/api/osint/urls/8.8.8.8')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Check structure
        assert 'ip' in data
        assert 'search_urls' in data
        assert 'google_dorks' in data
        
        # Check IP is echoed back
        assert data['ip'] == '8.8.8.8'
        
        # Check search URLs contain expected platforms
        search_urls = data['search_urls']
        assert 'shodan' in search_urls
        assert 'censys' in search_urls
        assert 'zoomeye' in search_urls
        
        # Check search URLs contain the IP
        assert '8.8.8.8' in search_urls['shodan']
        assert '8.8.8.8' in search_urls['censys']
        
        # Check Google dorks are returned as list
        assert isinstance(data['google_dorks'], list)
        if len(data['google_dorks']) > 0:
            dork = data['google_dorks'][0]
            assert 'query' in dork
            assert 'url' in dork
    
    def test_osint_urls_invalid_ip(self, client):
        """Test OSINT URLs endpoint with invalid IP."""
        response = client.get('/api/osint/urls/not-an-ip')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid IP address' in data['error']
    
    def test_osint_urls_private_ip(self, client):
        """Test OSINT URLs endpoint with private IP (should still work)."""
        response = client.get('/api/osint/urls/192.168.1.1')
        
        # Private IPs are valid, just won't have useful OSINT data
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['ip'] == '192.168.1.1'


class TestOsintGeoEndpoint:
    """Tests for /api/osint/geo/<ip> endpoint."""
    
    @patch('gridland.core.osint.IPGeolocationService.get_location_sync')
    def test_osint_geo_valid_ip_success(self, mock_get_location, client):
        """Test geo endpoint with valid IP and successful lookup."""
        from gridland.core.osint import GeoLocation
        
        mock_geo = GeoLocation(
            ip='8.8.8.8',
            city='Mountain View',
            region='California',
            country='US',
            latitude=37.4056,
            longitude=-122.0775,
            org='Google LLC',
        )
        mock_get_location.return_value = mock_geo
        
        response = client.get('/api/osint/geo/8.8.8.8')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['ip'] == '8.8.8.8'
        assert data['city'] == 'Mountain View'
        assert data['country'] == 'US'
        assert data['google_maps_url'] is not None
    
    @patch('gridland.core.osint.IPGeolocationService.get_location_sync')
    def test_osint_geo_lookup_failure(self, mock_get_location, client):
        """Test geo endpoint when lookup fails."""
        mock_get_location.return_value = None
        
        response = client.get('/api/osint/geo/1.2.3.4')
        
        # Should return 404 when lookup fails
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Geolocation lookup failed' in data['error']
    
    def test_osint_geo_invalid_ip(self, client):
        """Test geo endpoint with invalid IP."""
        response = client.get('/api/osint/geo/invalid')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid IP address' in data['error']


class TestOsintFullEndpoint:
    """Tests for /api/osint/full/<ip> endpoint."""
    
    @patch('gridland.core.osint.osint_report')
    def test_osint_full_valid_ip(self, mock_osint_report, client):
        """Test full OSINT report endpoint with valid IP."""
        mock_osint_report.return_value = {
            'ip': '8.8.8.8',
            'geolocation': {
                'city': 'Mountain View',
                'country': 'US',
            },
            'search_engine_urls': {
                'urls': {
                    'shodan': 'https://www.shodan.io/search?query=8.8.8.8',
                }
            },
            'google_dorks': [
                {'query': 'site:8.8.8.8', 'url': 'https://google.com/search?q=site:8.8.8.8'}
            ],
        }
        
        response = client.get('/api/osint/full/8.8.8.8')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['ip'] == '8.8.8.8'
        assert 'geolocation' in data
        assert 'search_engine_urls' in data
        assert 'google_dorks' in data
    
    def test_osint_full_invalid_ip(self, client):
        """Test full endpoint with invalid IP."""
        response = client.get('/api/osint/full/bad-ip')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid IP address' in data['error']


class TestOsintIntegration:
    """Integration tests that hit real endpoints (no mocking)."""
    
    def test_osint_urls_integration(self, client):
        """Integration test for OSINT URLs (no external calls)."""
        response = client.get('/api/osint/urls/1.1.1.1')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify we get real URLs back
        assert 'shodan.io' in data['search_urls']['shodan']
        assert 'censys.io' in data['search_urls']['censys']
        assert len(data['google_dorks']) > 0
