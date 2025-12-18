"""
Tests for GRIDLAND Server CLI API Endpoints

Tests the /api/cli/* endpoints for invoking CLI commands.
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


class TestInvokeCliEndpoint:
    """Tests for /api/cli endpoint."""
    
    def test_cli_missing_command(self, client):
        """Test CLI endpoint without command."""
        response = client.post('/api/cli', json={})
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Command is required' in data['error']
    
    def test_cli_unknown_command(self, client):
        """Test CLI endpoint with unknown command."""
        response = client.post('/api/cli', json={'command': 'unknown'})
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Unknown command' in data['error']
        assert 'available_commands' in data
        assert 'osint' in data['available_commands']
        assert 'stream' in data['available_commands']
    
    def test_cli_valid_commands_recognized(self, client):
        """Test that all 4 CLI commands are recognized."""
        for command in ['discover', 'analyze', 'osint', 'stream']:
            # Just test that the command is recognized (not unknown error)
            response = client.post('/api/cli', json={
                'command': command,
                'subcommand': 'help' if command != 'stream' else None,
                'args': ['--help'] if command != 'stream' else []
            })
            
            data = json.loads(response.data)
            # Should either succeed or fail on execution, not "unknown command"
            assert 'Unknown command' not in data.get('error', '')


class TestOsintCliDirectEndpoints:
    """Tests for /api/cli/osint/<subcommand>/<ip> direct endpoints."""
    
    def test_osint_dorks_endpoint(self, client):
        """Test direct OSINT dorks endpoint."""
        response = client.get('/api/cli/osint/dorks/8.8.8.8')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['ip'] == '8.8.8.8'
        assert data['command'] == 'osint dorks'
        assert 'dorks' in data
        assert 'count' in data
        assert data['count'] > 0
        
        # Check dork structure
        dork = data['dorks'][0]
        assert 'query' in dork
        assert 'url' in dork
        assert '8.8.8.8' in dork['query']
    
    def test_osint_search_urls_endpoint(self, client):
        """Test direct OSINT search-urls endpoint."""
        response = client.get('/api/cli/osint/search-urls/1.1.1.1')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['ip'] == '1.1.1.1'
        assert data['command'] == 'osint search-urls'
        assert 'urls' in data
        assert 'count' in data
        
        # Check URL structure
        urls = data['urls']
        assert 'shodan' in urls
        assert 'censys' in urls
        assert '1.1.1.1' in urls['shodan']
    
    @patch('gridland.core.osint.IPGeolocationService.get_location_sync')
    def test_osint_geolocate_endpoint(self, mock_get_location, client):
        """Test direct OSINT geolocate endpoint."""
        from gridland.core.osint import GeoLocation
        
        mock_geo = GeoLocation(
            ip='8.8.8.8',
            city='Mountain View',
            region='California',
            country='US',
            latitude=37.4056,
            longitude=-122.0775,
        )
        mock_get_location.return_value = mock_geo
        
        response = client.get('/api/cli/osint/geolocate/8.8.8.8')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['ip'] == '8.8.8.8'
        assert data['command'] == 'osint geolocate'
        assert data['city'] == 'Mountain View'
    
    @patch('gridland.core.osint.osint_report')
    def test_osint_full_endpoint(self, mock_report, client):
        """Test direct OSINT full endpoint."""
        mock_report.return_value = {
            'ip': '8.8.8.8',
            'geolocation': {'city': 'Test City'},
            'search_engine_urls': {'urls': {}},
            'google_dorks': [],
        }
        
        response = client.get('/api/cli/osint/full/8.8.8.8')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['command'] == 'osint full'
        assert data['ip'] == '8.8.8.8'
        assert 'geolocation' in data
    
    def test_osint_invalid_ip(self, client):
        """Test OSINT endpoint with invalid IP."""
        response = client.get('/api/cli/osint/dorks/invalid')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid IP address' in data['error']
    
    def test_osint_invalid_subcommand(self, client):
        """Test OSINT endpoint with invalid subcommand."""
        response = client.get('/api/cli/osint/invalid/8.8.8.8')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Unknown subcommand' in data['error']
        assert 'valid_subcommands' in data


class TestAvailableCommandsEndpoint:
    """Tests for /api/cli/available endpoint."""
    
    def test_available_commands(self, client):
        """Test available commands endpoint."""
        response = client.get('/api/cli/available')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert 'commands' in data
        commands = data['commands']
        
        # All 4 commands should be listed
        assert 'discover' in commands
        assert 'analyze' in commands
        assert 'osint' in commands
        assert 'stream' in commands
        
        # Each command should have description and subcommands
        for cmd_name, cmd_info in commands.items():
            assert 'description' in cmd_info
            assert 'subcommands' in cmd_info
        
        # OSINT should have direct endpoints
        assert 'direct_endpoints' in commands['osint']
        assert len(commands['osint']['direct_endpoints']) == 4


class TestCliIntegration:
    """Integration tests for CLI API."""
    
    def test_osint_dorks_integration(self, client):
        """Integration test for OSINT dorks (no mocking)."""
        response = client.get('/api/cli/osint/dorks/192.168.1.1')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify real data is returned
        assert data['count'] > 0
        assert len(data['dorks']) > 0
    
    def test_osint_search_urls_integration(self, client):
        """Integration test for OSINT search-urls (no mocking)."""
        response = client.get('/api/cli/osint/search-urls/10.0.0.1')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify real URLs are returned
        assert 'shodan.io' in data['urls']['shodan']
        assert 'censys.io' in data['urls']['censys']
