"""
Tests for GRIDLAND Server SSE Streaming Endpoints

Tests the /api/osint/stream and /api/analyze/stream SSE endpoints.
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


def parse_sse_events(response_data):
    """Parse SSE events from response data."""
    events = []
    lines = response_data.decode('utf-8').strip().split('\n\n')
    for line in lines:
        if line.startswith('data: '):
            try:
                event_data = json.loads(line[6:])
                events.append(event_data)
            except json.JSONDecodeError:
                pass
    return events


class TestOsintStreamEndpoint:
    """Tests for /api/osint/stream/<ip> SSE endpoint."""
    
    def test_osint_stream_valid_ip(self, client):
        """Test OSINT stream endpoint with valid IP."""
        response = client.get('/api/osint/stream/8.8.8.8')
        
        assert response.status_code == 200
        assert response.mimetype == 'text/event-stream'
        
        events = parse_sse_events(response.data)
        
        # Should have multiple events
        assert len(events) >= 5
        
        # Check for expected phases
        phases = [e.get('phase') for e in events]
        assert 'start' in phases
        assert 'search_urls' in phases
        assert 'google_dorks' in phases
        assert 'geolocation' in phases
        assert 'complete' in phases
    
    def test_osint_stream_progress_updates(self, client):
        """Test that OSINT stream includes progress updates."""
        response = client.get('/api/osint/stream/1.1.1.1')
        
        events = parse_sse_events(response.data)
        
        # Check progress increases
        progress_values = [e.get('progress', 0) for e in events if 'progress' in e]
        assert len(progress_values) > 0
        
        # Should start at 0 and end at 100
        assert progress_values[0] == 0
        assert progress_values[-1] == 100
        
        # Progress should generally increase
        for i in range(1, len(progress_values)):
            assert progress_values[i] >= progress_values[i-1]
    
    def test_osint_stream_data_returned(self, client):
        """Test that OSINT stream returns actual data."""
        response = client.get('/api/osint/stream/8.8.8.8')
        
        events = parse_sse_events(response.data)
        
        # Find search_urls complete event
        url_events = [e for e in events if e.get('phase') == 'search_urls' and e.get('status') == 'complete']
        assert len(url_events) > 0
        
        url_data = url_events[0].get('data', {})
        assert 'urls' in url_data
        assert 'count' in url_data
        assert url_data['count'] > 0
    
    def test_osint_stream_invalid_ip(self, client):
        """Test OSINT stream endpoint with invalid IP."""
        response = client.get('/api/osint/stream/not-valid')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid IP address' in data['error']


class TestAnalyzeStreamEndpoint:
    """Tests for /api/analyze/stream/<ip> SSE endpoint."""
    
    def test_analyze_stream_valid_ip(self, client):
        """Test analyze stream endpoint with valid IP (localhost)."""
        # Use localhost which should respond fast
        response = client.get('/api/analyze/stream/127.0.0.1')
        
        assert response.status_code == 200
        assert response.mimetype == 'text/event-stream'
        
        events = parse_sse_events(response.data)
        
        # Should have multiple events
        assert len(events) >= 5
        
        # Check for expected phases
        phases = [e.get('phase') for e in events]
        assert 'start' in phases
        assert 'port_scan' in phases
        assert 'service_detection' in phases
        assert 'camera_detection' in phases
        assert 'complete' in phases
    
    def test_analyze_stream_port_scan_data(self, client):
        """Test that analyze stream includes port scan data."""
        response = client.get('/api/analyze/stream/127.0.0.1')
        
        events = parse_sse_events(response.data)
        
        # Find port_scan complete event
        port_events = [e for e in events if e.get('phase') == 'port_scan' and e.get('status') == 'complete']
        assert len(port_events) > 0
        
        port_data = port_events[0].get('data', {})
        assert 'open_ports' in port_data
        assert 'count' in port_data
        assert isinstance(port_data['open_ports'], list)
    
    def test_analyze_stream_final_report(self, client):
        """Test that analyze stream returns final report."""
        response = client.get('/api/analyze/stream/127.0.0.1')
        
        events = parse_sse_events(response.data)
        
        # Find complete event
        complete_events = [e for e in events if e.get('phase') == 'complete' and e.get('status') == 'done']
        assert len(complete_events) > 0
        
        report = complete_events[0].get('data', {})
        assert 'ip' in report
        assert 'open_ports' in report
        assert 'services' in report
        assert 'camera' in report
        assert 'summary' in report
    
    def test_analyze_stream_invalid_ip(self, client):
        """Test analyze stream endpoint with invalid IP."""
        response = client.get('/api/analyze/stream/invalid')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid IP address' in data['error']


class TestSSEIntegration:
    """Integration tests for SSE streaming."""
    
    def test_osint_stream_headers(self, client):
        """Test SSE response headers."""
        response = client.get('/api/osint/stream/1.2.3.4')
        
        assert response.headers.get('Cache-Control') == 'no-cache'
        assert response.headers.get('Connection') == 'keep-alive'
    
    def test_analyze_stream_headers(self, client):
        """Test analyze SSE response headers."""
        response = client.get('/api/analyze/stream/127.0.0.1')
        
        assert response.headers.get('Cache-Control') == 'no-cache'
        assert response.headers.get('Connection') == 'keep-alive'
    
    def test_osint_stream_complete_cycle(self, client):
        """Test complete OSINT stream cycle."""
        response = client.get('/api/osint/stream/8.8.8.8')
        
        events = parse_sse_events(response.data)
        
        # Should complete successfully
        complete_events = [e for e in events if e.get('status') == 'done']
        assert len(complete_events) > 0
        
        # Should not have any errors in main phases
        error_events = [e for e in events if e.get('status') == 'error']
        assert len(error_events) == 0
