"""
Tests for GRIDLAND OSINT Module

Tests Google dorking, IP geolocation, and search engine URL generation.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from gridland.core.osint import (
    GeoLocation,
    SearchEngineURLs,
    GoogleDork,
    GoogleDorkGenerator,
    IPGeolocationService,
    OSINTEngine,
    get_osint_engine,
    get_search_urls,
    get_google_dork_urls,
)


class TestGeoLocation:
    """Tests for GeoLocation dataclass."""
    
    def test_geolocation_creation(self):
        """Test GeoLocation can be created with all fields."""
        geo = GeoLocation(
            ip="8.8.8.8",
            city="Mountain View",
            region="California",
            country="US",
            latitude=37.4056,
            longitude=-122.0775,
            org="Google LLC",
        )
        assert geo.ip == "8.8.8.8"
        assert geo.city == "Mountain View"
        assert geo.country == "US"
    
    def test_google_maps_url(self):
        """Test Google Maps URL generation."""
        geo = GeoLocation(
            ip="8.8.8.8",
            latitude=37.4056,
            longitude=-122.0775,
        )
        assert geo.google_maps_url is not None
        assert "37.4056" in geo.google_maps_url
        assert "-122.0775" in geo.google_maps_url
        assert "google.com/maps" in geo.google_maps_url
    
    def test_google_earth_url(self):
        """Test Google Earth URL generation."""
        geo = GeoLocation(
            ip="8.8.8.8",
            latitude=37.4056,
            longitude=-122.0775,
        )
        assert geo.google_earth_url is not None
        assert "earth.google.com" in geo.google_earth_url
    
    def test_no_coordinates_returns_none(self):
        """Test that missing coordinates return None for map URLs."""
        geo = GeoLocation(ip="8.8.8.8")
        assert geo.google_maps_url is None
        assert geo.google_earth_url is None
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        geo = GeoLocation(
            ip="192.168.1.1",
            city="Test City",
            latitude=10.0,
            longitude=20.0,
        )
        result = geo.to_dict()
        assert result["ip"] == "192.168.1.1"
        assert result["city"] == "Test City"
        assert result["google_maps_url"] is not None


class TestSearchEngineURLs:
    """Tests for SearchEngineURLs dataclass."""
    
    def test_search_urls_creation(self):
        """Test SearchEngineURLs generates all expected URLs."""
        urls = SearchEngineURLs(ip="192.168.1.1")
        assert "shodan" in urls.urls
        assert "censys" in urls.urls
        assert "zoomeye" in urls.urls
        assert "greynoise" in urls.urls
        assert "virustotal" in urls.urls
    
    def test_shodan_url_format(self):
        """Test Shodan URL format."""
        urls = SearchEngineURLs(ip="10.0.0.1")
        assert "10.0.0.1" in urls.urls["shodan"]
        assert "shodan.io" in urls.urls["shodan"]
    
    def test_censys_url_format(self):
        """Test Censys URL format."""
        urls = SearchEngineURLs(ip="1.2.3.4")
        assert "1.2.3.4" in urls.urls["censys"]
        assert "censys.io" in urls.urls["censys"]
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        urls = SearchEngineURLs(ip="8.8.8.8")
        result = urls.to_dict()
        assert result["ip"] == "8.8.8.8"
        assert "urls" in result
        assert len(result["urls"]) >= 5


class TestGoogleDorkGenerator:
    """Tests for GoogleDorkGenerator class."""
    
    def test_generate_ip_dorks(self):
        """Test IP-specific dork generation."""
        generator = GoogleDorkGenerator()
        dorks = generator.generate_ip_dorks("192.168.1.100")
        
        assert len(dorks) > 0
        assert all(isinstance(d, GoogleDork) for d in dorks)
        
        # Check IP is substituted
        for dork in dorks:
            assert "192.168.1.100" in dork.query
    
    def test_generate_general_dorks(self):
        """Test general dork generation."""
        generator = GoogleDorkGenerator()
        dorks = generator.generate_general_dorks()
        
        assert len(dorks) > 0
        assert all(isinstance(d, GoogleDork) for d in dorks)
    
    def test_dork_has_search_url(self):
        """Test that dorks have valid search URLs."""
        generator = GoogleDorkGenerator()
        dorks = generator.generate_ip_dorks("10.0.0.1")
        
        for dork in dorks:
            assert dork.search_url.startswith("https://www.google.com/search")
    
    def test_dork_categories(self):
        """Test that dorks have categories."""
        generator = GoogleDorkGenerator()
        dorks = generator.generate_ip_dorks("1.1.1.1")
        
        categories = {d.category for d in dorks}
        assert len(categories) > 1  # Multiple categories
    
    def test_get_dork_urls(self):
        """Test get_dork_urls returns dict."""
        generator = GoogleDorkGenerator()
        urls = generator.get_dork_urls("8.8.4.4")
        
        assert isinstance(urls, dict)
        assert len(urls) > 0


class TestIPGeolocationService:
    """Tests for IPGeolocationService class."""
    
    def test_api_url_format(self):
        """Test API URL is correctly formatted."""
        service = IPGeolocationService()
        assert "{ip}" in service.API_URL
        assert "ipinfo.io" in service.API_URL
    
    @patch("requests.get")
    def test_get_location_sync_success(self, mock_get):
        """Test successful sync geolocation lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "Google LLC",
            "timezone": "America/Los_Angeles",
        }
        mock_get.return_value = mock_response
        
        service = IPGeolocationService()
        result = service.get_location_sync("8.8.8.8")
        
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.city == "Mountain View"
        assert result.latitude == pytest.approx(37.4056)
        assert result.longitude == pytest.approx(-122.0775)
    
    @patch("requests.get")
    def test_get_location_sync_failure(self, mock_get):
        """Test failed sync geolocation lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        service = IPGeolocationService()
        result = service.get_location_sync("invalid")
        
        assert result is None


class TestOSINTEngine:
    """Tests for OSINTEngine class."""
    
    def test_engine_creation(self):
        """Test OSINTEngine can be created."""
        engine = OSINTEngine()
        assert engine.dork_generator is not None
        assert engine.geolocation_service is not None
    
    def test_get_search_engine_urls(self):
        """Test getting search engine URLs."""
        engine = OSINTEngine()
        urls = engine.get_search_engine_urls("1.2.3.4")
        
        assert isinstance(urls, SearchEngineURLs)
        assert urls.ip == "1.2.3.4"
    
    def test_get_google_dorks(self):
        """Test getting Google dorks."""
        engine = OSINTEngine()
        dorks = engine.get_google_dorks("10.0.0.1")
        
        assert len(dorks) > 0
        assert all(isinstance(d, GoogleDork) for d in dorks)


class TestModuleFunctions:
    """Tests for module-level convenience functions."""
    
    def test_get_osint_engine_singleton(self):
        """Test that get_osint_engine returns same instance."""
        engine1 = get_osint_engine()
        engine2 = get_osint_engine()
        assert engine1 is engine2
    
    def test_get_search_urls(self):
        """Test get_search_urls function."""
        urls = get_search_urls("192.168.0.1")
        
        assert isinstance(urls, dict)
        assert "shodan" in urls
        assert "censys" in urls
    
    def test_get_google_dork_urls(self):
        """Test get_google_dork_urls function."""
        urls = get_google_dork_urls("10.10.10.10")
        
        assert isinstance(urls, dict)
        assert len(urls) > 0
        for query, url in urls.items():
            assert "10.10.10.10" in query
            assert url.startswith("https://")
