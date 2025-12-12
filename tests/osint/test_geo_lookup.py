"""Unit tests for IP Geolocation Lookup.

Tests async IP lookup with mocked IPinfo.io API responses.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gridland.analyze.core.osint.geo_lookup import GeoLookup


class TestGeoLookup:
    """Tests for GeoLookup class."""

    @pytest.fixture
    def mock_ip_response(self):
        """Mock IPinfo.io API response."""
        return {
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "org": "AS15169 Google LLC",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
        }

    @pytest.mark.asyncio
    async def test_get_ip_info_success(self, mock_ip_response):
        """Test successful IP lookup."""
        geo = GeoLookup()

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_ip_response)
            mock_response.raise_for_status = MagicMock()

            # Create async context manager for get()
            mock_get = AsyncMock()
            mock_get.__aenter__.return_value = mock_response

            mock_session.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_get)

            result = await geo.get_ip_info("8.8.8.8")

            assert result["ip"] == "8.8.8.8"
            assert result["city"] == "Mountain View"
            assert result["region"] == "California"
            assert result["country"] == "US"
            assert result["loc"] == "37.4056,-122.0775"
            assert result["org"] == "AS15169 Google LLC"

    @pytest.mark.asyncio
    async def test_get_ip_info_caching(self, mock_ip_response):
        """Test that results are cached correctly."""
        geo = GeoLookup(cache_duration=60)

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_ip_response)
            mock_response.raise_for_status = MagicMock()

            # Create async context manager for get()
            mock_get = AsyncMock()
            mock_get.__aenter__.return_value = mock_response

            mock_session.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_get)

            # First call - should hit API
            result1 = await geo.get_ip_info("8.8.8.8", use_cache=True)
            assert "8.8.8.8" in geo.cache

            # Second call - should use cache
            result2 = await geo.get_ip_info("8.8.8.8", use_cache=True)

            # Results should be identical
            assert result1 == result2

            # API should only be called once
            assert mock_response.json.call_count == 1

    @pytest.mark.asyncio
    async def test_get_ip_info_cache_bypass(self, mock_ip_response):
        """Test cache bypass when use_cache=False."""
        geo = GeoLookup()

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_ip_response)
            mock_response.raise_for_status = MagicMock()

            # Create async context manager for get()
            mock_get = AsyncMock()
            mock_get.__aenter__.return_value = mock_response

            mock_session.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_get)

            # First call with caching
            await geo.get_ip_info("8.8.8.8", use_cache=True)

            # Second call bypassing cache
            await geo.get_ip_info("8.8.8.8", use_cache=False)

            # API should be called twice
            assert mock_response.json.call_count == 2

    @pytest.mark.asyncio
    async def test_get_ip_info_cache_expiration(self, mock_ip_response):
        """Test that cache expires after duration."""
        geo = GeoLookup(cache_duration=1)  # 1 second cache

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_ip_response)
            mock_response.raise_for_status = MagicMock()

            # Create async context manager for get()
            mock_get = AsyncMock()
            mock_get.__aenter__.return_value = mock_response

            mock_session.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_get)

            # First call
            await geo.get_ip_info("8.8.8.8")

            # Manually expire cache
            cached_data, _ = geo.cache["8.8.8.8"]
            geo.cache["8.8.8.8"] = (
                cached_data,
                datetime.now() - timedelta(seconds=2),
            )

            # Second call should hit API again
            await geo.get_ip_info("8.8.8.8")

            assert mock_response.json.call_count == 2

    @pytest.mark.asyncio
    async def test_get_ip_info_api_error(self):
        """Test API failure handling."""
        geo = GeoLookup()

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 500
            mock_response.raise_for_status = MagicMock(side_effect=Exception("API Error"))

            # Create async context manager for get()
            mock_get = AsyncMock()
            mock_get.__aenter__.return_value = mock_response

            mock_session.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_get)

            with pytest.raises(Exception, match="API Error"):
                await geo.get_ip_info("8.8.8.8")

    @pytest.mark.asyncio
    async def test_rate_limiting(self, mock_ip_response):
        """Test rate limiting behavior."""
        geo = GeoLookup(rate_limit_delay=0.1)

        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_ip_response)
            mock_response.raise_for_status = MagicMock()

            # Create async context manager for get()
            mock_get = AsyncMock()
            mock_get.__aenter__.return_value = mock_response

            mock_session.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_get)

            start_time = datetime.now()

            # Make two requests (cache disabled)
            await geo.get_ip_info("8.8.8.8", use_cache=False)
            await geo.get_ip_info("1.1.1.1", use_cache=False)

            elapsed = (datetime.now() - start_time).total_seconds()

            # Should have at least rate_limit_delay between calls
            assert elapsed >= geo.rate_limit_delay

    def test_generate_map_urls_with_coordinates(self):
        """Test map URL generation from IP info with coordinates."""
        ip_info = {
            "ip": "8.8.8.8",
            "loc": "37.4056,-122.0775",
            "city": "Mountain View",
        }

        urls = GeoLookup.generate_map_urls(ip_info)

        assert "openstreetmap" in urls
        assert "latitude" in urls
        assert "longitude" in urls

        # Verify OSM URL format (public instance)
        expected_osm = (
            "https://www.openstreetmap.org/?mlat=37.4056&mlon=-122.0775" "#map=12/37.4056/-122.0775"
        )
        assert urls["openstreetmap"] == expected_osm

        # Verify separate lat/lon values
        assert urls["latitude"] == "37.4056"
        assert urls["longitude"] == "-122.0775"

    def test_generate_map_urls_without_coordinates(self):
        """Test map URL generation when no coordinates available."""
        ip_info = {"ip": "8.8.8.8", "city": "Mountain View"}

        urls = GeoLookup.generate_map_urls(ip_info)

        assert urls == {}

    def test_generate_map_urls_lat_lon_parsing(self):
        """Test that lat/lon are correctly parsed from loc field."""
        ip_info = {"loc": "51.5074,-0.1278"}  # London

        urls = GeoLookup.generate_map_urls(ip_info)

        # Check OSM URL contains coordinates
        assert "51.5074" in urls["openstreetmap"]
        assert "-0.1278" in urls["openstreetmap"]

        # Check separate lat/lon fields
        assert urls["latitude"] == "51.5074"
        assert urls["longitude"] == "-0.1278"

    def test_clear_cache(self):
        """Test cache clearing."""
        geo = GeoLookup()
        geo.cache["8.8.8.8"] = ({"ip": "8.8.8.8"}, datetime.now())
        geo.cache["1.1.1.1"] = ({"ip": "1.1.1.1"}, datetime.now())

        assert len(geo.cache) == 2

        geo.clear_cache()

        assert len(geo.cache) == 0

    def test_get_cache_stats(self):
        """Test cache statistics."""
        geo = GeoLookup(cache_duration=60)

        # Add some cached entries
        now = datetime.now()
        geo.cache["8.8.8.8"] = ({"ip": "8.8.8.8"}, now)
        geo.cache["1.1.1.1"] = (
            {"ip": "1.1.1.1"},
            now - timedelta(seconds=100),
        )  # Expired

        stats = geo.get_cache_stats()

        assert stats["total_cached"] == 2
        assert stats["expired"] == 1

    def test_initialization_with_custom_params(self):
        """Test initialization with custom parameters."""
        geo = GeoLookup(cache_duration=7200, rate_limit_delay=0.5)

        assert geo.cache_duration == 7200
        assert geo.rate_limit_delay == 0.5
        assert geo.api_endpoint == "https://ipinfo.io"
        assert geo.last_request_time is None

    def test_initialization_defaults(self):
        """Test default initialization parameters."""
        geo = GeoLookup()

        assert geo.cache_duration == 3600
        assert geo.rate_limit_delay == 0.1
        assert len(geo.cache) == 0

    @pytest.mark.asyncio
    async def test_aiohttp_not_installed(self):
        """Test error when aiohttp is not installed."""
        geo = GeoLookup()

        with patch("gridland.analyze.core.osint.geo_lookup.aiohttp", None):
            with pytest.raises(ValueError, match="aiohttp is required"):
                await geo.get_ip_info("8.8.8.8")

    def test_static_method_callable_without_instance(self):
        """Test that generate_map_urls works as static method."""
        ip_info = {"loc": "40.7128,-74.0060"}  # NYC

        urls = GeoLookup.generate_map_urls(ip_info)

        assert "openstreetmap" in urls
        assert "latitude" in urls
        assert "longitude" in urls

    def test_generate_map_urls_local_osm_instance(self):
        """Test map URL generation with local OSM instance."""
        ip_info = {"loc": "48.8566,2.3522"}  # Paris

        urls = GeoLookup.generate_map_urls(ip_info, osm_base_url="http://localhost:8080")

        # Verify local instance URL
        expected_osm = "http://localhost:8080/?mlat=48.8566&mlon=2.3522" "#map=12/48.8566/2.3522"
        assert urls["openstreetmap"] == expected_osm

        # Lat/lon should still be present
        assert urls["latitude"] == "48.8566"
        assert urls["longitude"] == "2.3522"
