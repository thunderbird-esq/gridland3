"""IP Geolocation Lookup for GRIDLAND.

This module provides async IP geolocation lookup using IPinfo.io API,
including map URL generation for Google Maps and Google Earth.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

try:
    import aiohttp
except ImportError:
    aiohttp = None


class GeoLookup:
    """Async IP geolocation lookup service.

    Provides IP address geolocation using IPinfo.io API with caching
    and rate limiting support. Generates map URLs for visualization.

    Attributes:
        api_endpoint: Base URL for IPinfo.io API.
        cache: Dictionary storing cached lookup results.
        cache_duration: How long to cache results (seconds).
        rate_limit_delay: Minimum delay between API calls (seconds).
        last_request_time: Timestamp of last API request.

    Example:
        >>> async def lookup_ip():
        ...     geo = GeoLookup()
        ...     info = await geo.get_ip_info("8.8.8.8")
        ...     print(info['city'])
        >>> asyncio.run(lookup_ip())
    """

    def __init__(
        self,
        cache_duration: int = 3600,
        rate_limit_delay: float = 0.1,
    ):
        """Initialize GeoLookup service.

        Args:
            cache_duration: How long to cache results in seconds (default: 3600).
            rate_limit_delay: Minimum seconds between API calls (default: 0.1).
        """
        self.api_endpoint = "https://ipinfo.io"
        self.cache: dict[str, tuple[dict, datetime]] = {}
        self.cache_duration = cache_duration
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time: datetime | None = None

    async def get_ip_info(
        self,
        ip: str,
        use_cache: bool = True,
    ) -> dict[str, str]:
        """Get comprehensive geolocation information for an IP address.

        Performs async lookup using IPinfo.io API (CamXploit.py line 877).
        Returns location data including coordinates, city, region, country,
        and ISP information.

        Args:
            ip: IP address to lookup (IPv4 or IPv6).
            use_cache: Whether to use cached results (default: True).

        Returns:
            Dict[str, str]: Dictionary containing:
                - ip: IP address
                - org: ISP/Organization
                - loc: Coordinates as "lat,lon" string
                - city: City name
                - region: Region/state name
                - country: Country code
                - postal: Postal/ZIP code (if available)
                - timezone: Timezone (if available)

        Raises:
            aiohttp.ClientError: If API request fails.
            ValueError: If aiohttp is not installed.

        Example:
            >>> async def example():
            ...     geo = GeoLookup()
            ...     info = await geo.get_ip_info("8.8.8.8")
            ...     return info
            >>> result = asyncio.run(example())
            >>> print(result['city'])
            Mountain View
        """
        if aiohttp is None:
            raise ValueError(
                "aiohttp is required for GeoLookup. " "Install with: pip install aiohttp"
            )

        # Check cache first
        if use_cache and ip in self.cache:
            cached_data, cached_time = self.cache[ip]
            if datetime.now() - cached_time < timedelta(seconds=self.cache_duration):
                return cached_data

        # Apply rate limiting
        if self.last_request_time:
            elapsed = (datetime.now() - self.last_request_time).total_seconds()
            if elapsed < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - elapsed)

        # Perform API request
        url = f"{self.api_endpoint}/{ip}/json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()

        self.last_request_time = datetime.now()

        # Cache the result
        self.cache[ip] = (data, datetime.now())

        return data

    @staticmethod
    def generate_map_urls(
        ip_info: dict[str, str], osm_base_url: str = "https://www.openstreetmap.org"
    ) -> dict[str, str]:
        """Generate map visualization URLs from IP geolocation data.

        Creates OpenStreetMap URLs using coordinates from IP lookup results.
        Supports both public OSM and local hosted instances for privacy.

        Args:
            ip_info: IP info dict from get_ip_info() containing 'loc' key.
            osm_base_url: Base URL for OpenStreetMap instance. Defaults to
                         public OSM. Use "http://localhost:PORT" for local.

        Returns:
            Dict[str, str]: Dictionary with 'openstreetmap' URL and separate
                           'latitude'/'longitude' values. Returns empty dict
                           if no coordinates are available.

        Example:
            >>> async def example():
            ...     geo = GeoLookup()
            ...     info = await geo.get_ip_info("8.8.8.8")
            ...     # Public OSM
            ...     urls = GeoLookup.generate_map_urls(info)
            ...     # Local OSM instance
            ...     urls_local = GeoLookup.generate_map_urls(
            ...         info, osm_base_url="http://localhost:8080"
            ...     )
            ...     return urls
            >>> urls = asyncio.run(example())
            >>> print(urls['openstreetmap'])
            https://www.openstreetmap.org/?mlat=37.4056&mlon=-122.0775#map=12/37.4056/-122.0775
        """
        if "loc" not in ip_info:
            return {}

        lat, lon = ip_info["loc"].split(",")

        return {
            "openstreetmap": f"{osm_base_url}/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}",
            "latitude": lat,
            "longitude": lon,
        }

    def clear_cache(self) -> None:
        """Clear all cached IP lookup results.

        Example:
            >>> geo = GeoLookup()
            >>> geo.clear_cache()
        """
        self.cache.clear()

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics.

        Returns:
            Dict[str, int]: Dictionary with 'total_cached' and 'expired' counts.

        Example:
            >>> geo = GeoLookup()
            >>> stats = geo.get_cache_stats()
            >>> print(f"Cached: {stats['total_cached']}")
        """
        now = datetime.now()
        expired = sum(
            1
            for _, cached_time in self.cache.values()
            if now - cached_time >= timedelta(seconds=self.cache_duration)
        )

        return {
            "total_cached": len(self.cache),
            "expired": expired,
        }
