"""
GRIDLAND OSINT (Open Source Intelligence) Module

Provides intelligence gathering capabilities from CamXploit.py:
- Google dorking query generation
- IP geolocation via ipinfo.io
- Search engine URL generation (Shodan, Censys, ZoomEye, etc.)

Ported from CamXploit.py functions:
- google_dork_search() (lines 901-910)
- get_ip_location_info() (lines 913-950)
- print_search_urls() (lines 891-898)
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote_plus

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GeoLocation:
    """IP geolocation result from ipinfo.io."""
    
    ip: str
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    org: Optional[str] = None  # ISP
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    @property
    def google_maps_url(self) -> Optional[str]:
        """Generate Google Maps URL for coordinates."""
        if self.latitude and self.longitude:
            return f"https://www.google.com/maps?q={self.latitude},{self.longitude}"
        return None
    
    @property
    def google_earth_url(self) -> Optional[str]:
        """Generate Google Earth URL for coordinates."""
        if self.latitude and self.longitude:
            return f"https://earth.google.com/web/@{self.latitude},{self.longitude},0a,1000d,35y,0h,0t,0r"
        return None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "postal": self.postal,
            "timezone": self.timezone,
            "org": self.org,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "google_maps_url": self.google_maps_url,
            "google_earth_url": self.google_earth_url,
        }


@dataclass
class SearchEngineURLs:
    """Search engine URLs for IP investigation."""
    
    ip: str
    urls: dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Generate all search engine URLs."""
        self.urls = {
            "shodan": f"https://www.shodan.io/search?query={self.ip}",
            "censys": f"https://search.censys.io/hosts/{self.ip}",
            "zoomeye": f"https://www.zoomeye.org/searchResult?q={self.ip}",
            "greynoise": f"https://viz.greynoise.io/ip/{self.ip}",
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{self.ip}",
            "abuseipdb": f"https://www.abuseipdb.com/check/{self.ip}",
            "ipinfo": f"https://ipinfo.io/{self.ip}",
            "whois": f"https://whois.domaintools.com/{self.ip}",
        }
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {"ip": self.ip, "urls": self.urls}


@dataclass
class GoogleDork:
    """A Google dork query for camera discovery."""
    
    query: str
    description: str
    category: str  # e.g., "camera_interface", "login", "stream"
    
    @property
    def search_url(self) -> str:
        """Generate Google search URL."""
        return f"https://www.google.com/search?q={quote_plus(self.query)}"


class GoogleDorkGenerator:
    """
    Generate Google dork queries for camera discovery.
    
    Ported from CamXploit.py google_dork_search() function.
    """
    
    # Camera-specific dork templates
    CAMERA_DORKS = [
        # IP-specific dorks
        ("site:{ip} inurl:view/view.shtml", "Camera view page", "camera_interface"),
        ("site:{ip} inurl:admin.html", "Admin interface", "admin"),
        ("site:{ip} inurl:login", "Login page", "login"),
        ("intitle:'webcam' inurl:{ip}", "Webcam interface", "webcam"),
        ("site:{ip} inurl:cgi-bin", "CGI endpoints", "cgi"),
        ("site:{ip} inurl:video", "Video endpoints", "stream"),
        ("site:{ip} inurl:stream", "Stream endpoints", "stream"),
        ("site:{ip} inurl:mjpg", "MJPEG streams", "stream"),
        ("site:{ip} inurl:snapshot", "Snapshot endpoints", "snapshot"),
        
        # Brand-specific dorks
        ("site:{ip} intitle:'Hikvision'", "Hikvision camera", "brand"),
        ("site:{ip} intitle:'Dahua'", "Dahua camera", "brand"),
        ("site:{ip} intitle:'Axis'", "Axis camera", "brand"),
        ("site:{ip} intitle:'DVR'", "DVR interface", "dvr"),
        ("site:{ip} intitle:'NVR'", "NVR interface", "nvr"),
        ("site:{ip} intitle:'Network Camera'", "Network camera", "camera_interface"),
        ("site:{ip} intitle:'IP Camera'", "IP camera", "camera_interface"),
        
        # Vulnerability-related dorks
        ("site:{ip} inurl:ISAPI", "Hikvision ISAPI", "vulnerability"),
        ("site:{ip} inurl:cgi-bin/magicBox", "Dahua endpoint", "vulnerability"),
        ("site:{ip} inurl:onvif", "ONVIF endpoint", "onvif"),
    ]
    
    # General camera dorks (not IP-specific)
    GENERAL_DORKS = [
        ('intitle:"Live View / - AXIS"', "Axis cameras", "axis"),
        ('inurl:ViewerFrame?Mode=', "Generic webcams", "webcam"),
        ('inurl:axis-cgi/mjpg', "Axis MJPEG streams", "axis"),
        ('inurl:view/singleFrame', "Single frame viewers", "viewer"),
        ('intitle:"webcamXP 5"', "WebcamXP software", "software"),
        ('inurl:"ViewerFrame?Mode=Motion"', "Motion detection cams", "motion"),
        ('inurl:CgiStart', "CGI webcams", "cgi"),
        ('inurl:video/mjpg.cgi', "MJPEG CGI streams", "stream"),
        ('intitle:"Network Camera" inurl:main.cgi', "Network cameras", "camera"),
        ('inurl:/view/index.shtml', "View pages", "viewer"),
        ('inurl:cgi-bin/viewer/video.jpg', "Video viewers", "viewer"),
        ('intitle:"BlueIris Login"', "Blue Iris NVR", "nvr"),
        ('intitle:"DVR Login"', "DVR login pages", "dvr"),
        ('inurl:8080 intitle:webcam', "Webcams on port 8080", "webcam"),
    ]
    
    def generate_ip_dorks(self, ip: str) -> list[GoogleDork]:
        """Generate IP-specific Google dork queries."""
        dorks = []
        for template, description, category in self.CAMERA_DORKS:
            query = template.format(ip=ip)
            dorks.append(GoogleDork(query=query, description=description, category=category))
        return dorks
    
    def generate_general_dorks(self) -> list[GoogleDork]:
        """Generate general camera discovery dorks."""
        dorks = []
        for query, description, category in self.GENERAL_DORKS:
            dorks.append(GoogleDork(query=query, description=description, category=category))
        return dorks
    
    def get_dork_urls(self, ip: str) -> dict[str, str]:
        """Get dictionary of dork queries and their Google search URLs."""
        dorks = self.generate_ip_dorks(ip)
        return {dork.query: dork.search_url for dork in dorks}


class IPGeolocationService:
    """
    IP geolocation service using ipinfo.io.
    
    Ported from CamXploit.py get_ip_location_info() function.
    """
    
    API_URL = "https://ipinfo.io/{ip}/json"
    
    async def get_location(self, ip: str, timeout: float = 10.0) -> Optional[GeoLocation]:
        """
        Get geolocation information for an IP address.
        
        Args:
            ip: IP address to look up
            timeout: Request timeout in seconds
            
        Returns:
            GeoLocation object or None if lookup fails
        """
        try:
            url = self.API_URL.format(ip=ip)
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Parse coordinates
                        latitude = None
                        longitude = None
                        if "loc" in data:
                            try:
                                lat_str, lon_str = data["loc"].split(",")
                                latitude = float(lat_str)
                                longitude = float(lon_str)
                            except (ValueError, TypeError):
                                pass
                        
                        return GeoLocation(
                            ip=data.get("ip", ip),
                            city=data.get("city"),
                            region=data.get("region"),
                            country=data.get("country"),
                            postal=data.get("postal"),
                            timezone=data.get("timezone"),
                            org=data.get("org"),
                            latitude=latitude,
                            longitude=longitude,
                        )
                    else:
                        logger.warning(f"IP geolocation failed with status {response.status}")
                        return None
                        
        except asyncio.TimeoutError:
            logger.warning(f"IP geolocation timed out for {ip}")
            return None
        except Exception as e:
            logger.error(f"IP geolocation error: {e}")
            return None
    
    def get_location_sync(self, ip: str, timeout: float = 10.0) -> Optional[GeoLocation]:
        """Synchronous wrapper for get_location."""
        import requests
        
        try:
            url = self.API_URL.format(ip=ip)
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                latitude = None
                longitude = None
                if "loc" in data:
                    try:
                        lat_str, lon_str = data["loc"].split(",")
                        latitude = float(lat_str)
                        longitude = float(lon_str)
                    except (ValueError, TypeError):
                        pass
                
                return GeoLocation(
                    ip=data.get("ip", ip),
                    city=data.get("city"),
                    region=data.get("region"),
                    country=data.get("country"),
                    postal=data.get("postal"),
                    timezone=data.get("timezone"),
                    org=data.get("org"),
                    latitude=latitude,
                    longitude=longitude,
                )
            return None
            
        except Exception as e:
            logger.error(f"IP geolocation error: {e}")
            return None


class OSINTEngine:
    """
    Main OSINT engine combining all intelligence gathering capabilities.
    """
    
    def __init__(self):
        self.dork_generator = GoogleDorkGenerator()
        self.geolocation_service = IPGeolocationService()
    
    def get_search_engine_urls(self, ip: str) -> SearchEngineURLs:
        """Get search engine investigation URLs for an IP."""
        return SearchEngineURLs(ip=ip)
    
    def get_google_dorks(self, ip: str) -> list[GoogleDork]:
        """Get Google dork queries for an IP."""
        return self.dork_generator.generate_ip_dorks(ip)
    
    async def get_geolocation(self, ip: str) -> Optional[GeoLocation]:
        """Get IP geolocation."""
        return await self.geolocation_service.get_location(ip)
    
    def get_geolocation_sync(self, ip: str) -> Optional[GeoLocation]:
        """Get IP geolocation (synchronous)."""
        return self.geolocation_service.get_location_sync(ip)
    
    async def full_osint_report(self, ip: str) -> dict:
        """
        Generate a full OSINT report for an IP address.
        
        Returns:
            Dictionary containing all OSINT data
        """
        # Get all data
        geolocation = await self.get_geolocation(ip)
        search_urls = self.get_search_engine_urls(ip)
        dorks = self.get_google_dorks(ip)
        
        return {
            "ip": ip,
            "geolocation": geolocation.to_dict() if geolocation else None,
            "search_engine_urls": search_urls.to_dict(),
            "google_dorks": [
                {"query": d.query, "url": d.search_url, "category": d.category}
                for d in dorks
            ],
        }
    
    def full_osint_report_sync(self, ip: str) -> dict:
        """Generate a full OSINT report (synchronous)."""
        geolocation = self.get_geolocation_sync(ip)
        search_urls = self.get_search_engine_urls(ip)
        dorks = self.get_google_dorks(ip)
        
        return {
            "ip": ip,
            "geolocation": geolocation.to_dict() if geolocation else None,
            "search_engine_urls": search_urls.to_dict(),
            "google_dorks": [
                {"query": d.query, "url": d.search_url, "category": d.category}
                for d in dorks
            ],
        }


# Module-level convenience functions
_engine = None


def get_osint_engine() -> OSINTEngine:
    """Get or create the singleton OSINT engine."""
    global _engine
    if _engine is None:
        _engine = OSINTEngine()
    return _engine


def get_search_urls(ip: str) -> dict[str, str]:
    """Get search engine URLs for an IP address."""
    return get_osint_engine().get_search_engine_urls(ip).urls


def get_google_dork_urls(ip: str) -> dict[str, str]:
    """Get Google dork URLs for an IP address."""
    return get_osint_engine().dork_generator.get_dork_urls(ip)


def get_geolocation(ip: str) -> Optional[GeoLocation]:
    """Get IP geolocation (synchronous)."""
    return get_osint_engine().get_geolocation_sync(ip)


async def get_geolocation_async(ip: str) -> Optional[GeoLocation]:
    """Get IP geolocation (asynchronous)."""
    return await get_osint_engine().get_geolocation(ip)


def osint_report(ip: str) -> dict:
    """Generate full OSINT report (synchronous)."""
    return get_osint_engine().full_osint_report_sync(ip)


async def osint_report_async(ip: str) -> dict:
    """Generate full OSINT report (asynchronous)."""
    return await get_osint_engine().full_osint_report(ip)
