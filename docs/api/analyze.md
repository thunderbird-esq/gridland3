# Analyze Modules API

The analyze modules provide camera brand detection, CVE lookup, OSINT reconnaissance, and stream discovery capabilities.

## gridland.analyze.core

Core analysis functionality.

### BrandDetector

Camera manufacturer identification through HTTP response analysis.

#### \_\_init\_\_()

```python
from gridland.analyze.core import BrandDetector

detector = BrandDetector()
```

#### detect_brand(port_data)

Analyze a single port's HTTP response.

```python
port_data = {
    'server_header': 'hikvision-dvr',
    'content_type': 'image/jpeg',
    'response_body': '<html>Camera Login</html>'
}

result = detector.detect_brand(port_data)
# Returns: {
#   'brand': 'hikvision',
#   'confidence': 0.7,
#   'evidence': ['Server header: hikvision-dvr', 'Content-type: image/jpeg']
# }
```

**Parameters:**
- `port_data` (dict): HTTP response data with keys:
  - `server_header` (str, optional): Server HTTP header
  - `content_type` (str, optional): Content-Type HTTP header
  - `response_body` (str, optional): Response body text

**Returns:**
- `dict`: Detection result with keys:
  - `brand` (str): Detected brand name
  - `confidence` (float): Confidence score (0.0-1.0)
  - `evidence` (list[str]): List of evidence strings

**Supported Brands:**
- hikvision
- dahua
- axis
- sony
- bosch
- samsung
- panasonic
- vivotek
- cp_plus
- generic

#### analyze_all_ports(ports_data)

Aggregate brand detections across multiple ports.

```python
ports_data = [
    {
        'port': 80,
        'server_header': 'camera',
        'content_type': 'text/html',
        'response_body': 'surveillance'
    },
    {
        'port': 8080,
        'server_header': 'hikvision-dvr',
        'content_type': 'image/jpeg',
        'response_body': ''
    }
]

result = detector.analyze_all_ports(ports_data)
# Returns: {
#   'brand': 'hikvision',  # Specific brand wins over generic
#   'confidence': 0.7,
#   'evidence': [...]
# }
```

**Parameters:**
- `ports_data` (list[dict]): List of port response data

**Returns:**
- `dict`: Aggregated detection result

**Conflict Resolution:**
- Specific brands (hikvision, dahua, etc.) take precedence over generic
- Highest confidence score wins
- Evidence is merged from all detections

### CVELookup

CVE database integration with filtering and URL generation.

#### \_\_init\_\_()

```python
from gridland.analyze.core import CVELookup

lookup = CVELookup()
```

#### get_cves(brand, min_severity=None, exploits_only=False)

Retrieve CVEs with optional filtering.

```python
# Get all CVEs for Hikvision
hik_cves = lookup.get_cves('hikvision')
# Returns: list of 12 CVE dicts

# Get only critical CVEs
critical = lookup.get_cves('hikvision', min_severity='critical')
# Returns: list of CVEs with severity >= critical

# Get only exploitable CVEs
exploitable = lookup.get_cves('dahua', exploits_only=True)
# Returns: list of CVEs with exploit_available=True
```

**Parameters:**
- `brand` (str): Camera brand name
- `min_severity` (str, optional): Minimum severity filter (`'critical'`, `'high'`, `'medium'`, `'low'`)
- `exploits_only` (bool): Return only CVEs with public exploits

**Returns:**
- `list[dict]`: List of CVE objects with keys:
  - `id` (str): CVE identifier
  - `severity` (str): Severity level
  - `cvss_score` (float): CVSS v3 score
  - `description` (str): Vulnerability description
  - `affected_versions` (str): Affected product versions
  - `exploit_available` (bool): Public exploit exists
  - `references` (list[str]): Reference URLs

#### generate_nvd_urls(cves)

Generate NVD URLs for CVE list.

```python
cves = lookup.get_cves('hikvision')
urls = lookup.generate_nvd_urls(cves)
# Returns: [
#   'https://nvd.nist.gov/vuln/detail/CVE-2021-36260',
#   'https://nvd.nist.gov/vuln/detail/CVE-2017-7921',
#   ...
# ]
```

**Parameters:**
- `cves` (list[dict]): List of CVE objects

**Returns:**
- `list[str]`: List of NVD URLs

#### get_cve_by_id(cve_id)

Lookup specific CVE by ID.

```python
cve = lookup.get_cve_by_id('CVE-2021-36260')
# Returns: {
#   'id': 'CVE-2021-36260',
#   'brand': 'hikvision',
#   'severity': 'critical',
#   'cvss_score': 9.8,
#   ...
# }
```

**Parameters:**
- `cve_id` (str): CVE identifier

**Returns:**
- `dict | None`: CVE object or None if not found

#### get_available_brands()

List all brands in CVE database.

```python
brands = lookup.get_available_brands()
# Returns: ['hikvision', 'dahua', 'axis', 'cp_plus']
```

**Returns:**
- `list[str]`: List of brand names

#### get_cve_statistics(brand=None)

Get CVE statistics.

```python
# Global statistics
stats = lookup.get_cve_statistics()
# Returns: {
#   'total_cves': 39,
#   'by_severity': {'critical': 5, 'high': 22, 'medium': 12},
#   'with_exploits': 5,
#   'by_brand': {'hikvision': 12, 'dahua': 12, ...}
# }

# Brand-specific
hik_stats = lookup.get_cve_statistics(brand='hikvision')
```

**Parameters:**
- `brand` (str, optional): Brand name for specific stats

**Returns:**
- `dict`: Statistics dictionary

## gridland.analyze.core.osint

OSINT reconnaissance capabilities.

### OSINTURLGenerator

OSINT platform URL generation (static methods).

#### generate_search_urls(ip_or_query)

Generate search URLs for major platforms.

```python
from gridland.analyze.core.osint import OSINTURLGenerator

urls = OSINTURLGenerator.generate_search_urls("192.168.1.100")
# Returns: {
#   'shodan': 'https://www.shodan.io/search?query=192.168.1.100',
#   'censys': 'https://search.censys.io/hosts/192.168.1.100',
#   'zoomeye': 'https://www.zoomeye.org/searchResult?q=192.168.1.100',
#   'google': 'https://www.google.com/search?q=192.168.1.100'
# }
```

**Parameters:**
- `ip_or_query` (str): IP address or search query

**Returns:**
- `dict[str, str]`: Dictionary of platform URLs

**Platforms:**
- shodan
- censys
- zoomeye
- google

#### generate_google_dorks(ip_or_query)

Generate Google Dork queries for camera discovery.

```python
dorks = OSINTURLGenerator.generate_google_dorks("192.168.1.100")
# Returns: [
#   {
#     'name': 'Camera Login Pages',
#     'query': 'inurl:"/view/index.shtml" 192.168.1.100',
#     'url': 'https://www.google.com/search?q=...'
#   },
#   ...
# ]
```

**Parameters:**
- `ip_or_query` (str): IP address or search query

**Returns:**
- `list[dict]`: List of dork objects with `name`, `query`, and `url` keys

**Dork Categories:**
1. Camera Login Pages
2. Live Camera Streams
3. Camera Configuration Pages
4. DVR/NVR Systems

### GeoLookup

Async IP geolocation with caching.

#### \_\_init\_\_(cache_duration=3600, rate_limit_delay=0.1)

```python
from gridland.analyze.core.osint import GeoLookup

geo = GeoLookup(
    cache_duration=7200,  # Cache for 2 hours
    rate_limit_delay=0.2  # 200ms between requests
)
```

**Parameters:**
- `cache_duration` (int): Cache duration in seconds (default: 3600)
- `rate_limit_delay` (float): Delay between API requests in seconds (default: 0.1)

#### get_ip_info(ip_address)

Get IP geolocation information (async).

```python
import asyncio

async def lookup():
    geo = GeoLookup()
    info = await geo.get_ip_info("8.8.8.8")
    # Returns: {
    #   'ip': '8.8.8.8',
    #   'city': 'Mountain View',
    #   'region': 'California',
    #   'country': 'US',
    #   'loc': '37.4056,-122.0775',
    #   'org': 'Google LLC',
    #   'timezone': 'America/Los_Angeles'
    # }
    return info

asyncio.run(lookup())
```

**Parameters:**
- `ip_address` (str): IP address to lookup

**Returns:**
- `dict`: IPinfo.io response data

**Raises:**
- `Exception`: If API request fails

#### generate_map_urls(ip_info, osm_base_url=None)

Generate OpenStreetMap URLs (static method).

```python
map_urls = GeoLookup.generate_map_urls(ip_info)
# Returns: {
#   'openstreetmap': 'https://www.openstreetmap.org/?mlat=37.4056...',
#   'latitude': 37.4056,
#   'longitude': -122.0775
# }

# Use custom OSM instance
local_urls = GeoLookup.generate_map_urls(
    ip_info,
    osm_base_url="http://localhost:8080"
)
```

**Parameters:**
- `ip_info` (dict): IP information from get_ip_info()
- `osm_base_url` (str, optional): Custom OSM base URL

**Returns:**
- `dict`: Map URLs and coordinates

#### clear_cache()

Clear all cached IP data.

```python
geo.clear_cache()
```

#### get_cache_stats()

Get cache statistics.

```python
stats = geo.get_cache_stats()
# Returns: {
#   'total_cached': 15,
#   'expired': 3
# }
```

**Returns:**
- `dict`: Cache statistics

## gridland.analyze.core.stream

Stream detection and discovery.

### StreamDetector

Stream validation and metadata extraction.

#### \_\_init\_\_()

```python
from gridland.analyze.core.stream import StreamDetector

detector = StreamDetector()
```

#### check_stream_url(url, timeout=5)

Comprehensive stream detection.

```python
result = detector.check_stream_url(
    "rtsp://192.168.1.100:554/live.sdp",
    timeout=5
)
# Returns: {
#   'is_stream': True,
#   'detection_method': 'protocol',
#   'details': 'RTSP protocol detected'
# }
```

**Parameters:**
- `url` (str): Stream URL to check
- `timeout` (int): Timeout in seconds (default: 5)

**Returns:**
- `dict`: Detection result with keys:
  - `is_stream` (bool): Stream detected
  - `detection_method` (str): Detection method used
  - `details` (str): Additional details

**Detection Methods:**
1. Protocol detection (rtsp://, rtmp://, etc.)
2. HEAD request (Content-Type check)
3. GET request (content analysis)
4. Path pattern matching

#### get_stream_details(url, timeout=5)

Extract stream metadata.

```python
details = detector.get_stream_details(
    "http://192.168.1.100:80/video/live_1080p.h264"
)
# Returns: {
#   'resolution': (1920, 1080),
#   'codec': 'h264',
#   'category': 'live'
# }
```

**Parameters:**
- `url` (str): Stream URL
- `timeout` (int): Timeout in seconds

**Returns:**
- `dict`: Stream details with keys:
  - `resolution` (tuple[int, int] | None): Width and height
  - `codec` (str | None): Video codec
  - `category` (str): Stream category

**Resolutions:**
- 4K (3840x2160)
- 1080p (1920x1080)
- 720p (1280x720)
- 480p (640x480)

**Codecs:**
- h264, h265, mpeg4, mjpeg, vp8, vp9

**Categories:**
- live, snapshot, recorded, unknown

#### validate_stream_url(url, timeout=5)

Simple boolean validation.

```python
is_stream = detector.validate_stream_url("rtsp://192.168.1.100:554/live.sdp")
# Returns: True or False
```

**Parameters:**
- `url` (str): Stream URL
- `timeout` (int): Timeout in seconds

**Returns:**
- `bool`: True if stream detected

## Complete Example

```python
import asyncio
from gridland.analyze.core import BrandDetector, CVELookup
from gridland.analyze.core.osint import OSINTURLGenerator, GeoLookup
from gridland.analyze.core.stream import StreamDetector

# Brand detection
detector = BrandDetector()
result = detector.detect_brand({
    'server_header': 'hikvision-dvr',
    'content_type': 'image/jpeg'
})
print(f"Brand: {result['brand']}, Confidence: {result['confidence']}")

# CVE lookup
lookup = CVELookup()
cves = lookup.get_cves(result['brand'], min_severity='critical')
print(f"Critical CVEs: {len(cves)}")
for cve in cves:
    print(f"  {cve['id']}: {cve['description']}")

# Generate OSINT URLs
urls = OSINTURLGenerator.generate_search_urls("8.8.8.8")
print(f"Shodan: {urls['shodan']}")

# Geolocation (async)
async def geo_lookup():
    geo = GeoLookup()
    info = await geo.get_ip_info("8.8.8.8")
    print(f"Location: {info['city']}, {info['country']}")

    map_urls = GeoLookup.generate_map_urls(info)
    print(f"Map: {map_urls['openstreetmap']}")

asyncio.run(geo_lookup())

# Stream detection
stream_detector = StreamDetector()
is_stream = stream_detector.validate_stream_url(
    "rtsp://192.168.1.100:554/live.sdp"
)
if is_stream:
    details = stream_detector.get_stream_details(
        "rtsp://192.168.1.100:554/live.sdp"
    )
    print(f"Stream: {details['codec']} @ {details['resolution']}")
```

## See Also

- [Core Modules API](core.md) - Data loading and validation
- [Discover Modules API](discover.md) - Port scanning
- [Plugins API](plugins.md) - Vulnerability scanning plugins
- [CLI Reference](../cli/analyze.md) - Command-line usage
