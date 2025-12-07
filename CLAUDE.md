# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HelloBird is a web-based sousveillance console for educational security research and authorized auditing of publicly accessible camera feeds. The project consists of a Flask backend that wraps the CamXploit.py reconnaissance script with a web interface for discovery and analysis of camera endpoints.

**⚠️ IMPORTANT ETHICAL NOTICE**: This tool is designed for defensive security research, education, and authorized auditing ONLY. All usage must comply with applicable laws and ethical guidelines. Unauthorized scanning of systems you do not own is prohibited.

## Development Commands

### Running the Application

**Local Development:**

```bash
python server.py
```

- Runs Flask server on <http://localhost:8080>
- Requires SHODAN_API_KEY environment variable for discovery features

**Docker (Recommended):**

```bash
# Build the Docker image
docker build --build-arg SHODAN_API_KEY_ARG=your_api_key_here -t hellobird .

# Run the container
docker run -p 8080:8080 hellobird
```

### Dependencies

```bash
pip install -r requirements.txt
```

Required packages: requests, ipaddress, flask, shodan, python-dotenv

### Testing Individual Components

```bash
# Test the core scanning script directly
python CamXploit.py

# Test server endpoints manually via curl
curl -X POST http://localhost:8080/scan -H "Content-Type: application/json" -d '{"ip":"TARGET_IP"}'
```

## Architecture Overview

### Backend Structure (server.py)

- **Flask Web Server**: Main application server with three core endpoints
- **/discover**: Shodan API integration for target discovery (requires API key)
- **/scan**: Executes CamXploit.py via subprocess, streams output via Server-Sent Events
- **/stream**: GStreamer-based RTSP stream transcoding to MPEG-TS for browser playback
- **Static File Serving**: Serves frontend assets from /static directory

### Core Scanning Engine (CamXploit.py)

- Multi-threaded port scanner targeting common camera ports (80, 443, 554, 8080, etc.)
- Camera brand detection (Hikvision, Dahua, Axis, Sony, Bosch, etc.)
- Default credential testing and authentication bypass detection
- Live stream discovery (RTSP, HTTP, RTMP, MMS protocols)
- ONVIF protocol support for standardized camera communication

### Frontend Architecture

- **Single Page Application**: index.html with vanilla JavaScript
- **Real-time Communication**: Server-Sent Events for live scan output streaming
- **Three Main Panels**:
  - "The Net": Shodan-based target discovery interface
  - "The Scalpel": IP analysis and scanning interface
  - Video player for stream viewing
- **Styling**: Uses system.css theme for retro computing aesthetic

### Docker Environment

- **Base Image**: python:3.9-slim
- **System Dependencies**: GStreamer multimedia framework with all plugin sets
- **Build Arguments**: SHODAN_API_KEY passed at build time
- **Port Exposure**: 8080 for web interface

## Key Implementation Details

### Stream Processing Pipeline

The /stream endpoint implements a GStreamer pipeline:

```
rtspsrc -> rtph264depay -> h264parse -> mpegtsmux -> fdsink
```

This converts RTSP H.264 streams to browser-compatible MPEG-TS format.

### Security Considerations

- Input validation using ipaddress.ip_address() for IP parameters
- Secure filename handling with werkzeug.utils.secure_filename()
- Subprocess isolation for CamXploit.py execution
- SSL certificate verification disabled for camera endpoints (common in embedded devices)

### Error Handling Patterns

- Graceful degradation when Shodan API is unavailable
- Process cleanup for long-running scans and streams
- Exception handling for network timeouts and malformed responses

## Development Workflows

### Adding New Camera Brand Detection

1. Update brand detection logic in CamXploit.py around line 200-300
2. Add corresponding HTTP headers/response patterns
3. Test against known camera models

### Extending Stream Protocol Support

1. Modify GStreamer pipeline in server.py /stream endpoint
2. Update frontend video player MIME type handling
3. Test codec compatibility across browsers

### API Integration Changes

1. Shodan query modifications in /discover endpoint
2. Update frontend discovery panel JavaScript
3. Handle new API response formats

## Project Status Notes

Based on DEVLOG.md, current implementation status:

- ✅ Core Flask server and frontend working
- ✅ Docker containerization complete
- ✅ CamXploit.py integration functional
- ⚠️ Shodan discovery limited by API tier restrictions
- ❓ Stream transcoding implemented but requires testing
- ❓ Analysis scanning needs validation with live targets

The next development phase focuses on testing the analysis and streaming features with legitimate test targets.

---

## GRIDLAND v3.0 Migration (In Progress)

### Overview

GRIDLAND v3.0 is a complete modernization and migration of the CamXploit.py functionality into a modular, async-capable Python package. The migration ensures 100% feature parity while introducing improved architecture, comprehensive testing, and enhanced security research capabilities.

### Migration Status

- **Current Phase**: Phase 3 - Port Scanner ✓ COMPLETE
- **Progress**: 109/405 tasks complete (26.9%)
- **Next Phase**: Phase 4 - Brand Detection (TASKS 110-132)

### Data Files (Phase 1 Complete)

#### Camera Ports (`gridland/data/camera_ports.json`)

- **Count**: 685 unique ports (688 total in CamXploit.py with 3 duplicates)
- **Categories**: web, rtsp, rtmp, mms, onvif, custom
- **Source**: CamXploit.py lines 59-760
- **Format**: Structured JSON with metadata and protocol categorization

**Usage Example:**

```python
from gridland.core.data_loader import load_camera_ports, get_all_ports

# Load all port data
ports_data = load_camera_ports()

# Get flat list of unique ports
all_ports = get_all_ports()  # Returns [80, 443, 554, ...]

# Get ports by category
from gridland.core.data_loader import get_ports_by_category
rtsp_ports = get_ports_by_category('rtsp')  # Returns [554, 1554, ...]
```

#### Login Paths (`gridland/data/login_paths.json`)

- **Count**: 72 authentication paths
- **Brands**: generic, hikvision, dahua, axis, sony, bosch, panasonic, cp_plus
- **Auth Types**: 33 digest, 31 basic, 8 form
- **Source**: CamXploit.py lines 763-781

**Usage Example:**

```python
from gridland.core.data_loader import get_login_paths_by_brand, get_login_paths_by_auth_type

# Get Hikvision-specific paths
hik_paths = get_login_paths_by_brand('hikvision')

# Get all digest auth paths
digest_paths = get_login_paths_by_auth_type('digest')
```

#### CVE Database (`gridland/data/cve_database.json`)

- **Count**: 39 CVEs across 4 brands
- **Brands**: hikvision (12), dahua (12), axis (12), cp_plus (3)
- **Severity**: 5 critical, 22 high, 12 medium
- **With Exploits**: 5 CVEs have public exploits
- **Source**: CamXploit.py lines 801-845 + security research enhancements

**Features:**

- CVSS v3 scores for all vulnerabilities
- Detailed descriptions and affected versions
- Exploit availability tracking
- Reference URLs to advisories and PoCs

**Usage Example:**

```python
from gridland.core.data_loader import get_cves_by_severity, get_cves_with_exploits

# Get critical vulnerabilities
critical_cves = get_cves_by_severity('critical')

# Get CVEs with public exploits
exploitable = get_cves_with_exploits()
```

#### Stream Paths (`gridland/data/stream_paths.json`)

- **Count**: 138+ stream discovery paths
- **Protocols**: RTSP, RTMP, HTTP, WebSocket, WebRTC
- **Brands**: Generic + brand-specific paths for major manufacturers
- **Source**: CamXploit.py lines 1579-1683 + enhancements

**Features:**

- Detection patterns for successful stream discovery
- Content-type mappings for protocol identification
- Optimization hints for high-success paths
- Port-protocol recommendations

### OSINT Module (Phase 2 Complete)

The OSINT (Open Source Intelligence) module provides URL generation for reconnaissance platforms and async IP geolocation capabilities.

#### OSINTURLGenerator (`gridland/analyze/core/osint/url_generator.py`)

Generate search URLs for major OSINT platforms and Google Dorking queries for camera discovery.

**Usage Example:**

```python
from gridland.analyze.core.osint import OSINTURLGenerator

# Generate OSINT platform URLs
urls = OSINTURLGenerator.generate_search_urls("192.168.1.1")
print(urls["shodan"])   # https://www.shodan.io/search?query=192.168.1.1
print(urls["censys"])   # https://search.censys.io/hosts/192.168.1.1
print(urls["zoomeye"])  # https://www.zoomeye.org/searchResult?q=192.168.1.1

# Generate Google Dork queries
dorks = OSINTURLGenerator.generate_google_dorks("192.168.1.1")
for dork in dorks:
    print(f"{dork['query']} -> {dork['url']}")
```

**Features:**

- 4 OSINT platform integrations (Shodan, Censys, ZoomEye, Google)
- 4 Google Dork queries for camera discovery
- All URL formats match CamXploit.py exactly
- Proper URL encoding for special characters
- Static methods (no instance needed)

#### GeoLookup (`gridland/analyze/core/osint/geo_lookup.py`)

Async IP geolocation with IPinfo.io API integration, caching, and rate limiting.

**Usage Example:**

```python
from gridland.analyze.core.osint import GeoLookup
import asyncio

async def lookup_ip():
    geo = GeoLookup(cache_duration=3600, rate_limit_delay=0.1)

    # Get IP information
    ip_info = await geo.get_ip_info("8.8.8.8")
    print(f"City: {ip_info['city']}")
    print(f"Country: {ip_info['country']}")
    print(f"Location: {ip_info['loc']}")

    # Generate map URLs (OpenStreetMap)
    map_urls = GeoLookup.generate_map_urls(ip_info)
    print(f"OSM: {map_urls['openstreetmap']}")
    print(f"Lat: {map_urls['latitude']}, Lon: {map_urls['longitude']}")

    # For local hosted OSM instance
    local_urls = GeoLookup.generate_map_urls(
        ip_info, osm_base_url="http://localhost:8080"
    )

    # Get cache statistics
    stats = geo.get_cache_stats()
    print(f"Cached entries: {stats['total_cached']}")

asyncio.run(lookup_ip())
```

**Features:**

- Async/await pattern with aiohttp for non-blocking I/O
- Time-based caching (configurable duration)
- Rate limiting to respect API limits
- OpenStreetMap URL generation (supports local hosted instances)
- Separate latitude/longitude extraction
- Cache management methods
- Error handling for API failures

**Cache Methods:**

- `clear_cache()` - Clear all cached IP data
- `get_cache_stats()` - Get cache statistics (total, expired entries)

**Map URL Generation:**

- `generate_map_urls(ip_info)` - Generate public OSM URLs
- `generate_map_urls(ip_info, osm_base_url="http://localhost:PORT")` - Use local OSM instance

### Port Scanner Module (Phase 3 Complete)

The Port Scanner module provides network discovery capabilities for camera reconnaissance through multi-threaded port scanning and intelligent port selection.

#### PythonPortScanner (`gridland/discover/python_scanner.py`)

Multi-threaded TCP port scanner with configurable concurrency and timeouts.

**Usage Example:**

```python
from gridland.discover import PythonPortScanner
import threading

# Initialize scanner (matches CamXploit.py defaults)
scanner = PythonPortScanner(max_threads=100, timeout=1.5)

# Define progress callback
def progress(scanned, total):
    print(f"Progress: {scanned}/{total} ports scanned")

# Optional early termination flag
termination_flag = threading.Event()

# Scan ports
ports_to_scan = [80, 443, 554, 8080, 8554]
open_ports = scanner.scan_ports(
    "192.168.1.100",
    ports_to_scan,
    progress_callback=progress,
    termination_flag=termination_flag
)

print(f"Open ports: {open_ports}")  # [80, 8080]
```

**Features:**

- Multi-threaded scanning (default 100 concurrent threads)
- Configurable timeout per port (default 1.5 seconds)
- Progress reporting callback (invoked every 50 ports)
- Early termination support via threading.Event()
- Thread-safe result collection with locks
- Returns sorted list of open ports
- Comprehensive input validation (IP addresses, port ranges)
- 100% feature parity with CamXploit.py check_ports()

**Methods:**

- `__init__(max_threads=100, timeout=1.5)` - Initialize scanner
- `scan_ports(ip, ports, progress_callback=None, termination_flag=None)` - Scan specified ports

#### PortSelector (`gridland/discover/port_selector.py`)

Port selection utility for retrieving camera-specific ports by category.

**Usage Example:**

```python
from gridland.discover import PortSelector

# Get all camera ports (685 unique ports)
all_ports = PortSelector.get_camera_ports()

# Get RTSP-specific ports
rtsp_ports = PortSelector.get_camera_ports(category='rtsp')  # [554, 1554, ...]

# Get web ports
web_ports = PortSelector.get_camera_ports(category='web')  # [80, 443, 8080, ...]

# Get ONVIF ports
onvif_ports = PortSelector.get_camera_ports(category='onvif')  # [80, 8080, ...]
```

**Supported Categories:**

- `all` - All 685 unique camera ports (default)
- `web` - HTTP/HTTPS ports for web interfaces
- `rtsp` - Real Time Streaming Protocol ports
- `rtmp` - Real Time Messaging Protocol ports
- `mms` - Microsoft Media Server ports
- `onvif` - ONVIF protocol ports
- `custom` - Custom/proprietary camera ports

**Features:**

- Static method (no instance required)
- Integrates with Phase 1 data loader
- Port range validation (1-65535)
- Raises ValueError for invalid categories
- Deterministic results (consistent ordering)

**Methods:**

- `get_camera_ports(category='all')` - Retrieve ports by category

### Brand Detection & Analysis Module (Phase 4 Complete)

The Brand Detection module provides camera manufacturer identification and vulnerability lookup capabilities.

#### BrandDetector (`gridland/analyze/core/brand_detector.py`)

Camera brand identification through multi-source analysis (server headers, content-type, response body).

**Usage Example:**

```python
from gridland.analyze.core import BrandDetector

# Initialize detector
detector = BrandDetector()

# Analyze single port response
port_data = {
    'server_header': 'hikvision-dvr',
    'content_type': 'image/mjpeg',
    'response_body': '<html>Camera Login</html>'
}
result = detector.detect_brand(port_data)
print(f"Brand: {result['brand']}")           # 'hikvision'
print(f"Confidence: {result['confidence']}")  # 0.7
print(f"Evidence: {result['evidence']}")      # ['Server header...', 'Content-type...']

# Analyze multiple ports (aggregated detection)
ports_data = [
    {'port': 80, 'server_header': 'camera', 'content_type': 'text/html', 'response_body': 'surveillance'},
    {'port': 8080, 'server_header': 'hikvision-dvr', 'content_type': 'image/jpeg', 'response_body': ''}
]
result = detector.analyze_all_ports(ports_data)
print(f"Brand: {result['brand']}")  # 'hikvision' (specific brand wins over generic)
```

**Features:**

- 10 supported brands: Hikvision, Dahua, Axis, Sony, Bosch, Samsung, Panasonic, Vivotek, CP Plus, Generic
- Multi-source detection: server headers, content-type headers, response body keywords
- Confidence scoring system (0.0-1.0 range)
- Evidence tracking with source attribution
- Conflict resolution prioritizing specific brands over generic
- Special CP Plus detection (uvr, cpplus, 0401e1 indicators)
- 100% feature parity with CamXploit.py (lines 989-1079)

**Methods:**

- `detect_brand(port_data)` - Analyze single port HTTP response
- `analyze_all_ports(ports_data)` - Aggregate brand detections across multiple ports

#### CVELookup (`gridland/analyze/core/cve_lookup.py`)

CVE database integration with filtering and NVD URL generation.

**Usage Example:**

```python
from gridland.analyze.core import CVELookup

# Initialize lookup
lookup = CVELookup()

# Get all CVEs for a brand
hik_cves = lookup.get_cves('hikvision')
print(f"Found {len(hik_cves)} Hikvision CVEs")  # 12 CVEs

# Filter by severity
critical_cves = lookup.get_cves('hikvision', min_severity='critical')
print(f"Critical CVEs: {len(critical_cves)}")  # CVEs with severity >= critical

# Get only CVEs with public exploits
exploitable = lookup.get_cves('dahua', exploits_only=True)

# Generate NVD URLs
urls = lookup.generate_nvd_urls(hik_cves)
# ['https://nvd.nist.gov/vuln/detail/CVE-2021-36260', ...]

# Get specific CVE by ID
cve = lookup.get_cve_by_id('CVE-2021-36260')
print(f"CVSS: {cve['cvss_score']}, Severity: {cve['severity']}")

# Get available brands
brands = lookup.get_available_brands()  # ['hikvision', 'dahua', 'axis', 'cp_plus']

# Get statistics
stats = lookup.get_cve_statistics()  # Global stats
hik_stats = lookup.get_cve_statistics(brand='hikvision')  # Brand-specific stats
```

**Features:**

- Integrates with Phase 1 CVE database (39 CVEs across 4 brands)
- CVSS score filtering and severity categorization
- Exploit availability filtering
- NVD URL generation (format: <https://nvd.nist.gov/vuln/detail/{cve_id}>)
- Brand-specific and global statistics
- 100% feature parity with CamXploit.py (line 1309)

**Methods:**

- `get_cves(brand, min_severity=None, exploits_only=False)` - Retrieve CVEs with filtering
- `generate_nvd_urls(cves)` - Generate NVD URLs for CVE list
- `get_cve_by_id(cve_id)` - Lookup specific CVE
- `get_available_brands()` - List all brands in database
- `get_cve_statistics(brand=None)` - Get aggregate statistics

#### IPValidator (`gridland/core/validators.py`)

IP address validation with private IP detection.

**Usage Example:**

```python
from gridland.core import IPValidator

# Validate public IP
is_valid, warning = IPValidator.validate_ip('8.8.8.8')
# is_valid=True, warning=None

# Validate private IP
is_valid, warning = IPValidator.validate_ip('192.168.1.1')
# is_valid=True, warning='Warning: Private IP address detected. This tool is meant for public IPs.'

# Validate invalid IP
is_valid, warning = IPValidator.validate_ip('999.999.999.999')
# is_valid=False, warning=None

# Additional utilities
IPValidator.is_ipv4('8.8.8.8')         # True
IPValidator.is_ipv6('2001:db8::1')     # True
IPValidator.is_public_ip('8.8.8.8')    # True
IPValidator.is_private_ip('10.0.0.1')  # True
IPValidator.get_ip_type('8.8.8.8')     # 'public_ipv4'
```

**Features:**

- IPv4 and IPv6 support
- Private IP range detection (RFC 1918 for IPv4, fc00::/7 and fe80::/10 for IPv6)
- Exact warning message from CamXploit.py (lines 917-918)
- Static methods (no instance required)
- Comprehensive validation utilities
- 100% feature parity with CamXploit.py

**Methods:**

- `validate_ip(ip_str)` - Validate IP and detect private addresses
- `is_ipv4(ip_str)` - Check if string is valid IPv4
- `is_ipv6(ip_str)` - Check if string is valid IPv6
- `is_public_ip(ip_str)` - Check if IP is public
- `is_private_ip(ip_str)` - Check if IP is private
- `get_ip_type(ip_str)` - Get detailed IP type info

### Authentication Testing Plugins (Phase 5 Complete)

The Authentication Testing module provides vulnerability scanning plugins for detecting login endpoints and testing default credentials.

#### LoginPageScanner (`gridland/analyze/plugins/builtin/login_scanner.py`)

Multi-threaded authentication endpoint discovery plugin.

**Usage Example:**

```python
from gridland.analyze.plugins.builtin import LoginPageScanner

# Initialize scanner
scanner = LoginPageScanner()

# Define progress callback (optional)
def progress(completed, total):
    print(f"Scanned {completed}/{total} endpoints")

# Scan for login pages
result = scanner.scan_login_pages(
    ip="192.168.1.100",
    open_ports=[80, 443, 8080],
    progress_callback=progress
)

# Result structure
print(f"Found {len(result['login_pages'])} login pages")
for page in result['login_pages']:
    print(f"  {page['url']} - {page['auth_type']} (HTTP {page['status_code']})")
# Output:
#   http://192.168.1.100:80/admin - basic (HTTP 401)
#   https://192.168.1.100:443/login - form (HTTP 200)
```

**Features:**
- Multi-threaded login page detection (max 50 concurrent threads)
- Loads 72 authentication paths from login_paths.json
- Detects Basic, Digest, and Form authentication types
- Parses WWW-Authenticate headers for auth type identification
- Detects HTML form fields (username, password, login)
- Checks HTTP status codes: 200, 401, 403
- Progress callback support for real-time updates
- Thread-safe result collection with locks
- HTTP/HTTPS protocol auto-detection
- 100% feature parity with CamXploit.py check_login_pages() (lines 1155-1199)

**Methods:**
- `scan_login_pages(ip, open_ports, progress_callback=None)` - Scan for login pages
- `scan_vulnerabilities(ip, open_ports, **kwargs)` - Async interface for plugin framework
- `get_metadata()` - Return plugin metadata

#### CredentialTester (`gridland/analyze/plugins/builtin/credential_tester.py`)

Multi-threaded default credential testing plugin.

**Usage Example:**

```python
from gridland.analyze.plugins.builtin import CredentialTester

# Initialize tester
tester = CredentialTester()

# Test default credentials
result = tester.test_default_credentials(
    ip="192.168.1.100",
    open_ports=[80, 8080]
)

# Check if credentials were found
if result['success']:
    creds = result['credentials']
    print(f"Valid credentials found!")
    print(f"  Username: {creds['username']}")
    print(f"  Password: {creds['password']}")
    print(f"  URL: {creds['url']}")
    print(f"  Auth Type: {creds['auth_type']}")
else:
    print("No default credentials found")
```

**Features:**
- Multi-threaded credential testing (max 20 concurrent threads)
- Loads 30 credential combinations from default_credentials.json
- Tests 4 endpoints per port: /, /login, /admin/login, /cgi-bin/login
- Supports Basic, Digest, and Form authentication
- Early termination when credentials found (thread-safe)
- HTTP/HTTPS protocol auto-detection
- Thread-safe credential discovery with locks
- Progress callback support
- 100% feature parity with CamXploit.py test_default_passwords() (lines 1201-1283)

**Methods:**
- `test_default_credentials(ip, open_ports, progress_callback=None)` - Test credentials
- `scan_vulnerabilities(ip, open_ports, **kwargs)` - Async interface for plugin framework
- `get_metadata()` - Return plugin metadata

**Credential Database Format:**
```python
{
    "admin": ["admin", "1234", "admin123", "password", "12345", "123456", "1111", "default"],
    "root": ["root", "toor", "1234", "pass", "root123"],
    "user": ["user", "user123", "password"],
    "guest": ["guest", "guest123"],
    "operator": ["operator", "operator123"]
}
# Total: 30 username/password combinations
```

### Data Loader Module (`gridland/core/data_loader.py`)

The `data_loader` module provides 23 functions for accessing camera reconnaissance data:

#### Port Functions (6)

- `load_camera_ports()` - Load full port data structure
- `get_all_ports()` - Get flat list of all unique ports
- `get_ports_by_category(category)` - Query ports by protocol
- `get_port_categories()` - List available categories
- `get_metadata()` - Access port data metadata

#### Login Path Functions (5)

- `load_login_paths()` - Load full login paths structure
- `get_all_login_paths()` - Get all paths with brand information
- `get_login_paths_by_brand(brand)` - Query paths by camera brand
- `get_login_paths_by_auth_type(auth_type)` - Filter by authentication type
- `get_login_path_brands()` - List available brands

#### CVE Functions (8)

- `load_cve_database()` - Load full CVE database
- `get_all_cves()` - Get all CVEs with brand information
- `get_cves_by_brand(brand)` - Query CVEs by manufacturer
- `get_cves_by_severity(severity)` - Filter by severity level
- `get_cves_with_exploits()` - Get CVEs with public exploits
- `get_cve_brands()` - List brands in database
- `get_cve_statistics()` - Get aggregate CVE statistics

### Testing

#### Phase 1 Test Suite (`tests/test_data_loader.py`)

- **Total Tests**: 41 unit tests
- **Coverage**: All data loader functions
- **Status**: All tests passing ✓

**Test Categories:**

- Camera Ports: 11 tests validating structure, counts, queries
- Login Paths: 11 tests validating brands, auth types, structure
- CVE Database: 16 tests validating CVEs, severity, exploits
- Integration: 3 tests validating cross-file consistency

**Running Tests:**

```bash
pytest tests/test_data_loader.py -v
# Result: 41 passed, 1 warning in 0.14s
```

#### Phase 2 Test Suite (`tests/osint/`)

- **Total Tests**: 30 unit tests (14 URL generator + 16 geo lookup)
- **Coverage**: 100% coverage on OSINT modules
- **Status**: All tests passing ✓

**Test Categories:**

- URL Generator: 14 tests validating URL formats, encoding, Google Dorks
- Geo Lookup: 16 tests validating async API calls, caching, rate limiting, OSM URLs

**Running Tests:**

```bash
pytest tests/osint/ -v
# Result: 30 passed in 0.86s
```

#### Phase 3 Test Suite (`tests/discover/`)

- **Total Tests**: 41 unit tests (22 scanner + 19 selector)
- **Coverage**: ~97% average coverage
- **Status**: All tests passing ✓

**Test Categories:**

- PythonPortScanner: 22 tests validating scanning, threading, progress, termination
- PortSelector: 19 tests validating category selection, port validation, integration

**Running Tests:**

```bash
pytest tests/discover/ -v
# Result: 41 passed in 0.32s
```

#### Phase 4 Test Suite (`tests/analyze/core/` and `tests/core/`)

- **Total Tests**: 108 unit tests (38 brand detector + 30 CVE lookup + 40 IP validator)
- **Coverage**: ~95% average coverage
- **Status**: All tests passing ✓

**Test Categories:**

- BrandDetector: 38 tests validating brand detection, conflict resolution, aggregation, CP Plus special indicators
- CVELookup: 30 tests validating CVE retrieval, filtering, URL generation, statistics, data validation
- IPValidator: 40 tests validating public/private IPs, IPv4/IPv6, validation, edge cases, consistency

**Running Tests:**

```bash
pytest tests/analyze/core/ tests/core/test_validators.py -v
# Result: 108 passed in 0.65s
```

#### Phase 5 Test Suite (`tests/plugins/`)

- **Total Tests**: 51 unit tests (24 login scanner + 27 credential tester)
- **Coverage**: ~90% average coverage
- **Status**: All tests passing ✓

**Test Categories:**

- LoginPageScanner: 24 tests validating auth detection, threading, progress callbacks, HTML form detection
- CredentialTester: 27 tests validating basic/form/digest auth, early termination, thread safety, multi-endpoint testing

**Running Tests:**

```bash
pytest tests/plugins/ -v
# Result: 51 passed in 2.66s
```

### Development Workflow for Migration

#### When Adding New Features

1. Check MIGRATION_TASKS.md for atomic task breakdown
2. Implement feature with tests
3. Validate against CamXploit.py for feature parity
4. Update CHANGELOG.md with changes
5. Update DEVLOG.md with implementation notes

#### When Modifying Data Files

1. Read the corresponding function in data_loader.py
2. Understand the data structure and validation requirements
3. Make changes while preserving JSON schema
4. Run unit tests to validate: `pytest tests/test_data_loader.py -v`
5. Update metadata (version, last_updated)

#### Migration Phases

**Phase 1: Data Migration** ✓ COMPLETE (TASKS 001-042)

- Camera ports, login paths, CVE database, stream paths

**Phase 2: OSINT Integration** ✓ COMPLETE (TASKS 043-075)

- OSINTURLGenerator for Shodan, Censys, ZoomEye, Google Dorks
- GeoLookup for async IP geolocation with caching and rate limiting
- 30/30 unit tests passing

**Phase 3: Port Scanner** ✓ COMPLETE (TASKS 080-109)

- PythonPortScanner for multi-threaded port scanning
- PortSelector for category-based port selection
- 41/41 unit tests passing

**Phase 4: Brand Detection & CVE Lookup** ✓ COMPLETE (TASKS 110-161)

- BrandDetector for camera manufacturer identification
- CVELookup for vulnerability database integration
- IPValidator for IP address validation with private detection
- 108/108 unit tests passing

**Phase 5: Login Scanner & Credential Tester** ✓ COMPLETE (TASKS 162-192)

- LoginPageScanner for authentication endpoint discovery
- CredentialTester for default credential testing
- VulnerabilityPlugin base class for plugin architecture
- 51/51 unit tests passing

**Phase 6: Stream Discovery** (TASKS 193-228)

- Default credential validation
- Authentication bypass testing

**Phase 6: Stream Discovery** (TASKS 157-192)

- RTSP/HTTP/RTMP stream enumeration
- Protocol detection and validation

**Phase 7: ONVIF Integration** (TASKS 193-228)

- ONVIF service discovery
- Camera control and configuration

**Phase 8: CVE Scanning** (TASKS 229-266)

- Vulnerability detection and validation
- Exploit availability checking

**Phase 9: Reporting & Logging** (TASKS 267-315)

- Output formatting and export
- Comprehensive logging system

**Phase 10: CLI & Integration** (TASKS 316-405)

- Command-line interface
- API design and documentation

### Key Differences from CamXploit.py

**Architecture:**

- CamXploit.py: Monolithic 1,853-line script
- GRIDLAND v3.0: Modular package with separation of concerns

**Data Storage:**

- CamXploit.py: Hardcoded lists and dictionaries
- GRIDLAND v3.0: Structured JSON files with metadata

**Testing:**

- CamXploit.py: No automated tests
- GRIDLAND v3.0: Comprehensive test suite (271+ tests across 5 phases)

**Security Data:**

- CamXploit.py: Basic CVE IDs only
- GRIDLAND v3.0: Enhanced with CVSS scores, exploit references, descriptions

**Error Handling:**

- CamXploit.py: Basic exception handling
- GRIDLAND v3.0: Comprehensive error handling with descriptive exceptions

**Async Support:**

- CamXploit.py: Threaded synchronous operations
- GRIDLAND v3.0: Designed for async/await patterns (Phase 3+)

### Documentation References

- **Migration Plan**: See `CAMXPLOIT_MIGRATION_PLAN.md` for strategic overview
- **Task Breakdown**: See `MIGRATION_TASKS.md` for atomic task list (405 tasks)
- **Change Log**: See `CHANGELOG.md` for version history
- **Development Log**: See `DEVLOG.md` for detailed implementation notes

### Important Notes

1. **Feature Parity**: Every feature in CamXploit.py will be preserved in GRIDLAND v3.0
2. **Ethical Use**: All security research tools are for authorized testing only
3. **Testing Required**: All changes must pass unit tests before committing
4. **Data Validation**: JSON files are validated by unit tests on every change
