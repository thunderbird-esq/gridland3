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

- **Current Phase**: Phase 1 - Data Migration ✓ COMPLETE
- **Progress**: 42/405 tasks complete (10.4%)
- **Next Phase**: Phase 2 - OSINT Integration (TASKS 043-075)

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

#### Test Suite (`tests/test_data_loader.py`)

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

**Phase 2: OSINT Integration** (TASKS 043-075)

- Shodan, Censys, ZoomEye API integration
- Passive reconnaissance modules

**Phase 3: Port Scanner** (TASKS 076-104)

- Async port scanning implementation
- Multi-threaded/multi-process architecture

**Phase 4: Brand Detection** (TASKS 105-128)

- Camera manufacturer identification
- Fingerprinting and heuristics

**Phase 5: Credential Testing** (TASKS 129-156)

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
- GRIDLAND v3.0: Comprehensive test suite (41+ tests)

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
