# GRIDLAND v3.0

**Professional Camera Reconnaissance Toolkit for Security Research**

!!! warning "Authorized Use Only"
    GRIDLAND is designed for defensive security research, education, and authorized auditing ONLY. All usage must comply with applicable laws and ethical guidelines. Unauthorized scanning of systems you do not own is prohibited and may be illegal in your jurisdiction.

## Overview

GRIDLAND v3.0 is a complete modernization of camera reconnaissance capabilities, transforming the monolithic CamXploit.py script into a modular, async-capable Python package with comprehensive testing and enhanced security research features.

## Key Features

### Comprehensive Data Coverage

- **685 Camera Ports** - Categorized by protocol (RTSP, RTMP, HTTP, ONVIF, MMS)
- **72 Login Paths** - Authentication endpoints across 8 camera brands
- **39 CVEs** - Vulnerability database with CVSS v3 scores and exploit references
- **138+ Stream Paths** - Multi-protocol stream discovery (RTSP, RTMP, HTTP, WebSocket)
- **30 Default Credentials** - Common username/password combinations

### Supported Camera Brands

- **Hikvision** - 12 CVEs, industry leader detection
- **Dahua** - 12 CVEs, comprehensive fingerprinting
- **Axis** - 12 CVEs, professional series support
- **Sony** - Professional camera detection
- **Bosch** - Security camera identification
- **Samsung** - Smart camera support
- **Panasonic** - Network camera detection
- **Vivotek** - IP camera fingerprinting
- **CP Plus** - DVR/NVR specialized detection
- **Generic** - Universal camera patterns

### OSINT Integration

- **Shodan** - Query URL generation for IP reconnaissance
- **Censys** - Host intelligence platform integration
- **ZoomEye** - Cyberspace search engine support
- **Google Dorks** - 4 specialized camera discovery queries
- **IP Geolocation** - Async IPinfo.io integration with caching
- **OpenStreetMap** - Geographic visualization URLs

### Ethical Safeguards

- **Rate Limiting** - Configurable delays between credential attempts
- **Attempt Limiting** - Maximum attempts per target enforcement
- **Audit Logging** - CSV audit trail for credential testing
- **Input Validation** - Comprehensive IP and port validation
- **Private IP Warnings** - Detection of RFC 1918 addresses

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/thunderbird-esq/gridland3.git
cd gridland3

# Install dependencies
pip install -r requirements.txt

# Install GRIDLAND in development mode
pip install -e .
```

### Basic Usage

```bash
# Discover cameras on a network
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Analyze a specific IP
gridland analyze 192.168.1.100 --full-scan

# Get OSINT URLs for reconnaissance
gridland analyze 8.8.8.8 --show-search-urls --geo-lookup

# Scan for login pages
gridland analyze 192.168.1.100 --scan-logins

# Test default credentials (with ethical safeguards)
gridland analyze 192.168.1.100 --test-credentials
```

### Advanced Features

```bash
# Full reconnaissance scan
gridland analyze 192.168.1.100 \
  --full-scan \
  --show-search-urls \
  --geo-lookup \
  --google-dorks \
  --show-cves

# Custom port scanning
gridland discover \
  --use-python-scanner \
  --camera-port-category rtsp \
  --target 192.168.1.0/24

# Stream discovery
gridland analyze 192.168.1.100 --discover-streams
```

## Performance Benchmarks

| Component | Performance | Description |
|-----------|-------------|-------------|
| Brand Detection | ~205,000/sec | Camera manufacturer identification |
| IP Validation | ~188,000/sec | Public/private IP classification |
| Port Scanning | ~1,975/sec | Multi-threaded TCP scanning |
| CVE Lookup | ~47,000/sec | Vulnerability database queries |
| Login Detection | ~850/sec | Authentication endpoint discovery |

## Architecture

GRIDLAND v3.0 follows a modular architecture:

```
gridland/
├── core/              # Core utilities (data loader, validators)
├── discover/          # Network discovery (port scanning)
├── analyze/           # Analysis modules
│   ├── core/          # Brand detection, CVE lookup, OSINT, stream detection
│   └── plugins/       # Vulnerability scanning plugins
└── data/              # JSON databases (ports, CVEs, credentials)
```

## Migration from CamXploit.py

GRIDLAND v3.0 maintains 100% feature parity with CamXploit.py while introducing:

- **Modular Architecture** - Separation of concerns vs monolithic script
- **Comprehensive Testing** - 521+ unit tests (100% passing)
- **Async Support** - Non-blocking I/O for network operations
- **Enhanced Data** - Structured JSON with metadata and versioning
- **Plugin System** - Extensible vulnerability scanning framework
- **CLI Improvements** - Modern argparse interface with subcommands

See the [Migration Guide](migration/from-camxploit.md) for detailed migration instructions.

## Documentation Structure

- **[Getting Started](getting-started/installation.md)** - Installation, quick start, configuration
- **[CLI Reference](cli/overview.md)** - Complete command-line interface documentation
- **[API Reference](api/core.md)** - Python API documentation for all modules
- **[Migration Guide](migration/from-camxploit.md)** - Migrating from CamXploit.py
- **[Contributing](contributing/guidelines.md)** - Development guidelines and ethical use

## Test Coverage

| Phase | Tests | Status | Coverage |
|-------|-------|--------|----------|
| Phase 1: Data Migration | 41 | ✓ Passing | 100% |
| Phase 2: OSINT Integration | 30 | ✓ Passing | 100% |
| Phase 3: Port Scanner | 41 | ✓ Passing | ~97% |
| Phase 4: Brand Detection | 108 | ✓ Passing | ~95% |
| Phase 5: Auth Testing | 51 | ✓ Passing | ~90% |
| Phase 6: Ethical Safeguards | 101 | ✓ Passing | ~92% |
| Phase 7: Stream Discovery | 112 | ✓ Passing | ~90% |
| Phase 8: CLI Integration | 26 | ✓ Passing | ~85% |
| Phase 9: Validation | 62 | ✓ Passing | 100% |
| **Total** | **521+** | **✓ All Passing** | **~95%** |

## Project Status

**Current Version:** 3.0.0
**Migration Status:** ✓ COMPLETE (405/405 tasks)
**Test Suite:** 521+ tests passing
**Feature Parity:** 100% with CamXploit.py

## License

This project is for educational and authorized security research purposes only. See [Ethical Use Guidelines](contributing/ethics.md) for responsible usage.

## Support

- **GitHub Issues:** [Report bugs and request features](https://github.com/thunderbird-esq/gridland3/issues)
- **Discussions:** [Ask questions and share ideas](https://github.com/thunderbird-esq/gridland3/discussions)
- **Security:** Report security vulnerabilities privately to the maintainers

## Acknowledgments

GRIDLAND v3.0 builds upon the pioneering work of CamXploit.py and the broader security research community. Special thanks to all contributors who helped identify vulnerabilities and improve camera security.
