# GRIDLAND v3.0

**Professional Camera Reconnaissance and Security Analysis Toolkit**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> ⚠️ **IMPORTANT**: This tool is designed for **defensive security research**, **education**, and **authorized auditing** ONLY. All usage must comply with applicable laws and ethical guidelines. Unauthorized scanning of systems you do not own or operate is prohibited and may be illegal.

---

## Overview

GRIDLAND is a next-generation reconnaissance toolkit for security researchers, penetration testers, and defensive security teams. Built from the ground up with a modular plugin architecture, GRIDLAND provides comprehensive camera system discovery, analysis, and stream intelligence capabilities.

### Key Features

- 🔍 **Multi-Engine Discovery** - Masscan, Shodan, Censys integration
- 🎯 **Advanced Fingerprinting** - Brand detection, firmware analysis, model identification
- 🔌 **Plugin Architecture** - Extensible vulnerability scanner system
- 🎬 **Stream Intelligence** - RTSP, HTTP, RTMP protocol analysis with validation
- 🧠 **Machine Learning** - Vulnerability prediction and pattern recognition
- ⚡ **High Performance** - Memory pooling, async I/O, work-stealing scheduler
- 🔐 **Security First** - Built-in secrets scanning, bandit integration, comprehensive testing
- 📊 **Rich Output** - JSON, markdown, and terminal-formatted results

---

## GRIDLAND v3.0 - Modern Camera Reconnaissance Platform

GRIDLAND v3.0 is a complete modernization and successor to the original CamXploit.py script, featuring:

- **Modular Architecture**: Separation of concerns with extensible plugin system
- **Comprehensive Testing**: 521+ unit tests across 9 phases (100% feature parity validation)
- **Enhanced Data**: Structured JSON databases for 685 camera ports, 39 CVEs, 72 login paths, 138+ stream paths
- **Modern CLI**: Click-based command-line interface with rich OSINT features
- **Performance**: ~205,000 brand detections/sec, ~188,000 IP validations/sec
- **Ethical Safeguards**: Rate limiting, attempt limiting, and audit logging for credential testing
- **Async Capabilities**: Built for non-blocking I/O with async/await patterns

### Quick Start

```bash
# Install GRIDLAND
pip install -e .

# Discover cameras using Python scanner (no masscan required)
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Analyze a specific IP with full reconnaissance
gridland analyze 192.168.1.100 --full-scan

# Get OSINT search URLs and geolocation
gridland analyze 192.168.1.100 --show-search-urls --geo-lookup

# Test for default credentials (authorized systems only!)
gridland analyze 192.168.1.100 --test-credentials
```

### Command Mapping: CamXploit.py → GRIDLAND v3.0

| CamXploit.py Command | GRIDLAND v3.0 CLI | Description |
|---------------------|-------------------|-------------|
| `python CamXploit.py` | `gridland analyze <IP>` | Analyze single IP address |
| Port scanning (check_ports) | `gridland discover --use-python-scanner --camera-ports` | Multi-threaded port scanning (685 camera ports) |
| Brand detection (detect_camera_brand) | `gridland analyze <IP> --detect-brand` | Camera manufacturer identification |
| Default credentials (test_default_passwords) | `gridland analyze <IP> --test-credentials` | Credential testing with ethical safeguards |
| Stream discovery (detect_live_streams) | `gridland analyze <IP> --full-scan` | Multi-protocol stream enumeration |
| OSINT URLs (generate_osint_urls) | `gridland analyze <IP> --show-search-urls` | Shodan, Censys, ZoomEye, Google Dork URLs |
| Geolocation (get_ip_location) | `gridland analyze <IP> --geo-lookup` | IPinfo.io async geolocation with caching |
| CVE lookup (lookup_cves) | `gridland analyze <IP> --show-cves` | CVE database with CVSS scores and exploits |
| Login pages (check_login_pages) | `gridland analyze <IP> --scan-logins` | Authentication endpoint discovery |
| All features | `gridland analyze <IP> --full-scan` | Comprehensive reconnaissance |

### New CLI Flags

#### Analyze CLI (`gridland analyze`)

**OSINT & Intelligence:**
- `--show-search-urls` - Display OSINT platform search URLs (Shodan, Censys, ZoomEye, Google)
- `--geo-lookup` - Perform async IP geolocation via IPinfo.io API with caching
- `--google-dorks` - Generate Google Dork queries for camera discovery
- `--show-cves` - Show CVE database entries for detected camera brand

**Reconnaissance:**
- `--detect-brand` - Detect camera manufacturer (Hikvision, Dahua, Axis, CP Plus, etc.)
- `--scan-logins` - Scan for authentication endpoints (72 login paths)
- `--test-credentials` - Test default credentials (30 combinations, ethical safeguards enabled)
- `--full-scan` - Enable all reconnaissance features in one command

**Example:**
```bash
# Full OSINT reconnaissance
gridland analyze 192.168.1.100 --show-search-urls --geo-lookup --google-dorks

# Security analysis with credential testing
gridland analyze 192.168.1.100 --detect-brand --show-cves --scan-logins --test-credentials

# Or simply use --full-scan for everything
gridland analyze 192.168.1.100 --full-scan
```

#### Discover CLI (`gridland discover`)

**Scanner Options:**
- `--use-python-scanner` - Use built-in Python port scanner (no masscan dependency)
- `--camera-ports` - Scan all 685 camera-specific ports from database
- `--camera-port-category <category>` - Filter ports by category: `web`, `rtsp`, `rtmp`, `onvif`, `mms`, `custom`

**Example:**
```bash
# Discover using Python scanner with all camera ports
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Discover only RTSP ports
gridland discover --use-python-scanner --camera-port-category rtsp --target 10.0.0.0/8

# Traditional masscan with camera ports
gridland discover --engine masscan --camera-ports --target 172.16.0.0/16
```

### Credential Testing - Important Warnings

⚠️ **CRITICAL**: Credential testing (`--test-credentials`) must ONLY be used on:
- Systems you own
- Systems you have explicit written authorization to test
- Educational lab environments you control

**Unauthorized access to computer systems is illegal** under laws including:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar cybercrime laws in other jurisdictions

### Ethical Safeguards in GRIDLAND v3.0

The credential tester includes built-in ethical safeguards:

1. **Rate Limiting**: Configurable delay between authentication attempts (default 0.1 seconds)
2. **Attempt Limiting**: Maximum attempts per target (default 100 attempts)
3. **Audit Logging**: Optional CSV audit trail logging all attempts with timestamps
4. **Explicit Consent**: Credential testing flag must be explicitly set (not enabled by default)
5. **Progress Transparency**: Real-time progress reporting of attempts made

**Example with custom safeguards:**
```python
from gridland.analyze.plugins.builtin import CredentialTester

tester = CredentialTester(
    rate_limit_delay=0.5,           # 0.5s delay between attempts
    max_attempts_per_target=50,     # Max 50 attempts
    audit_log_path="audit.csv"      # Log all attempts
)
```

### Migration Benefits

**Why migrate from CamXploit.py to GRIDLAND v3.0?**

1. **Maintainability**: Modular codebase vs. 1,853-line monolithic script
2. **Testing**: 521+ automated tests ensure reliability and feature parity
3. **Performance**: 2-3x faster with optimized data structures and threading
4. **Security**: Enhanced CVE database with CVSS scores, exploit references, affected versions
5. **Extensibility**: Plugin architecture allows custom vulnerability scanners
6. **Modern Python**: Async/await patterns, type hints, comprehensive error handling
7. **Data Quality**: Structured JSON databases with validation and metadata
8. **Ethical Features**: Rate limiting, audit logging, attempt limiting for responsible testing

---

## Architecture

```
gridland/
├── discover/          # Discovery engines (Masscan, Shodan, Censys)
├── analyze/           # Analysis framework
│   ├── core/          # Advanced fingerprinting, ML, topology
│   ├── engines/       # Analysis engine orchestration
│   ├── plugins/       # Vulnerability scanner plugins
│   └── memory/        # Memory pooling system
├── stream/            # Stream intelligence and validation
├── core/              # Shared utilities (logger, config, network)
└── cli/               # Command-line interface
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager
- (Optional) Docker for containerized deployment

### Quick Start

```bash
# Clone the repository
git clone https://github.com/thunderbird-esq/gridland3.git
cd gridland3

# Install dependencies
pip install -r requirements.txt

# Install development tools (optional)
pip install -r requirements-dev.txt

# Run validation tests
python validate_gridland.py
```

### Docker Deployment

```bash
# Build the Docker image
docker build --build-arg SHODAN_API_KEY_ARG=your_api_key_here -t gridland .

# Run the container
docker run -p 8080:8080 gridland
```

---

## Usage

### Command-Line Interface

GRIDLAND v3.0 provides a modern, user-friendly CLI with two main commands: `gridland discover` and `gridland analyze`.

```bash
# Discovery - Find cameras on network
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Discovery - Use masscan for faster scanning
gridland discover --engine masscan --camera-ports --target 10.0.0.0/8

# Discovery - Scan specific port category (RTSP)
gridland discover --use-python-scanner --camera-port-category rtsp --target 192.168.1.0/24

# Analysis - Comprehensive reconnaissance
gridland analyze 192.168.1.100 --full-scan

# Analysis - OSINT only
gridland analyze 192.168.1.100 --show-search-urls --geo-lookup --google-dorks

# Analysis - Security testing (authorized systems only!)
gridland analyze 192.168.1.100 --detect-brand --scan-logins --test-credentials

# Analysis - CVE lookup
gridland analyze 192.168.1.100 --detect-brand --show-cves
```

**Legacy CLI (still supported):**
```bash
# If you prefer the old module-based CLI
python -m gridland.cli.discover_cli --engine masscan --target 192.168.1.0/24
python -m gridland.cli.analyze_cli --ip 192.168.1.100
```

### Web Interface

```bash
# Start the Flask server
python server.py

# Access at http://localhost:8080
```

### Programmatic Usage

```python
from gridland.discover.masscan_engine import MasscanEngine
from gridland.analyze.engines.analysis_engine import AnalysisEngine

# Discover targets
discovery = MasscanEngine()
targets = await discovery.discover(target="192.168.1.0/24", ports="80,443,554,8080")

# Analyze target
analysis = AnalysisEngine()
results = await analysis.analyze_target("192.168.1.100")
```

---

## Plugin System

GRIDLAND uses a modular plugin architecture for vulnerability scanning:

```python
from gridland.analyze.plugins.base import VulnerabilityPlugin

class CustomScanner(VulnerabilityPlugin):
    def get_metadata(self):
        return {"name": "custom-scanner", "version": "1.0"}

    async def scan_vulnerabilities(self, target_ip, scan_result):
        # Custom scanning logic
        return results
```

Built-in plugins:

- Hikvision scanner (CVE detection, auth bypass)
- Dahua scanner (credential testing, firmware checks)
- Axis scanner (VAPIX API analysis)
- Generic camera scanner (pattern matching)
- Banner grabber (service identification)
- RTSP stream scanner (protocol analysis)
- IP context scanner (geolocation, ASN lookup)

---

## Configuration

### Environment Variables

```bash
# API Keys (optional but recommended)
export SHODAN_API_KEY="your_shodan_key"  # pragma: allowlist secret
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"  # pragma: allowlist secret

# Logging
export GRIDLAND_LOG_LEVEL="INFO"
export GRIDLAND_LOG_FILE="gridland.log"
```

### Configuration File

Create `~/.gridland/config.json`:

```json
{
  "discovery": {
    "masscan_rate": 1000,
    "timeout": 30
  },
  "analysis": {
    "max_threads": 10,
    "plugin_timeout": 15
  }
}
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=gridland --cov-report=html

# Run specific test suite
pytest tests/discover/ -v
```

---

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run linting
black gridland/ tests/
flake8 gridland/ tests/
mypy gridland/

# Run security checks
bandit -r gridland/
```

### Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, development process, and how to submit pull requests.

---

## Performance

GRIDLAND is optimized for high-performance reconnaissance:

- **Memory Pooling**: Pre-allocated objects eliminate GC overhead
- **AsyncIO + Threading**: Hybrid concurrent execution model
- **Work-Stealing Scheduler**: Dynamic load balancing across cores
- **Trie-Based Pattern Matching**: O(m) lookup for brand detection
- **Zero-Copy Stream Validation**: Efficient protocol analysis

Benchmarks:

- Discovery: 1000 IPs/minute (masscan mode)
- Analysis: 50 targets/minute (all plugins)
- Fingerprinting: <500ms per target
- Stream validation: <2s per URL

---

## Security Considerations

- All API keys are encrypted at rest
- Secrets scanning enabled via detect-secrets
- Rate limiting prevents accidental DoS
- Comprehensive input validation
- No credential storage (memory-only)
- Audit logging for all operations

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Legacy Notice

**CamXploit.py has been deprecated** in favor of GRIDLAND v3.0. The original monolithic script has been completely reimagined as a modular, well-tested, and performant Python package.

### What happened to CamXploit.py?

- **Status**: Deprecated (no new features, bug fixes only for critical issues)
- **Location**: Available in `legacy/CamXploit.py` for reference
- **Reason**: Monolithic 1,853-line script difficult to maintain, test, and extend
- **Replacement**: GRIDLAND v3.0 with 100% feature parity + enhancements

### Migration Path

**Step 1: Install GRIDLAND v3.0**
```bash
pip install -e .
```

**Step 2: Update your commands**
- Replace `python CamXploit.py` with `gridland analyze <IP>`
- Use `--full-scan` flag for comprehensive analysis (equivalent to CamXploit.py default behavior)
- See command mapping table above for feature-specific equivalents

**Step 3: Review new features**
- Explore new CLI flags (`--show-search-urls`, `--geo-lookup`, `--google-dorks`)
- Leverage ethical safeguards for credential testing
- Use Python scanner for masscan-free port scanning

**Step 4: Test in your environment**
```bash
# Run feature parity validation
python validate_migration.py

# Test against known targets
gridland analyze <test-ip> --full-scan
```

### Feature Parity Guarantee

GRIDLAND v3.0 maintains **100% feature parity** with CamXploit.py:

- ✅ All 685 camera ports preserved
- ✅ All 72 login paths maintained
- ✅ All 39 CVEs with enhanced metadata
- ✅ All 138+ stream paths supported
- ✅ All 30 default credential combinations
- ✅ All brand detection patterns
- ✅ All OSINT integrations (Shodan, Censys, ZoomEye, Google)
- ✅ All authentication types (Basic, Digest, Form)
- ✅ All stream protocols (RTSP, RTMP, HTTP, MMS, ONVIF)

Plus new enhancements:
- ⭐ Ethical safeguards (rate limiting, audit logging)
- ⭐ 521+ automated unit tests
- ⭐ Modular plugin architecture
- ⭐ Enhanced CVE database with CVSS scores
- ⭐ Async capabilities for performance
- ⭐ Type hints and comprehensive documentation

### Need Help Migrating?

- **Documentation**: See `CLAUDE.md` for detailed migration guide
- **Issues**: Report migration issues on [GitHub Issues](https://github.com/thunderbird-esq/gridland3/issues)
- **Validation**: Run `python validate_migration.py` to verify feature parity
- **Rollback**: CamXploit.py remains available in `legacy/` directory if needed

---

## Acknowledgments

- Original CamXploit.py concept for camera reconnaissance
- Security research community for vulnerability databases
- Contributors to open-source security tools

---

## Support

- **Issues**: [GitHub Issues](https://github.com/thunderbird-esq/gridland3/issues)
- **Documentation**: See `CLAUDE.md` for development guides
- **Troubleshooting**: See `TROUBLESHOOTING.md` for common issues

---

## Responsible Disclosure

If you discover security vulnerabilities in GRIDLAND itself, please report them responsibly:

1. Do not open public issues
2. Email details to the maintainers
3. Allow reasonable time for patching
4. Coordinate public disclosure

---

**Built with ❤️ for the security research community**
