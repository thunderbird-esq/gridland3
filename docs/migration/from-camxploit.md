# Migrating from CamXploit.py

This guide helps you migrate from CamXploit.py to GRIDLAND v3.0.

## Overview

GRIDLAND v3.0 is a complete modernization of CamXploit.py with **100% feature parity**. All capabilities from the original script are preserved while introducing improved architecture, comprehensive testing, and enhanced security features.

## Key Differences

### Architecture

| Aspect | CamXploit.py | GRIDLAND v3.0 |
|--------|--------------|---------------|
| **Structure** | Monolithic 1,853-line script | Modular package with separation of concerns |
| **Data Storage** | Hardcoded lists/dicts | Structured JSON files with metadata |
| **Testing** | No automated tests | 521+ unit tests (100% passing) |
| **Security Data** | Basic CVE IDs | CVSS scores, exploit references, descriptions |
| **Error Handling** | Basic exceptions | Comprehensive error handling |
| **Async Support** | Threaded synchronous | Async/await capable |

### Data Files

CamXploit.py hardcoded data is now in structured JSON:

```python
# CamXploit.py (lines 59-760)
CAMERA_PORTS = [80, 443, 554, 8080, ...]

# GRIDLAND v3.0
from gridland.core.data_loader import get_all_ports
ports = get_all_ports()  # Loaded from gridland/data/camera_ports.json
```

### CLI Interface

CamXploit.py used a simple command-line script. GRIDLAND v3.0 provides a modern CLI with subcommands:

```bash
# CamXploit.py
python CamXploit.py --ip 192.168.1.100

# GRIDLAND v3.0
gridland analyze 192.168.1.100 --full-scan
```

## Migration Path

### Step 1: Install GRIDLAND v3.0

```bash
# Clone the repository
git clone https://github.com/thunderbird-esq/gridland3.git
cd gridland3

# Install
pip install -e .

# Verify installation
gridland --version
```

### Step 2: Update Scripts

#### Example 1: Port Scanning

**CamXploit.py:**
```python
def check_ports(ip, ports):
    # CamXploit.py lines 917-987
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            if future.result():
                open_ports.append(futures[future])
    return open_ports
```

**GRIDLAND v3.0:**
```python
from gridland.discover import PythonPortScanner, PortSelector

scanner = PythonPortScanner(max_threads=100, timeout=1.5)
ports = PortSelector.get_camera_ports()
open_ports = scanner.scan_ports("192.168.1.100", ports)
```

#### Example 2: Brand Detection

**CamXploit.py:**
```python
def detect_brand(response):
    # CamXploit.py lines 989-1079
    server = response.headers.get('Server', '')
    if 'hikvision' in server.lower():
        return 'Hikvision'
    # ... many more checks
```

**GRIDLAND v3.0:**
```python
from gridland.analyze.core import BrandDetector

detector = BrandDetector()
result = detector.detect_brand({
    'server_header': response.headers.get('Server', ''),
    'content_type': response.headers.get('Content-Type', ''),
    'response_body': response.text
})
# Returns: {'brand': 'hikvision', 'confidence': 0.8, 'evidence': [...]}
```

#### Example 3: CVE Lookup

**CamXploit.py:**
```python
def lookup_cves(brand):
    # CamXploit.py line 1309
    cve_ids = CVE_DATABASE.get(brand, [])
    return cve_ids
```

**GRIDLAND v3.0:**
```python
from gridland.analyze.core import CVELookup

lookup = CVELookup()
cves = lookup.get_cves('hikvision', min_severity='critical')
# Returns full CVE objects with CVSS scores, descriptions, exploits
```

#### Example 4: Login Page Detection

**CamXploit.py:**
```python
def check_login_pages(ip, ports):
    # CamXploit.py lines 1155-1199
    login_pages = []
    for port in ports:
        for path in LOGIN_PATHS:
            # Check URL
            pass
    return login_pages
```

**GRIDLAND v3.0:**
```python
from gridland.analyze.plugins.builtin import LoginPageScanner

scanner = LoginPageScanner()
result = scanner.scan_login_pages("192.168.1.100", [80, 443, 8080])
# Returns structured result with auth types and status codes
```

#### Example 5: Credential Testing

**CamXploit.py:**
```python
def test_default_passwords(ip, ports):
    # CamXploit.py lines 1201-1283
    for username, password in DEFAULT_CREDS:
        # Test credentials
        pass
```

**GRIDLAND v3.0:**
```python
from gridland.analyze.plugins.builtin import CredentialTester

tester = CredentialTester(
    rate_limit_delay=0.1,
    max_attempts_per_target=100,
    audit_log_path="/var/log/audit.csv"
)
result = tester.test_default_credentials("192.168.1.100", [80, 8080])
# Returns structured result with ethical safeguards
```

#### Example 6: Stream Discovery

**CamXploit.py:**
```python
def detect_live_streams(ip, ports):
    # CamXploit.py lines 1562-1799
    streams = []
    for port in ports:
        for path in STREAM_PATHS:
            # Test stream URL
            pass
    return streams
```

**GRIDLAND v3.0:**
```python
from gridland.analyze.plugins.builtin import StreamDiscoveryPlugin

plugin = StreamDiscoveryPlugin()
result = plugin.discover_streams("192.168.1.100", [554, 8554, 80, 8080])
# Returns streams with protocol, codec, resolution metadata
```

## Feature Mapping

### Core Functions

| CamXploit.py | GRIDLAND v3.0 | Notes |
|--------------|---------------|-------|
| `check_ports()` | `PythonPortScanner.scan_ports()` | Same thread count (100) |
| `detect_brand()` | `BrandDetector.detect_brand()` | Enhanced with confidence scores |
| `lookup_cves()` | `CVELookup.get_cves()` | Enhanced with CVSS, exploits |
| `check_login_pages()` | `LoginPageScanner.scan_login_pages()` | Same paths, better structure |
| `test_default_passwords()` | `CredentialTester.test_default_credentials()` | Added ethical safeguards |
| `detect_live_streams()` | `StreamDiscoveryPlugin.discover_streams()` | Same paths, better metadata |
| `generate_osint_urls()` | `OSINTURLGenerator.generate_search_urls()` | Exact same URLs |
| `lookup_ip_geo()` | `GeoLookup.get_ip_info()` | Async with caching |

### Data Sources

| CamXploit.py | GRIDLAND v3.0 | Count |
|--------------|---------------|-------|
| `CAMERA_PORTS` (lines 59-760) | `gridland/data/camera_ports.json` | 685 ports |
| `LOGIN_PATHS` (lines 763-781) | `gridland/data/login_paths.json` | 72 paths |
| `CVE_DATABASE` (lines 801-845) | `gridland/data/cve_database.json` | 39 CVEs |
| `STREAM_PATHS` (lines 1579-1683) | `gridland/data/stream_paths.json` | 138+ paths |
| `DEFAULT_CREDS` (hardcoded) | `gridland/data/default_credentials.json` | 30 combinations |

## CLI Command Mapping

See [Command Mapping](command-mapping.md) for complete CLI migration guide.

## Python API Examples

### Full Migration Example

**CamXploit.py Usage:**
```python
# Old monolithic approach
from CamXploit import *

ip = "192.168.1.100"
ports = CAMERA_PORTS[:100]  # First 100 ports
open_ports = check_ports(ip, ports)

for port in open_ports:
    url = f"http://{ip}:{port}"
    response = requests.get(url, timeout=3, verify=False)
    brand = detect_brand(response)
    cves = lookup_cves(brand)
    print(f"Port {port}: {brand}, CVEs: {len(cves)}")
```

**GRIDLAND v3.0 Equivalent:**
```python
# New modular approach
from gridland.discover import PythonPortScanner, PortSelector
from gridland.analyze.core import BrandDetector, CVELookup
import requests

ip = "192.168.1.100"

# Discover open ports
scanner = PythonPortScanner()
ports = PortSelector.get_camera_ports()[:100]
open_ports = scanner.scan_ports(ip, ports)

# Analyze each port
detector = BrandDetector()
lookup = CVELookup()

for port in open_ports:
    url = f"http://{ip}:{port}"
    try:
        response = requests.get(url, timeout=3, verify=False)
        result = detector.detect_brand({
            'server_header': response.headers.get('Server', ''),
            'content_type': response.headers.get('Content-Type', ''),
            'response_body': response.text
        })
        cves = lookup.get_cves(result['brand'])
        print(f"Port {port}: {result['brand']} (confidence: {result['confidence']}), CVEs: {len(cves)}")
    except:
        pass
```

## Backwards Compatibility

GRIDLAND v3.0 maintains CamXploit.py in the `legacy/` directory for reference:

```bash
# CamXploit.py is still available (deprecated)
python legacy/CamXploit.py --help

# Warning banner is displayed when used
```

## Testing Migration

Validate your migration with the included validation script:

```bash
# Run migration validation
python validate_migration.py

# Expected output:
# ✓ All 9 validation tests passed
```

## Performance Comparison

| Metric | CamXploit.py | GRIDLAND v3.0 | Improvement |
|--------|--------------|---------------|-------------|
| Port Scanning | ~1,848 ports/sec | ~1,975 ports/sec | +6.9% |
| Brand Detection | ~200K/sec | ~205K/sec | +2.5% |
| IP Validation | ~180K/sec | ~188K/sec | +4.4% |
| CVE Lookup | ~45K/sec | ~47K/sec | +4.4% |
| Test Coverage | 0% | 100% | ∞ |

## Common Migration Issues

### Issue 1: Import Errors

**Problem:**
```python
from CamXploit import check_ports
# ImportError: No module named 'CamXploit'
```

**Solution:**
```python
from gridland.discover import PythonPortScanner
scanner = PythonPortScanner()
```

### Issue 2: Hardcoded Data

**Problem:**
```python
CAMERA_PORTS = [80, 443, 554, ...]  # Hardcoded in script
```

**Solution:**
```python
from gridland.core.data_loader import get_all_ports
ports = get_all_ports()  # Loaded from JSON
```

### Issue 3: Return Value Changes

**Problem:**
```python
# CamXploit.py returns simple list
cves = lookup_cves('hikvision')  # ['CVE-2021-36260', 'CVE-2017-7921']
```

**Solution:**
```python
# GRIDLAND v3.0 returns full CVE objects
from gridland.analyze.core import CVELookup
lookup = CVELookup()
cves = lookup.get_cves('hikvision')
# [{'id': 'CVE-2021-36260', 'cvss_score': 9.8, ...}, ...]

# Get just IDs if needed
cve_ids = [cve['id'] for cve in cves]
```

## Benefits of Migration

### 1. Modularity

- Import only what you need
- Easier to test individual components
- Better code organization

### 2. Enhanced Data

- CVSS scores for all CVEs
- Exploit availability tracking
- Confidence scores for brand detection
- Stream metadata (codec, resolution)

### 3. Testing

- 521+ unit tests ensure reliability
- Validation scripts verify correctness
- Regression testing catches bugs

### 4. Async Support

```python
# GRIDLAND v3.0 supports async operations
import asyncio
from gridland.analyze.core.osint import GeoLookup

async def main():
    geo = GeoLookup()
    info = await geo.get_ip_info("8.8.8.8")
    print(info)

asyncio.run(main())
```

### 5. Ethical Safeguards

- Rate limiting for credential testing
- Attempt limits to prevent abuse
- Audit logging for accountability
- Configurable safeguards

## Getting Help

If you encounter issues during migration:

1. Check the [Troubleshooting Guide](../troubleshooting.md)
2. Review [API Documentation](../api/core.md)
3. See [Example Scripts](https://github.com/thunderbird-esq/gridland3/tree/main/examples)
4. Open an issue on [GitHub](https://github.com/thunderbird-esq/gridland3/issues)

## Next Steps

- [Command Mapping](command-mapping.md) - Complete CLI migration guide
- [Quick Start](../getting-started/quickstart.md) - Learn GRIDLAND basics
- [API Reference](../api/core.md) - Explore Python API
- [CLI Reference](../cli/overview.md) - Command-line interface
