# Quick Start

This guide will get you started with GRIDLAND v3.0 in minutes.

!!! warning "Ethical Use Required"
    Only scan systems you own or have explicit authorization to test. Unauthorized scanning is illegal.

## Basic Workflow

GRIDLAND follows a two-phase workflow:

1. **Discover** - Find cameras on the network
2. **Analyze** - Investigate specific targets

## Phase 1: Discovery

### Discover Cameras on a Network

```bash
# Scan a /24 subnet using Python scanner
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Use masscan for faster scanning (Linux only)
sudo gridland discover --target 192.168.1.0/24 --rate 1000

# Scan specific port category (RTSP only)
gridland discover --use-python-scanner --camera-port-category rtsp --target 192.168.1.0/24
```

### Discovery Options

| Flag | Description |
|------|-------------|
| `--target` | IP address or CIDR range (e.g., 192.168.1.100 or 192.168.1.0/24) |
| `--use-python-scanner` | Use built-in Python scanner (cross-platform) |
| `--camera-ports` | Scan all 685 camera ports |
| `--camera-port-category` | Scan specific category (rtsp, http, onvif, etc.) |
| `--rate` | Packets per second for masscan (requires sudo) |
| `--output` | Save results to file |

### Example Output

```
[*] Starting camera discovery scan...
[*] Target: 192.168.1.0/24
[*] Ports: 685 camera-specific ports
[*] Scanner: Python (multi-threaded)

[+] 192.168.1.100:80 - OPEN
[+] 192.168.1.100:554 - OPEN (RTSP)
[+] 192.168.1.100:8080 - OPEN
[+] 192.168.1.101:80 - OPEN
[+] 192.168.1.101:37777 - OPEN

[*] Scan complete: 5 open ports found
```

## Phase 2: Analysis

### Analyze a Specific Target

```bash
# Basic analysis
gridland analyze 192.168.1.100

# Full reconnaissance scan
gridland analyze 192.168.1.100 --full-scan

# OSINT reconnaissance
gridland analyze 8.8.8.8 --show-search-urls --geo-lookup
```

### Analysis Options

| Flag | Description |
|------|-------------|
| `--full-scan` | Run all analysis modules (OSINT + vulnerabilities) |
| `--show-search-urls` | Generate Shodan, Censys, ZoomEye URLs |
| `--geo-lookup` | Perform IP geolocation |
| `--google-dorks` | Generate Google Dork queries |
| `--show-cves` | Display known CVEs for detected brand |
| `--detect-brand` | Identify camera manufacturer |
| `--scan-logins` | Discover authentication endpoints |
| `--test-credentials` | Test default credentials (with safeguards) |
| `--discover-streams` | Find RTSP/RTMP/HTTP streams |

## Common Use Cases

### Use Case 1: Quick Network Survey

Find all cameras on your network:

```bash
# Step 1: Discover cameras
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Step 2: Analyze each discovered IP
gridland analyze 192.168.1.100 --detect-brand --show-cves
```

### Use Case 2: OSINT Reconnaissance

Gather intelligence on a public IP:

```bash
# Generate search URLs and geolocation
gridland analyze 8.8.8.8 --show-search-urls --geo-lookup --google-dorks

# Example output:
# [*] OSINT Search URLs:
# [+] Shodan: https://www.shodan.io/search?query=8.8.8.8
# [+] Censys: https://search.censys.io/hosts/8.8.8.8
# [+] ZoomEye: https://www.zoomeye.org/searchResult?q=8.8.8.8
#
# [*] IP Geolocation:
# [+] City: Mountain View
# [+] Country: US
# [+] Location: 37.4056,-122.0775
# [+] OpenStreetMap: https://www.openstreetmap.org/?mlat=37.4056&mlon=-122.0775#map=13/37.4056/-122.0775
```

### Use Case 3: Vulnerability Assessment

Identify vulnerabilities on a camera:

```bash
# Full vulnerability scan
gridland analyze 192.168.1.100 --full-scan

# This runs:
# 1. Brand detection
# 2. CVE lookup
# 3. Login page scanning
# 4. Default credential testing (with rate limiting)
# 5. Stream discovery
# 6. OSINT reconnaissance
```

### Use Case 4: Stream Discovery

Find live camera streams:

```bash
# Discover all streams
gridland analyze 192.168.1.100 --discover-streams

# Example output:
# [*] Stream Discovery Results:
# [+] rtsp://192.168.1.100:554/live.sdp - RTSP (h264, 1080p)
# [+] http://192.168.1.100:80/video/live_1080p.h264 - HTTP (h264, 1080p)
# [+] rtmp://192.168.1.100:1935/live - RTMP (live stream)
```

### Use Case 5: Authentication Testing

Test for weak credentials (ethically):

```bash
# Test default credentials with safeguards
gridland analyze 192.168.1.100 --test-credentials

# Safeguards:
# - Rate limiting: 0.1s delay between attempts
# - Attempt limit: Maximum 100 attempts per target
# - Audit logging: All attempts logged to CSV
```

## Example Workflow

Here's a complete workflow for assessing a camera device:

```bash
# Step 1: Discover open ports
gridland discover --use-python-scanner --camera-ports --target 192.168.1.100

# Step 2: Identify the brand
gridland analyze 192.168.1.100 --detect-brand

# Output: [+] Brand detected: Hikvision (confidence: 0.8)

# Step 3: Check for known vulnerabilities
gridland analyze 192.168.1.100 --show-cves

# Output: [+] Found 12 CVEs for Hikvision (5 Critical, 7 High)

# Step 4: Scan for login pages
gridland analyze 192.168.1.100 --scan-logins

# Output: [+] Found login page: http://192.168.1.100/login (Basic Auth)

# Step 5: Test default credentials (if authorized)
gridland analyze 192.168.1.100 --test-credentials

# Step 6: Discover streams
gridland analyze 192.168.1.100 --discover-streams

# Step 7: Full OSINT report
gridland analyze 192.168.1.100 --show-search-urls --geo-lookup
```

## Python API Usage

### Using GRIDLAND in Python Scripts

```python
from gridland.discover import PythonPortScanner, PortSelector
from gridland.analyze.core import BrandDetector, CVELookup
from gridland.analyze.core.osint import OSINTURLGenerator, GeoLookup
import asyncio

# Port scanning
scanner = PythonPortScanner()
ports = PortSelector.get_camera_ports(category='rtsp')
open_ports = scanner.scan_ports("192.168.1.100", ports)
print(f"Open ports: {open_ports}")

# Brand detection
detector = BrandDetector()
result = detector.detect_brand({
    'server_header': 'hikvision-dvr',
    'content_type': 'image/jpeg',
    'response_body': '<html>Camera Login</html>'
})
print(f"Brand: {result['brand']} (confidence: {result['confidence']})")

# CVE lookup
lookup = CVELookup()
cves = lookup.get_cves('hikvision', min_severity='critical')
print(f"Found {len(cves)} critical CVEs")

# OSINT URLs
urls = OSINTURLGenerator.generate_search_urls("8.8.8.8")
print(f"Shodan: {urls['shodan']}")

# Geolocation (async)
async def lookup_ip():
    geo = GeoLookup()
    info = await geo.get_ip_info("8.8.8.8")
    print(f"Location: {info['city']}, {info['country']}")

asyncio.run(lookup_ip())
```

## Tips and Best Practices

### Performance Optimization

1. **Use masscan for large networks** (Linux only):
   ```bash
   sudo gridland discover --target 10.0.0.0/8 --rate 10000
   ```

2. **Filter by port category** to reduce scan time:
   ```bash
   gridland discover --camera-port-category rtsp --target 192.168.1.0/24
   ```

3. **Adjust thread count** for Python scanner (modify scanner initialization)

### Ethical Scanning

1. **Always get authorization** before scanning
2. **Use rate limiting** for credential testing:
   ```python
   from gridland.analyze.plugins.builtin import CredentialTester
   tester = CredentialTester(rate_limit_delay=1.0, max_attempts_per_target=50)
   ```
3. **Enable audit logging** to track all actions:
   ```python
   tester = CredentialTester(audit_log_path="/var/log/gridland_audit.csv")
   ```

### Output Management

1. **Save scan results** for later analysis:
   ```bash
   gridland discover --target 192.168.1.0/24 --output scan_results.txt
   ```

2. **Parse JSON output** in scripts:
   ```bash
   gridland analyze 192.168.1.100 --full-scan --json > report.json
   ```

## Next Steps

- [Configuration Guide](configuration.md) - Customize GRIDLAND settings
- [CLI Reference](../cli/overview.md) - Explore all command options
- [API Documentation](../api/core.md) - Use GRIDLAND in Python scripts
- [Migration Guide](../migration/from-camxploit.md) - Migrate from CamXploit.py

## Getting Help

- Check the [Troubleshooting Guide](../troubleshooting.md)
- Review [Example Scripts](https://github.com/thunderbird-esq/gridland3/tree/main/examples)
- Ask questions in [GitHub Discussions](https://github.com/thunderbird-esq/gridland3/discussions)
