# Configuration

GRIDLAND v3.0 can be configured through environment variables, configuration files, and programmatic settings.

## Environment Variables

### Core Settings

Create a `.env` file in the project root or set environment variables:

```bash
# OSINT API Keys
SHODAN_API_KEY=your_shodan_api_key_here
IPINFO_API_KEY=your_ipinfo_api_key_here

# Data Directory (optional)
GRIDLAND_DATA_DIR=/path/to/custom/data

# Audit Logging (optional)
GRIDLAND_AUDIT_LOG=/var/log/gridland_audit.csv

# Network Settings
GRIDLAND_TIMEOUT=5
GRIDLAND_MAX_THREADS=100
```

### API Key Configuration

#### Shodan API Key

Required for legacy server.py Shodan discovery features:

```bash
# Get your API key from https://account.shodan.io/
export SHODAN_API_KEY=your_api_key_here
```

#### IPinfo.io API Key

Optional for enhanced geolocation features (free tier available):

```bash
# Get your API key from https://ipinfo.io/signup
export IPINFO_API_KEY=your_api_key_here
```

## Data Directory Configuration

### Default Data Files

GRIDLAND uses JSON data files located in `gridland/data/`:

```
gridland/data/
├── camera_ports.json       # 685 camera ports
├── login_paths.json        # 72 authentication endpoints
├── cve_database.json       # 39 CVEs with metadata
├── stream_paths.json       # 138+ stream paths
├── default_credentials.json # 30 credential combinations
└── cpplus_data.json        # CP Plus detection data
```

### Custom Data Directory

To use a custom data directory:

```bash
# Set environment variable
export GRIDLAND_DATA_DIR=/path/to/custom/data

# Copy default data files
cp -r gridland/data/* /path/to/custom/data/
```

### Data File Format

All data files follow a structured JSON format with metadata:

```json
{
  "metadata": {
    "version": "3.0.0",
    "last_updated": "2025-01-15",
    "description": "Camera port database"
  },
  "data": {
    // ... data content
  }
}
```

## Scanner Configuration

### Python Port Scanner

Configure the multi-threaded Python scanner:

```python
from gridland.discover import PythonPortScanner

# Custom configuration
scanner = PythonPortScanner(
    max_threads=50,      # Number of concurrent threads (default: 100)
    timeout=2.0          # Timeout per port in seconds (default: 1.5)
)

# Scan with custom settings
open_ports = scanner.scan_ports("192.168.1.100", [80, 443, 554, 8080])
```

### masscan Configuration

Configure masscan for high-speed scanning (Linux only):

```bash
# High-speed scan (requires root)
sudo gridland discover --target 192.168.1.0/24 --rate 10000

# Conservative scan
sudo gridland discover --target 192.168.1.0/24 --rate 100

# Custom masscan options
sudo masscan 192.168.1.0/24 -p80,443,554 --rate 1000
```

## Analysis Configuration

### Brand Detection

Configure brand detection sensitivity:

```python
from gridland.analyze.core import BrandDetector

detector = BrandDetector()

# Analyze with custom confidence threshold
result = detector.detect_brand(port_data)
if result['confidence'] >= 0.7:  # High confidence only
    print(f"Brand: {result['brand']}")
```

### CVE Lookup

Configure CVE filtering:

```python
from gridland.analyze.core import CVELookup

lookup = CVELookup()

# Get only critical CVEs with exploits
cves = lookup.get_cves(
    brand='hikvision',
    min_severity='critical',
    exploits_only=True
)
```

### OSINT Configuration

#### URL Generator

No configuration needed (static methods):

```python
from gridland.analyze.core.osint import OSINTURLGenerator

# Generate URLs with custom parameters
urls = OSINTURLGenerator.generate_search_urls("192.168.1.100")
dorks = OSINTURLGenerator.generate_google_dorks("192.168.1.100")
```

#### Geolocation

Configure caching and rate limiting:

```python
from gridland.analyze.core.osint import GeoLookup
import asyncio

async def configure_geo():
    geo = GeoLookup(
        cache_duration=7200,      # Cache for 2 hours (default: 3600)
        rate_limit_delay=0.2      # Delay between requests (default: 0.1)
    )

    info = await geo.get_ip_info("8.8.8.8")

    # Use custom OpenStreetMap instance
    map_urls = GeoLookup.generate_map_urls(
        info,
        osm_base_url="http://localhost:8080"
    )

    return info

asyncio.run(configure_geo())
```

## Plugin Configuration

### Login Page Scanner

Configure authentication endpoint scanning:

```python
from gridland.analyze.plugins.builtin import LoginPageScanner

scanner = LoginPageScanner()

# Custom progress callback
def progress(completed, total):
    percent = (completed / total) * 100
    print(f"Progress: {percent:.1f}%")

result = scanner.scan_login_pages(
    ip="192.168.1.100",
    open_ports=[80, 443, 8080],
    progress_callback=progress
)
```

### Credential Tester

Configure ethical safeguards:

```python
from gridland.analyze.plugins.builtin import CredentialTester

# Production configuration (strict limits)
tester = CredentialTester(
    max_threads=10,                # Reduce concurrency (default: 20)
    timeout=10,                    # Longer timeout (default: 5)
    rate_limit_delay=1.0,          # 1 second between attempts (default: 0.1)
    max_attempts_per_target=50,    # Limit attempts (default: 100)
    audit_log_path="/var/log/gridland/credential_tests.csv"  # Audit trail
)

# Development configuration (faster, no limits)
tester_dev = CredentialTester(
    rate_limit_delay=0.0,          # No delay
    max_attempts_per_target=None   # No limit
)
```

### Stream Discovery

Configure stream detection:

```python
from gridland.analyze.plugins.builtin import StreamDiscoveryPlugin

plugin = StreamDiscoveryPlugin()

# Custom progress tracking
def track_progress(checked, total):
    print(f"Checked {checked}/{total} URLs ({checked/total*100:.1f}%)")

result = plugin.discover_streams(
    ip="192.168.1.100",
    open_ports=[554, 8554, 80, 8080],
    progress_callback=track_progress
)
```

### CP Plus Scanner

Configure CP Plus device detection:

```python
from gridland.analyze.plugins.builtin import CPPlusScanner

scanner = CPPlusScanner()

# Detect with confidence threshold
result = scanner.detect_cp_plus(
    ip="192.168.1.100",
    open_ports=[80, 8080, 37777]
)

if result['brand_detected'] and result['confidence'] >= 0.8:
    print(f"High confidence CP Plus device detected")
    print(f"Model: {result['model']}")
    print(f"Type: {result['device_type']}")
```

## Network Configuration

### Timeout Settings

Configure network timeouts globally:

```bash
# Set default timeout for all HTTP requests
export GRIDLAND_TIMEOUT=10  # seconds
```

Or programmatically:

```python
import requests

# Configure requests session
session = requests.Session()
session.timeout = 10  # 10 second timeout

# Use in custom scanner
response = session.get("http://192.168.1.100", timeout=5)
```

### Proxy Configuration

Use GRIDLAND through a proxy:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=https://proxy.example.com:8080

# Run GRIDLAND (will use proxy)
gridland analyze 192.168.1.100
```

Or programmatically:

```python
import requests

proxies = {
    'http': 'http://proxy.example.com:8080',
    'https': 'https://proxy.example.com:8080'
}

response = requests.get("http://192.168.1.100", proxies=proxies)
```

### SSL Verification

GRIDLAND disables SSL verification for camera endpoints (common in embedded devices).

To enable strict SSL verification:

```python
import requests

# Enable SSL verification
response = requests.get("https://192.168.1.100", verify=True)
```

## Logging Configuration

### Python Logging

Configure GRIDLAND logging:

```python
import logging

# Enable debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Configure specific loggers
logger = logging.getLogger('gridland')
logger.setLevel(logging.INFO)

# Add file handler
handler = logging.FileHandler('/var/log/gridland.log')
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)
```

### Audit Logging

Enable comprehensive audit trails:

```python
from gridland.analyze.plugins.builtin import CredentialTester

# Enable audit logging
tester = CredentialTester(
    audit_log_path="/var/log/gridland/audit.csv"
)

# Audit log format:
# timestamp,ip,port,username,password,url,auth_type,result
# 2025-01-15T10:30:45,192.168.1.100,80,admin,admin,http://...,basic,success
```

## Performance Tuning

### Thread Pool Configuration

Adjust concurrency for different workloads:

```python
# High concurrency (fast networks)
scanner = PythonPortScanner(max_threads=200, timeout=1.0)

# Conservative (slow networks)
scanner = PythonPortScanner(max_threads=50, timeout=5.0)

# Balanced (default)
scanner = PythonPortScanner(max_threads=100, timeout=1.5)
```

### Memory Management

For large-scale scans:

```python
# Process results in batches
from gridland.discover import PortSelector

# Get ports in chunks
all_ports = PortSelector.get_camera_ports()
chunk_size = 100

for i in range(0, len(all_ports), chunk_size):
    chunk = all_ports[i:i+chunk_size]
    open_ports = scanner.scan_ports(ip, chunk)
    # Process open_ports immediately
    process_results(open_ports)
```

## Configuration Files

### Custom Configuration File

Create a `gridland.conf` configuration file:

```ini
[scanner]
max_threads = 100
timeout = 1.5

[osint]
cache_duration = 3600
rate_limit_delay = 0.1

[credentials]
rate_limit_delay = 1.0
max_attempts_per_target = 50
audit_log_path = /var/log/gridland_audit.csv

[paths]
data_dir = /usr/local/share/gridland/data
log_dir = /var/log/gridland
```

Load configuration in Python:

```python
import configparser

config = configparser.ConfigParser()
config.read('gridland.conf')

max_threads = config.getint('scanner', 'max_threads')
timeout = config.getfloat('scanner', 'timeout')
```

## Advanced Configuration

### Custom Data Loaders

Extend data loading for custom sources:

```python
from gridland.core.data_loader import load_camera_ports
import json

# Load custom port database
def load_custom_ports(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data['data']['ports']

# Use custom ports
custom_ports = load_custom_ports('/path/to/custom_ports.json')
```

### Plugin Development

Create custom vulnerability scanning plugins:

```python
from gridland.analyze.plugins.base import VulnerabilityPlugin

class MyCustomPlugin(VulnerabilityPlugin):
    def __init__(self):
        super().__init__(
            name="my_custom_plugin",
            version="1.0.0",
            description="My custom vulnerability scanner"
        )

    async def scan_vulnerabilities(self, ip, open_ports, **kwargs):
        # Implement custom scanning logic
        return {
            'vulnerabilities_found': [],
            'scan_complete': True
        }

    def get_metadata(self):
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description
        }
```

## Next Steps

- [CLI Reference](../cli/overview.md) - Explore all command-line options
- [API Documentation](../api/core.md) - Use GRIDLAND in Python scripts
- [Contributing Guide](../contributing/guidelines.md) - Extend GRIDLAND functionality
