# Plugins API

GRIDLAND provides a plugin system for vulnerability scanning. Built-in plugins include login scanning, credential testing, stream discovery, and CP Plus device detection.

## Plugin Base Class

### VulnerabilityPlugin

Base class for creating custom vulnerability scanning plugins.

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
        # Implement scanning logic
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

## Built-in Plugins

### LoginPageScanner

Multi-threaded authentication endpoint discovery.

#### \_\_init\_\_()

```python
from gridland.analyze.plugins.builtin import LoginPageScanner

scanner = LoginPageScanner()
```

#### scan_login_pages(ip, open_ports, progress_callback=None)

Discover authentication endpoints.

```python
def progress(completed, total):
    print(f"Scanned {completed}/{total} endpoints")

result = scanner.scan_login_pages(
    ip="192.168.1.100",
    open_ports=[80, 443, 8080],
    progress_callback=progress
)

# Result structure
print(f"Found {len(result['login_pages'])} login pages")
for page in result['login_pages']:
    print(f"  {page['url']} - {page['auth_type']} (HTTP {page['status_code']})")
```

**Parameters:**
- `ip` (str): Target IP address
- `open_ports` (list[int]): List of open ports to check
- `progress_callback` (callable, optional): Progress callback(completed, total)

**Returns:**
- `dict`: Result dictionary with keys:
  - `login_pages` (list[dict]): List of login page objects
    - `url` (str): Login page URL
    - `auth_type` (str): Authentication type (`'basic'`, `'digest'`, `'form'`)
    - `status_code` (int): HTTP status code
    - `port` (int): Port number
    - `path` (str): URL path

**Features:**
- Multi-threaded scanning (max 50 concurrent threads)
- Tests 72 authentication paths from login_paths.json
- Detects Basic, Digest, and Form authentication
- Checks HTTP status codes: 200, 401, 403
- HTTP/HTTPS protocol auto-detection
- Thread-safe result collection

**Authentication Types:**
- **Basic** - WWW-Authenticate: Basic realm=...
- **Digest** - WWW-Authenticate: Digest realm=...
- **Form** - HTML forms with username/password fields

### CredentialTester

Multi-threaded default credential testing with ethical safeguards.

#### \_\_init\_\_(max_threads=20, timeout=5, rate_limit_delay=0.1, max_attempts_per_target=100, audit_log_path=None)

```python
from gridland.analyze.plugins.builtin import CredentialTester

# Production configuration (with safeguards)
tester = CredentialTester(
    max_threads=10,
    timeout=10,
    rate_limit_delay=1.0,           # 1 second between attempts
    max_attempts_per_target=50,     # Max 50 attempts
    audit_log_path="/var/log/gridland/audit.csv"
)

# Development configuration (faster, no limits)
tester_dev = CredentialTester(
    rate_limit_delay=0.0,           # No delay
    max_attempts_per_target=None    # No limit
)
```

**Parameters:**
- `max_threads` (int): Maximum concurrent threads (default: 20)
- `timeout` (int): Timeout per request in seconds (default: 5)
- `rate_limit_delay` (float): Delay between attempts in seconds (default: 0.1)
- `max_attempts_per_target` (int): Maximum attempts per target (default: 100)
- `audit_log_path` (str, optional): Path to audit log CSV file

#### test_default_credentials(ip, open_ports, progress_callback=None)

Test default credentials on authentication endpoints.

```python
result = tester.test_default_credentials(
    ip="192.168.1.100",
    open_ports=[80, 8080]
)

# Check if credentials found
if result['success']:
    creds = result['credentials']
    print(f"Valid credentials found!")
    print(f"  Username: {creds['username']}")
    print(f"  Password: {creds['password']}")
    print(f"  URL: {creds['url']}")
    print(f"  Auth Type: {creds['auth_type']}")
    print(f"  Attempts: {result['attempts_made']}")
else:
    print(f"No credentials found")
    print(f"  Attempts: {result['attempts_made']}")
    if result['stopped_by_limit']:
        print("  (stopped by attempt limit)")
```

**Parameters:**
- `ip` (str): Target IP address
- `open_ports` (list[int]): List of open ports
- `progress_callback` (callable, optional): Progress callback

**Returns:**
- `dict`: Result dictionary with keys:
  - `success` (bool): Credentials found
  - `credentials` (dict | None): Credential information if found
    - `username` (str): Username
    - `password` (str): Password
    - `url` (str): Authentication URL
    - `auth_type` (str): Authentication type
  - `attempts_made` (int): Total attempts made
  - `stopped_by_limit` (bool): Hit attempt limit

**Ethical Safeguards:**
- **Rate Limiting** - Configurable delay between attempts (default: 0.1s)
- **Attempt Limiting** - Maximum attempts per target (default: 100)
- **Audit Logging** - Optional CSV audit trail of all attempts
- **Early Termination** - Stops when valid credentials found

**Audit Log Format:**
```csv
timestamp,ip,port,username,password,url,auth_type,result
2025-01-15T10:30:45,192.168.1.100,80,admin,admin,http://...,basic,success
2025-01-15T10:30:46,192.168.1.100,80,root,root,http://...,basic,failure
```

**Credentials Tested:**
- 30 default username/password combinations
- Brands: admin, root, user, guest, operator
- 4 endpoints per port: /, /login, /admin/login, /cgi-bin/login
- Supports Basic, Digest, and Form authentication

### StreamDiscoveryPlugin

Multi-threaded stream enumeration across multiple protocols.

#### \_\_init\_\_()

```python
from gridland.analyze.plugins.builtin import StreamDiscoveryPlugin

plugin = StreamDiscoveryPlugin()
```

#### discover_streams(ip, open_ports, progress_callback=None)

Discover camera streams on open ports.

```python
def progress(checked, total):
    print(f"Progress: {checked}/{total} URLs checked")

result = plugin.discover_streams(
    ip="192.168.1.100",
    open_ports=[80, 554, 8080, 8554],
    progress_callback=progress
)

# Analyze results
print(f"Found {len(result['streams_found'])} streams")
print(f"Checked {result['total_checked']} URLs")

for stream in result['streams_found']:
    print(f"  {stream['url']}")
    print(f"    Protocol: {stream['protocol']}")
    print(f"    Port: {stream['port']}")
    print(f"    Codec: {stream.get('codec', 'unknown')}")
    print(f"    Resolution: {stream.get('resolution', 'unknown')}")
```

**Parameters:**
- `ip` (str): Target IP address
- `open_ports` (list[int]): List of open ports
- `progress_callback` (callable, optional): Progress callback(checked, total)

**Returns:**
- `dict`: Result dictionary with keys:
  - `streams_found` (list[dict]): List of stream objects
    - `url` (str): Stream URL
    - `protocol` (str): Protocol (rtsp, rtmp, http, mms, onvif)
    - `port` (int): Port number
    - `path` (str): URL path
    - `detection_method` (str): How stream was detected
    - `codec` (str, optional): Video codec
    - `resolution` (str, optional): Video resolution
    - `category` (str, optional): Stream category (live, snapshot, recorded)
  - `total_checked` (int): Total URLs checked

**Supported Protocols:**
- **RTSP** - Real-Time Streaming Protocol (34 paths)
- **RTMP** - Real-Time Messaging Protocol (15 paths)
- **HTTP/HTTPS** - HTTP Live Streaming (38 paths)
- **MMS** - Microsoft Media Server (4 paths)
- **ONVIF** - ONVIF protocol (7 paths)

**Features:**
- Multi-threaded scanning (max 30 concurrent threads)
- Protocol-aware path selection (RTSP for port 554, HTTP for port 80, etc.)
- 138+ stream paths tested
- Progress updates every 50 URLs
- Codec and resolution detection
- Stream categorization (live, snapshot, recorded)

### CPPlusScanner

CP Plus DVR/NVR detection and fingerprinting.

#### \_\_init\_\_()

```python
from gridland.analyze.plugins.builtin import CPPlusScanner

scanner = CPPlusScanner()
```

#### detect_cp_plus(ip, open_ports, **kwargs)

Detect CP Plus devices.

```python
result = scanner.detect_cp_plus(
    ip="192.168.1.100",
    open_ports=[80, 8080, 37777]
)

# Check detection results
if result['brand_detected']:
    print(f"CP Plus device detected!")
    print(f"  Brand: {result['brand']}")
    print(f"  Model: {result['model']}")
    print(f"  Device Type: {result['device_type']}")
    print(f"  Confidence: {result['confidence']}")
    print(f"  Evidence:")
    for evidence in result['evidence']:
        print(f"    - {evidence}")
else:
    print("No CP Plus device detected")
```

**Parameters:**
- `ip` (str): Target IP address
- `open_ports` (list[int]): List of open ports

**Returns:**
- `dict`: Detection result with keys:
  - `brand_detected` (bool): CP Plus device detected
  - `brand` (str): Brand name ('cp_plus' or 'unknown')
  - `model` (str | None): Device model (e.g., 'CP-UVR-0401E1-IC2')
  - `device_type` (str | None): Device type ('DVR' or 'NVR')
  - `confidence` (float): Confidence score (0.0-1.0)
  - `evidence` (list[str]): Detection evidence

**Detection Indicators:**
- Brand keywords: "cp plus", "cp-plus", "cpplus", "cp_plus", "uvr", "0401e1"
- Model series: CP-UVR-*, CP-DVR-*, CP-NVR-*
- Device type indicators: DVR (Digital Video Recorder), NVR (Network Video Recorder)

**Features:**
- Multi-threaded scanning (max 20 concurrent threads)
- Brand keyword detection
- Model number extraction via regex
- Device type classification
- 7 endpoints tested: /, /index.html, /login, /admin, /cgi-bin, /api, /config
- Confidence scoring with evidence tracking
- Early termination when brand detected

## Complete Plugin Example

```python
from gridland.analyze.plugins.builtin import (
    LoginPageScanner,
    CredentialTester,
    StreamDiscoveryPlugin,
    CPPlusScanner
)

# Target information
ip = "192.168.1.100"
open_ports = [80, 554, 8080, 37777]

# 1. Scan for login pages
print("[*] Scanning for login pages...")
login_scanner = LoginPageScanner()
login_result = login_scanner.scan_login_pages(ip, open_ports)
print(f"[+] Found {len(login_result['login_pages'])} login pages")

# 2. Test default credentials (with safeguards)
print("[*] Testing default credentials...")
tester = CredentialTester(
    rate_limit_delay=1.0,
    max_attempts_per_target=50,
    audit_log_path="/var/log/gridland_audit.csv"
)
cred_result = tester.test_default_credentials(ip, open_ports)
if cred_result['success']:
    print(f"[+] Valid credentials found: {cred_result['credentials']['username']}:{cred_result['credentials']['password']}")
else:
    print("[-] No valid credentials found")

# 3. Discover streams
print("[*] Discovering streams...")
stream_plugin = StreamDiscoveryPlugin()
stream_result = stream_plugin.discover_streams(ip, open_ports)
print(f"[+] Found {len(stream_result['streams_found'])} streams")
for stream in stream_result['streams_found']:
    print(f"    {stream['url']} ({stream['protocol']})")

# 4. Check for CP Plus device
print("[*] Checking for CP Plus device...")
cpplus_scanner = CPPlusScanner()
cpplus_result = cpplus_scanner.detect_cp_plus(ip, open_ports)
if cpplus_result['brand_detected']:
    print(f"[+] CP Plus device: {cpplus_result['model']} ({cpplus_result['device_type']})")
else:
    print("[-] Not a CP Plus device")
```

## Creating Custom Plugins

### Example: Custom Port Banner Scanner

```python
from gridland.analyze.plugins.base import VulnerabilityPlugin
import socket

class PortBannerScanner(VulnerabilityPlugin):
    def __init__(self):
        super().__init__(
            name="port_banner_scanner",
            version="1.0.0",
            description="Collects banners from open ports"
        )

    async def scan_vulnerabilities(self, ip, open_ports, **kwargs):
        banners = []

        for port in open_ports:
            try:
                # Connect and grab banner
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))

                # Send HTTP request if web port
                if port in [80, 443, 8080, 8443]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

                # Receive banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()

                if banner:
                    banners.append({
                        'port': port,
                        'banner': banner.strip()
                    })
            except:
                pass

        return {
            'banners_found': banners,
            'scan_complete': True
        }

    def get_metadata(self):
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': 'Your Name'
        }

# Use the custom plugin
scanner = PortBannerScanner()
result = await scanner.scan_vulnerabilities("192.168.1.100", [80, 443, 8080])
for banner in result['banners_found']:
    print(f"Port {banner['port']}: {banner['banner']}")
```

## Plugin Best Practices

### 1. Ethical Safeguards

Always implement rate limiting and attempt limiting:

```python
class MyPlugin(VulnerabilityPlugin):
    def __init__(self, rate_limit_delay=0.1, max_attempts=100):
        super().__init__(name="my_plugin", version="1.0.0", description="...")
        self.rate_limit_delay = rate_limit_delay
        self.max_attempts = max_attempts

    async def scan_vulnerabilities(self, ip, open_ports, **kwargs):
        attempts = 0
        for attempt in range(self.max_attempts):
            # Do scanning
            attempts += 1
            time.sleep(self.rate_limit_delay)

        return {'attempts_made': attempts}
```

### 2. Progress Reporting

Provide progress callbacks for long-running operations:

```python
def scan_with_progress(self, ip, open_ports, progress_callback=None):
    total = len(open_ports)
    for i, port in enumerate(open_ports):
        # Scan port
        if progress_callback:
            progress_callback(i + 1, total)
```

### 3. Thread Safety

Use locks for shared state:

```python
import threading

class ThreadSafePlugin(VulnerabilityPlugin):
    def __init__(self):
        super().__init__(name="thread_safe", version="1.0.0", description="...")
        self.results = []
        self.lock = threading.Lock()

    def add_result(self, result):
        with self.lock:
            self.results.append(result)
```

### 4. Error Handling

Handle errors gracefully:

```python
async def scan_vulnerabilities(self, ip, open_ports, **kwargs):
    results = []
    errors = []

    for port in open_ports:
        try:
            # Scan logic
            result = self.scan_port(ip, port)
            results.append(result)
        except Exception as e:
            errors.append({'port': port, 'error': str(e)})

    return {
        'results': results,
        'errors': errors,
        'scan_complete': True
    }
```

## See Also

- [Analyze Modules API](analyze.md) - Brand detection and analysis
- [Core Modules API](core.md) - Data loading and validation
- [CLI Reference](../cli/analyze.md) - Command-line usage
- [Contributing Guide](../contributing/guidelines.md) - Extend GRIDLAND
