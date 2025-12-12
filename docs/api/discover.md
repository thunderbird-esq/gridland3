# Discover Modules API

The discover modules provide network discovery and port scanning capabilities.

## gridland.discover

Network discovery and port scanning.

### PythonPortScanner

Multi-threaded TCP port scanner with progress reporting.

#### \_\_init\_\_(max_threads=100, timeout=1.5)

```python
from gridland.discover import PythonPortScanner

# Default configuration
scanner = PythonPortScanner()

# Custom configuration
scanner = PythonPortScanner(
    max_threads=200,  # More concurrency
    timeout=3.0       # Longer timeout
)
```

**Parameters:**
- `max_threads` (int): Maximum concurrent threads (default: 100)
- `timeout` (float): Timeout per port in seconds (default: 1.5)

#### scan_ports(ip, ports, progress_callback=None, termination_flag=None)

Scan specified ports on target IP.

```python
# Basic scan
open_ports = scanner.scan_ports("192.168.1.100", [80, 443, 554, 8080])
# Returns: [80, 554, 8080]  # List of open ports

# With progress callback
def progress(scanned, total):
    percent = (scanned / total) * 100
    print(f"Progress: {percent:.1f}%")

open_ports = scanner.scan_ports(
    "192.168.1.100",
    [80, 443, 554, 8080],
    progress_callback=progress
)

# With early termination
import threading
termination_flag = threading.Event()

# Start scan in background
def scan_task():
    return scanner.scan_ports(
        "192.168.1.100",
        range(1, 65536),
        termination_flag=termination_flag
    )

# Terminate after 10 seconds
threading.Timer(10.0, termination_flag.set).start()
open_ports = scan_task()
```

**Parameters:**
- `ip` (str): Target IP address
- `ports` (list[int]): List of ports to scan
- `progress_callback` (callable, optional): Progress callback function(scanned, total)
- `termination_flag` (threading.Event, optional): Flag for early termination

**Returns:**
- `list[int]`: Sorted list of open ports

**Raises:**
- `ValueError`: If IP address is invalid or ports are out of range (1-65535)

**Features:**
- Multi-threaded scanning (configurable thread pool)
- Progress reporting (callback invoked every 50 ports)
- Early termination support
- Thread-safe result collection
- Input validation

**Performance:**
- ~1,975 ports/sec (100 threads, 1.5s timeout)
- Suitable for /24 and /16 networks
- Adjust threads and timeout based on network conditions

### PortSelector

Port selection utility for camera-specific ports.

#### get_camera_ports(category='all')

Retrieve camera ports by category (static method).

```python
from gridland.discover import PortSelector

# Get all camera ports (685 unique ports)
all_ports = PortSelector.get_camera_ports()
# Returns: [80, 443, 554, 8080, ...]

# Get RTSP ports only
rtsp_ports = PortSelector.get_camera_ports(category='rtsp')
# Returns: [554, 1554, 8554, 10554, ...]

# Get web ports only
web_ports = PortSelector.get_camera_ports(category='web')
# Returns: [80, 443, 8080, 8443, 8888, ...]

# Get ONVIF ports
onvif_ports = PortSelector.get_camera_ports(category='onvif')
# Returns: [80, 8080, ...]
```

**Parameters:**
- `category` (str): Port category (default: `'all'`)

**Categories:**
- `'all'` - All 685 unique camera ports
- `'web'` - HTTP/HTTPS ports for web interfaces
- `'rtsp'` - Real Time Streaming Protocol ports
- `'rtmp'` - Real Time Messaging Protocol ports
- `'mms'` - Microsoft Media Server ports
- `'onvif'` - ONVIF protocol ports
- `'custom'` - Custom/proprietary camera ports

**Returns:**
- `list[int]`: Sorted list of ports in the category

**Raises:**
- `ValueError`: If category is invalid

**Features:**
- Static method (no instance required)
- Integrates with Phase 1 data loader
- Port range validation (1-65535)
- Deterministic ordering

## Complete Examples

### Example 1: Basic Port Scanning

```python
from gridland.discover import PythonPortScanner, PortSelector

# Initialize scanner
scanner = PythonPortScanner()

# Get camera ports to scan
ports = PortSelector.get_camera_ports(category='rtsp')

# Scan for open RTSP ports
open_ports = scanner.scan_ports("192.168.1.100", ports)

print(f"Found {len(open_ports)} open RTSP ports:")
for port in open_ports:
    print(f"  - Port {port}")
```

### Example 2: Progress Tracking

```python
from gridland.discover import PythonPortScanner, PortSelector

scanner = PythonPortScanner()
ports = PortSelector.get_camera_ports()  # All 685 ports

def progress_handler(scanned, total):
    percent = (scanned / total) * 100
    print(f"\rScanning: {percent:.1f}% ({scanned}/{total})", end='', flush=True)

open_ports = scanner.scan_ports(
    "192.168.1.100",
    ports,
    progress_callback=progress_handler
)
print(f"\nFound {len(open_ports)} open ports")
```

### Example 3: Multi-Target Scanning

```python
from gridland.discover import PythonPortScanner, PortSelector

scanner = PythonPortScanner()
targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
ports = PortSelector.get_camera_ports(category='web')

results = {}
for target in targets:
    print(f"Scanning {target}...")
    open_ports = scanner.scan_ports(target, ports)
    results[target] = open_ports

# Display results
for target, open_ports in results.items():
    print(f"{target}: {len(open_ports)} open ports")
    for port in open_ports:
        print(f"  - {port}")
```

### Example 4: Early Termination

```python
from gridland.discover import PythonPortScanner
import threading
import time

scanner = PythonPortScanner()
termination_flag = threading.Event()

# Scan all ports (will take a while)
def scan_task():
    ports = list(range(1, 65536))
    return scanner.scan_ports(
        "192.168.1.100",
        ports,
        termination_flag=termination_flag
    )

# Start scan in background thread
scan_thread = threading.Thread(target=scan_task)
scan_thread.start()

# Terminate after 30 seconds
time.sleep(30)
print("Terminating scan...")
termination_flag.set()

scan_thread.join()
print("Scan terminated")
```

### Example 5: Custom Thread Configuration

```python
from gridland.discover import PythonPortScanner, PortSelector

# High concurrency for fast networks
fast_scanner = PythonPortScanner(max_threads=200, timeout=1.0)

# Conservative for slow networks
slow_scanner = PythonPortScanner(max_threads=50, timeout=5.0)

# Scan with appropriate scanner
ports = PortSelector.get_camera_ports()
open_ports = fast_scanner.scan_ports("192.168.1.100", ports)
```

### Example 6: Category-Based Scanning

```python
from gridland.discover import PythonPortScanner, PortSelector

scanner = PythonPortScanner()
target = "192.168.1.100"

# Scan different categories
categories = ['web', 'rtsp', 'rtmp', 'onvif']
results = {}

for category in categories:
    ports = PortSelector.get_camera_ports(category=category)
    open_ports = scanner.scan_ports(target, ports)
    results[category] = open_ports

# Display results by category
for category, open_ports in results.items():
    print(f"{category}: {open_ports}")
```

### Example 7: Subnet Scanning

```python
from gridland.discover import PythonPortScanner, PortSelector
import ipaddress

scanner = PythonPortScanner()
ports = PortSelector.get_camera_ports(category='rtsp')

# Scan entire /24 subnet
network = ipaddress.IPv4Network("192.168.1.0/24")
for ip in network.hosts():
    ip_str = str(ip)
    open_ports = scanner.scan_ports(ip_str, ports)
    if open_ports:
        print(f"{ip_str}: {open_ports}")
```

## Performance Optimization

### Thread Pool Tuning

```python
from gridland.discover import PythonPortScanner

# Optimize for different scenarios
configs = {
    'fast_network': PythonPortScanner(max_threads=200, timeout=1.0),
    'slow_network': PythonPortScanner(max_threads=50, timeout=5.0),
    'balanced': PythonPortScanner(max_threads=100, timeout=1.5)
}

# Use appropriate scanner
scanner = configs['balanced']
```

### Port Selection Strategy

```python
from gridland.discover import PortSelector

# Fast scan (most common ports)
common_ports = [80, 443, 554, 8080, 8554]

# Balanced scan (category-specific)
rtsp_ports = PortSelector.get_camera_ports(category='rtsp')  # ~34 ports

# Comprehensive scan (all camera ports)
all_ports = PortSelector.get_camera_ports()  # 685 ports
```

### Batch Processing

```python
from gridland.discover import PythonPortScanner, PortSelector

scanner = PythonPortScanner()
all_ports = PortSelector.get_camera_ports()

# Process in chunks to avoid memory issues
chunk_size = 100
for i in range(0, len(all_ports), chunk_size):
    chunk = all_ports[i:i+chunk_size]
    open_ports = scanner.scan_ports("192.168.1.100", chunk)
    # Process results immediately
    for port in open_ports:
        print(f"Open port: {port}")
```

## Integration with Analyze

Chain discovery and analysis:

```python
from gridland.discover import PythonPortScanner, PortSelector
from gridland.analyze.core import BrandDetector

# Step 1: Discover open ports
scanner = PythonPortScanner()
ports = PortSelector.get_camera_ports()
open_ports = scanner.scan_ports("192.168.1.100", ports)

# Step 2: Analyze each open port
import requests
detector = BrandDetector()

for port in open_ports:
    url = f"http://192.168.1.100:{port}"
    try:
        response = requests.get(url, timeout=3, verify=False)
        port_data = {
            'port': port,
            'server_header': response.headers.get('Server', ''),
            'content_type': response.headers.get('Content-Type', ''),
            'response_body': response.text
        }
        result = detector.detect_brand(port_data)
        if result['brand'] != 'generic':
            print(f"Port {port}: {result['brand']} (confidence: {result['confidence']})")
    except:
        pass
```

## Error Handling

```python
from gridland.discover import PythonPortScanner

scanner = PythonPortScanner()

try:
    # Invalid IP
    open_ports = scanner.scan_ports("999.999.999.999", [80])
except ValueError as e:
    print(f"Invalid IP: {e}")

try:
    # Invalid port range
    open_ports = scanner.scan_ports("192.168.1.100", [0, 70000])
except ValueError as e:
    print(f"Invalid ports: {e}")

try:
    # Invalid category
    from gridland.discover import PortSelector
    ports = PortSelector.get_camera_ports(category='invalid')
except ValueError as e:
    print(f"Invalid category: {e}")
```

## See Also

- [Core Modules API](core.md) - Data loading and validation
- [Analyze Modules API](analyze.md) - Brand detection and analysis
- [CLI Reference](../cli/discover.md) - Command-line usage
- [Configuration Guide](../getting-started/configuration.md) - Configure scanners
