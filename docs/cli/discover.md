# Discover Command

The `discover` command performs network discovery and port scanning to identify camera devices.

## Synopsis

```bash
gridland discover [OPTIONS]
```

## Description

The discover command supports multiple discovery engines:

- **masscan** - High-speed port scanning (Linux, requires root)
- **Python scanner** - Multi-threaded scanning (cross-platform)
- **ShodanSpider v2** - Internet-wide device discovery
- **Censys** - Professional search capabilities

## Options

### Target Selection

| Option | Description | Example |
|--------|-------------|---------|
| `--range`, `-r` | IP range to scan (CIDR, range, or single IP) | `192.168.1.0/24` |
| `--query`, `-q` | Search query for ShodanSpider/Censys | `"port:554 country:US"` |

### Engine Selection

| Option | Description | Default |
|--------|-------------|---------|
| `--engine` | Discovery engine: `masscan`, `shodanspider`, `censys`, `auto` | `auto` |

### Port Selection

| Option | Description |
|--------|-------------|
| `--ports`, `-p` | Comma-separated port list |
| `--scan-mode` | Scan intensity: `FAST`, `BALANCED`, `COMPREHENSIVE` |
| `--port-categories` | Port categories: `standard_web`, `rtsp_ecosystem`, `onvif`, etc. |

### Performance

| Option | Description | Default |
|--------|-------------|---------|
| `--rate` | Packets per second (masscan only) | 1000 |
| `--threads` | Concurrent threads (Python scanner) | 100 |
| `--timeout` | Timeout per port in seconds | 1.5 |

### Output

| Option | Description |
|--------|-------------|
| `--output`, `-o` | Save results to file |
| `--json` | Output in JSON format |
| `--verbose`, `-v` | Enable verbose logging |
| `--quiet`, `-q` | Suppress informational output |

## Discovery Engines

### Masscan Engine

High-speed port scanning using the masscan tool.

**Requirements:**
- Linux operating system
- Root privileges (sudo)
- masscan installed (`sudo apt-get install masscan`)

**Usage:**

```bash
# High-speed scan
sudo gridland discover --engine masscan --range 192.168.1.0/24 --rate 10000

# Conservative scan
sudo gridland discover --engine masscan --range 10.0.0.0/8 --rate 100

# Custom ports
sudo gridland discover --engine masscan --range 192.168.1.0/24 --ports 80,443,554
```

**Performance:**
- Up to 10,000 packets/sec
- Suitable for large networks (/8, /16 ranges)
- Requires careful rate configuration to avoid network congestion

### Python Scanner Engine

Multi-threaded TCP port scanner (no external dependencies).

**Usage:**

```bash
# Basic scan
gridland discover --engine auto --range 192.168.1.0/24

# Custom thread count
gridland discover --engine auto --range 192.168.1.0/24 --threads 200

# Custom timeout
gridland discover --engine auto --range 192.168.1.0/24 --timeout 3.0
```

**Features:**
- Cross-platform (Linux, macOS, Windows)
- No root privileges required
- Configurable thread pool
- Progress reporting

**Performance:**
- ~1,975 ports/sec (100 threads)
- Suitable for /24 and /16 networks
- Automatic fallback from masscan

### ShodanSpider v2 Engine

Internet-wide device discovery using Shodan's database.

**Requirements:**
- Shodan API key (`export SHODAN_API_KEY=your_key`)

**Usage:**

```bash
# Search for RTSP cameras in the US
gridland discover --engine shodanspider --query "port:554 country:US"

# Search for Hikvision cameras
gridland discover --engine shodanspider --query "Hikvision"

# Search by organization
gridland discover --engine shodanspider --query "org:\"Example Corp\""
```

**Query Syntax:**
- `port:554` - Specific port
- `country:US` - Country code
- `city:"Los Angeles"` - City name
- `org:"Company"` - Organization
- `product:camera` - Product type

### Censys Engine

Professional search with historical data and certificates.

**Requirements:**
- Censys API credentials
- `export CENSYS_API_ID=your_id`
- `export CENSYS_API_SECRET=your_secret`

**Usage:**

```bash
# Search for cameras by port
gridland discover --engine censys --query "services.port:554"

# Search by protocol
gridland discover --engine censys --query "services.service_name:RTSP"

# Search by certificate
gridland discover --engine censys --query "services.tls.certificate.subject.common_name:camera"
```

## Scan Modes

### FAST Mode

Scans the 20 most common camera ports.

```bash
gridland discover --scan-mode FAST --range 192.168.1.0/24
```

**Ports included:**
- Web: 80, 443, 8080, 8443
- RTSP: 554, 8554
- ONVIF: 80, 8080
- Other: 37777, 34567

**Performance:** ~5 seconds per /24 subnet

### BALANCED Mode (Default)

Scans 100 high-value camera ports.

```bash
gridland discover --scan-mode BALANCED --range 192.168.1.0/24
```

**Performance:** ~30 seconds per /24 subnet

### COMPREHENSIVE Mode

Scans 500+ camera-specific ports.

```bash
gridland discover --scan-mode COMPREHENSIVE --range 192.168.1.0/24
```

**Performance:** ~2-3 minutes per /24 subnet

## Port Categories

### Available Categories

```bash
# List available categories
gridland discover --help  # See --port-categories options
```

| Category | Description | Ports |
|----------|-------------|-------|
| `standard_web` | HTTP/HTTPS ports | 80, 443, 8080, 8443, etc. |
| `rtsp_ecosystem` | RTSP streaming ports | 554, 8554, 10554, etc. |
| `rtmp_ecosystem` | RTMP streaming ports | 1935, 19350, etc. |
| `onvif` | ONVIF protocol ports | 80, 8080, etc. |
| `proprietary` | Vendor-specific ports | 37777, 34567, etc. |

### Using Categories

```bash
# Single category
gridland discover --port-categories rtsp_ecosystem --range 192.168.1.0/24

# Multiple categories
gridland discover --port-categories standard_web rtsp_ecosystem --range 192.168.1.0/24

# All camera ports (default with --scan-mode COMPREHENSIVE)
gridland discover --scan-mode COMPREHENSIVE --range 192.168.1.0/24
```

## Examples

### Example 1: Basic Network Scan

```bash
# Scan local network for cameras
gridland discover --range 192.168.1.0/24 --scan-mode BALANCED
```

**Output:**
```
[*] Starting discovery scan...
[*] Engine: Auto (using Python scanner)
[*] Target: 192.168.1.0/24
[*] Ports: 100 (BALANCED mode)
[*] Threads: 100

⠋ Scanning network... [25/255] 9.8%

[+] 192.168.1.100:80 - OPEN
[+] 192.168.1.100:554 - OPEN (RTSP)
[+] 192.168.1.100:8080 - OPEN
[+] 192.168.1.101:80 - OPEN
[+] 192.168.1.101:37777 - OPEN

[*] Scan complete: 5 open ports on 2 hosts
[*] Duration: 28.3 seconds
```

### Example 2: High-Speed Masscan

```bash
# Fast scan of large network
sudo gridland discover \
  --engine masscan \
  --range 10.0.0.0/16 \
  --rate 5000 \
  --output results.txt
```

### Example 3: RTSP Camera Discovery

```bash
# Find only RTSP streaming cameras
gridland discover \
  --port-categories rtsp_ecosystem \
  --range 192.168.1.0/24 \
  --output rtsp_cameras.txt
```

### Example 4: Internet-Wide Search

```bash
# Find Hikvision cameras in the US
gridland discover \
  --engine shodanspider \
  --query "Hikvision country:US port:80" \
  --output hikvision_us.json \
  --json
```

### Example 5: Multi-Network Scan

```bash
# Scan multiple networks
for network in 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24; do
    gridland discover --range $network --output "scan_${network//\//_}.txt"
done
```

### Example 6: Custom Port List

```bash
# Scan specific ports
gridland discover \
  --range 192.168.1.0/24 \
  --ports 80,443,554,8080,8554,37777 \
  --output custom_scan.txt
```

## Output Formats

### Human-Readable Output (Default)

```
[+] 192.168.1.100:80 - OPEN
[+] 192.168.1.100:554 - OPEN (RTSP)
[+] 192.168.1.100:8080 - OPEN
```

### JSON Output

```bash
gridland discover --range 192.168.1.100 --json
```

```json
{
  "scan_info": {
    "engine": "python",
    "target": "192.168.1.100",
    "scan_mode": "BALANCED",
    "ports_scanned": 100,
    "duration": 2.3
  },
  "results": [
    {
      "ip": "192.168.1.100",
      "port": 80,
      "state": "open",
      "protocol": "tcp"
    },
    {
      "ip": "192.168.1.100",
      "port": 554,
      "state": "open",
      "protocol": "tcp",
      "service": "rtsp"
    }
  ]
}
```

### File Output

```bash
# Save to file
gridland discover --range 192.168.1.0/24 --output results.txt

# Pipe to other tools
gridland discover --range 192.168.1.0/24 | grep ":554" | tee rtsp_hosts.txt
```

## Performance Tuning

### Masscan Optimization

```bash
# Maximum speed (use with caution)
sudo gridland discover --engine masscan --range 192.168.1.0/24 --rate 10000

# Conservative (for production networks)
sudo gridland discover --engine masscan --range 192.168.1.0/24 --rate 100

# Balanced (recommended)
sudo gridland discover --engine masscan --range 192.168.1.0/24 --rate 1000
```

### Python Scanner Optimization

```bash
# High concurrency (fast networks)
gridland discover --threads 200 --timeout 1.0 --range 192.168.1.0/24

# Conservative (slow networks)
gridland discover --threads 50 --timeout 5.0 --range 192.168.1.0/24

# Balanced (default)
gridland discover --threads 100 --timeout 1.5 --range 192.168.1.0/24
```

## Integration with Analyze

Chain discovery and analysis:

```bash
# Method 1: Direct piping
gridland discover --range 192.168.1.0/24 | while read ip port; do
    gridland analyze $ip --full-scan
done

# Method 2: Save and batch process
gridland discover --range 192.168.1.0/24 --output targets.txt
cat targets.txt | awk '{print $1}' | sort -u | while read ip; do
    gridland analyze $ip --full-scan --output "report_${ip}.json"
done

# Method 3: Parallel processing
gridland discover --range 192.168.1.0/24 --output targets.txt
cat targets.txt | awk '{print $1}' | sort -u | \
    parallel -j 10 gridland analyze {} --full-scan
```

## Troubleshooting

### masscan: permission denied

**Solution:** Run with sudo or use Python scanner:
```bash
sudo gridland discover --engine masscan --range 192.168.1.0/24
# OR
gridland discover --engine auto --range 192.168.1.0/24  # Auto-switches to Python
```

### Slow scanning

**Solution:** Adjust thread count and timeout:
```bash
gridland discover --threads 200 --timeout 1.0 --range 192.168.1.0/24
```

### ShodanSpider authentication failed

**Solution:** Set API key:
```bash
export SHODAN_API_KEY=your_key_here
gridland discover --engine shodanspider --query "port:554"
```

## See Also

- [Analyze Command](analyze.md) - Target analysis and vulnerability assessment
- [CLI Overview](overview.md) - General CLI usage
- [Configuration Guide](../getting-started/configuration.md) - Configure discovery engines
