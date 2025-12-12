# CLI Reference Overview

GRIDLAND v3.0 provides a powerful command-line interface with two main commands: `discover` and `analyze`.

## Command Structure

```bash
gridland [COMMAND] [OPTIONS]
```

## Available Commands

| Command | Description |
|---------|-------------|
| `discover` | Network discovery and port scanning |
| `analyze` | Target analysis and vulnerability assessment |
| `--version` | Show version information |
| `--help` | Show help message |

## Global Options

| Option | Description |
|--------|-------------|
| `--verbose`, `-v` | Enable verbose logging |
| `--quiet`, `-q` | Suppress informational output |
| `--json` | Output results in JSON format |
| `--output`, `-o` | Save results to file |

## Quick Examples

### Discovery

```bash
# Discover cameras on a network
gridland discover --range 192.168.1.0/24 --scan-mode BALANCED

# High-speed masscan discovery
sudo gridland discover --engine masscan --range 10.0.0.0/8 --rate 10000

# Shodan-based discovery
gridland discover --engine shodanspider --query "port:554 country:US"
```

### Analysis

```bash
# Basic analysis
gridland analyze 192.168.1.100

# Full vulnerability scan
gridland analyze 192.168.1.100 --full-scan

# OSINT reconnaissance
gridland analyze 8.8.8.8 --show-search-urls --geo-lookup
```

## Command Workflow

GRIDLAND follows a two-phase workflow:

1. **Discovery Phase** - Identify targets
   - Network scanning with masscan or Python scanner
   - Internet-wide discovery with ShodanSpider
   - Professional search with Censys
   - Custom port selection and scan modes

2. **Analysis Phase** - Investigate targets
   - Brand detection and CVE lookup
   - Authentication endpoint scanning
   - Default credential testing
   - Stream discovery
   - OSINT reconnaissance

## Common Patterns

### Pattern 1: Network Survey

```bash
# Step 1: Discover all cameras
gridland discover --range 192.168.1.0/24 --scan-mode COMPREHENSIVE > targets.txt

# Step 2: Analyze each target
while read ip port; do
    gridland analyze $ip --full-scan --output "report_${ip}.json"
done < targets.txt
```

### Pattern 2: Focused Reconnaissance

```bash
# Discover RTSP cameras only
gridland discover --range 192.168.1.0/24 --port-categories rtsp_ecosystem

# Analyze with stream discovery
gridland analyze 192.168.1.100 --discover-streams
```

### Pattern 3: OSINT Collection

```bash
# Gather intelligence on public IPs
for ip in $(cat public_ips.txt); do
    gridland analyze $ip --show-search-urls --geo-lookup --google-dorks
done
```

## Output Formats

### Human-Readable Output (Default)

```
[*] Starting analysis for 192.168.1.100
[+] Brand detected: Hikvision (confidence: 0.8)
[+] Found 12 CVEs (5 Critical, 7 High)
[+] Login page: http://192.168.1.100/login (Basic Auth)
[+] Stream: rtsp://192.168.1.100:554/live.sdp (h264, 1080p)
[*] Analysis complete
```

### JSON Output

```bash
gridland analyze 192.168.1.100 --full-scan --json
```

```json
{
  "ip": "192.168.1.100",
  "brand": {
    "name": "hikvision",
    "confidence": 0.8
  },
  "cves": [
    {
      "id": "CVE-2021-36260",
      "severity": "critical",
      "cvss_score": 9.8
    }
  ],
  "login_pages": [
    {
      "url": "http://192.168.1.100/login",
      "auth_type": "basic"
    }
  ],
  "streams": [
    {
      "url": "rtsp://192.168.1.100:554/live.sdp",
      "protocol": "rtsp",
      "codec": "h264",
      "resolution": "1080p"
    }
  ]
}
```

## Performance Tips

### 1. Choose the Right Engine

- **masscan** - Fastest for large networks (requires root on Linux)
- **Python scanner** - Cross-platform, no root required
- **ShodanSpider** - Internet-wide discovery without scanning
- **Censys** - Professional search with historical data

### 2. Optimize Scan Modes

- **FAST** - 20 most common ports (~5 seconds per /24)
- **BALANCED** - 100 high-value ports (~30 seconds per /24)
- **COMPREHENSIVE** - 500+ ports (~2-3 minutes per /24)

### 3. Use Port Categories

```bash
# Scan only RTSP ports (fastest for stream cameras)
gridland discover --port-categories rtsp_ecosystem

# Scan only web interfaces
gridland discover --port-categories standard_web

# Combine categories
gridland discover --port-categories rtsp_ecosystem standard_web
```

### 4. Parallel Analysis

```bash
# Discover targets
gridland discover --range 192.168.1.0/24 > targets.txt

# Analyze in parallel with GNU parallel
cat targets.txt | parallel -j 10 gridland analyze {} --full-scan
```

## Error Handling

### Common Errors

**Permission denied (masscan)**

```bash
# Solution: Run with sudo
sudo gridland discover --engine masscan --range 192.168.1.0/24
```

**Connection timeout**

```bash
# Solution: Increase timeout or check network connectivity
gridland analyze 192.168.1.100 --timeout 10
```

**Rate limiting**

```bash
# Solution: Reduce scan rate or use Python scanner
gridland discover --engine masscan --rate 100  # Slower rate
# OR
gridland discover --engine auto  # Auto-switches to Python if masscan unavailable
```

## Environment Variables

Configure GRIDLAND behavior with environment variables:

```bash
# API keys
export SHODAN_API_KEY=your_key_here
export CENSYS_API_ID=your_id_here
export CENSYS_API_SECRET=your_secret_here

# Timeouts and limits
export GRIDLAND_TIMEOUT=5
export GRIDLAND_MAX_THREADS=100
export GRIDLAND_RATE_LIMIT=0.1

# Audit logging
export GRIDLAND_AUDIT_LOG=/var/log/gridland_audit.csv
```

## Next Steps

- [Discover Command Reference](discover.md) - Detailed discovery options
- [Analyze Command Reference](analyze.md) - Detailed analysis options
- [API Documentation](../api/core.md) - Use GRIDLAND in Python scripts
- [Configuration Guide](../getting-started/configuration.md) - Customize GRIDLAND

## Getting Help

```bash
# General help
gridland --help

# Command-specific help
gridland discover --help
gridland analyze --help

# Version information
gridland --version
```

For additional support:

- Check [GitHub Issues](https://github.com/thunderbird-esq/gridland3/issues)
- Read the [Troubleshooting Guide](../troubleshooting.md)
- Join [GitHub Discussions](https://github.com/thunderbird-esq/gridland3/discussions)
