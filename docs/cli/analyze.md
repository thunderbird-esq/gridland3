# Analyze Command

The `analyze` command performs comprehensive target analysis including brand detection, CVE lookup, OSINT reconnaissance, authentication testing, and stream discovery.

## Synopsis

```bash
gridland analyze TARGET [OPTIONS]
```

## Description

The analyze command investigates a specific IP address or hostname, performing various reconnaissance and vulnerability assessment tasks.

## Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `TARGET` | IP address or hostname to analyze | `192.168.1.100` or `camera.example.com` |

## Analysis Options

### Comprehensive Scans

| Option | Description |
|--------|-------------|
| `--full-scan` | Run all analysis modules (OSINT + vulnerabilities) |

### OSINT Reconnaissance

| Option | Description |
|--------|-------------|
| `--show-search-urls` | Generate Shodan, Censys, ZoomEye search URLs |
| `--geo-lookup` | Perform IP geolocation with IPinfo.io |
| `--google-dorks` | Generate Google Dork queries for camera discovery |

### Brand Detection & CVE Lookup

| Option | Description |
|--------|-------------|
| `--detect-brand` | Identify camera manufacturer |
| `--show-cves` | Display known CVEs for detected brand |

### Authentication Testing

| Option | Description |
|--------|-------------|
| `--scan-logins` | Discover authentication endpoints |
| `--test-credentials` | Test default credentials (with ethical safeguards) |

### Stream Discovery

| Option | Description |
|--------|-------------|
| `--discover-streams` | Find RTSP/RTMP/HTTP camera streams |

### Output Options

| Option | Description |
|--------|-------------|
| `--output`, `-o` | Save results to file |
| `--json` | Output in JSON format |
| `--verbose`, `-v` | Enable verbose logging |
| `--quiet`, `-q` | Suppress informational output |

## Full Scan Mode

The `--full-scan` flag runs all analysis modules:

```bash
gridland analyze 192.168.1.100 --full-scan
```

**Modules executed:**

1. **IP Validation** - Verify IP and detect private addresses
2. **OSINT URLs** - Generate search platform URLs
3. **Geolocation** - Lookup IP location
4. **Google Dorks** - Generate camera discovery queries
5. **Brand Detection** - Identify manufacturer
6. **CVE Lookup** - Find known vulnerabilities
7. **Login Scanning** - Discover authentication endpoints
8. **Credential Testing** - Test default passwords (with safeguards)
9. **Stream Discovery** - Find live camera streams

## OSINT Reconnaissance

### Search URLs

Generate URLs for major OSINT platforms:

```bash
gridland analyze 8.8.8.8 --show-search-urls
```

**Output:**
```
[*] OSINT Search URLs:

[+] Shodan:
    https://www.shodan.io/search?query=8.8.8.8

[+] Censys:
    https://search.censys.io/hosts/8.8.8.8

[+] ZoomEye:
    https://www.zoomeye.org/searchResult?q=8.8.8.8

[+] Google:
    https://www.google.com/search?q=8.8.8.8
```

### IP Geolocation

Lookup geographic location:

```bash
gridland analyze 8.8.8.8 --geo-lookup
```

**Output:**
```
[*] IP Geolocation:

[+] IP: 8.8.8.8
[+] City: Mountain View
[+] Region: California
[+] Country: US
[+] Location: 37.4056,-122.0775
[+] Organization: Google LLC
[+] Timezone: America/Los_Angeles

[+] OpenStreetMap:
    https://www.openstreetmap.org/?mlat=37.4056&mlon=-122.0775#map=13/37.4056/-122.0775
```

### Google Dorks

Generate camera discovery queries:

```bash
gridland analyze 192.168.1.100 --google-dorks
```

**Output:**
```
[*] Google Dork Queries:

[+] Camera Login Pages:
    inurl:"/view/index.shtml" 192.168.1.100
    https://www.google.com/search?q=inurl%3A%22%2Fview%2Findex.shtml%22+192.168.1.100

[+] Live Camera Streams:
    inurl:"live.htm" OR inurl:"live_view.htm" 192.168.1.100
    https://www.google.com/search?q=inurl%3A%22live.htm%22+OR+inurl%3A%22live_view.htm%22+192.168.1.100

[+] Camera Configuration:
    intitle:"Network Camera" 192.168.1.100
    https://www.google.com/search?q=intitle%3A%22Network+Camera%22+192.168.1.100

[+] DVR/NVR Systems:
    inurl:"view.htm" OR inurl:"viewer.htm" 192.168.1.100
    https://www.google.com/search?q=inurl%3A%22view.htm%22+OR+inurl%3A%22viewer.htm%22+192.168.1.100
```

## Brand Detection

Identify camera manufacturer:

```bash
gridland analyze 192.168.1.100 --detect-brand
```

**Output:**
```
[*] Brand Detection:

[+] Brand: Hikvision
[+] Confidence: 0.85
[+] Evidence:
    - Server header: hikvision-dvr
    - Content-type: image/jpeg
    - Response body contains: Hikvision Digital Technology
```

**Supported Brands:**
- Hikvision
- Dahua
- Axis
- Sony
- Bosch
- Samsung
- Panasonic
- Vivotek
- CP Plus
- Generic

## CVE Lookup

Display known vulnerabilities:

```bash
gridland analyze 192.168.1.100 --show-cves
```

**Output:**
```
[*] CVE Database Lookup:

[+] Brand: Hikvision
[+] Found 12 CVEs

┌──────────────────┬──────────┬────────┬────────────────────────────────────┐
│ CVE ID           │ Severity │ CVSS   │ Description                        │
├──────────────────┼──────────┼────────┼────────────────────────────────────┤
│ CVE-2021-36260   │ Critical │ 9.8    │ Authentication bypass vulnerability│
│ CVE-2017-7921    │ Critical │ 9.8    │ Backdoor account access            │
│ CVE-2020-25078   │ High     │ 8.8    │ Command injection vulnerability    │
└──────────────────┴──────────┴────────┴────────────────────────────────────┘

[+] NVD URLs:
    https://nvd.nist.gov/vuln/detail/CVE-2021-36260
    https://nvd.nist.gov/vuln/detail/CVE-2017-7921
    https://nvd.nist.gov/vuln/detail/CVE-2020-25078
```

## Authentication Testing

### Login Page Scanning

Discover authentication endpoints:

```bash
gridland analyze 192.168.1.100 --scan-logins
```

**Output:**
```
[*] Login Page Scanning:

[+] Found 4 login pages:

┌─────────────────────────────────────────┬───────────┬────────────┐
│ URL                                     │ Auth Type │ Status     │
├─────────────────────────────────────────┼───────────┼────────────┤
│ http://192.168.1.100/                   │ Basic     │ 401        │
│ http://192.168.1.100/login              │ Form      │ 200        │
│ http://192.168.1.100/admin/login        │ Basic     │ 401        │
│ https://192.168.1.100:443/cgi-bin/login │ Digest    │ 401        │
└─────────────────────────────────────────┴───────────┴────────────┘
```

### Credential Testing

Test default credentials with ethical safeguards:

```bash
gridland analyze 192.168.1.100 --test-credentials
```

**Ethical Safeguards:**
- **Rate Limiting:** 0.1 second delay between attempts
- **Attempt Limiting:** Maximum 100 attempts per target
- **Audit Logging:** All attempts logged to CSV (optional)

**Output (no credentials found):**
```
[*] Credential Testing:

[!] Testing default credentials with ethical safeguards:
    - Rate limit: 0.1s delay between attempts
    - Maximum attempts: 100 per target
    - Audit logging: Enabled

[*] Testing 30 credential combinations...
[*] Attempts made: 100/100
[*] Stopped by attempt limit
[-] No valid credentials found
```

**Output (credentials found):**
```
[*] Credential Testing:

[+] Valid credentials found!
[+] Username: admin
[+] Password: admin123
[+] URL: http://192.168.1.100/login
[+] Auth Type: Basic
[+] Attempts: 12
```

!!! warning "Ethical Use Required"
    Credential testing must only be performed on systems you own or have explicit authorization to test. Unauthorized access is illegal.

## Stream Discovery

Find live camera streams:

```bash
gridland analyze 192.168.1.100 --discover-streams
```

**Output:**
```
[*] Stream Discovery:

[+] Found 5 streams:

┌──────────────────────────────────────────────────────┬──────────┬───────┬────────────┬──────────┐
│ URL                                                  │ Protocol │ Codec │ Resolution │ Category │
├──────────────────────────────────────────────────────┼──────────┼───────┼────────────┼──────────┤
│ rtsp://192.168.1.100:554/live.sdp                    │ RTSP     │ h264  │ 1080p      │ live     │
│ rtsp://192.168.1.100:554/stream1                     │ RTSP     │ h264  │ 720p       │ live     │
│ http://192.168.1.100:80/video/live_1080p.h264        │ HTTP     │ h264  │ 1080p      │ live     │
│ rtmp://192.168.1.100:1935/live                       │ RTMP     │ -     │ -          │ live     │
│ http://192.168.1.100:80/snapshot.jpg                 │ HTTP     │ jpeg  │ -          │ snapshot │
└──────────────────────────────────────────────────────┴──────────┴───────┴────────────┴──────────┘
```

**Supported Protocols:**
- **RTSP** - Real-Time Streaming Protocol
- **RTMP** - Real-Time Messaging Protocol
- **HTTP** - HTTP Live Streaming
- **MMS** - Microsoft Media Server
- **ONVIF** - Open Network Video Interface Forum

## Examples

### Example 1: Basic Analysis

```bash
# Quick analysis of a single target
gridland analyze 192.168.1.100
```

### Example 2: Full Vulnerability Scan

```bash
# Comprehensive security assessment
gridland analyze 192.168.1.100 --full-scan --output report.json --json
```

### Example 3: OSINT Reconnaissance

```bash
# Gather intelligence without active scanning
gridland analyze 8.8.8.8 \
  --show-search-urls \
  --geo-lookup \
  --google-dorks \
  --output osint_report.txt
```

### Example 4: Stream Discovery Only

```bash
# Find only camera streams
gridland analyze 192.168.1.100 --discover-streams
```

### Example 5: Brand and CVE Lookup

```bash
# Identify brand and check for vulnerabilities
gridland analyze 192.168.1.100 --detect-brand --show-cves
```

### Example 6: Authentication Assessment

```bash
# Test authentication security
gridland analyze 192.168.1.100 \
  --scan-logins \
  --test-credentials \
  --output auth_report.txt
```

### Example 7: Batch Analysis

```bash
# Analyze multiple targets
for ip in $(cat targets.txt); do
    gridland analyze $ip --full-scan --output "report_${ip}.json" --json
done
```

### Example 8: Parallel Analysis

```bash
# Analyze targets in parallel (requires GNU parallel)
cat targets.txt | parallel -j 10 \
  gridland analyze {} --full-scan --output "report_{}.json" --json
```

## Output Formats

### Human-Readable Output (Default)

```
[*] Analyzing target: 192.168.1.100
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
  "target": "192.168.1.100",
  "timestamp": "2025-01-15T10:30:45Z",
  "ip_validation": {
    "is_valid": true,
    "is_private": true,
    "warning": "Warning: Private IP address detected..."
  },
  "osint": {
    "search_urls": {
      "shodan": "https://www.shodan.io/search?query=192.168.1.100",
      "censys": "https://search.censys.io/hosts/192.168.1.100",
      "zoomeye": "https://www.zoomeye.org/searchResult?q=192.168.1.100"
    },
    "geolocation": {
      "ip": "192.168.1.100",
      "city": "Private Network",
      "country": "N/A"
    }
  },
  "brand_detection": {
    "brand": "hikvision",
    "confidence": 0.85,
    "evidence": [
      "Server header: hikvision-dvr",
      "Content-type: image/jpeg"
    ]
  },
  "cves": [
    {
      "id": "CVE-2021-36260",
      "severity": "critical",
      "cvss_score": 9.8,
      "description": "Authentication bypass vulnerability",
      "exploit_available": true
    }
  ],
  "login_pages": [
    {
      "url": "http://192.168.1.100/login",
      "auth_type": "basic",
      "status_code": 401
    }
  ],
  "credentials": {
    "found": false,
    "attempts_made": 100,
    "stopped_by_limit": true
  },
  "streams": [
    {
      "url": "rtsp://192.168.1.100:554/live.sdp",
      "protocol": "rtsp",
      "codec": "h264",
      "resolution": "1080p",
      "category": "live"
    }
  ]
}
```

## Performance Tuning

### Parallel Module Execution

GRIDLAND automatically parallelizes independent modules during `--full-scan`:

```bash
# All modules run concurrently where possible
gridland analyze 192.168.1.100 --full-scan
```

### Custom Timeout

```bash
# Increase timeout for slow networks
gridland analyze 192.168.1.100 --full-scan --timeout 10
```

### Selective Module Execution

Run only specific modules to reduce scan time:

```bash
# OSINT only (fastest, no active scanning)
gridland analyze 8.8.8.8 --show-search-urls --geo-lookup

# Authentication only
gridland analyze 192.168.1.100 --scan-logins --test-credentials

# Stream discovery only
gridland analyze 192.168.1.100 --discover-streams
```

## Integration with Discover

Chain discovery and analysis:

```bash
# Method 1: Sequential
gridland discover --range 192.168.1.0/24 > targets.txt
cat targets.txt | awk '{print $1}' | sort -u | while read ip; do
    gridland analyze $ip --full-scan
done

# Method 2: Parallel with GNU parallel
gridland discover --range 192.168.1.0/24 | \
  awk '{print $1}' | sort -u | \
  parallel -j 10 gridland analyze {} --full-scan --output "report_{}.json" --json

# Method 3: Direct piping with filtering
gridland discover --port-categories rtsp_ecosystem --range 192.168.1.0/24 | \
  grep ":554" | awk '{print $1}' | sort -u | \
  while read ip; do
    gridland analyze $ip --discover-streams
  done
```

## Troubleshooting

### Connection timeout errors

**Solution:** Increase timeout:
```bash
gridland analyze 192.168.1.100 --full-scan --timeout 10
```

### Rate limiting from IPinfo.io

**Solution:** Reduce frequency or use API key:
```bash
export IPINFO_API_KEY=your_key_here
gridland analyze 8.8.8.8 --geo-lookup
```

### No streams found

**Possible causes:**
1. Camera doesn't have open ports (run `discover` first)
2. Streams require authentication
3. Camera uses non-standard paths

**Solution:** Check open ports first:
```bash
gridland discover --range 192.168.1.100 --ports 80,554,8080,8554
gridland analyze 192.168.1.100 --discover-streams
```

### Credential testing stops early

This is expected behavior due to attempt limiting (default: 100 attempts).

**Solution:** This is an ethical safeguard. If needed for authorized testing, adjust limits programmatically:
```python
from gridland.analyze.plugins.builtin import CredentialTester
tester = CredentialTester(max_attempts_per_target=200)
```

## Ethical Guidelines

!!! danger "Authorization Required"
    All analysis operations must be performed on systems you own or have explicit written authorization to test. Unauthorized access and testing is illegal and unethical.

**Best Practices:**

1. **Get Authorization** - Always obtain written permission before testing
2. **Use Rate Limiting** - Don't overwhelm target systems
3. **Enable Audit Logging** - Keep records of all testing activities
4. **Respect Privacy** - Don't access or share unauthorized camera feeds
5. **Responsible Disclosure** - Report vulnerabilities through proper channels

**Audit Logging:**

Enable comprehensive audit trails:

```python
from gridland.analyze.plugins.builtin import CredentialTester

tester = CredentialTester(
    audit_log_path="/var/log/gridland/audit.csv"
)
```

Audit log format:
```
timestamp,ip,port,username,password,url,auth_type,result
2025-01-15T10:30:45,192.168.1.100,80,admin,admin,http://...,basic,success
```

## See Also

- [Discover Command](discover.md) - Network discovery and port scanning
- [CLI Overview](overview.md) - General CLI usage
- [Ethical Use Guidelines](../contributing/ethics.md) - Responsible usage
- [API Documentation](../api/analyze.md) - Use analyze modules in Python
