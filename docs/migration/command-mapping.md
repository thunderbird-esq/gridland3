# Command Mapping

This guide maps CamXploit.py commands to their GRIDLAND v3.0 equivalents.

## Quick Reference

| CamXploit.py | GRIDLAND v3.0 | Description |
|--------------|---------------|-------------|
| `python CamXploit.py` | `gridland analyze <IP> --full-scan` | Full analysis |
| Port scanning | `gridland discover --use-python-scanner` | Port discovery |
| Brand detection | `gridland analyze --detect-brand` | Identify manufacturer |
| Credential testing | `gridland analyze --test-credentials` | Test default passwords |
| Stream discovery | `gridland analyze --full-scan` | Find live streams |
| OSINT lookup | `gridland analyze --show-search-urls` | Generate OSINT URLs |
| Geo lookup | `gridland analyze --geo-lookup` | IP geolocation |
| CVE lookup | `gridland analyze --show-cves` | Show vulnerabilities |

## Detailed Examples

### Basic Analysis

**CamXploit.py:**
```bash
python CamXploit.py
# Enter IP when prompted
```

**GRIDLAND v3.0:**
```bash
gridland analyze 192.168.1.100 --full-scan
```

### Port Scanning

**CamXploit.py:**
```bash
# Built-in port scanning during analysis
python CamXploit.py
```

**GRIDLAND v3.0:**
```bash
# Dedicated discovery command with camera-specific ports
gridland discover --use-python-scanner --camera-ports --target 192.168.1.0/24

# Filter by port category
gridland discover --use-python-scanner --camera-ports --camera-port-category rtsp --target 192.168.1.100
```

### OSINT Integration

**CamXploit.py:**
```bash
# Displayed URLs during analysis
python CamXploit.py
```

**GRIDLAND v3.0:**
```bash
# Generate OSINT search URLs
gridland analyze 8.8.8.8 --show-search-urls

# Include Google dork queries
gridland analyze 8.8.8.8 --google-dorks

# Full OSINT with geolocation
gridland analyze 8.8.8.8 --show-search-urls --geo-lookup --google-dorks
```

### Credential Testing

**CamXploit.py:**
```bash
# Automatic credential testing during analysis
python CamXploit.py
```

**GRIDLAND v3.0:**
```bash
# Explicit consent required
gridland analyze 192.168.1.100 --test-credentials

# Combined with brand detection
gridland analyze 192.168.1.100 --detect-brand --test-credentials
```

!!! warning "Authorization Required"
    Credential testing requires explicit authorization. The `--test-credentials` flag includes ethical safeguards (rate limiting, audit logging).

## New Features in GRIDLAND v3.0

These features are **new** and have no CamXploit.py equivalent:

| Feature | Command | Description |
|---------|---------|-------------|
| Port categories | `--camera-port-category` | Filter by protocol (rtsp, web, onvif) |
| Audit logging | Built-in | CSV trail of credential tests |
| Rate limiting | Built-in | Prevent account lockouts |
| Python scanner | `--use-python-scanner` | No masscan dependency |
| JSON output | `--output json` | Machine-readable output |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `SHODAN_API_KEY` | Enable Shodan API integration |
| `IPINFO_TOKEN` | Enhanced geolocation accuracy |
