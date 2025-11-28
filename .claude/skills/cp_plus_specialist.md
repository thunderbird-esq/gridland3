# CP Plus Vulnerability Scanner Specialist Skill

## Skill Purpose

Expert in creating brand-specific vulnerability scanner plugins for IP cameras. Specializes in CVE research, default credential testing, authentication bypass detection, and plugin architecture integration.

## Core Competencies

### 1. Vulnerability Scanner Plugin Development

- Extend VulnerabilityPlugin base class
- Implement async scan_vulnerabilities() method
- Use memory pool for VulnerabilityResult allocation
- Follow plugin metadata standards
- Register plugins correctly

### 2. CVE Research & Implementation

- Research CP Plus specific CVEs
- Understand vulnerability exploitation methods
- Implement CVE detection logic
- Create proof-of-concept tests (non-destructive)
- Document CVE references

### 3. Credential Testing

- Implement non-invasive authentication testing
- Rate-limited credential attempts
- Support multiple authentication schemes (Basic, Digest, Form-based)
- Graceful failure handling
- Audit trail logging

### 4. Brand Detection

- HTTP banner analysis
- Server header inspection
- Path-based detection
- Response pattern matching
- Confidence scoring

## Implementation Guidelines

### File Structure

```
gridland/analyze/plugins/builtin/cp_plus_scanner.py
├── CPPlusScanner (extends VulnerabilityPlugin)
│   ├── __init__()
│   ├── get_metadata()
│   ├── scan_vulnerabilities()
│   ├── _is_cp_plus_device()
│   ├── _test_default_credentials()
│   ├── _test_known_cves()
│   ├── _test_info_disclosure()
│   └── _test_auth_bypass()
└── Registration in __init__.py
```

### Plugin Metadata Template

```python
PluginMetadata(
    name="CP Plus Vulnerability Scanner",
    version="1.0.0",
    author="GRIDLAND Security Team",
    plugin_type="vulnerability",
    supported_ports=[80, 443, 8080, 8000, 8443, 8888],
    supported_services=["http", "https"],
    description="Comprehensive CP Plus camera vulnerability scanner"
)
```

### Default Credentials Research

CP Plus cameras commonly use:

- admin:admin
- admin:12345
- admin:admin123
- admin:cpplus
- admin:""
- root:root
- 888888:888888
- supervisor:supervisor

**IMPORTANT**: Research additional credentials from:

- Default password databases
- Security advisories
- Manufacturer documentation
- Public vulnerability disclosures

### CVE Research Strategy

1. Search CVE databases:
   - <https://nvd.nist.gov/vuln/search>
   - <https://cve.mitre.org/cve/search_cve_list.html>
   - Search terms: "CP Plus", "CPPlus", "CP-Plus camera"

2. Search exploit databases:
   - <https://www.exploit-db.com/>
   - Search terms: "CP Plus"

3. Minimum 3 CVEs required:
   - At least 1 CRITICAL or HIGH severity
   - At least 1 authentication bypass
   - At least 1 information disclosure

### Testing Requirements

```
tests/analyze/plugins/builtin/test_cp_plus_scanner.py
├── TestCPPlusDetection (5 tests)
├── TestDefaultCredentials (8 tests)
├── TestCVEImplementations (9 tests - 3 per CVE)
├── TestPluginMetadata (2 tests)
└── TestIntegration (1 test)
```

### Mock HTTP Response Examples

**CP Plus Login Page**:

```html
<!DOCTYPE html>
<html>
<head><title>CP PLUS DVR/NVR</title></head>
<body>
    <div id="login">
        <h1>CP PLUS Network Camera</h1>
        <form action="/cgi-bin/login.cgi">
            <input name="username" />
            <input name="password" type="password" />
        </form>
    </div>
</body>
</html>
```

**CP Plus System Info Response**:

```
DeviceType=CP-PLUS-IPC-HDBW
Model=CP-UNC-TA10L2-V3
FirmwareVersion=V2.800.0000000.16.R
SerialNumber=CPPLUS123456789
```

## Code Quality Requirements

### Error Handling Pattern

```python
try:
    async with self.session.get(url, timeout=10) as response:
        if response.status == 200:
            # Success path
            pass
        elif response.status == 401:
            # Authentication required
            pass
        else:
            logger.debug(f"Unexpected status {response.status} for {url}")
except asyncio.TimeoutError:
    logger.debug(f"Timeout querying {url}")
except aiohttp.ClientError as e:
    logger.debug(f"Connection error for {url}: {e}")
except Exception as e:
    logger.error(f"Unexpected error for {url}: {e}")
```

### VulnerabilityResult Template

```python
vuln = self.memory_pool.acquire_vulnerability_result()
vuln.ip = target_ip
vuln.port = target_port
vuln.service = service
vuln.vulnerability_id = "cp-plus-default-creds"
vuln.severity = "HIGH"
vuln.confidence = 0.95
vuln.description = "CP Plus camera accessible with default credentials: admin:12345"
vuln.exploit_available = True
vuln.cve_ids = []
vuln.references = []
results.append(vuln)
```

## Performance Benchmarks

- ✅ Complete scan: <30 seconds per target
- ✅ Credential testing: <15 seconds (15 combos @ 1 second each)
- ✅ CVE testing: <10 seconds (3 CVEs)
- ✅ Brand detection: <2 seconds
- ✅ Memory usage: <5MB per scan

## Success Criteria

### Functionality

- [ ] Plugin detects CP Plus devices with 95%+ accuracy
- [ ] Tests 15+ default credential combinations
- [ ] Implements 3+ specific CVE checks
- [ ] Generates accurate VulnerabilityResults
- [ ] Integrates with memory pool correctly

### Testing

- [ ] 25+ unit tests passing
- [ ] All HTTP calls mocked
- [ ] CVE detection accuracy validated
- [ ] Credential testing logic validated

### Integration

- [ ] Registered in BUILTIN_PLUGINS
- [ ] Imports correctly in plugin manager
- [ ] Metadata returned correctly
- [ ] Works in analysis engine workflow

### Documentation

- [ ] CVE references documented
- [ ] Credential sources cited
- [ ] Method docstrings complete
- [ ] Usage example provided

## CVE Implementation Template

```python
async def _test_cve_XXXX_YYYY(self, base_url: str, target_ip: str, target_port: int) -> Optional[Any]:
    """
    Test for CVE-XXXX-YYYY: [Vulnerability Name]

    Description: [Brief description of vulnerability]
    Severity: CRITICAL
    Reference: https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY

    Args:
        base_url: Base URL (http://ip:port)
        target_ip: Target IP address
        target_port: Target port

    Returns:
        VulnerabilityResult if vulnerable, None otherwise
    """
    exploit_url = f"{base_url}/path/to/vulnerable/endpoint"

    try:
        async with self.session.get(exploit_url, timeout=10) as response:
            if response.status == 200:
                content = await response.text()

                # Check for vulnerability indicator
                if "sensitive_data" in content:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.vulnerability_id = "CVE-XXXX-YYYY"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.98
                    vuln.description = "[Vulnerability description]"
                    vuln.exploit_available = True
                    vuln.cve_ids = ["CVE-XXXX-YYYY"]
                    vuln.references = ["https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY"]
                    return vuln

    except Exception as e:
        logger.debug(f"CVE-XXXX-YYYY test failed: {e}")

    return None
```

## Common Pitfalls to Avoid

❌ **DO NOT**:

- Perform destructive testing
- Brute-force credentials (rate limit!)
- Skip brand detection (waste resources)
- Hardcode sensitive data
- Use print() statements
- Leave TODOs in code

✅ **DO**:

- Non-invasive testing only
- Rate limit: max 1 attempt per second
- Check _is_cp_plus_device() first
- Use environment variables for test data
- Use logger properly
- Complete all implementations

## Plugin Registration

### Update **init**.py

```python
from .cp_plus_scanner import cp_plus_scanner

__all__ = [
    'hikvision_scanner',
    'dahua_scanner',
    'axis_scanner',
    'rtsp_stream_scanner',
    'generic_camera_scanner',
    'banner_grabber',
    'ip_context_scanner',
    'cp_plus_scanner'  # ADD THIS
]

BUILTIN_PLUGINS = [
    hikvision_scanner,
    dahua_scanner,
    axis_scanner,
    rtsp_stream_scanner,
    generic_camera_scanner,
    banner_grabber,
    ip_context_scanner,
    cp_plus_scanner  # ADD THIS
]
```

### Create Plugin Instance

```python
# At bottom of cp_plus_scanner.py
cp_plus_scanner = CPPlusScanner()
```

## Ready for Deployment

- Agent can work independently
- CVE research process defined
- Testing requirements clear
- Integration path specified
