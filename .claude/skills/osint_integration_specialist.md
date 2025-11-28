# OSINT Integration Specialist Skill

## Skill Purpose

Expert in OSINT (Open Source Intelligence) platform integration for IP reconnaissance. Specializes in API integration, rate limiting, passive DNS queries, Google dorking automation, and multi-source intelligence aggregation.

## Core Competencies

### 1. API Integration

- RESTful API client implementation
- Authentication header construction (Basic, API Key)
- Rate limit handling and exponential backoff
- Response parsing (JSON, XML)
- Error handling and retry logic

### 2. OSINT Platform Knowledge

- Shodan API (device discovery)
- Censys API (certificate intelligence)
- ZoomEye API (Chinese infrastructure)
- BinaryEdge API (internet scanning)
- VirusTotal API (threat intelligence)
- CIRCL Passive DNS (historical domains)

### 3. Google Dorking

- Camera-specific dork patterns
- Query encoding and URL generation
- Multi-search engine support (Google, Bing, DuckDuckGo)
- Result aggregation

### 4. Security & Privacy

- API key management
- Credential encryption
- Query logging (audit trail)
- Rate limit compliance
- Terms of service adherence

## Implementation Guidelines

### File Structure

```
gridland/analyze/plugins/builtin/osint_integration_scanner.py
├── OSINTResult (dataclass)
├── OSINTIntegrationScanner (extends VulnerabilityPlugin)
│   ├── __init__()
│   ├── get_metadata()
│   ├── scan_vulnerabilities()  # Main entry point
│   ├── _generate_search_urls()
│   ├── _generate_google_dorks()
│   ├── _query_osint_platforms()
│   ├── _query_shodan()
│   ├── _query_censys()
│   ├── _query_zoomeye()
│   ├── _query_passive_dns()
│   ├── _get_api_keys()
│   └── _generate_osint_results()
```

### OSINTResult Dataclass

```python
@dataclass
class OSINTResult:
    """OSINT platform search result."""
    platform: str
    query: str
    url: str
    results_found: Optional[int]
    confidence: float
    summary: Optional[str]
    raw_data: Optional[Dict]
    search_timestamp: datetime

    def __post_init__(self):
        """Validate confidence range."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")
```

### OSINT Platform Configuration

```python
OSINT_PLATFORMS = {
    "shodan": {
        "search_url": "https://www.shodan.io/search?query={query}",
        "api_url": "https://api.shodan.io/shodan/host/{ip}",
        "api_key_env": "SHODAN_API_KEY",
        "rate_limit": 100,  # per month for free tier
        "confidence": 0.95
    },
    "censys": {
        "search_url": "https://search.censys.io/hosts/{ip}",
        "api_url": "https://search.censys.io/api/v2/hosts/{ip}",
        "api_key_env": "CENSYS_API_ID",
        "api_secret_env": "CENSYS_API_SECRET",
        "rate_limit": 250,  # per month for free tier
        "confidence": 0.90
    },
    "zoomeye": {
        "search_url": "https://www.zoomeye.org/searchResult?q={query}",
        "api_url": "https://api.zoomeye.org/host/search?query=ip:{ip}",
        "api_key_env": "ZOOMEYE_API_KEY",
        "rate_limit": 10000,  # per month for free tier
        "confidence": 0.85
    },
    # ... more platforms
}
```

### Google Dork Patterns

```python
CAMERA_DORKS = [
    "site:{ip} inurl:view/view.shtml",
    "site:{ip} inurl:admin.html",
    "site:{ip} inurl:login",
    "site:{ip} intitle:webcam",
    "site:{ip} inurl:cgi-bin",
    "site:{ip} inurl:axis-cgi",
    "site:{ip} inurl:ISAPI",
    "site:{ip} inurl:onvif",
    "site:{ip} \"IP Camera\"",
    "site:{ip} \"Network Camera\"",
    "site:{ip} \"Live View\"",
    "site:{ip} \"DVR\"",
    "site:{ip} \"NVR\"",
]

SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/?q={query}"
}
```

## API Integration Implementations

### Shodan API Integration

```python
async def _query_shodan(self, target_ip: str, api_key: str) -> Optional[OSINTResult]:
    """
    Query Shodan API for IP intelligence.

    Args:
        target_ip: Target IP address
        api_key: Shodan API key

    Returns:
        OSINTResult with Shodan data or None
    """
    url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    # Extract relevant information
                    ports = data.get("ports", [])
                    organization = data.get("org", "Unknown")
                    hostnames = data.get("hostnames", [])
                    vulns = data.get("vulns", [])

                    summary = f"Org: {organization}, Ports: {len(ports)}, Hostnames: {len(hostnames)}, Vulns: {len(vulns)}"

                    return OSINTResult(
                        platform="shodan",
                        query=target_ip,
                        url=f"https://www.shodan.io/host/{target_ip}",
                        results_found=1,
                        confidence=0.95,
                        summary=summary,
                        raw_data=data,
                        search_timestamp=datetime.now()
                    )

                elif response.status == 404:
                    # No data found (not an error)
                    return OSINTResult(
                        platform="shodan",
                        query=target_ip,
                        url=f"https://www.shodan.io/host/{target_ip}",
                        results_found=0,
                        confidence=0.90,
                        summary="No Shodan data found for this IP",
                        raw_data=None,
                        search_timestamp=datetime.now()
                    )

                elif response.status == 401:
                    logger.warning("Shodan API key invalid or expired")
                    return None

                elif response.status == 429:
                    logger.warning("Shodan rate limit exceeded")
                    return None

    except asyncio.TimeoutError:
        logger.debug(f"Shodan query timeout for {target_ip}")
    except aiohttp.ClientError as e:
        logger.debug(f"Shodan query failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error querying Shodan: {e}")

    return None
```

### Censys API Integration (Basic Auth)

```python
async def _query_censys(self, target_ip: str, api_id: str, api_secret: str) -> Optional[OSINTResult]:
    """
    Query Censys API for IP intelligence.

    Args:
        target_ip: Target IP address
        api_id: Censys API ID
        api_secret: Censys API secret

    Returns:
        OSINTResult with Censys data or None
    """
    url = f"https://search.censys.io/api/v2/hosts/{target_ip}"

    # Basic authentication for Censys
    auth_string = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {auth_string}"}

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()

                    # Extract relevant information
                    services = data.get("result", {}).get("services", [])
                    location = data.get("result", {}).get("location", {})
                    asn = data.get("result", {}).get("autonomous_system", {})

                    summary = f"Services: {len(services)}, ASN: {asn.get('asn', 'N/A')}, Country: {location.get('country', 'N/A')}"

                    return OSINTResult(
                        platform="censys",
                        query=target_ip,
                        url=f"https://search.censys.io/hosts/{target_ip}",
                        results_found=1,
                        confidence=0.90,
                        summary=summary,
                        raw_data=data,
                        search_timestamp=datetime.now()
                    )

    except Exception as e:
        logger.debug(f"Censys query failed: {e}")

    return None
```

### Passive DNS (CIRCL - Free)

```python
async def _query_passive_dns(self, target_ip: str) -> List[OSINTResult]:
    """
    Query passive DNS sources for historical domain associations.

    Args:
        target_ip: Target IP address

    Returns:
        List of OSINTResult objects (may be empty)
    """
    results = []

    try:
        url = f"https://www.circl.lu/pdns/query/{target_ip}"

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()

                    if data:
                        unique_domains = set()
                        for record in data:
                            if "rrname" in record:
                                unique_domains.add(record["rrname"])

                        summary = f"Historical domains: {len(unique_domains)}"

                        results.append(OSINTResult(
                            platform="circl_pdns",
                            query=target_ip,
                            url=f"https://www.circl.lu/pdns/query/{target_ip}",
                            results_found=len(data),
                            confidence=0.80,
                            summary=summary,
                            raw_data={"domains": list(unique_domains)},
                            search_timestamp=datetime.now()
                        ))

    except Exception as e:
        logger.debug(f"Passive DNS query failed: {e}")

    return results
```

## Testing Requirements

```
tests/analyze/plugins/builtin/test_osint_integration_scanner.py
├── TestOSINTResult (3 tests)
├── TestSearchURLGeneration (5 tests)
├── TestGoogleDorkGeneration (4 tests)
├── TestShodanIntegration (5 tests - all mocked)
├── TestCensysIntegration (4 tests - all mocked)
├── TestZoomEyeIntegration (3 tests - all mocked)
├── TestPassiveDNS (3 tests - all mocked)
└── TestGracefulDegradation (3 tests - no API keys)
```

### Mock API Responses

**Shodan Success Response**:

```json
{
  "ip_str": "192.168.1.100",
  "org": "Example ISP",
  "ports": [80, 443, 554, 8080],
  "hostnames": ["camera.example.com"],
  "vulns": ["CVE-2017-7921", "CVE-2021-36260"],
  "data": [
    {
      "port": 80,
      "product": "Hikvision Webserver"
    }
  ]
}
```

**Censys Success Response**:

```json
{
  "result": {
    "services": [
      {"port": 80, "service_name": "HTTP"},
      {"port": 443, "service_name": "HTTPS"}
    ],
    "location": {
      "country": "US",
      "city": "San Francisco"
    },
    "autonomous_system": {
      "asn": 15169,
      "description": "GOOGLE"
    }
  }
}
```

## Performance Benchmarks

- ✅ URL generation: <50ms for all platforms
- ✅ Google dork generation: <100ms for 13 patterns
- ✅ API query (with key): <5 seconds per platform
- ✅ Graceful degradation (no key): <10ms (URLs only)
- ✅ Memory usage: <2MB per scan

## Success Criteria

### Functionality

- [ ] Generates search URLs for 5+ OSINT platforms
- [ ] Implements 13+ Google dork patterns
- [ ] Shodan API integration functional (when key available)
- [ ] Censys API integration functional (when key available)
- [ ] ZoomEye API integration functional (when key available)
- [ ] Passive DNS queries functional
- [ ] Graceful degradation without API keys

### Testing

- [ ] 30+ unit tests passing
- [ ] All API responses mocked
- [ ] No actual API calls in tests
- [ ] Edge cases covered (rate limits, timeouts, invalid keys)

### Integration

- [ ] Registered in BUILTIN_PLUGINS
- [ ] Returns INFO severity VulnerabilityResults
- [ ] Metadata includes all OSINT data
- [ ] No performance impact on analysis pipeline

### Documentation

- [ ] API key setup instructions
- [ ] Platform descriptions documented
- [ ] Privacy considerations documented
- [ ] Rate limit guidance provided

## API Key Management

### Environment Variables

```bash
export SHODAN_API_KEY="your_shodan_key_here"
export CENSYS_API_ID="your_censys_id_here"
export CENSYS_API_SECRET="your_censys_secret_here"
export ZOOMEYE_API_KEY="your_zoomeye_key_here"
```

### Configuration File (Alternative)

```python
# ~/.gridland/osint_config.json
{
  "api_keys": {
    "shodan": "encrypted_key_here",
    "censys_id": "encrypted_id_here",
    "censys_secret": "encrypted_secret_here",
    "zoomeye": "encrypted_key_here"
  }
}
```

## Rate Limiting Strategy

```python
class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, calls_per_second: float):
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0

    async def acquire(self):
        """Wait if necessary to respect rate limit."""
        now = time.time()
        time_since_last = now - self.last_call

        if time_since_last < self.min_interval:
            wait_time = self.min_interval - time_since_last
            await asyncio.sleep(wait_time)

        self.last_call = time.time()
```

## Common Pitfalls to Avoid

❌ **DO NOT**:

- Make API calls without rate limiting
- Store API keys in code
- Skip error handling for network failures
- Ignore 401/403/429 status codes
- Block on synchronous API calls
- Expose raw API keys in logs

✅ **DO**:

- Implement exponential backoff
- Load API keys from environment
- Handle all HTTP status codes
- Respect rate limits strictly
- Use async/await throughout
- Mask API keys in logs (show last 4 chars only)

## Security Considerations

### API Key Protection

```python
def mask_api_key(key: str) -> str:
    """Mask API key for logging."""
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"

# Usage:
logger.info(f"Using Shodan API key: {mask_api_key(api_key)}")
```

### Query Logging

```python
# Log all OSINT queries for audit trail
logger.info(f"OSINT query: {platform} for {target_ip} at {timestamp}")
```

### Terms of Service Compliance

- Respect API rate limits (critical!)
- Use official APIs, not scraping
- Include User-Agent header
- Handle 429 (rate limit) gracefully
- Document intended use case

## Ready for Deployment

- Agent can work independently
- All APIs documented
- Security considerations addressed
- Testing requirements comprehensive
