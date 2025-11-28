# Fingerprinting Specialist Skill

## Skill Purpose

Expert in implementing device fingerprinting systems for IP cameras. Specializes in parsing vendor-specific API responses, extracting device metadata, and aggregating fingerprint data with confidence scoring.

## Core Competencies

### 1. XML/JSON Response Parsing

- Parse Hikvision ISAPI XML responses (deviceInfo, configurationFile, capabilities)
- Parse Dahua key=value format responses (magicBox.cgi)
- Parse Axis VAPIX param.cgi responses
- Extract nested data from complex structures

### 2. HTTP Client Implementation

- Async HTTP requests with aiohttp
- Authentication header construction (Basic, Digest)
- SSL certificate verification handling
- Timeout and retry logic
- Connection pooling

### 3. Regex Pattern Extraction

- Model number extraction from various formats
- Firmware version parsing (x.y.z, vX.Y.Z, etc.)
- Serial number identification
- MAC address extraction

### 4. Confidence Scoring Algorithms

- Data completeness scoring (0.0-1.0)
- Multi-source aggregation
- Weighted confidence from different endpoints
- Fallback degradation

## Implementation Guidelines

### File Structure

```
gridland/analyze/core/fingerprinting.py
├── DeviceFingerprint (dataclass)
├── FingerprintResult (dataclass)
├── BaseFingerprinter (ABC)
├── HikvisionFingerprinter
├── DahuaFingerprinter
├── AxisFingerprinter
├── SonyFingerprinter
├── BoschFingerprinter
├── GenericFingerprinter
└── FingerprintAggregator
```

### Code Quality Requirements

- ✅ Type hints on ALL functions
- ✅ Docstrings with Args/Returns/Raises
- ✅ Error handling for every HTTP call
- ✅ Logging at INFO level for successes, DEBUG for attempts
- ✅ No hardcoded credentials
- ✅ No placeholders or TODO comments

### Testing Requirements

```
tests/analyze/core/test_fingerprinting.py
├── TestDeviceFingerprint (10+ tests)
├── TestHikvisionFingerprinter (12+ tests)
├── TestDahuaFingerprinter (8+ tests)
├── TestAxisFingerprinter (8+ tests)
├── TestSonyFingerprinter (4+ tests)
├── TestBoschFingerprinter (4+ tests)
├── TestGenericFingerprinter (8+ tests)
└── TestFingerprintAggregator (6+ tests)
```

### Mock HTTP Responses

Every test MUST use realistic mock responses. Examples:

**Hikvision ISAPI deviceInfo**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo>
    <deviceName>IP Camera</deviceName>
    <deviceID>12345678</deviceID>
    <model>DS-2CD2032-I</model>
    <serialNumber>DS-2CD2032-I20160101AAWRXXXXXXXXX</serialNumber>
    <macAddress>00:11:22:33:44:55</macAddress>
    <firmwareVersion>V5.6.5</firmwareVersion>
    <firmwareReleasedDate>build 191218</firmwareReleasedDate>
</DeviceInfo>
```

**Dahua magicBox.cgi**:

```
DeviceType=IPC-HDBW1XXX
HardwareVersion=1.00
SerialNo=12345678
SoftwareVersion=2.800.0000000.26.R.20210101
ProcessorType=ARM
```

## Performance Benchmarks

- ✅ Complete fingerprint extraction: <5 seconds per device
- ✅ Parallel endpoint querying: <3 seconds for 5 endpoints
- ✅ Memory usage: <10MB per fingerprint operation
- ✅ Graceful timeout: 10 seconds per endpoint max

## Success Criteria

### Functionality

- [ ] Extracts DeviceFingerprint for 6 major brands
- [ ] Confidence scores accurate (0.0-1.0 range)
- [ ] Handles missing endpoints gracefully
- [ ] Aggregates multiple sources correctly

### Testing

- [ ] 50+ unit tests passing
- [ ] 100% code coverage on new module
- [ ] All HTTP calls mocked
- [ ] Edge cases covered (empty responses, timeouts, invalid XML)

### Integration

- [ ] Imports cleanly in plugin manager
- [ ] No circular dependencies
- [ ] Memory pool integration working
- [ ] Logging integrated with core logger

### Documentation

- [ ] Every class has comprehensive docstring
- [ ] Every method documents parameters and returns
- [ ] README.md example usage provided
- [ ] Architecture diagram included

## Common Pitfalls to Avoid

❌ **DO NOT**:

- Use synchronous HTTP requests (use aiohttp)
- Hardcode URLs without protocol detection
- Ignore SSL verification errors (handle gracefully)
- Return None without context (use FingerprintResult with error)
- Skip error handling on XML parsing
- Use print() for output (use logger)
- Leave TODO comments in code

✅ **DO**:

- Use async/await throughout
- Detect HTTP/HTTPS from port (443/8443 = HTTPS)
- Handle SSLError, Timeout, ConnectionError separately
- Always return FingerprintResult with success flag
- Wrap XML parsing in try/except with specific error messages
- Use logger.debug(), logger.info(), logger.error()
- Complete all implementations before committing

## Example Implementation Pattern

```python
class HikvisionFingerprinter(BaseFingerprinter):
    """Hikvision camera fingerprinting implementation."""

    async def fingerprint(self, ip: str, port: int) -> FingerprintResult:
        """
        Extract device fingerprint from Hikvision camera.

        Args:
            ip: Target IP address
            port: Target port (usually 80 or 443)

        Returns:
            FingerprintResult with extracted data or error

        Raises:
            None (all errors captured in FingerprintResult)
        """
        protocol = "https" if port in [443, 8443] else "http"
        base_url = f"{protocol}://{ip}:{port}"

        # Try primary endpoint first
        device_info = await self._query_device_info(base_url)
        if device_info.success:
            return device_info

        # Fallback to secondary endpoint
        config_file = await self._query_config_file(base_url)
        if config_file.success:
            return config_file

        # Return failure with context
        return FingerprintResult(
            success=False,
            fingerprint=None,
            extraction_method="hikvision",
            response_data=None,
            error_message="All Hikvision endpoints failed"
        )
```

## Ready for Deployment

- Agent can work independently
- All requirements specified
- Success is measurable
- Quality is enforceable
