"""
Advanced Fingerprinting Scanner with brand-specific intelligence extraction.
Implements CamXploit.py fingerprinting methods (lines 616-765) with enhanced capabilities.
"""

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
import re
import base64
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import json

from gridland.analyze.memory.pool import get_memory_pool, VulnerabilityResult
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class DeviceFingerprint:
    """Comprehensive device fingerprint information"""
    brand: str
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    hardware_version: Optional[str] = None
    serial_number: Optional[str] = None
    device_type: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    authentication_methods: List[str] = field(default_factory=list)
    configuration_access: bool = False
    vulnerability_indicators: List[str] = field(default_factory=list)

class AdvancedFingerprintingScanner(VulnerabilityPlugin):
    """
    Advanced device fingerprinting with brand-specific intelligence extraction.

    Implements sophisticated fingerprinting methods from CamXploit.py with
    enhanced device intelligence collection and vulnerability correlation.
    """

    metadata = PluginMetadata(
        name="Advanced Fingerprinting Scanner",
        version="2.0.0",
        author="GRIDLAND Security Team",
        plugin_type="vulnerability",
        supported_services=["http", "https"],
        supported_ports=[80, 443, 8080, 8443, 8000, 8001],
        description="Brand-specific device fingerprinting with model/firmware extraction"
    )

    def __init__(self):
        super().__init__()
        self.fingerprinting_database = self._load_fingerprinting_database()
        self.memory_pool = get_memory_pool()

    def _load_fingerprinting_database(self) -> Dict:
        """Load brand-specific fingerprinting patterns and endpoints"""
        return {
            "hikvision": {
                "endpoints": [
                    "/ISAPI/System/deviceInfo",
                    "/ISAPI/System/capabilities",
                    "/System/configurationFile",
                    "/ISAPI/Security/users",
                    "/ISAPI/Streaming/channels"
                ],
                "xml_paths": {
                    "model": [".//model", ".//deviceModel", ".//ModelName"],
                    "firmware": [".//firmwareVersion", ".//FirmwareVersion", ".//version"],
                    "hardware": [".//hardwareVersion", ".//HardwareVersion"],
                    "serial": [".//serialNumber", ".//SerialNumber", ".//deviceID"]
                },
                "auth_methods": ["basic", "digest", "form"],
                "default_credentials": [
                    ("admin", "12345"),
                    ("admin", "admin"),
                    ("admin", "hikadmin")
                ]
            },
            "dahua": {
                "endpoints": [
                    "/cgi-bin/magicBox.cgi?action=getSystemInfo",
                    "/cgi-bin/magicBox.cgi?action=getDeviceInfo",
                    "/cgi-bin/magicBox.cgi?action=getProductDefinition",
                    "/cgi-bin/configManager.cgi?action=getConfig&name=General",
                    "/RPC2"
                ],
                "response_patterns": {
                    "model": [r"deviceType=([^\\r\\n]+)", r"model=([^\\r\\n]+)"],
                    "firmware": [r"version=([^\\r\\n]+)", r"buildDate=([^\\r\\n]+)"],
                    "serial": [r"serialNumber=([^\\r\\n]+)", r"machineID=([^\\r\\n]+)"]
                },
                "auth_methods": ["basic", "rpc2_challenge"],
                "default_credentials": [
                    ("admin", "admin"),
                    ("admin", "dahua123"),
                    ("admin", "")
                ]
            },
            "axis": {
                "endpoints": [
                    "/axis-cgi/admin/param.cgi?action=list",
                    "/axis-cgi/admin/param.cgi?action=list&group=Brand",
                    "/axis-cgi/admin/param.cgi?action=list&group=Properties",
                    "/axis-cgi/vapix/services",
                    "/axis-cgi/basicdeviceinfo.cgi"
                ],
                "parameter_patterns": {
                    "model": ["root.Brand.ProdFullName", "root.Properties.ProductFullName"],
                    "firmware": ["root.Properties.Firmware.Version", "root.Brand.Version"],
                    "hardware": ["root.Properties.Hardware.Architecture"],
                    "serial": ["root.Properties.System.SerialNumber"]
                },
                "auth_methods": ["basic", "digest"],
                "default_credentials": [
                    ("admin", "admin"),
                    ("root", "pass"),
                    ("admin", "")
                ]
            },
            "cp_plus": {
                "endpoints": [
                    "/cgi-bin/snapshot.cgi",
                    "/cgi-bin/webproc",
                    "/api/system/deviceinfo",
                    "/config",
                    "/"
                ],
                "content_patterns": {
                    "model": [r"model[\"']?\s*[:=]\s*[\"']?([^\"',\\s]+)", r"uvr-?([0-9a-z]+)"],
                    "firmware": [r"version[\"']?\s*[:=]\s*[\"']?([^\"',\\s]+)"],
                    "device_type": ["dvr", "nvr", "camera"]
                },
                "auth_methods": ["basic", "form"],
                "default_credentials": [
                    ("admin", "admin"),
                    ("admin", "cpplus"),
                    ("admin", "guardian")
                ]
            }
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                    service: str, banner: str) -> List[VulnerabilityResult]:
        """Advanced fingerprinting with brand-specific intelligence extraction"""

        # Only analyze web ports
        if target_port not in [80, 443, 8080, 8443, 8000, 8001]:
            return []

        # Detect brand first
        detected_brand = await self._detect_device_brand(target_ip, target_port, banner)

        if not detected_brand:
            return []

        logger.info(f"Brand detected: {detected_brand} at {target_ip}:{target_port}")

        # Perform brand-specific fingerprinting
        fingerprint = await self._perform_brand_fingerprinting(
            target_ip, target_port, detected_brand
        )

        if not fingerprint:
            return []

        # Generate comprehensive fingerprint result
        return self._generate_fingerprint_results(fingerprint, target_ip, target_port)

    async def _detect_device_brand(self, target_ip: str, target_port: int,
                                 banner: Optional[str]) -> Optional[str]:
        """Detect device brand using multiple methods"""

        # Check banner first if available
        if banner:
            banner_lower = banner.lower()
            if 'hikvision' in banner_lower:
                return 'hikvision'
            elif 'dahua' in banner_lower:
                return 'dahua'
            elif 'axis' in banner_lower:
                return 'axis'
            elif any(cp in banner_lower for cp in ['cp plus', 'cp-plus', 'cpplus']):
                return 'cp_plus'

        # Probe for brand-specific endpoints
        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                # Test brand-specific endpoints
                brand_tests = [
                    ('hikvision', '/ISAPI/System/deviceInfo'),
                    ('dahua', '/cgi-bin/magicBox.cgi?action=getSystemInfo'),
                    ('axis', '/axis-cgi/admin/param.cgi?action=list'),
                    ('cp_plus', '/cgi-bin/snapshot.cgi')
                ]

                for brand, endpoint in brand_tests:
                    try:
                        url = f"{base_url}{endpoint}"
                        async with session.head(url, timeout=aiohttp.ClientTimeout(total=2)) as response:
                            if response.status in [200, 401]:  # Endpoint exists
                                return brand
                    except Exception:
                        continue

        except Exception as e:
            logger.debug(f"Brand detection failed: {e}")

        return None

    def _generate_fingerprint_results(self, fingerprint: DeviceFingerprint,
                                    target_ip: str, target_port: int) -> List[VulnerabilityResult]:
        """Generate comprehensive fingerprint vulnerability results"""

        results = []

        # Main fingerprint result
        main_result = self.memory_pool.acquire_vulnerability_result()
        main_result.vulnerability_id = "advanced-device-fingerprint"
        main_result.severity = "INFO"
        main_result.confidence = 0.95
        main_result.ip = target_ip
        main_result.port = target_port
        main_result.description = self._generate_fingerprint_description(fingerprint)
        main_result.exploit_available = False

        results.append(main_result)

        # Generate firmware-specific vulnerability alerts if applicable
        if fingerprint.firmware_version:
            firmware_vulns = self._check_firmware_vulnerabilities(fingerprint)
            results.extend(firmware_vulns)

        return results

    def _generate_fingerprint_description(self, fingerprint: DeviceFingerprint) -> str:
        """Generate human-readable fingerprint description"""

        parts = [f"Advanced fingerprinting completed for {fingerprint.brand.replace('_', ' ').title()} device"]

        if fingerprint.model:
            parts.append(f"Model: {fingerprint.model}")

        if fingerprint.firmware_version:
            parts.append(f"Firmware: {fingerprint.firmware_version}")

        if fingerprint.device_type:
            parts.append(f"Type: {fingerprint.device_type}")

        if fingerprint.api_endpoints:
            parts.append(f"API endpoints: {len(fingerprint.api_endpoints)} discovered")

        if fingerprint.configuration_access:
            parts.append("Configuration access available")

        return " | ".join(parts)

    def _check_firmware_vulnerabilities(self, fingerprint: DeviceFingerprint) -> List[VulnerabilityResult]:
        """Check firmware version against known vulnerabilities"""

        # This would integrate with CVE database to match firmware versions
        # to specific vulnerabilities - placeholder for future implementation

        vulnerabilities = []

        # Example: Check for known vulnerable firmware versions
        if fingerprint.brand == 'hikvision' and fingerprint.firmware_version:
            if any(vuln_version in fingerprint.firmware_version.lower()
                   for vuln_version in ['v5.4.1', 'v5.4.0', 'v5.3']):

                vuln_result = self.memory_pool.acquire_vulnerability_result()
                vuln_result.vulnerability_id = "firmware-vulnerability-detected"
                vuln_result.severity = "HIGH"
                vuln_result.confidence = 0.90
                vuln_result.description = f"Potentially vulnerable firmware version detected: {fingerprint.firmware_version}"
                vuln_result.exploit_available = True

                vulnerabilities.append(vuln_result)

        return vulnerabilities

    async def _perform_brand_fingerprinting(self, target_ip: str, target_port: int,
                                          brand: str) -> Optional[DeviceFingerprint]:
        """Perform brand-specific detailed fingerprinting"""

        if brand == 'hikvision':
            return await self._fingerprint_hikvision(target_ip, target_port)
        elif brand == 'dahua':
            return await self._fingerprint_dahua(target_ip, target_port)
        elif brand == 'axis':
            return await self._fingerprint_axis(target_ip, target_port)
        elif brand == 'cp_plus':
            return await self._fingerprint_cp_plus(target_ip, target_port)

        return None

    async def _fingerprint_hikvision(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
        """Hikvision-specific fingerprinting using ISAPI"""

        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        fingerprint = DeviceFingerprint(brand="hikvision", capabilities=[], api_endpoints=[])

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                # Test authentication first
                credentials = await self._test_credentials(session, base_url, 'hikvision')

                hik_db = self.fingerprinting_database['hikvision']

                for endpoint in hik_db['endpoints']:
                    try:
                        url = f"{base_url}{endpoint}"

                        # Try with credentials if available
                        auth = None
                        if credentials:
                            auth = aiohttp.BasicAuth(credentials[0], credentials[1])

                        async with session.get(url, auth=auth) as response:
                            if response.status == 200:
                                fingerprint.api_endpoints.append(endpoint)
                                content = await response.text()

                                # Parse XML responses for device info
                                if endpoint in ['/ISAPI/System/deviceInfo', '/System/configurationFile']:
                                    await self._parse_hikvision_xml(content, fingerprint)

                                # Check for configuration access
                                if 'configurationFile' in endpoint:
                                    fingerprint.configuration_access = True

                            elif response.status == 401:
                                fingerprint.api_endpoints.append(f"{endpoint} (auth required)")

                    except Exception as e:
                        logger.debug(f"Hikvision endpoint test failed for {endpoint}: {e}")

        except Exception as e:
            logger.debug(f"Hikvision fingerprinting failed: {e}")

        return fingerprint if fingerprint.api_endpoints else None

    async def _parse_hikvision_xml(self, content: str, fingerprint: DeviceFingerprint):
        """Parse Hikvision ISAPI XML responses"""

        try:
            root = ET.fromstring(content)

            # Extract device information using multiple XPath patterns
            hik_db = self.fingerprinting_database['hikvision']

            for field, paths in hik_db['xml_paths'].items():
                for path in paths:
                    element = root.find(path)
                    if element is not None and element.text:
                        if field == 'model':
                            fingerprint.model = element.text.strip()
                        elif field == 'firmware':
                            fingerprint.firmware_version = element.text.strip()
                        elif field == 'hardware':
                            fingerprint.hardware_version = element.text.strip()
                        elif field == 'serial':
                            fingerprint.serial_number = element.text.strip()
                        break

            # Extract capabilities
            caps = root.findall('.//capability') + root.findall('.//Channel')
            if caps:
                fingerprint.capabilities.extend([cap.get('name', 'unknown') for cap in caps[:5]])

        except ET.ParseError as e:
            logger.debug(f"XML parsing failed: {e}")

    async def _parse_dahua_response(self, content: str, fingerprint: DeviceFingerprint):
        """Parse Dahua magicBox.cgi responses"""

        dahua_db = self.fingerprinting_database['dahua']

        for field, patterns in dahua_db['response_patterns'].items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if field == 'model':
                        fingerprint.model = value
                    elif field == 'firmware':
                        fingerprint.firmware_version = value
                    elif field == 'serial':
                        fingerprint.serial_number = value
                    break

    async def _parse_axis_parameters(self, content: str, fingerprint: DeviceFingerprint):
        """Parse Axis VAPIX parameter responses"""

        axis_db = self.fingerprinting_database['axis']

        for field, param_names in axis_db['parameter_patterns'].items():
            for param_name in param_names:
                pattern = rf"{param_name}=([^\\r\\n]+)"
                match = re.search(pattern, content)
                if match:
                    value = match.group(1).strip()
                    if field == 'model':
                        fingerprint.model = value
                    elif field == 'firmware':
                        fingerprint.firmware_version = value
                    elif field == 'hardware':
                        fingerprint.hardware_version = value
                    elif field == 'serial':
                        fingerprint.serial_number = value
                    break

    async def _parse_cp_plus_content(self, content: str, fingerprint: DeviceFingerprint):
        """Parse CP Plus content for device information"""

        cp_db = self.fingerprinting_database['cp_plus']
        content_lower = content.lower()

        for field, patterns in cp_db['content_patterns'].items():
            for pattern in patterns:
                try:
                    if isinstance(pattern, str) and pattern in content_lower:
                        if field == 'device_type':
                            fingerprint.device_type = pattern.upper()
                    else:
                        # Regex pattern
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            if field == 'model':
                                fingerprint.model = value
                            elif field == 'firmware':
                                fingerprint.firmware_version = value
                            break
                except Exception as e:
                    logger.debug(f"Firmware pattern extraction error: {e}")

    async def _test_credentials(self, session: aiohttp.ClientSession, base_url: str,
                              brand: str) -> Optional[Tuple[str, str]]:
        """Test default credentials for the brand"""

        brand_db = self.fingerprinting_database.get(brand, {})
        credentials = brand_db.get('default_credentials', [])

        for username, password in credentials:
            try:
                auth = aiohttp.BasicAuth(username, password)
                async with session.get(base_url, auth=auth, timeout=aiohttp.ClientTimeout(total=3)) as response:
                    if response.status == 200:
                        return (username, password)
            except Exception:
                continue

        return None

    async def _fingerprint_dahua(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
        """Dahua-specific fingerprinting using magicBox.cgi"""

        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        fingerprint = DeviceFingerprint(brand="dahua", capabilities=[], api_endpoints=[])

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                dahua_db = self.fingerprinting_database['dahua']

                for endpoint in dahua_db['endpoints']:
                    try:
                        url = f"{base_url}{endpoint}"

                        async with session.get(url) as response:
                            if response.status == 200:
                                fingerprint.api_endpoints.append(endpoint)
                                content = await response.text()

                                # Parse Dahua response format
                                if 'magicBox.cgi' in endpoint:
                                    await self._parse_dahua_response(content, fingerprint)

                            elif response.status == 401:
                                fingerprint.api_endpoints.append(f"{endpoint} (auth required)")

                    except Exception as e:
                        logger.debug(f"Dahua endpoint test failed for {endpoint}: {e}")

        except Exception as e:
            logger.debug(f"Dahua fingerprinting failed: {e}")

        return fingerprint if fingerprint.api_endpoints else None

    async def _fingerprint_axis(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
        """Axis-specific fingerprinting using VAPIX API"""

        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        fingerprint = DeviceFingerprint(brand="axis", capabilities=[], api_endpoints=[])

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                axis_db = self.fingerprinting_database['axis']

                for endpoint in axis_db['endpoints']:
                    try:
                        url = f"{base_url}{endpoint}"

                        async with session.get(url) as response:
                            if response.status == 200:
                                fingerprint.api_endpoints.append(endpoint)
                                content = await response.text()

                                # Parse VAPIX parameter format
                                if 'param.cgi' in endpoint:
                                    await self._parse_axis_parameters(content, fingerprint)

                            elif response.status == 401:
                                fingerprint.api_endpoints.append(f"{endpoint} (auth required)")

                    except Exception as e:
                        logger.debug(f"Axis endpoint test failed for {endpoint}: {e}")

        except Exception as e:
            logger.debug(f"Axis fingerprinting failed: {e}")

        return fingerprint if fingerprint.api_endpoints else None

    async def _fingerprint_cp_plus(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
        """CP Plus-specific fingerprinting"""

        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        fingerprint = DeviceFingerprint(brand="cp_plus", capabilities=[], api_endpoints=[])

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                cp_db = self.fingerprinting_database['cp_plus']

                for endpoint in cp_db['endpoints']:
                    try:
                        url = f"{base_url}{endpoint}"

                        async with session.get(url) as response:
                            if response.status == 200:
                                fingerprint.api_endpoints.append(endpoint)
                                content = await response.text()

                                # Parse CP Plus content patterns
                                await self._parse_cp_plus_content(content, fingerprint)

                            elif response.status == 401:
                                fingerprint.api_endpoints.append(f"{endpoint} (auth required)")

                    except Exception as e:
                        logger.debug(f"CP Plus endpoint test failed for {endpoint}: {e}")

        except Exception as e:
            logger.debug(f"CP Plus fingerprinting failed: {e}")

        return fingerprint if fingerprint.api_endpoints else None
