"""
CP Plus Camera Scanner with specialized detection and vulnerability assessment.
Implements CamXploit.py CP Plus intelligence (lines 684-720) with enhanced capabilities.
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import json

from gridland.analyze.memory.pool import get_memory_pool, VulnerabilityResult
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata, AnalysisPlugin
from gridland.core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class CPPlusModel:
    """CP Plus device model information"""
    model_id: str
    full_name: str
    device_type: str  # DVR, NVR, Camera
    known_vulnerabilities: List[str]
    default_credentials: List[tuple]

class CPPlusScanner(VulnerabilityPlugin):
    """
    Specialized scanner for CP Plus camera and DVR systems.

    Implements comprehensive CP Plus detection and vulnerability assessment
    based on CamXploit.py intelligence with enhanced model identification.
    """

    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="CP Plus Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=[80, 443, 8080, 8443, 8000, 8001],
            description="Specialized vulnerability scanner for CP Plus cameras and DVR systems"
        )
        self.cp_plus_database = self._load_cp_plus_database()
        self.memory_pool = get_memory_pool()


    def _load_cp_plus_database(self) -> Dict:
        """Load CP Plus device database with models and vulnerabilities"""
        return {
            "brand_indicators": [
                'cp plus', 'cp-plus', 'cpplus', 'cp_plus', 'uvr', 'guardian',
                'cp plus security', 'cpplus.co.in', 'aditya infotech'
            ],
            "models": {
                "UVR-0401E1": CPPlusModel(
                    model_id="UVR-0401E1",
                    full_name="CP-UVR-0401E1-IC2",
                    device_type="DVR",
                    known_vulnerabilities=[
                        "default-credentials",
                        "weak-authentication",
                        "information-disclosure",
                        "csrf-vulnerability"
                    ],
                    default_credentials=[
                        ("admin", "admin"),
                        ("admin", "123456"),
                        ("admin", ""),
                        ("user", "user"),
                        ("guest", "")
                    ]
                ),
                "UVR-0801E1": CPPlusModel(
                    model_id="UVR-0801E1",
                    full_name="CP-UVR-0801E1-IC2",
                    device_type="DVR",
                    known_vulnerabilities=[
                        "default-credentials",
                        "weak-authentication",
                        "remote-code-execution"
                    ],
                    default_credentials=[
                        ("admin", "admin"),
                        ("admin", "123456"),
                        ("admin", "cpplus123")
                    ]
                ),
                "UNR-1601E2": CPPlusModel(
                    model_id="UNR-1601E2",
                    full_name="CP-UNR-1601E2-IC",
                    device_type="NVR",
                    known_vulnerabilities=[
                        "default-credentials",
                        "authentication-bypass",
                        "directory-traversal"
                    ],
                    default_credentials=[
                        ("admin", "admin"),
                        ("admin", "cpplus"),
                        ("admin", "guardian")
                    ]
                )
            },
            "endpoints": [
                "/", "/index.html", "/login", "/admin", "/cgi-bin",
                "/api", "/config", "/viewer", "/webadmin", "/setup",
                "/cgi-bin/webproc", "/cgi-bin/snapshot.cgi",
                "/cgi-bin/video.cgi", "/cgi-bin/stream.cgi"
            ],
            "vulnerability_signatures": {
                "information-disclosure": {
                    "patterns": ["system.ini", "config.xml", "device.conf"],
                    "endpoints": ["/system.ini", "/config.xml", "/cgi-bin/config"]
                },
                "authentication-bypass": {
                    "patterns": ["guest access", "anonymous login"],
                    "endpoints": ["/cgi-bin/nobody", "/guest"]
                },
                "csrf-vulnerability": {
                    "patterns": ["no csrf token", "missing referer check"],
                    "endpoints": ["/cgi-bin/webproc"]
                }
            }
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                    service: str, banner: str) -> List[VulnerabilityResult]:
        """Comprehensive CP Plus vulnerability analysis"""

        # Only analyze web ports
        if target_port not in [80, 443, 8080, 8443, 8000, 8001]:
            return []

        vulnerabilities = []
        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        # Step 1: Detect if this is a CP Plus device
        is_cp_plus, detected_model = await self._detect_cp_plus_device(base_url)

        if not is_cp_plus:
            return []

        logger.info(f"CP Plus device detected at {base_url}")
        if detected_model:
            logger.info(f"Model identified: {detected_model.full_name}")

        # Step 2: Test for CP Plus specific vulnerabilities
        default_cred_vulns = await self._test_default_credentials(base_url, detected_model)
        vulnerabilities.extend(default_cred_vulns)

        info_disclosure_vulns = await self._test_information_disclosure(base_url)
        vulnerabilities.extend(info_disclosure_vulns)

        auth_bypass_vulns = await self._test_authentication_bypass(base_url)
        vulnerabilities.extend(auth_bypass_vulns)

        csrf_vulns = await self._test_csrf_vulnerabilities(base_url)
        vulnerabilities.extend(csrf_vulns)

        # Step 3: Generate device fingerprint result
        fingerprint_result = self._generate_fingerprint_result(detected_model, target_ip, target_port)
        vulnerabilities.append(fingerprint_result)

        return vulnerabilities

    async def _detect_cp_plus_device(self, base_url: str) -> tuple[bool, Optional[CPPlusModel]]:
        """Detect CP Plus device and identify model"""

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Test primary endpoints for CP Plus indicators
                for endpoint in ["", "/index.html", "/login", "/admin"]:
                    try:
                        url = f"{base_url}{endpoint}"
                        async with session.get(url) as response:

                            if response.status == 200:
                                content = await response.text()
                                content_lower = content.lower()

                                # Check for CP Plus brand indicators
                                brand_detected = any(
                                    indicator in content_lower
                                    for indicator in self.cp_plus_database["brand_indicators"]
                                )

                                if brand_detected:
                                    # Try to identify specific model
                                    detected_model = self._identify_model(content_lower)
                                    return True, detected_model

                    except Exception as e:
                        logger.debug(f"Failed to test {url}: {e}")
                        continue

            return False, None

        except Exception as e:
            logger.debug(f"CP Plus detection failed for {base_url}: {e}")
            return False, None

    def _identify_model(self, content: str) -> Optional[CPPlusModel]:
        """Identify specific CP Plus model from content"""

        # Check for specific model identifiers
        model_patterns = {
            "UVR-0401E1": ["uvr-0401e1", "uvr0401e1", "0401e1"],
            "UVR-0801E1": ["uvr-0801e1", "uvr0801e1", "0801e1"],
            "UNR-1601E2": ["unr-1601e2", "unr1601e2", "1601e2"]
        }

        for model_id, patterns in model_patterns.items():
            if any(pattern in content for pattern in patterns):
                return self.cp_plus_database["models"][model_id]

        return None

    async def _test_default_credentials(self, base_url: str,
                                      model: Optional[CPPlusModel]) -> List[VulnerabilityResult]:
        """Test CP Plus default credentials"""

        vulnerabilities = []

        # Get credentials to test
        if model:
            credentials = model.default_credentials
        else:
            # Generic CP Plus credentials
            credentials = [
                ("admin", "admin"),
                ("admin", "123456"),
                ("admin", ""),
                ("admin", "cpplus"),
                ("admin", "guardian"),
                ("user", "user"),
                ("guest", "")
            ]

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                # Test credentials against login endpoints
                login_endpoints = ["/", "/login", "/admin", "/cgi-bin/webproc"]

                for endpoint in login_endpoints:
                    for username, password in credentials:
                        try:
                            # Test HTTP Basic Auth
                            auth = aiohttp.BasicAuth(username, password)
                            url = f"{base_url}{endpoint}"

                            async with session.get(url, auth=auth) as response:
                                if response.status == 200:
                                    # Verify successful authentication
                                    content = await response.text()
                                    if self._is_authenticated_response(content):

                                        vuln_result = self.memory_pool.acquire_vulnerability_result()
                                        vuln_result.vulnerability_id = "cp-plus-default-credentials"
                                        vuln_result.severity = "HIGH"
                                        vuln_result.confidence = 0.95
                                        vuln_result.description = f"CP Plus device accessible with default credentials: {username}:{password}"
                                        vuln_result.exploit_available = True

                                        vulnerabilities.append(vuln_result)

                                        # Stop after first successful login
                                        return vulnerabilities

                        except Exception as e:
                            logger.debug(f"Credential test failed for {username}:{password} at {endpoint}: {e}")
                            continue

        except Exception as e:
            logger.debug(f"Default credential testing failed: {e}")

        return vulnerabilities

    async def _test_information_disclosure(self, base_url: str) -> List[VulnerabilityResult]:
        """Test for information disclosure vulnerabilities"""

        vulnerabilities = []
        info_disclosure = self.cp_plus_database["vulnerability_signatures"]["information-disclosure"]

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                for endpoint in info_disclosure["endpoints"]:
                    try:
                        url = f"{base_url}{endpoint}"
                        async with session.get(url) as response:

                            if response.status == 200:
                                content = await response.text()

                                # Check for sensitive information patterns
                                for pattern in info_disclosure["patterns"]:
                                    if pattern in content.lower():

                                        vuln_result = self.memory_pool.acquire_vulnerability_result()
                                        vuln_result.vulnerability_id = "cp-plus-information-disclosure"
                                        vuln_result.severity = "MEDIUM"
                                        vuln_result.confidence = 0.85
                                        vuln_result.description = f"Information disclosure via {endpoint}: {pattern} detected"
                                        vuln_result.exploit_available = False

                                        vulnerabilities.append(vuln_result)

                    except Exception as e:
                        logger.debug(f"Info disclosure test failed for {endpoint}: {e}")
                        continue

        except Exception as e:
            logger.debug(f"Information disclosure testing failed: {e}")

        return vulnerabilities

    async def _test_authentication_bypass(self, base_url: str) -> List[VulnerabilityResult]:
        """Test for authentication bypass vulnerabilities"""

        vulnerabilities = []
        auth_bypass = self.cp_plus_database["vulnerability_signatures"]["authentication-bypass"]

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                for endpoint in auth_bypass["endpoints"]:
                    try:
                        url = f"{base_url}{endpoint}"
                        async with session.get(url) as response:

                            if response.status == 200:
                                content = await response.text()

                                # Check if administrative content is accessible without auth
                                if self._is_admin_content(content):

                                    vuln_result = self.memory_pool.acquire_vulnerability_result()
                                    vuln_result.vulnerability_id = "cp-plus-authentication-bypass"
                                    vuln_result.severity = "HIGH"
                                    vuln_result.confidence = 0.90
                                    vuln_result.description = f"Authentication bypass allows unauthorized access to {endpoint}"
                                    vuln_result.exploit_available = True

                                    vulnerabilities.append(vuln_result)

                    except Exception as e:
                        logger.debug(f"Auth bypass test failed for {endpoint}: {e}")
                        continue

        except Exception as e:
            logger.debug(f"Authentication bypass testing failed: {e}")

        return vulnerabilities

    async def _test_csrf_vulnerabilities(self, base_url: str) -> List[VulnerabilityResult]:
        """Test for CSRF vulnerabilities in CP Plus devices"""

        vulnerabilities = []
        csrf_sigs = self.cp_plus_database["vulnerability_signatures"]["csrf-vulnerability"]

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                for endpoint in csrf_sigs["endpoints"]:
                    try:
                        url = f"{base_url}{endpoint}"

                        # Test POST request without CSRF token
                        data = {"action": "test", "value": "1"}
                        async with session.post(url, data=data) as response:

                            if response.status == 200:
                                content = await response.text()

                                # Check if action was processed without CSRF protection
                                if not self._has_csrf_protection(content):

                                    vuln_result = self.memory_pool.acquire_vulnerability_result()
                                    vuln_result.vulnerability_id = "cp-plus-csrf-vulnerability"
                                    vuln_result.severity = "MEDIUM"
                                    vuln_result.confidence = 0.75
                                    vuln_result.description = f"CSRF vulnerability in {endpoint} allows unauthorized actions"
                                    vuln_result.exploit_available = True

                                    vulnerabilities.append(vuln_result)

                    except Exception as e:
                        logger.debug(f"CSRF test failed for {endpoint}: {e}")
                        continue

        except Exception as e:
            logger.debug(f"CSRF testing failed: {e}")

        return vulnerabilities

    def _generate_fingerprint_result(self, model: Optional[CPPlusModel],
                                   target_ip: str, target_port: int) -> VulnerabilityResult:
        """Generate device fingerprint result"""

        fingerprint_result = self.memory_pool.acquire_vulnerability_result()
        fingerprint_result.vulnerability_id = "cp-plus-device-fingerprint"
        fingerprint_result.severity = "INFO"
        fingerprint_result.confidence = 0.95
        fingerprint_result.ip = target_ip
        fingerprint_result.port = target_port

        if model:
            fingerprint_result.description = f"CP Plus {model.device_type} identified: {model.full_name}"

        else:
            fingerprint_result.description = "CP Plus device detected (model unknown)"


        fingerprint_result.exploit_available = False

        return fingerprint_result

    def _is_authenticated_response(self, content: str) -> bool:
        """Check if response indicates successful authentication"""

        auth_indicators = [
            "welcome", "dashboard", "main menu", "logout", "settings",
            "configuration", "admin panel", "control panel"
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in auth_indicators)

    def _is_admin_content(self, content: str) -> bool:
        """Check if content appears to be administrative interface"""

        admin_indicators = [
            "admin", "configuration", "settings", "control", "management",
            "system info", "device info", "network settings"
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in admin_indicators)

    def _has_csrf_protection(self, content: str) -> bool:
        """Check if response indicates CSRF protection is present"""

        csrf_indicators = [
            "csrf", "token", "_token", "authenticity_token", "csrf_token"
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in csrf_indicators)

    def get_metadata(self) -> PluginMetadata:
        return self.metadata
