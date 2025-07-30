"""
Enhanced Credential Scanner with intelligent testing patterns and brand optimization.
Implements comprehensive credential testing from CamXploit.py with performance enhancements.
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import itertools

from gridland.analyze.memory.pool import get_memory_pool, VulnerabilityResult
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class CredentialMatch:
    """Successful credential authentication result"""
    username: str
    password: str
    endpoint: str
    authentication_method: str
    access_level: str
    response_indicators: List[str]
    confidence: float

class EnhancedCredentialScanner(VulnerabilityPlugin):
    """
    Enhanced credential scanner with intelligent testing patterns.

    Implements comprehensive credential testing with brand-specific optimization,
    early termination, and intelligent pattern recognition.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Enhanced Credential Scanner",
            version="2.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=[80, 443, 8080, 8443, 8000, 8001, 8008, 8081],
            description="Intelligent credential testing with brand optimization and pattern recognition"
        )

    def __init__(self):
        super().__init__()
        self.credential_database = self._load_credential_database()
        self.memory_pool = get_memory_pool()
        self.tested_credentials = set()  # Avoid duplicate testing

    def _load_credential_database(self) -> Dict:
        """Load enhanced credential database"""
        try:
            db_path = Path(__file__).parent.parent.parent.parent / "data" / "default_credentials.json"
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load credential database: {e}, using defaults")
            return self._get_default_credentials()

    def _get_default_credentials(self) -> Dict:
        """Fallback credential database"""
        return {
            "credentials": {
                "admin": ["admin", "12345", "admin123", "password", ""],
                "root": ["root", "toor", "pass", ""],
                "user": ["user", "password", ""]
            }
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                    service: str, banner: str) -> List[VulnerabilityResult]:
        """Enhanced credential testing with brand-specific optimization"""

        # Only test web ports that could have authentication
        if target_port not in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081]:
            return []

        # Detect brand for optimized credential testing
        detected_brand = self._detect_brand(banner)

        # Get optimized credential list
        credentials_to_test = self._get_optimized_credentials(detected_brand)

        # Test credentials with intelligent ordering
        successful_auths = await self._test_credentials_intelligently(
            target_ip, target_port, credentials_to_test, detected_brand
        )

        # Generate results
        return self._generate_credential_results(successful_auths, target_ip, target_port)

    def _detect_brand(self, banner: Optional[str]) -> Optional[str]:
        """Detect device brand for credential optimization"""

        if not banner:
            return None

        banner_lower = banner.lower()

        brand_indicators = {
            'hikvision': ['hikvision', 'dvr', 'web server'],
            'dahua': ['dahua', 'dvr'],
            'axis': ['axis', 'axis communications'],
            'cp_plus': ['cp plus', 'cp-plus', 'cpplus', 'guardian'],
            'sony': ['sony', 'ipela'],
            'panasonic': ['panasonic', 'network camera'],
            'samsung': ['samsung', 'samsung techwin'],
            'bosch': ['bosch', 'security systems']
        }

        for brand, indicators in brand_indicators.items():
            if any(indicator in banner_lower for indicator in indicators):
                return brand

        return None

    def _get_optimized_credentials(self, detected_brand: Optional[str]) -> List[Tuple[str, str]]:
        """Get optimized credential list based on detected brand"""

        credentials = []
        base_creds = self.credential_database.get("credentials", {})

        # Add brand-specific credentials first (highest priority)
        if detected_brand:
            brand_specific = self.credential_database.get("brand_specific", {}).get(detected_brand, {})
            accounts = brand_specific.get("common_accounts", [])
            passwords = brand_specific.get("common_passwords", [])

            # Generate brand-specific combinations
            for account in accounts:
                for password in passwords:
                    credentials.append((account, password))

        # Add high-probability generic credentials
        high_priority_combos = [
            ("admin", "admin"),
            ("admin", ""),
            ("admin", "12345"),
            ("admin", "123456"),
            ("admin", "password"),
            ("root", ""),
            ("root", "root"),
            ("user", ""),
            ("guest", ""),
            ("admin", "1234"),
            ("admin", "admin123")
        ]

        credentials.extend(high_priority_combos)

        # Add systematic combinations from database
        for username, password_list in base_creds.items():
            for password in password_list:
                combo = (username, password)
                if combo not in credentials:  # Avoid duplicates
                    credentials.append(combo)

        # Remove duplicates while preserving order
        seen = set()
        unique_credentials = []
        for combo in credentials:
            if combo not in seen:
                seen.add(combo)
                unique_credentials.append(combo)

        return unique_credentials[:100]  # Limit to top 100 combinations

    async def _test_credentials_intelligently(self, target_ip: str, target_port: int,
                                            credentials: List[Tuple[str, str]],
                                            detected_brand: Optional[str]) -> List[CredentialMatch]:
        """Test credentials with intelligent ordering and early termination"""

        successful_auths = []
        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        # Define authentication endpoints to test
        auth_endpoints = [
            "/", "/login", "/admin", "/cgi-bin/webproc", "/api/login",
            "/axis-cgi/admin/param.cgi", "/ISAPI/Security/sessionLogin",
            "/cgi-bin/magicBox.cgi", "/admin/login"
        ]

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=3)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                # Test credentials with concurrency control
                semaphore = asyncio.Semaphore(5)  # Limit concurrent tests

                for endpoint in auth_endpoints:
                    # Test high-priority credentials first
                    for username, password in credentials[:20]:  # Test top 20 first
                        if len(successful_auths) >= 3:  # Stop after finding 3 successful auths
                            break

                        match = await self._test_single_credential(
                            session, semaphore, base_url, endpoint, username, password
                        )

                        if match:
                            successful_auths.append(match)

                    if successful_auths:  # Found working credentials, stop testing this endpoint
                        continue

                    # If no success with high-priority, test remaining credentials
                    for username, password in credentials[20:]:
                        if len(successful_auths) >= 3:
                            break

                        match = await self._test_single_credential(
                            session, semaphore, base_url, endpoint, username, password
                        )

                        if match:
                            successful_auths.append(match)
                            break  # Stop after first success per endpoint

        except Exception as e:
            logger.debug(f"Credential testing failed: {e}")

        return successful_auths

    async def _test_single_credential(self, session: aiohttp.ClientSession,
                                    semaphore: asyncio.Semaphore,
                                    base_url: str, endpoint: str,
                                    username: str, password: str) -> Optional[CredentialMatch]:
        """Test single credential combination"""

        async with semaphore:
            try:
                url = f"{base_url}{endpoint}"
                credential_key = f"{username}:{password}:{endpoint}"

                # Skip if already tested
                if credential_key in self.tested_credentials:
                    return None

                self.tested_credentials.add(credential_key)

                # Test HTTP Basic Authentication
                auth = aiohttp.BasicAuth(username, password)

                async with session.get(url, auth=auth, timeout=aiohttp.ClientTimeout(total=2)) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Verify successful authentication
                        access_level, indicators = self._analyze_authentication_response(content)

                        if access_level != "failed":
                            confidence = self._calculate_auth_confidence(
                                response, content, username, password
                            )

                            return CredentialMatch(
                                username=username,
                                password=password,
                                endpoint=endpoint,
                                authentication_method="basic_auth",
                                access_level=access_level,
                                response_indicators=indicators,
                                confidence=confidence
                            )

                # Test form-based authentication for login endpoints
                if "login" in endpoint:
                    return await self._test_form_authentication(
                        session, url, username, password
                    )

            except Exception as e:
                logger.debug(f"Single credential test failed for {username}:{password} at {endpoint}: {e}")

            return None

    async def _test_form_authentication(self, session: aiohttp.ClientSession,
                                      url: str, username: str, password: str) -> Optional[CredentialMatch]:
        """Test form-based authentication"""

        try:
            # Common form field names
            form_variants = [
                {"username": username, "password": password},
                {"user": username, "pass": password},
                {"login": username, "passwd": password},
                {"uid": username, "pwd": password},
                {"name": username, "word": password}
            ]

            for form_data in form_variants:
                async with session.post(url, data=form_data,
                                      timeout=aiohttp.ClientTimeout(total=3)) as response:

                    if response.status in [200, 302]:  # Success or redirect
                        content = await response.text()
                        access_level, indicators = self._analyze_authentication_response(content)

                        if access_level != "failed":
                            confidence = self._calculate_auth_confidence(
                                response, content, username, password
                            )

                            return CredentialMatch(
                                username=username,
                                password=password,
                                endpoint=url,
                                authentication_method="form_auth",
                                access_level=access_level,
                                response_indicators=indicators,
                                confidence=confidence
                            )

        except Exception as e:
            logger.debug(f"Form authentication test failed: {e}")

        return None

    def _analyze_authentication_response(self, content: str) -> Tuple[str, List[str]]:
        """Analyze response to determine authentication success and access level"""

        content_lower = content.lower()
        indicators = []

        # Success indicators
        success_patterns = [
            "welcome", "dashboard", "main menu", "control panel", "admin panel",
            "configuration", "settings", "logout", "home", "index", "menu"
        ]

        admin_patterns = [
            "administrator", "admin", "system configuration", "user management",
            "security settings", "network settings", "device management"
        ]

        user_patterns = [
            "user", "viewer", "monitor", "live view", "playback", "camera"
        ]

        failure_patterns = [
            "login failed", "invalid", "incorrect", "unauthorized", "access denied",
            "authentication failed", "wrong password", "login error"
        ]

        # Check for failure first
        for pattern in failure_patterns:
            if pattern in content_lower:
                indicators.append(f"failure: {pattern}")
                return "failed", indicators

        # Check for success patterns
        found_success = False
        for pattern in success_patterns:
            if pattern in content_lower:
                indicators.append(f"success: {pattern}")
                found_success = True

        if not found_success:
            return "failed", indicators

        # Determine access level
        for pattern in admin_patterns:
            if pattern in content_lower:
                indicators.append(f"admin: {pattern}")
                return "administrator", indicators

        for pattern in user_patterns:
            if pattern in content_lower:
                indicators.append(f"user: {pattern}")
                return "user", indicators

        return "authenticated", indicators

    def _calculate_auth_confidence(self, response, content: str,
                                 username: str, password: str) -> float:
        """Calculate confidence score for authentication success"""

        confidence = 0.70  # Base confidence

        # Response code bonus
        if response.status == 200:
            confidence += 0.20
        elif response.status == 302:
            confidence += 0.15

        # Content analysis bonus
        content_lower = content.lower()

        high_confidence_indicators = [
            "welcome", "dashboard", "logout", "admin panel", "control panel"
        ]

        medium_confidence_indicators = [
            "menu", "home", "settings", "configuration"
        ]

        for indicator in high_confidence_indicators:
            if indicator in content_lower:
                confidence += 0.10

        for indicator in medium_confidence_indicators:
            if indicator in content_lower:
                confidence += 0.05

        # Credential type bonus
        if password == "":  # Empty password is high impact
            confidence += 0.05
        elif username == "admin" and password in ["admin", "12345"]:
            confidence += 0.05

        return min(confidence, 0.98)

    def _generate_credential_results(self, successful_auths: List[CredentialMatch],
                                   target_ip: str, target_port: int) -> List[VulnerabilityResult]:
        """Generate vulnerability results for successful authentications"""

        results = []

        for auth in successful_auths:
            vuln_result = self.memory_pool.acquire_vulnerability_result()
            vuln_result.vulnerability_id = "enhanced-default-credentials"

            # Set severity based on access level
            if auth.access_level == "administrator":
                vuln_result.severity = "CRITICAL"
            elif auth.access_level == "user":
                vuln_result.severity = "HIGH"
            else:
                vuln_result.severity = "MEDIUM"

            vuln_result.confidence = auth.confidence
            vuln_result.description = f"Default credentials provide {auth.access_level} access: {auth.username}:{auth.password}"
            vuln_result.exploit_available = True

            results.append(vuln_result)

        return results
