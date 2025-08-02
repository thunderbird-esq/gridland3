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

    @property
    def metadata(self) -> dict:
        return {
            "name": "Enhanced Credential Scanner",
            "version": "2.0.0",
            "author": "GRIDLAND Security Team",
            "plugin_type": "vulnerability",
            "supported_services": ["http", "https"],
            "supported_ports": [80, 443, 8080, 8443, 8000, 8001, 8008, 8081],
            "description": "Intelligent credential testing with brand optimization and pattern recognition"
        }

    def __init__(self):
        super().__init__()
        self.credential_database = self._load_credential_database()
        self.memory_pool = get_memory_pool()
        self.tested_credentials = set()

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
        detected_brand = self._detect_brand(banner)
        credentials_to_test = self._get_optimized_credentials(detected_brand)
        successful_auths = await self._test_credentials_intelligently(
            target_ip, target_port, credentials_to_test, detected_brand
        )
        return self._generate_credential_results(successful_auths)

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
                logger.debug(f"Detected brand '{brand}' from banner.")
                return brand
        return None

    def _get_optimized_credentials(self, detected_brand: Optional[str]) -> List[Tuple[str, str]]:
        """Get optimized credential list based on detected brand"""
        credentials = []
        base_creds = self.credential_database.get("credentials", {})
        if detected_brand:
            brand_specific = self.credential_database.get("brand_specific", {}).get(detected_brand, {})
            accounts = brand_specific.get("common_accounts", [])
            passwords = brand_specific.get("common_passwords", [])
            for account in accounts:
                for password in passwords:
                    credentials.append((account, password))

        high_priority_combos = [
            ("admin", "admin"), ("admin", ""), ("admin", "12345"), ("admin", "123456"),
            ("admin", "password"), ("root", ""), ("root", "root"), ("user", ""),
            ("guest", ""), ("admin", "1234"), ("admin", "admin123")
        ]
        credentials.extend(high_priority_combos)

        for username, password_list in base_creds.items():
            for password in password_list:
                credentials.append((username, password))

        seen = set()
        unique_credentials = [c for c in credentials if not (c in seen or seen.add(c))]
        logger.info(f"Generated {len(unique_credentials)} unique credential combinations for testing.")
        return unique_credentials[:150]

    async def _test_credentials_intelligently(self, target_ip: str, target_port: int,
                                            credentials: List[Tuple[str, str]],
                                            detected_brand: Optional[str]) -> List[CredentialMatch]:
        """Test credentials with intelligent ordering and early termination"""
        successful_auths = []
        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        auth_endpoints = [
            "/", "/login", "/admin", "/cgi-bin/webproc", "/api/login",
            "/axis-cgi/admin/param.cgi", "/ISAPI/Security/sessionLogin",
            "/cgi-bin/magicBox.cgi", "/admin/login"
        ]

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                tasks = []
                for endpoint in auth_endpoints:
                    for username, password in credentials:
                        if len(successful_auths) >= 3: break
                        task = self._test_single_credential(session, base_url, endpoint, username, password)
                        tasks.append(task)

                results = await asyncio.gather(*tasks)
                for match in results:
                    if match:
                        successful_auths.append(match)

        except Exception as e:
            logger.debug(f"Credential testing session failed for {base_url}: {e}")

        return successful_auths

    async def _test_single_credential(self, session: aiohttp.ClientSession,
                                    base_url: str, endpoint: str,
                                    username: str, password: str) -> Optional[CredentialMatch]:
        """Test single credential combination for Basic Auth and Form Auth"""
        url = f"{base_url}{endpoint}"
        credential_key = f"{username}:{password}:{endpoint}"
        if credential_key in self.tested_credentials:
            return None
        self.tested_credentials.add(credential_key)

        try:
            # Test Basic Auth
            auth = aiohttp.BasicAuth(username, password)
            async with session.get(url, auth=auth, timeout=aiohttp.ClientTimeout(total=3)) as response:
                if response.status == 200:
                    content = await response.text()
                    access_level, indicators = self._analyze_authentication_response(content)
                    if access_level != "failed":
                        confidence = self._calculate_auth_confidence(response, content, username, password)
                        return CredentialMatch(username, password, endpoint, "basic_auth", access_level, indicators, confidence)

            # Test Form Auth
            if "login" in endpoint or endpoint == "/":
                 return await self._test_form_authentication(session, url, username, password)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"Credential test failed for {username}:{password} at {url}: {e}")
        return None

    async def _test_form_authentication(self, session: aiohttp.ClientSession,
                                      url: str, username: str, password: str) -> Optional[CredentialMatch]:
        """Test form-based authentication"""
        form_variants = [
            {"username": username, "password": password}, {"user": username, "pass": password},
            {"login": username, "passwd": password}, {"uid": username, "pwd": password},
        ]
        for form_data in form_variants:
            try:
                async with session.post(url, data=form_data, timeout=aiohttp.ClientTimeout(total=3)) as response:
                    if response.status in [200, 302]:
                        content = await response.text()
                        access_level, indicators = self._analyze_authentication_response(content)
                        if access_level != "failed":
                            confidence = self._calculate_auth_confidence(response, content, username, password)
                            return CredentialMatch(username, password, url, "form_auth", access_level, indicators, confidence)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Form auth test failed for {url} with data {form_data}: {e}")
        return None

    def _analyze_authentication_response(self, content: str) -> Tuple[str, List[str]]:
        """Analyze response to determine authentication success and access level"""
        content_lower = content.lower()
        indicators = []
        failure_patterns = ["login failed", "invalid", "incorrect", "unauthorized", "access denied"]
        if any(p in content_lower for p in failure_patterns):
            return "failed", ["failure pattern matched"]

        success_patterns = ["welcome", "dashboard", "logout", "control panel", "configuration", "settings"]
        if not any(p in content_lower for p in success_patterns):
            return "failed", ["no success pattern"]

        admin_patterns = ["administrator", "admin", "system config", "user management"]
        if any(p in content_lower for p in admin_patterns):
            return "administrator", ["admin pattern matched"]

        user_patterns = ["user", "viewer", "live view", "playback"]
        if any(p in content_lower for p in user_patterns):
            return "user", ["user pattern matched"]

        return "authenticated", ["generic success"]

    def _calculate_auth_confidence(self, response, content: str, username: str, password: str) -> float:
        """Calculate confidence score for authentication success"""
        confidence = 0.60
        if response.status == 200: confidence += 0.20
        if "welcome" in content.lower() or "dashboard" in content.lower(): confidence += 0.15
        if password == "" or username == password: confidence += 0.05
        return min(confidence, 0.98)

    def _generate_credential_results(self, successful_auths: List[CredentialMatch]) -> List[VulnerabilityResult]:
        """Generate vulnerability results for successful authentications"""
        results = []
        for auth in successful_auths:
            vuln_result = self.memory_pool.acquire_vulnerability_result()
            vuln_result.vulnerability_id = "enhanced-default-credentials"
            vuln_result.severity = "CRITICAL" if auth.access_level == "administrator" else "HIGH"
            vuln_result.confidence = auth.confidence
            vuln_result.description = f"Default credentials provide {auth.access_level} access: {auth.username}:{auth.password}"
            vuln_result.exploit_available = True
            vuln_result.details = {
                "username": auth.username, "password": auth.password, "endpoint": auth.endpoint,
                "authentication_method": auth.authentication_method, "access_level": auth.access_level,
                "response_indicators": auth.response_indicators
            }
            results.append(vuln_result)

        if results:
            logger.info(f"Found {len(results)} successful credential authentications.")
        return results
