"""
Hikvision Camera Vulnerability Scanner Plugin

Comprehensive vulnerability detection for Hikvision IP cameras including:
- Default credential detection
- Authentication bypass vulnerabilities
- Command injection flaws
- Directory traversal vulnerabilities
- Firmware-specific exploits
"""

import asyncio
import aiohttp
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class HikvisionScanner(VulnerabilityPlugin):
    """Professional Hikvision camera vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Hikvision Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_ports=[80, 443, 8080, 8000, 8443],
            supported_services=["http", "https"],
            description="Comprehensive Hikvision camera vulnerability scanner"
        )
        self.memory_pool = get_memory_pool()
        self.session = None
        
        # Common Hikvision default credentials
        self.default_credentials = [
            ('admin', 'admin'),
            ('admin', '12345'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('root', '12345'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('admin', 'admin123'),
            ('admin', 'hikadmin'),
        ]
        
        # Hikvision-specific URI paths for testing
        self.test_paths = {
            'web_interface': '/doc/page/login.asp',
            'api_login': '/ISAPI/Security/userCheck',
            'system_info': '/ISAPI/System/deviceInfo',
            'users_info': '/ISAPI/Security/users',
            'streaming': '/ISAPI/Streaming/channels',
            'config_export': '/ISAPI/System/configurationData',
            'logs': '/ISAPI/ContentMgmt/logSearch',
        }
        
        # Known vulnerability patterns
        self.vulnerability_signatures = {
            'CVE-2017-7921': {
                'path': '/System/configurationFile?auth=YWRtaW46MTEK',
                'method': 'GET',
                'description': 'Authentication bypass via malformed request',
                'severity': 'CRITICAL'
            },
            'CVE-2021-36260': {
                'path': '/SDK/webLanguage',
                'method': 'GET', 
                'description': 'Command injection in webLanguage endpoint',
                'severity': 'HIGH'
            },
            'CVE-2022-28219': {
                'path': '/ISAPI/System/Network/interfaces/1',
                'method': 'PUT',
                'description': 'Authentication bypass in network interface',
                'severity': 'HIGH'
            }
        }
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.metadata
    
    async def _init_session(self):
        """Initialize HTTP session if not already done."""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=False, limit=100)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'GRIDLAND Security Scanner v3.0'}
            )
    
    async def _cleanup_session(self):
        """Clean up HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def scan_vulnerabilities(self, target_ip: str, target_port: int, 
                                 service: str, banner: str) -> List[Any]:
        """
        Scan for Hikvision-specific vulnerabilities.
        
        Args:
            target_ip: Target IP address
            target_port: Target port
            service: Service type (http/https)
            banner: Service banner
            
        Returns:
            List of VulnerabilityResult objects
        """
        results = []
        
        # Only scan if this looks like a Hikvision device
        if not self._is_hikvision_device(banner):
            return results
        
        await self._init_session()
        
        try:
            base_url = f"{'https' if service == 'https' or target_port == 443 else 'http'}://{target_ip}:{target_port}"
            
            # Test for default credentials
            cred_vulns = await self._test_default_credentials(base_url, target_ip, target_port)
            results.extend(cred_vulns)
            
            # Test for authentication bypass vulnerabilities
            bypass_vulns = await self._test_auth_bypass(base_url, target_ip, target_port)
            results.extend(bypass_vulns)
            
            # Test for known CVE exploits
            cve_vulns = await self._test_known_cves(base_url, target_ip, target_port)
            results.extend(cve_vulns)
            
            # Test for information disclosure
            info_vulns = await self._test_info_disclosure(base_url, target_ip, target_port)
            results.extend(info_vulns)
            
        except Exception as e:
            logger.warning(f"Error scanning Hikvision device {target_ip}:{target_port}: {e}")
        
        finally:
            await self._cleanup_session()
        
        return results
    
    def _is_hikvision_device(self, banner: str) -> bool:
        """Check if banner indicates Hikvision device."""
        hikvision_indicators = [
            'hikvision',
            'webui/webclient',
            'ds-',  # Hikvision model prefix
            'nvr-',  # Network Video Recorder
            'ipcam',
            'HIKVISION',
            'Hikvision-Webs',
            'Hikvision-HTTP'
        ]
        
        banner_lower = banner.lower()
        return any(indicator.lower() in banner_lower for indicator in hikvision_indicators)
    
    async def _test_default_credentials(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for default credential vulnerabilities."""
        results = []
        
        for username, password in self.default_credentials:
            try:
                # Test web interface login
                login_success = await self._test_web_login(base_url, username, password)
                if login_success:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = "HIKVISION-DEFAULT-CREDS"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.95
                    vuln.description = f"Default credentials found: {username}/{password}"
                    vuln.exploit_available = True
                    results.append(vuln)
                    break  # Found working creds, no need to test more
                
                # Test ISAPI authentication
                api_success = await self._test_isapi_auth(base_url, username, password)
                if api_success:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = "HIKVISION-ISAPI-DEFAULT-CREDS"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.95
                    vuln.description = f"ISAPI default credentials: {username}/{password}"
                    vuln.exploit_available = True
                    results.append(vuln)
                    break
                    
            except Exception as e:
                logger.debug(f"Credential test error for {username}/{password}: {e}")
                continue
        
        return results
    
    async def _test_web_login(self, base_url: str, username: str, password: str) -> bool:
        """Test web interface authentication."""
        login_url = urljoin(base_url, '/doc/page/login.asp')
        
        try:
            # First, get the login page to check if it exists
            async with self.session.get(login_url) as response:
                if response.status != 200:
                    return False
            
            # Try digest authentication
            auth = aiohttp.BasicAuth(username, password)
            async with self.session.get(login_url, auth=auth) as response:
                # Success indicators: redirect, 200 with admin panel, etc.
                if response.status in [200, 302] and 'admin' in str(response.url).lower():
                    return True
                    
                content = await response.text()
                success_indicators = ['admin', 'logout', 'configuration', 'playback']
                return any(indicator in content.lower() for indicator in success_indicators)
                
        except Exception:
            return False
        
        return False
    
    async def _test_isapi_auth(self, base_url: str, username: str, password: str) -> bool:
        """Test ISAPI authentication."""
        isapi_url = urljoin(base_url, '/ISAPI/System/deviceInfo')
        
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with self.session.get(isapi_url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check for device info XML response
                    return '<DeviceInfo>' in content or 'deviceName' in content
                    
        except Exception:
            return False
        
        return False
    
    async def _test_auth_bypass(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for authentication bypass vulnerabilities."""
        results = []
        
        bypass_tests = [
            # CVE-2017-7921 style bypass
            {
                'path': '/System/configurationFile?auth=YWRtaW46MTEK',
                'vulnerability_id': 'CVE-2017-7921',
                'description': 'Authentication bypass via malformed auth parameter'
            },
            # Directory traversal attempts
            {
                'path': '/ISAPI/../../../etc/passwd',
                'vulnerability_id': 'HIKVISION-DIR-TRAVERSAL',
                'description': 'Directory traversal vulnerability'
            },
            # Configuration file access
            {
                'path': '/ISAPI/System/configurationData',
                'vulnerability_id': 'HIKVISION-CONFIG-EXPOSURE',
                'description': 'Unauthenticated configuration file access'
            }
        ]
        
        for test in bypass_tests:
            try:
                test_url = urljoin(base_url, test['path'])
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for successful bypass indicators
                        bypass_indicators = [
                            'configuration', 'password', 'admin', 'root:',
                            '<DeviceInfo>', 'deviceName', 'serialNumber'
                        ]
                        
                        if any(indicator in content.lower() for indicator in bypass_indicators):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = test['vulnerability_id']
                            vuln.severity = "HIGH"
                            vuln.confidence = 0.85
                            vuln.description = test['description']
                            vuln.exploit_available = True
                            results.append(vuln)
                            
            except Exception as e:
                logger.debug(f"Auth bypass test error for {test['path']}: {e}")
                continue
        
        return results
    
    async def _test_known_cves(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for known CVE vulnerabilities."""
        results = []
        
        for cve_id, cve_data in self.vulnerability_signatures.items():
            try:
                test_url = urljoin(base_url, cve_data['path'])
                
                if cve_data['method'] == 'GET':
                    async with self.session.get(test_url) as response:
                        vulnerable = await self._check_cve_response(response, cve_id)
                elif cve_data['method'] == 'PUT':
                    # For PUT requests, send minimal test payload
                    test_data = '{"test": "value"}'
                    async with self.session.put(test_url, data=test_data) as response:
                        vulnerable = await self._check_cve_response(response, cve_id)
                else:
                    continue
                
                if vulnerable:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = cve_id
                    vuln.severity = cve_data['severity']
                    vuln.confidence = 0.80
                    vuln.description = cve_data['description']
                    vuln.exploit_available = True
                    results.append(vuln)
                    
            except Exception as e:
                logger.debug(f"CVE test error for {cve_id}: {e}")
                continue
        
        return results
    
    async def _check_cve_response(self, response, cve_id: str) -> bool:
        """Check if response indicates vulnerability."""
        if response.status not in [200, 500]:
            return False
        
        content = await response.text()
        
        # CVE-specific indicators
        cve_indicators = {
            'CVE-2017-7921': ['configuration', 'users', 'password'],
            'CVE-2021-36260': ['error', 'command', 'injection'],
            'CVE-2022-28219': ['network', 'interface', 'configuration']
        }
        
        indicators = cve_indicators.get(cve_id, [])
        return any(indicator in content.lower() for indicator in indicators)
    
    async def _test_info_disclosure(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for information disclosure vulnerabilities and perform fingerprinting."""
        results = []
        
        # Endpoints for fingerprinting and info disclosure
        info_paths = {
            '/ISAPI/System/deviceInfo': self._parse_device_info_xml,
            '/System/configurationFile?auth=YWRtaW46MTEK': self._parse_config_file_xml,
            '/ISAPI/Security/users': None, # Generic check
            '/doc/script/common.js': None, # Generic check
        }
        
        for path, parser in info_paths.items():
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Use specific parser if available for fingerprinting
                        if parser:
                            fingerprint_vuln = parser(content, target_ip, target_port, path)
                            if fingerprint_vuln:
                                results.append(fingerprint_vuln)
                                # If we get a good fingerprint, we can stop checking other info paths
                                return results

                        # Generic check for sensitive information
                        sensitive_patterns = [
                            'password', 'username', 'admin', 'configuration',
                            'serialNumber', 'deviceName', 'macAddress',
                            'ipAddress', 'version', 'firmware'
                        ]
                        
                        if any(pattern.lower() in content.lower() for pattern in sensitive_patterns):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "HIKVISION-INFO-DISCLOSURE"
                            vuln.severity = "MEDIUM"
                            vuln.confidence = 0.70
                            vuln.description = f"Potential information disclosure at {path}"
                            vuln.exploit_available = False
                            results.append(vuln)
                            # Don't return here, keep checking other paths
                            
            except Exception as e:
                logger.debug(f"Info disclosure test error for {path}: {e}")
                continue
        
        return results

    def _parse_device_info_xml(self, xml_content: str, ip: str, port: int, path: str) -> Optional[Any]:
        """Parse deviceInfo XML for model and firmware."""
        try:
            from xml.etree import ElementTree as ET
            root = ET.fromstring(xml_content)
            model = root.findtext('.//model')
            firmware = root.findtext('.//firmwareVersion')
            
            if model or firmware:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = ip
                vuln.port = port
                vuln.service = "http"
                vuln.vulnerability_id = "HIKVISION-FINGERPRINT"
                vuln.severity = "INFO"
                vuln.confidence = 0.98
                description = f"Hikvision device fingerprinted at {path}."
                if model:
                    description += f" Model: {model}."
                if firmware:
                    description += f" Firmware: {firmware}."
                vuln.description = description
                vuln.exploit_available = False
                return vuln
        except Exception as e:
            logger.debug(f"Could not parse Hikvision deviceInfo XML: {e}")
        return None

    def _parse_config_file_xml(self, xml_content: str, ip: str, port: int, path: str) -> Optional[Any]:
        """Parse configurationFile XML for model and firmware."""
        # This is often the same structure as deviceInfo
        return self._parse_device_info_xml(xml_content, ip, port, path)


# Plugin instance for automatic discovery
hikvision_scanner = HikvisionScanner()