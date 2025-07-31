"""
Axis Camera Vulnerability Scanner Plugin

Comprehensive vulnerability detection for Axis IP cameras including:
- Default credential detection
- Authentication bypass vulnerabilities
- VAPIX API exploitation
- Information disclosure vulnerabilities
- Firmware-specific exploits
"""

import asyncio
import aiohttp
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, quote

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class AxisScanner(VulnerabilityPlugin):
    """Professional Axis camera vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="Axis Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_ports=[80, 443, 8080, 8443],
            supported_services=["http", "https"],
            description="Comprehensive Axis camera vulnerability scanner"
        )
        self.memory_pool = get_memory_pool()
        self.session = None
        
        # Common Axis default credentials
        self.default_credentials = [
            ('root', 'pass'),
            ('admin', 'admin'),
            ('root', 'root'),
            ('axis', 'axis'),
            ('admin', 'password'),
            ('admin', ''),
            ('guest', 'guest'),
            ('user', 'user'),
            ('operator', 'operator'),
            ('viewer', 'viewer'),
        ]
        
        # Axis-specific URI paths
        self.test_paths = {
            'vapix': '/axis-cgi/param.cgi',
            'admin': '/axis-cgi/admin/param.cgi',
            'serverreport': '/axis-cgi/serverreport.cgi',
            'view': '/axis-cgi/view/param.cgi',
            'usergroup': '/axis-cgi/usergroup.cgi',
            'pwdgrp': '/axis-cgi/pwdgrp.cgi',
            'anonymous': '/axis-cgi/anonymous/param.cgi',
            'applications': '/axis-cgi/applications/',
            'basicdeviceinfo': '/axis-cgi/basicdeviceinfo.cgi',
            'jpg': '/axis-cgi/jpg/image.cgi',
            'mjpg': '/axis-cgi/mjpg/video.cgi',
        }
        
        # Known vulnerability signatures
        self.vulnerability_signatures = {
            'CVE-2018-10660': {
                'path': '/axis-cgi/param.cgi?action=list&group=root.Users.*.Name',
                'method': 'GET',
                'description': 'User enumeration via VAPIX parameter access',
                'severity': 'MEDIUM'
            },
            'CVE-2019-12473': {
                'path': '/axis-cgi/admin/systemlog.cgi?internal=yes',
                'method': 'GET',
                'description': 'Authentication bypass in system log access',
                'severity': 'HIGH'
            },
            'CVE-2022-31199': {
                'path': '/axis-cgi/applications/upload.cgi',
                'method': 'POST',
                'description': 'Application upload without proper authentication',
                'severity': 'HIGH'
            }
        }
        
        # VAPIX parameter groups to test
        self.vapix_test_groups = [
            'root.Brand',
            'root.Properties',
            'root.Users',
            'root.System',
            'root.Network',
            'root.StreamProfile',
            'root.Image',
            'root.Motion'
        ]
    
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
        Scan for Axis-specific vulnerabilities.
        
        Args:
            target_ip: Target IP address
            target_port: Target port
            service: Service type (http/https)
            banner: Service banner
            
        Returns:
            List of VulnerabilityResult objects
        """
        results = []
        
        # Only scan if this looks like an Axis device
        if not self._is_axis_device(banner):
            return results
        
        await self._init_session()
        
        try:
            base_url = f"{'https' if service == 'https' or target_port == 443 else 'http'}://{target_ip}:{target_port}"
            
            # Test for default credentials
            cred_vulns = await self._test_default_credentials(base_url, target_ip, target_port)
            results.extend(cred_vulns)
            
            # Test VAPIX API vulnerabilities
            vapix_vulns = await self._test_vapix_vulnerabilities(base_url, target_ip, target_port)
            results.extend(vapix_vulns)
            
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
            logger.warning(f"Error scanning Axis device {target_ip}:{target_port}: {e}")
        
        finally:
            await self._cleanup_session()
        
        return results
    
    def _is_axis_device(self, banner: str) -> bool:
        """Check if banner indicates Axis device."""
        axis_indicators = [
            'axis',
            'axis_video_server',
            'axis communications',
            'axisnetwork',
            'axis-network',
            'vapix',
            'acap',
            'ACAP',
            'AXIS',
            'Axis Video Server'
        ]
        
        banner_lower = banner.lower()
        return any(indicator.lower() in banner_lower for indicator in axis_indicators)
    
    async def _test_default_credentials(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for default credential vulnerabilities."""
        results = []
        
        for username, password in self.default_credentials:
            try:
                # Test VAPIX authentication
                vapix_success = await self._test_vapix_auth(base_url, username, password)
                if vapix_success:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = "AXIS-DEFAULT-CREDS"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.95
                    vuln.description = f"Default credentials found: {username}/{password}"
                    vuln.exploit_available = True
                    results.append(vuln)
                    break  # Found working creds, no need to test more
                
                # Test admin interface authentication
                admin_success = await self._test_admin_auth(base_url, username, password)
                if admin_success:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target_ip
                    vuln.port = target_port
                    vuln.service = "http"
                    vuln.vulnerability_id = "AXIS-ADMIN-DEFAULT-CREDS"
                    vuln.severity = "CRITICAL"
                    vuln.confidence = 0.95
                    vuln.description = f"Admin default credentials: {username}/{password}"
                    vuln.exploit_available = True
                    results.append(vuln)
                    break
                    
            except Exception as e:
                logger.debug(f"Credential test error for {username}/{password}: {e}")
                continue
        
        return results
    
    async def _test_vapix_auth(self, base_url: str, username: str, password: str) -> bool:
        """Test VAPIX authentication."""
        vapix_url = urljoin(base_url, '/axis-cgi/param.cgi?action=list&group=root.Brand')
        
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with self.session.get(vapix_url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check for VAPIX parameter response
                    return 'root.Brand' in content or 'Brand=' in content
                    
        except Exception:
            return False
        
        return False
    
    async def _test_admin_auth(self, base_url: str, username: str, password: str) -> bool:
        """Test admin interface authentication."""
        admin_url = urljoin(base_url, '/axis-cgi/admin/param.cgi?action=list&group=root.System')
        
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with self.session.get(admin_url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check for admin parameter response
                    return any(indicator in content for indicator in 
                              ['root.System', 'System=', 'SerialNumber', 'HardwareID'])
                    
        except Exception:
            return False
        
        return False
    
    async def _test_vapix_vulnerabilities(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for VAPIX API vulnerabilities."""
        results = []
        
        # Test unauthenticated VAPIX access
        for group in self.vapix_test_groups:
            try:
                vapix_url = urljoin(base_url, f'/axis-cgi/param.cgi?action=list&group={group}')
                async with self.session.get(vapix_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for sensitive parameter disclosure
                        sensitive_patterns = [
                            'user', 'password', 'network', 'system',
                            'serialnumber', 'hardwareid', 'root.'
                        ]
                        
                        if any(pattern in content.lower() for pattern in sensitive_patterns):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "AXIS-VAPIX-UNAUTH"
                            vuln.severity = "HIGH"
                            vuln.confidence = 0.85
                            vuln.description = f"Unauthenticated VAPIX access to {group}"
                            vuln.exploit_available = True
                            results.append(vuln)
                            break  # Only report once per device
                            
            except Exception as e:
                logger.debug(f"VAPIX test error for {group}: {e}")
                continue
        
        # Test for parameter injection
        injection_tests = [
            '/axis-cgi/param.cgi?action=list&group=root.Users.*',
            '/axis-cgi/param.cgi?action=list&group=root.Network.*',
            '/axis-cgi/param.cgi?action=list&group=root.System.*',
        ]
        
        for test_url in injection_tests:
            try:
                full_url = urljoin(base_url, test_url)
                async with self.session.get(full_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if 'root.' in content and ('=' in content or 'Name' in content):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "AXIS-VAPIX-INJECTION"
                            vuln.severity = "MEDIUM"
                            vuln.confidence = 0.75
                            vuln.description = "VAPIX parameter injection vulnerability"
                            vuln.exploit_available = True
                            results.append(vuln)
                            break
                            
            except Exception as e:
                logger.debug(f"VAPIX injection test error: {e}")
                continue
        
        return results
    
    async def _test_auth_bypass(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for authentication bypass vulnerabilities."""
        results = []
        
        bypass_tests = [
            # Anonymous access tests
            {
                'path': '/axis-cgi/anonymous/param.cgi?action=list&group=root.Brand',
                'vulnerability_id': 'AXIS-ANONYMOUS-ACCESS',
                'description': 'Anonymous VAPIX parameter access'
            },
            # Direct file access
            {
                'path': '/axis-cgi/jpg/image.cgi',
                'vulnerability_id': 'AXIS-IMAGE-BYPASS',
                'description': 'Unauthenticated image access'
            },
            # System report access
            {
                'path': '/axis-cgi/serverreport.cgi',
                'vulnerability_id': 'AXIS-SERVERREPORT-BYPASS',
                'description': 'Unauthenticated server report access'
            },
            # Basic device info
            {
                'path': '/axis-cgi/basicdeviceinfo.cgi',
                'vulnerability_id': 'AXIS-DEVICEINFO-BYPASS',
                'description': 'Unauthenticated device info access'
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
                            'brand', 'model', 'serialnumber', 'version',
                            'image', 'jpeg', 'root.', 'axis', 'server'
                        ]
                        
                        if any(indicator in content.lower() for indicator in bypass_indicators):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = test['vulnerability_id']
                            vuln.severity = "MEDIUM"
                            vuln.confidence = 0.80
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
                elif cve_data['method'] == 'POST':
                    # For POST requests, send minimal test payload
                    test_data = b'test=test'
                    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    async with self.session.post(test_url, data=test_data, headers=headers) as response:
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
            'CVE-2018-10660': ['root.users', 'name=', 'user'],
            'CVE-2019-12473': ['log', 'system', 'error'],
            'CVE-2022-31199': ['upload', 'application', 'acap']
        }
        
        indicators = cve_indicators.get(cve_id, [])
        return any(indicator in content.lower() for indicator in indicators)
    
    async def _test_info_disclosure(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for information disclosure vulnerabilities and perform fingerprinting."""
        results = []
        
        # This path provides the most comprehensive info
        fingerprint_path = '/axis-cgi/param.cgi?action=list&group=root.Properties'
        
        try:
            test_url = urljoin(base_url, fingerprint_path)
            async with self.session.get(test_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Attempt to parse for a detailed fingerprint
                    fingerprint_vuln = self._parse_vapix_properties(content, target_ip, target_port, fingerprint_path)
                    if fingerprint_vuln:
                        results.append(fingerprint_vuln)
                        # We got a great fingerprint, no need for further generic checks
                        return results

                    # Fallback to generic check if parsing fails
                    sensitive_patterns = [
                        'serialnumber', 'hardwareid', 'version', 'model',
                        'brand', 'macaddress', 'ipaddress', 'firmware',
                        'root.', 'axis'
                    ]
                    if any(pattern.lower() in content.lower() for pattern in sensitive_patterns):
                        vuln = self.memory_pool.acquire_vulnerability_result()
                        vuln.ip = target_ip
                        vuln.port = target_port
                        vuln.service = "http"
                        vuln.vulnerability_id = "AXIS-INFO-DISCLOSURE"
                        vuln.severity = "LOW"
                        vuln.confidence = 0.70
                        vuln.description = f"Information disclosure at {fingerprint_path}"
                        vuln.exploit_available = False
                        results.append(vuln)
                        
        except Exception as e:
            logger.debug(f"Info disclosure test error for {fingerprint_path}: {e}")
        
        return results

    def _parse_vapix_properties(self, content: str, ip: str, port: int, path: str) -> Optional[Any]:
        """Parse Axis VAPIX properties for a detailed fingerprint."""
        try:
            lines = content.strip().split('\n')
            props = dict(line.split('=') for line in lines if '=' in line)
            
            brand = props.get('root.Brand.Brand')
            model = props.get('root.Brand.ProdFullName')
            serial = props.get('root.Properties.System.SerialNumber')
            firmware = props.get('root.Properties.Firmware.Version')

            if brand or model or serial or firmware:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = ip
                vuln.port = port
                vuln.service = "http"
                vuln.vulnerability_id = "AXIS-FINGERPRINT"
                vuln.severity = "INFO"
                vuln.confidence = 0.98
                description = f"Axis device fingerprinted at {path}."
                if brand:
                    description += f" Brand: {brand}."
                if model:
                    description += f" Model: {model}."
                if serial:
                    description += f" Serial: {serial}."
                if firmware:
                    description += f" Firmware: {firmware}."
                vuln.description = description
                vuln.exploit_available = False
                return vuln
        except Exception as e:
            logger.debug(f"Could not parse Axis VAPIX properties: {e}")
        return None


# Plugin instance for automatic discovery
axis_scanner = AxisScanner()