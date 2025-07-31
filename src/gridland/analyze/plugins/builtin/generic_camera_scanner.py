"""
Generic Camera Vulnerability Scanner Plugin

Universal vulnerability detection for IP cameras of any brand including:
- Default credential detection (comprehensive list)
- Common authentication bypass vulnerabilities
- Universal information disclosure tests
- Generic camera exploit patterns
- Web interface vulnerability assessment
"""

import asyncio
import aiohttp
import base64
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin

from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.analyze.memory import get_memory_pool
from gridland.core.logger import get_logger
from gridland.core.config import get_config

logger = get_logger(__name__)


class GenericCameraScanner(VulnerabilityPlugin):
    """Universal camera vulnerability scanner for any brand."""
    
    def __init__(self):
        super().__init__()
        self.memory_pool = get_memory_pool()
        self.session = None
        self.default_credentials = self._load_default_credentials()
        
        # Universal camera web interface paths, enhanced with CamXploit data
        self.common_paths = {
            'login': [
                # Original paths
                '/login.html', '/login.htm', '/login.php', '/login.asp', '/login.jsp',
                '/index.html', '/index.htm', '/default.htm', '/main.htm',
                '/admin/login.html', '/admin/index.html', '/admin.html',
                '/cgi-bin/login.cgi', '/web/login.html', '/ui/login.html',
                # From CamXploit
                '/', '/admin', '/login', '/viewer', '/webadmin'
            ],
            'config': [
                '/config.html', '/configuration.html', '/settings.html',
                '/system.html', '/admin.html', '/management.html',
                '/cgi-bin/config.cgi', '/cgi-bin/admin.cgi',
                # From CamXploit
                '/system.ini', '/config', '/setup'
            ],
            'info': [
                '/info.html', '/device.html', '/status.html', '/about.html',
                '/cgi-bin/info.cgi', '/cgi-bin/status.cgi', '/cgi-bin/device.cgi'
            ],
            'video': [
                '/video.html', '/live.html', '/viewer.html', '/stream.html',
                '/cgi-bin/video.cgi', '/cgi-bin/live.cgi', '/cgi-bin/stream.cgi',
                # From CamXploit
                '/video', '/stream', '/live', '/snapshot'
            ],
            'api': [
                '/api/', '/cgi-bin/', '/onvif-http/snapshot', '/img/main.cgi'
            ]
        }
        
        # Common camera vulnerability patterns
        self.vulnerability_patterns = {
            'info_disclosure': [
                r'serial.*?number',
                r'mac.*?address',
                r'ip.*?address',
                r'firmware.*?version',
                r'model.*?number',
                r'device.*?name',
                r'admin.*?password',
                r'configuration.*?backup',
                r'system.*?log'
            ],
            'auth_bypass': [
                '/admin/index.html',
                '/cgi-bin/admin.cgi',
                '/config/export',
                '/backup.bin',
                '/config.xml',
                '/system.xml'
            ],
            'directory_traversal': [
                '/../../../etc/passwd',
                '/../../../etc/shadow',
                '/../../../etc/config',
                '/..%2F..%2F..%2Fetc%2Fpasswd',
                '/....//....//....//etc/passwd'
            ]
        }
        
        # HTTP response indicators for successful access
        self.success_indicators = [
            'admin', 'configuration', 'settings', 'management',
            'video', 'camera', 'live', 'stream', 'device',
            'logout', 'password', 'user', 'system'
        ]

    def _load_default_credentials(self) -> List[Tuple[str, str]]:
        """Load default credentials from the centralized JSON file."""
        creds_list = []
        try:
            # Assuming the script runs from the project root or the path is relative to it
            creds_path = Path(__file__).parent.parent.parent.parent / 'data' / 'default_credentials.json'
            with open(creds_path, 'r') as f:
                data = json.load(f)
                creds_dict = data.get("credentials", {})
                for username, passwords in creds_dict.items():
                    for password in passwords:
                        creds_list.append((username, password))
            logger.info(f"Successfully loaded {len(creds_list)} default credentials.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load default credentials: {e}. Falling back to a minimal set.")
            # Fallback to a minimal list in case of file errors
            return [('admin', 'admin'), ('admin', 'password')]
        return creds_list
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="Generic Camera Scanner",
            version="1.0.2",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_ports=[80, 443, 8080, 8000, 8443, 8888, 9000],
            supported_services=["http", "https"],
            description="Universal camera vulnerability scanner for all brands"
        )
    
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
        Scan for generic camera vulnerabilities.
        
        Args:
            target_ip: Target IP address
            target_port: Target port
            service: Service type (http/https)
            banner: Service banner
            
        Returns:
            List of VulnerabilityResult objects
        """
        results = []
        await self._init_session()
        
        try:
            base_url = f"{'https' if service == 'https' or target_port == 443 else 'http'}://{target_ip}:{target_port}"
            
            # Perform intelligent interface identification
            is_camera, response_text = await self._identify_camera_interface(base_url, banner)
            if not is_camera:
                return results
            
            # Discover and report login pages
            login_page_vulns = await self._discover_and_report_login_pages(base_url, target_ip, target_port)
            results.extend(login_page_vulns)

            # Test for default credentials
            cred_vulns = await self._test_default_credentials(base_url, target_ip, target_port)
            results.extend(cred_vulns)
            
            # Test for authentication bypass vulnerabilities
            bypass_vulns = await self._test_auth_bypass(base_url, target_ip, target_port)
            results.extend(bypass_vulns)
            
            # Test for information disclosure
            info_vulns = await self._test_info_disclosure(base_url, target_ip, target_port)
            results.extend(info_vulns)
            
            # Test for directory traversal
            traversal_vulns = await self._test_directory_traversal(base_url, target_ip, target_port)
            results.extend(traversal_vulns)
            
            # Test for weak configurations
            config_vulns = await self._test_weak_configurations(base_url, target_ip, target_port)
            results.extend(config_vulns)

            # Test for common unprotected paths from CamXploit
            unprotected_path_vulns = await self._test_unprotected_paths(base_url, target_ip, target_port)
            results.extend(unprotected_path_vulns)
            
        except Exception as e:
            logger.warning(f"Error scanning generic camera {target_ip}:{target_port}: {e}")
        
        finally:
            await self._cleanup_session()
        
        return results
    
    async def _identify_camera_interface(self, base_url: str, banner: str) -> Tuple[bool, str]:
        """
        Intelligently determine if a web interface belongs to a camera.
        
        This method combines banner checking with analysis of page content,
        title, and headers for a more accurate identification.
        """
        # First, do a quick check on the banner
        banner_indicators = [
            'camera', 'ipcam', 'webcam', 'cctv', 'nvr', 'dvr', 'video', 'stream', 
            'surveillance', 'security', 'hikvision', 'dahua', 'axis'
        ]
        if any(indicator in banner.lower() for indicator in banner_indicators):
            return True, ""

        # If banner is inconclusive, perform a GET request for deeper analysis
        try:
            async with self.session.get(base_url) as response:
                # 1. Check Content-Type header
                content_type = response.headers.get('Content-Type', '').lower()
                if any(ct in content_type for ct in ['image/jpeg', 'video/mpeg', 'video/x-mjpeg']):
                    return True, ""

                # 2. Analyze HTML content
                if 'text/html' in content_type:
                    content = await response.text()
                    content_lower = content.lower()

                    # 2a. Check HTML Title
                    title_match = re.search(r'<title>(.*?)</title>', content_lower)
                    if title_match:
                        title = title_match.group(1)
                        if any(kw in title for kw in ['camera', 'webcam', 'dvr', 'nvr', 'surveillance']):
                            return True, content

                    # 2b. Check HTML Body for keywords
                    body_keywords = ['camera', 'live view', 'ptz', 'pan-tilt-zoom', 'ip camera']
                    if any(kw in content_lower for kw in body_keywords):
                        return True, content
                
                return False, await response.text()

        except Exception as e:
            logger.debug(f"Could not identify camera interface at {base_url}: {e}")
            return False, ""
    
    async def _test_default_credentials(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for default credential vulnerabilities."""
        results = []
        
        # Find login endpoints first
        login_endpoints = await self._discover_login_endpoints(base_url)
        
        for endpoint in login_endpoints:
            for username, password in self.default_credentials:
                try:
                    # Test HTTP Basic Authentication
                    basic_success = await self._test_basic_auth(urljoin(base_url, endpoint), username, password)
                    if basic_success:
                        vuln = self.memory_pool.acquire_vulnerability_result()
                        vuln.ip = target_ip
                        vuln.port = target_port
                        vuln.service = "http"
                        vuln.vulnerability_id = "GENERIC-CAMERA-DEFAULT-CREDS"
                        vuln.severity = "CRITICAL"
                        vuln.confidence = 0.90
                        vuln.description = f"Default credentials found: {username}/{password} at {endpoint}"
                        vuln.exploit_available = True
                        results.append(vuln)
                        return results  # Found working creds, stop testing
                    
                    # Test form-based authentication
                    form_success = await self._test_form_auth(urljoin(base_url, endpoint), username, password)
                    if form_success:
                        vuln = self.memory_pool.acquire_vulnerability_result()
                        vuln.ip = target_ip
                        vuln.port = target_port
                        vuln.service = "http"
                        vuln.vulnerability_id = "GENERIC-CAMERA-FORM-DEFAULT-CREDS"
                        vuln.severity = "CRITICAL"
                        vuln.confidence = 0.90
                        vuln.description = f"Form-based default credentials: {username}/{password} at {endpoint}"
                        vuln.exploit_available = True
                        results.append(vuln)
                        return results
                        
                except Exception as e:
                    logger.debug(f"Credential test error for {username}/{password}: {e}")
                    continue
        
        return results
    
    async def _discover_login_endpoints(self, base_url: str) -> List[str]:
        """Discover potential login endpoints."""
        endpoints = []
        
        # Test common login paths
        for path in self.common_paths['login']:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Check if it looks like a login page
                        login_indicators = ['login', 'password', 'username', 'admin', 'signin']
                        if any(indicator in content.lower() for indicator in login_indicators):
                            endpoints.append(path)
                            
            except Exception as e:
                logger.debug(f"Login endpoint discovery error for {path}: {e}")
                continue
        
        # If no specific login pages found, test root
        if not endpoints:
            endpoints.append('/')
        
        return endpoints
    
    async def _test_basic_auth(self, url: str, username: str, password: str) -> bool:
        """Test HTTP Basic Authentication."""
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check for successful access indicators
                    return any(indicator in content.lower() for indicator in self.success_indicators)
                    
        except Exception:
            return False
        
        return False
    
    async def _test_form_auth(self, url: str, username: str, password: str) -> bool:
        """Test form-based authentication."""
        try:
            # First, get the login page to find form fields
            async with self.session.get(url) as response:
                if response.status != 200:
                    return False
                
                content = await response.text()
                
                # Extract form action and method
                form_action = self._extract_form_action(content, url)
                if not form_action:
                    return False
                
                # Try different common field names
                field_combinations = [
                    {'username': username, 'password': password},
                    {'user': username, 'pass': password},
                    {'admin': username, 'pwd': password},
                    {'login': username, 'passwd': password},
                    {'name': username, 'password': password},
                    {'userid': username, 'userpwd': password},
                ]
                
                for fields in field_combinations:
                    try:
                        async with self.session.post(form_action, data=fields) as login_response:
                            if login_response.status in [200, 302]:
                                # Check for successful login indicators
                                if login_response.status == 302:
                                    # Redirect might indicate success
                                    location = login_response.headers.get('location', '')
                                    if any(indicator in location.lower() for indicator in 
                                          ['admin', 'main', 'home', 'dashboard', 'index']):
                                        return True
                                else:
                                    login_content = await login_response.text()
                                    if any(indicator in login_content.lower() for indicator in self.success_indicators):
                                        return True
                                        
                    except Exception:
                        continue
                        
        except Exception:
            return False
        
        return False
    
    def _extract_form_action(self, html_content: str, base_url: str) -> Optional[str]:
        """Extract form action URL from HTML content."""
        try:
            # Look for form tag with action
            form_match = re.search(r'<form[^>]*action=["\\]([^"\\]*)["\\]', html_content, re.IGNORECASE)
            if form_match:
                action = form_match.group(1)
                if action.startswith('http'):
                    return action
                else:
                    return urljoin(base_url, action)
            
            # If no action found, submit to same page
            return base_url
            
        except Exception:
            return base_url
    
    async def _test_auth_bypass(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for authentication bypass vulnerabilities."""
        results = []
        
        for path in self.vulnerability_patterns['auth_bypass']:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for successful bypass indicators
                        bypass_indicators = [
                            'configuration', 'settings', 'admin', 'password',
                            'backup', 'export', 'system', 'device'
                        ]
                        
                        if any(indicator in content.lower() for indicator in bypass_indicators):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "GENERIC-CAMERA-AUTH-BYPASS"
                            vuln.severity = "HIGH"
                            vuln.confidence = 0.80
                            vuln.description = f"Authentication bypass at {path}"
                            vuln.exploit_available = True
                            results.append(vuln)
                            
            except Exception as e:
                logger.debug(f"Auth bypass test error for {path}: {e}")
                continue
        
        return results
    
    async def _test_info_disclosure(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for information disclosure vulnerabilities."""
        results = []
        
        for path in self.common_paths['info']:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for sensitive information patterns
                        for pattern in self.vulnerability_patterns['info_disclosure']:
                            if re.search(pattern, content, re.IGNORECASE):
                                vuln = self.memory_pool.acquire_vulnerability_result()
                                vuln.ip = target_ip
                                vuln.port = target_port
                                vuln.service = "http"
                                vuln.vulnerability_id = "GENERIC-CAMERA-INFO-DISCLOSURE"
                                vuln.severity = "MEDIUM"
                                vuln.confidence = 0.75
                                vuln.description = f"Information disclosure at {path}"
                                vuln.exploit_available = False
                                results.append(vuln)
                                break
                                
            except Exception as e:
                logger.debug(f"Info disclosure test error for {path}: {e}")
                continue
        
        return results
    
    async def _test_directory_traversal(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for directory traversal vulnerabilities."""
        results = []
        
        for traversal_path in self.vulnerability_patterns['directory_traversal']:
            try:
                test_url = urljoin(base_url, traversal_path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for typical Unix/Linux file contents
                        unix_indicators = ['root:', 'bin:', 'daemon:', '/bin/sh', '/etc/']
                        if any(indicator in content for indicator in unix_indicators):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "GENERIC-CAMERA-DIR-TRAVERSAL"
                            vuln.severity = "HIGH"
                            vuln.confidence = 0.85
                            vuln.description = f"Directory traversal vulnerability: {traversal_path}"
                            vuln.exploit_available = True
                            results.append(vuln)
                            break
                            
            except Exception as e:
                logger.debug(f"Directory traversal test error for {traversal_path}: {e}")
                continue
        
        return results
    
    async def _test_weak_configurations(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for weak security configurations."""
        results = []
        
        # Test for unprotected configuration endpoints
        weak_endpoints = [
            '/cgi-bin/',
            '/admin/',
            '/config/',
            '/backup/',
            '/logs/',
            '/upload/',
            '/download/'
        ]
        
        for endpoint in weak_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for directory listing or sensitive content
                        weak_indicators = [
                            'index of', 'parent directory', 'directory listing',
                            'config', 'backup', 'log', 'admin', 'upload'
                        ]
                        
                        if any(indicator in content.lower() for indicator in weak_indicators):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "GENERIC-CAMERA-WEAK-CONFIG"
                            vuln.severity = "MEDIUM"
                            vuln.confidence = 0.70
                            vuln.description = f"Weak configuration exposure at {endpoint}"
                            vuln.exploit_available = False
                            results.append(vuln)
                            
            except Exception as e:
                logger.debug(f"Weak config test error for {endpoint}: {e}")
                continue
        
        return results

    async def _test_unprotected_paths(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Test for common unprotected paths found in CamXploit."""
        results = []
        all_paths = set(
            self.common_paths['login'] +
            self.common_paths['config'] +
            self.common_paths['video'] +
            self.common_paths['api']
        )

        for path in all_paths:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.head(test_url, allow_redirects=True) as response:
                    # 200 OK suggests the path exists and is accessible
                    if response.status == 200:
                        vuln = self.memory_pool.acquire_vulnerability_result()
                        vuln.ip = target_ip
                        vuln.port = target_port
                        vuln.service = "http"
                        vuln.vulnerability_id = "GENERIC-UNPROTECTED-PATH"
                        vuln.severity = "LOW"
                        vuln.confidence = 0.60
                        vuln.description = f"Publicly accessible, common camera path found: {path}"
                        vuln.exploit_available = False
                        results.append(vuln)

            except Exception as e:
                logger.debug(f"Unprotected path test error for {path}: {e}")
                continue
        
        return results


    async def get_screenshot(self, url: str, output_dir: str, target_ip: str, target_port: int) -> str | None:
        """
        Takes a screenshot of a given URL using pyppeteer and saves it to a specified directory.
        """
        import pyppeteer
        from pyppeteer.errors import PageError, TimeoutError
        import os
        import time

        browser = None
        try:
            # Ensure the output directory exists
            os.makedirs(output_dir, exist_ok=True)

            filename = f"{target_ip.replace('.', '_')}_{target_port}_{int(time.time())}.png"
            file_path = os.path.join(output_dir, filename)

            browser = await pyppeteer.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            page = await browser.newPage()

            await page.goto(url, {'waitUntil': 'networkidle0', 'timeout': 10000})
            await page.screenshot({'path': file_path})

            await browser.close()

            logger.info(f"Screenshot saved to {file_path}")
            return file_path

        except (PageError, TimeoutError, IOError) as e:
            logger.error(f"Could not take screenshot of {url}. Reason: {e}")
            if browser and browser.process is not None:
                await browser.close()
            return None

    async def _discover_and_report_login_pages(self, base_url: str, target_ip: str, target_port: int) -> List[Any]:
        """Discover potential login endpoints and report them as INFO vulnerabilities."""
        results = []
        config = get_config()
        screenshot_dir = config.output.get('screenshots', 'screenshots')

        # Test common login paths
        for path in self.common_paths['login']:
            try:
                test_url = urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Check if it looks like a login page
                        login_indicators = ['login', 'password', 'username', 'admin', 'signin']
                        if any(indicator in content.lower() for indicator in login_indicators):
                            vuln = self.memory_pool.acquire_vulnerability_result()
                            vuln.ip = target_ip
                            vuln.port = target_port
                            vuln.service = "http"
                            vuln.vulnerability_id = "LOGIN-PAGE-DISCOVERED"
                            vuln.severity = "INFO"
                            vuln.confidence = 0.80
                            vuln.description = f"Web login page discovered at: {test_url}"
                            vuln.exploit_available = False

                            # Take screenshot
                            screenshot_path = await self.get_screenshot(test_url, screenshot_dir, target_ip, target_port)

                            # Add metadata for the screenshot plugin
                            vuln.metadata = {'login_url': test_url, 'screenshot_path': screenshot_path}
                            results.append(vuln)
            except Exception as e:
                logger.debug(f"Login page discovery error for {path}: {e}")
                continue
        return results


# Plugin instance for automatic discovery
generic_camera_scanner = GenericCameraScanner()