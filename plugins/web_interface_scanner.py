"""
Web Interface Scanner Plugin for Gridland
Hidden admin panel discovery and web interface enumeration
"""
import requests
from typing import List, Dict, Set
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget


class WebInterfaceScannerPlugin(ScannerPlugin):
    """
    Web interface and admin panel discovery scanner.
    Enumerates hidden directories, admin panels, and debug interfaces.
    """
    
    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has web ports for interface scanning"""
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]
        return any(p.port in web_ports for p in target.open_ports)

    # Common admin panel and management interface paths
    ADMIN_PATHS = [
        # Generic admin panels
        "/admin", "/admin/", "/admin.html", "/admin.php", "/admin.asp", "/admin.aspx",
        "/administrator", "/administrator/", "/administration", "/management",
        "/manager", "/console", "/control", "/cp", "/panel",
        
        # Camera-specific admin interfaces
        "/home.html", "/main.html", "/index.html", "/login.html", "/auth.html",
        "/setup.html", "/config.html", "/settings.html", "/system.html",
        "/network.html", "/security.html", "/users.html", "/maintenance.html",
        
        # Brand-specific paths
        "/ISAPI/", "/ISAPI/System/", "/ISAPI/Security/",  # Hikvision
        "/dms/", "/RPC2", "/RPC2_Login",  # Dahua
        "/axis-cgi/", "/axis-cgi/admin/", "/axis-cgi/operator/",  # Axis
        "/sony/", "/sony/admin", "/sony/config",  # Sony
        "/panasonic/", "/panasonic/admin", "/panasonic/config",  # Panasonic
        "/bosch/", "/bosch/admin",  # Bosch
        "/pelco/", "/pelco/admin",  # Pelco
        
        # DVR/NVR interfaces
        "/dvr/", "/nvr/", "/recorder/", "/surveillance/", "/monitor/",
        "/video/", "/camera/", "/stream/", "/live/", "/view/",
        
        # Debug and development interfaces
        "/debug/", "/test/", "/dev/", "/development/", "/staging/",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.html",
        "/server-status", "/server-info", "/status", "/health",
        
        # Configuration and backup paths
        "/config/", "/configuration/", "/settings/", "/backup/",
        "/export/", "/import/", "/restore/", "/update/", "/upgrade/",
        
        # API endpoints
        "/api/", "/api/v1/", "/api/v2/", "/rest/", "/restapi/",
        "/json/", "/xml/", "/soap/", "/wsdl/", "/rpc/",
        
        # File managers and editors
        "/filemanager/", "/files/", "/upload/", "/downloads/",
        "/editor/", "/ide/", "/phpmyadmin/", "/adminer/",
        
        # Monitoring and statistics
        "/stats/", "/statistics/", "/metrics/", "/analytics/",
        "/logs/", "/log/", "/logging/", "/reports/", "/report/"
    ]

    # Paths that may expose sensitive information
    SENSITIVE_PATHS = [
        # Configuration files
        "/config.xml", "/config.json", "/config.php", "/configuration.xml",
        "/settings.xml", "/settings.json", "/app.config", "/web.config",
        
        # Backup files
        "/backup.sql", "/backup.zip", "/backup.tar.gz", "/config.bak",
        "/settings.bak", "/database.bak", "/dump.sql", "/export.sql",
        
        # Log files
        "/error.log", "/access.log", "/debug.log", "/system.log",
        "/application.log", "/security.log", "/audit.log",
        
        # Database files
        "/database.db", "/data.db", "/sqlite.db", "/users.db",
        "/passwords.txt", "/users.txt", "/accounts.txt",
        
        # Documentation and help files
        "/readme.txt", "/README", "/INSTALL", "/CHANGELOG",
        "/manual.pdf", "/help.html", "/documentation/",
        
        # Version and build information
        "/version.txt", "/VERSION", "/build.txt", "/release.txt",
        "/git.txt", "/svn.txt", "/version.php", "/build.xml"
    ]

    # Directory listing indicators
    DIRECTORY_LISTING_INDICATORS = [
        "index of", "directory listing", "[dir]", "parent directory",
        "<title>index of", "apache/", "nginx/", "iis/", "lighttpd/"
    ]

    # Admin panel indicators
    ADMIN_INDICATORS = [
        "administration", "control panel", "management", "dashboard",
        "login", "password", "username", "sign in", "authentication",
        "admin panel", "administrator", "configuration", "settings"
    ]

    def scan(self, target: ScanTarget, progress_callback=None) -> List[Finding]:
        """Perform web interface and admin panel discovery"""
        findings = []
        
        for port_result in target.open_ports:
            if port_result.port not in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]:
                continue
                
            protocol = "https" if port_result.port in [443, 8443] else "http"
            base_url = f"{protocol}://{target.ip}:{port_result.port}"
            
            # Scan for admin panels and management interfaces
            findings.extend(self._scan_admin_interfaces(base_url, port_result.port))
            
            # Scan for sensitive file exposure
            findings.extend(self._scan_sensitive_files(base_url, port_result.port))
            
            # Check for directory listing vulnerabilities
            findings.extend(self._scan_directory_listings(base_url, port_result.port))
        
        return findings

    def _scan_admin_interfaces(self, base_url: str, port: int) -> List[Finding]:
        """Scan for admin panels and management interfaces"""
        findings = []
        
        for path in self.ADMIN_PATHS:
            try:
                url = f"{base_url}{path}"
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 Web Scanner'}
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for admin panel indicators
                    is_admin = any(indicator in content for indicator in self.ADMIN_INDICATORS)
                    
                    if is_admin:
                        # Determine interface type
                        interface_type = self._identify_interface_type(content, path)
                        
                        finding = Finding(
                            category="web_interface",
                            description=f"Admin interface found: {interface_type}",
                            severity="medium",
                            port=port,
                            url=url,
                            data={
                                "interface_type": interface_type,
                                "path": path,
                                "requires_auth": "password" in content or "login" in content,
                                "status_code": response.status_code
                            }
                        )
                        findings.append(finding)
                
                # Check for authentication bypass (200 when expecting 401/403)
                elif response.status_code in [401, 403]:
                    finding = Finding(
                        category="web_interface",
                        description=f"Protected admin interface found: {path}",
                        severity="low",
                        port=port,
                        url=url,
                        data={
                            "path": path,
                            "status_code": response.status_code,
                            "auth_required": True
                        }
                    )
                    findings.append(finding)
                    
            except requests.RequestException:
                continue
                
        return findings

    def _scan_sensitive_files(self, base_url: str, port: int) -> List[Finding]:
        """Scan for exposed sensitive files and configurations"""
        findings = []
        
        for path in self.SENSITIVE_PATHS:
            try:
                url = f"{base_url}{path}"
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 Web Scanner'}
                )
                
                if response.status_code == 200 and len(response.content) > 0:
                    content = response.text
                    
                    # Analyze content for sensitivity
                    sensitivity_score = self._analyze_content_sensitivity(content, path)
                    
                    if sensitivity_score > 0:
                        severity = "high" if sensitivity_score >= 3 else "medium"
                        
                        finding = Finding(
                            category="information_disclosure",
                            description=f"Sensitive file exposed: {path}",
                            severity=severity,
                            port=port,
                            url=url,
                            data={
                                "file_type": self._get_file_type(path),
                                "content_size": len(content),
                                "sensitivity_score": sensitivity_score,
                                "content_preview": content[:200] if len(content) > 200 else content
                            }
                        )
                        findings.append(finding)
                        
            except requests.RequestException:
                continue
                
        return findings

    def _scan_directory_listings(self, base_url: str, port: int) -> List[Finding]:
        """Scan for directory listing vulnerabilities"""
        findings = []
        
        # Common directories that might have listings enabled
        directories = [
            "/", "/admin/", "/config/", "/backup/", "/uploads/", "/files/",
            "/logs/", "/temp/", "/tmp/", "/cache/", "/data/", "/docs/",
            "/images/", "/css/", "/js/", "/scripts/", "/includes/", "/lib/"
        ]
        
        for directory in directories:
            try:
                url = f"{base_url}{directory}"
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 Web Scanner'}
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for directory listing indicators
                    is_listing = any(indicator in content for indicator in self.DIRECTORY_LISTING_INDICATORS)
                    
                    if is_listing:
                        # Count visible files/directories
                        file_count = content.count('<a href=')
                        
                        finding = Finding(
                            category="vulnerability",
                            description=f"Directory listing enabled: {directory}",
                            severity="medium",
                            port=port,
                            url=url,
                            data={
                                "vulnerability_type": "directory_listing",
                                "directory": directory,
                                "file_count": file_count,
                                "server": response.headers.get('Server', 'Unknown')
                            }
                        )
                        findings.append(finding)
                        
            except requests.RequestException:
                continue
                
        return findings

    def _identify_interface_type(self, content: str, path: str) -> str:
        """Identify the type of admin interface"""
        
        # Brand-specific interface detection
        if any(brand in content for brand in ['hikvision', 'hik-connect']):
            return "Hikvision Admin Panel"
        elif any(brand in content for brand in ['dahua', 'dss']):
            return "Dahua Admin Panel"
        elif 'axis' in content:
            return "Axis Admin Panel"
        elif 'sony' in content:
            return "Sony Admin Panel"
        elif 'panasonic' in content:
            return "Panasonic Admin Panel"
        elif any(term in content for term in ['webcamxp', 'webcam']):
            return "WebcamXP Interface"
        
        # Generic interface type detection
        elif any(term in content for term in ['dvr', 'nvr', 'recorder']):
            return "DVR/NVR Management Interface"
        elif any(term in content for term in ['camera', 'video', 'surveillance']):
            return "Camera Management Interface"
        elif 'configuration' in content or 'settings' in content:
            return "Configuration Interface"
        elif 'dashboard' in content:
            return "Admin Dashboard"
        elif 'control panel' in content:
            return "Control Panel"
        else:
            return "Admin Interface"

    def _analyze_content_sensitivity(self, content: str, path: str) -> int:
        """Analyze content for sensitivity level (0-5 scale)"""
        score = 0
        content_lower = content.lower()
        
        # High sensitivity indicators
        high_sensitivity = [
            'password', 'passwd', 'secret', 'key', 'token', 'credential',
            'private', 'confidential', 'internal', 'admin', 'root'
        ]
        
        # Medium sensitivity indicators
        medium_sensitivity = [
            'config', 'configuration', 'setting', 'database', 'connection',
            'server', 'host', 'port', 'username', 'user', 'account'
        ]
        
        # File type scoring
        if path.endswith(('.xml', '.json', '.config', '.conf')):
            score += 1
        elif path.endswith(('.bak', '.backup', '.sql', '.db')):
            score += 2
        elif path.endswith(('.log', '.txt')):
            score += 1
            
        # Content analysis
        for indicator in high_sensitivity:
            if indicator in content_lower:
                score += 2
                
        for indicator in medium_sensitivity:
            if indicator in content_lower:
                score += 1
                
        return min(score, 5)  # Cap at 5

    def _get_file_type(self, path: str) -> str:
        """Determine file type from path"""
        if path.endswith(('.xml', '.json')):
            return "configuration"
        elif path.endswith(('.bak', '.backup')):
            return "backup"
        elif path.endswith(('.log')):
            return "log"
        elif path.endswith(('.sql', '.db')):
            return "database"
        elif path.endswith(('.txt', '.readme')):
            return "text"
        else:
            return "unknown"

    def get_description(self) -> str:
        """Get plugin description"""
        return "Web interface and admin panel discovery scanner"