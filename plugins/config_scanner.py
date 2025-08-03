"""
Configuration Scanner Plugin for Gridland
Detects exposed configuration files, backups, and debug endpoints
"""
import requests
import re
from typing import List, Dict, Optional
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os


class ConfigScannerPlugin(ScannerPlugin):
    """
    Configuration and backup file scanner.
    Detects exposed configuration files, database backups, and debug information.
    """
    
    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has web ports for configuration scanning"""
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]
        return any(p.port in web_ports for p in target.open_ports)

    # Configuration file patterns and paths
    CONFIG_FILES = {
        # Generic configuration files
        "config": [
            "/config.xml", "/config.json", "/config.php", "/config.asp", "/config.aspx",
            "/configuration.xml", "/configuration.json", "/app.config", "/web.config",
            "/settings.xml", "/settings.json", "/settings.php", "/settings.ini",
            "/conf/config.xml", "/etc/config", "/usr/local/etc/config"
        ],
        
        # Camera-specific configuration files
        "camera_config": [
            "/param.cgi", "/cgi-bin/param.cgi", "/cgi-bin/hi3510/param.cgi",
            "/ISAPI/System/configurationData", "/ISAPI/Security/users",
            "/axis-cgi/param.cgi", "/sony/config", "/panasonic/config.cgi",
            "/dahua/config", "/bosch/configuration", "/pelco/settings"
        ],
        
        # Network and system configuration
        "network_config": [
            "/network.xml", "/network.json", "/network_settings.xml",
            "/ip_config.xml", "/wifi_config.xml", "/ethernet_config.xml",
            "/dhcp.conf", "/resolv.conf", "/hosts", "/interfaces"
        ],
        
        # User and authentication configuration
        "auth_config": [
            "/users.xml", "/users.json", "/accounts.xml", "/passwords.xml",
            "/auth.xml", "/authentication.xml", "/security.xml", "/permissions.xml",
            "/htpasswd", "/.htpasswd", "/passwd", "/shadow"
        ],
        
        # Database configuration
        "database_config": [
            "/database.xml", "/database.json", "/db_config.xml", "/connection.xml",
            "/datasource.xml", "/hibernate.cfg.xml", "/persistence.xml"
        ]
    }

    # Backup file patterns
    BACKUP_FILES = {
        "config_backups": [
            "/config.bak", "/config.backup", "/config.old", "/config.orig",
            "/configuration.bak", "/settings.bak", "/web.config.bak",
            "/config.xml.bak", "/config.json.backup"
        ],
        
        "database_backups": [
            "/backup.sql", "/database.sql", "/dump.sql", "/export.sql",
            "/users.sql", "/accounts.sql", "/data.sql", "/schema.sql",
            "/backup.db", "/database.db", "/data.db", "/users.db"
        ],
        
        "system_backups": [
            "/backup.zip", "/backup.tar.gz", "/backup.tar", "/system_backup.zip",
            "/config_backup.zip", "/full_backup.tar.gz", "/export.zip"
        ],
        
        "log_backups": [
            "/error.log", "/access.log", "/debug.log", "/system.log",
            "/application.log", "/security.log", "/audit.log", "/activity.log"
        ]
    }

    # Debug and development endpoints
    DEBUG_ENDPOINTS = {
        "debug_info": [
            "/debug", "/debug/", "/debug.html", "/debug.php", "/debug.asp",
            "/test", "/test/", "/test.html", "/test.php", "/test.asp",
            "/dev", "/dev/", "/development", "/staging"
        ],
        
        "system_info": [
            "/info", "/info.php", "/phpinfo.php", "/system_info", "/server_info",
            "/version", "/version.txt", "/build", "/build.txt", "/release.txt"
        ],
        
        "status_pages": [
            "/status", "/health", "/ping", "/heartbeat", "/alive",
            "/server-status", "/server-info", "/stats", "/statistics"
        ],
        
        "api_debug": [
            "/api/debug", "/api/test", "/api/status", "/api/info",
            "/rest/debug", "/json/debug", "/xml/debug"
        ]
    }

    # Sensitive data patterns to look for in responses
    SENSITIVE_PATTERNS = {
        "credentials": [
            r"password\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"passwd\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"secret\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"key\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"token\s*[=:]\s*['\"]?([^'\"\s<>]+)"
        ],
        
        "network_info": [
            r"ip\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)",
            r"hostname\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"gateway\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)",
            r"dns\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)"
        ],
        
        "system_info": [
            r"version\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"build\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"serial\s*[=:]\s*['\"]?([^'\"\s<>]+)",
            r"mac\s*[=:]\s*['\"]?([a-fA-F0-9:]{17})"
        ]
    }

    def scan(self, target: ScanTarget) -> List[Finding]:
        """Perform configuration and backup file scanning"""
        findings = []
        proxy_url = os.environ.get('PROXY_URL')
        
        for port_result in target.open_ports:
            if port_result.port not in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]:
                continue
                
            protocol = "https" if port_result.port in [443, 8443] else "http"
            base_url = f"{protocol}://{target.ip}:{port_result.port}"
            
            # Scan for configuration files
            findings.extend(self._scan_config_files(base_url, port_result.port, proxy_url))
            
            # Scan for backup files
            findings.extend(self._scan_backup_files(base_url, port_result.port, proxy_url))
            
            # Scan for debug endpoints
            findings.extend(self._scan_debug_endpoints(base_url, port_result.port, proxy_url))
        
        return findings

    def _scan_config_files(self, base_url: str, port: int, proxy_url: str = None) -> List[Finding]:
        """Scan for exposed configuration files"""
        findings = []
        
        for category, file_list in self.CONFIG_FILES.items():
            for config_path in file_list:
                try:
                    url = f"{base_url}{config_path}"
                    response = requests.get(
                        url,
                        timeout=5,
                        verify=False,
                        headers=get_request_headers(),
                        proxies=get_proxies(proxy_url)
                    )
                    
                    if response.status_code == 200 and len(response.content) > 0:
                        content = response.text
                        
                        # Analyze configuration content
                        analysis = self._analyze_config_content(content, config_path)
                        
                        if analysis['is_config']:
                            severity = self._determine_severity(analysis)
                            
                            finding = Finding(
                                category="configuration_exposure",
                                description=f"Configuration file exposed: {config_path}",
                                severity=severity,
                                port=port,
                                url=url,
                                data={
                                    "config_type": category,
                                    "file_path": config_path,
                                    "content_size": len(content),
                                    "sensitive_data": analysis['sensitive_data'],
                                    "file_format": analysis['format']
                                }
                            )
                            findings.append(finding)
                            
                except requests.RequestException:
                    continue
                    
        return findings

    def _scan_backup_files(self, base_url: str, port: int, proxy_url: str = None) -> List[Finding]:
        """Scan for exposed backup files"""
        findings = []
        
        for category, file_list in self.BACKUP_FILES.items():
            for backup_path in file_list:
                try:
                    url = f"{base_url}{backup_path}"
                    response = requests.get(
                        url,
                        timeout=5,
                        verify=False,
                        headers=get_request_headers(),
                        proxies=get_proxies(proxy_url)
                    )
                    
                    if response.status_code == 200 and len(response.content) > 100:  # Minimum size check
                        content = response.text if len(response.content) < 10000 else response.text[:10000]
                        
                        # Analyze backup content
                        analysis = self._analyze_backup_content(content, backup_path)
                        
                        if analysis['is_backup']:
                            finding = Finding(
                                category="backup_exposure",
                                description=f"Backup file exposed: {backup_path}",
                                severity="high",  # Backups are usually high severity
                                port=port,
                                url=url,
                                data={
                                    "backup_type": category,
                                    "file_path": backup_path,
                                    "content_size": len(response.content),
                                    "contains_sensitive": analysis['contains_sensitive'],
                                    "file_type": analysis['file_type']
                                }
                            )
                            findings.append(finding)
                            
                except requests.RequestException:
                    continue
                    
        return findings

    def _scan_debug_endpoints(self, base_url: str, port: int, proxy_url: str = None) -> List[Finding]:
        """Scan for debug and development endpoints"""
        findings = []
        
        for category, endpoint_list in self.DEBUG_ENDPOINTS.items():
            for debug_path in endpoint_list:
                try:
                    url = f"{base_url}{debug_path}"
                    response = requests.get(
                        url,
                        timeout=5,
                        verify=False,
                        headers=get_request_headers(),
                        proxies=get_proxies(proxy_url)
                    )
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for debug/development indicators
                        debug_indicators = [
                            'debug', 'development', 'test', 'staging', 'error',
                            'stack trace', 'exception', 'phpinfo', 'server info',
                            'system information', 'environment', 'variables'
                        ]
                        
                        is_debug = any(indicator in content for indicator in debug_indicators)
                        
                        if is_debug:
                            # Extract system information if present
                            system_info = self._extract_system_info(response.text)
                            
                            finding = Finding(
                                category="debug_exposure",
                                description=f"Debug endpoint exposed: {debug_path}",
                                severity="medium",
                                port=port,
                                url=url,
                                data={
                                    "endpoint_type": category,
                                    "debug_path": debug_path,
                                    "system_info": system_info,
                                    "response_size": len(response.content)
                                }
                            )
                            findings.append(finding)
                            
                except requests.RequestException:
                    continue
                    
        return findings

    def _analyze_config_content(self, content: str, file_path: str) -> Dict:
        """Analyze configuration file content"""
        analysis = {
            'is_config': False,
            'format': 'unknown',
            'sensitive_data': []
        }
        
        content_lower = content.lower()
        
        # Determine file format
        if content.strip().startswith('<?xml') or '<configuration>' in content_lower:
            analysis['format'] = 'xml'
            analysis['is_config'] = True
        elif content.strip().startswith('{') and '}' in content:
            analysis['format'] = 'json'
            analysis['is_config'] = True
        elif any(indicator in content_lower for indicator in ['[section]', 'key=value', 'setting=']):
            analysis['format'] = 'ini'
            analysis['is_config'] = True
        elif any(indicator in content_lower for indicator in ['config', 'setting', 'parameter']):
            analysis['format'] = 'text'
            analysis['is_config'] = True
        
        # Extract sensitive data
        for data_type, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    analysis['sensitive_data'].extend([
                        {'type': data_type, 'value': match} for match in matches[:5]  # Limit to first 5
                    ])
        
        return analysis

    def _analyze_backup_content(self, content: str, file_path: str) -> Dict:
        """Analyze backup file content"""
        analysis = {
            'is_backup': False,
            'file_type': 'unknown',
            'contains_sensitive': False
        }
        
        content_lower = content.lower()
        
        # Determine backup type
        if file_path.endswith('.sql') or 'create table' in content_lower or 'insert into' in content_lower:
            analysis['file_type'] = 'sql_dump'
            analysis['is_backup'] = True
        elif file_path.endswith(('.zip', '.tar', '.gz')):
            analysis['file_type'] = 'archive'
            analysis['is_backup'] = True
        elif any(indicator in content_lower for indicator in ['backup', 'dump', 'export']):
            analysis['file_type'] = 'backup_file'
            analysis['is_backup'] = True
        elif len(content) > 1000 and any(char in content for char in ['\x00', '\x1f']):
            analysis['file_type'] = 'binary_backup'
            analysis['is_backup'] = True
        
        # Check for sensitive content
        sensitive_indicators = ['password', 'secret', 'key', 'token', 'credential', 'admin']
        analysis['contains_sensitive'] = any(indicator in content_lower for indicator in sensitive_indicators)
        
        return analysis

    def _extract_system_info(self, content: str) -> Dict:
        """Extract system information from debug pages"""
        system_info = {}
        
        # Extract common system information
        for info_type, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    system_info[info_type] = matches[:3]  # Limit to first 3 matches
        
        return system_info

    def _determine_severity(self, analysis: Dict) -> str:
        """Determine severity based on configuration analysis"""
        if analysis['sensitive_data']:
            # Check for high-risk sensitive data
            high_risk_types = ['credentials', 'secret', 'key', 'token']
            has_high_risk = any(
                item['type'] in high_risk_types or 'password' in str(item['value']).lower()
                for item in analysis['sensitive_data']
            )
            return "critical" if has_high_risk else "high"
        else:
            return "medium"

    def get_description(self) -> str:
        """Get plugin description"""
        return "Configuration file and backup exposure scanner"