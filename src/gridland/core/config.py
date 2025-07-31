"""
Configuration management for GRIDLAND.

Handles environment variables, user configuration files, and default settings
with validation and type conversion.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class GridlandConfig:
    """Central configuration class for GRIDLAND operations."""
    
    # Scanning configuration
    scan_timeout: int = field(default_factory=lambda: int(os.getenv('GL_SCAN_TIMEOUT', '10')))
    max_threads: int = field(default_factory=lambda: int(os.getenv('GL_MAX_THREADS', '100')))
    connect_timeout: int = field(default_factory=lambda: int(os.getenv('GL_CONNECT_TIMEOUT', '3')))
    
    # Discovery configuration
    masscan_rate: int = field(default_factory=lambda: int(os.getenv('GL_MASSCAN_RATE', '1000')))
    # Basic port list for backwards compatibility - comprehensive coverage handled by CameraPortManager
    default_ports: str = field(default_factory=lambda: os.getenv('GL_DEFAULT_PORTS', '80,443,554,8080,8443,8554,37777,37778,37779,3702,1935,8000,8001,8081,10554,1554,2554,8888,9999,5000'))
    
    # Output configuration
    output_format: str = field(default_factory=lambda: os.getenv('GL_OUTPUT_FORMAT', 'table'))
    verbose: bool = field(default_factory=lambda: os.getenv('GL_VERBOSE', 'false').lower() == 'true')
    color_output: bool = field(default_factory=lambda: os.getenv('GL_COLOR', 'true').lower() == 'true')
    
    # Authentication testing
    test_default_creds: bool = field(default_factory=lambda: os.getenv('GL_TEST_CREDS', 'true').lower() == 'true')
    auth_delay: float = field(default_factory=lambda: float(os.getenv('GL_AUTH_DELAY', '1.0')))
    max_auth_attempts: int = field(default_factory=lambda: int(os.getenv('GL_MAX_AUTH_ATTEMPTS', '3')))
    
    # API Keys and external services
    shodan_api_key: Optional[str] = field(default_factory=lambda: os.getenv('GL_SHODAN_API_KEY'))
    censys_api_id: Optional[str] = field(default_factory=lambda: os.getenv('GL_CENSYS_API_ID'))
    censys_api_secret: Optional[str] = field(default_factory=lambda: os.getenv('GL_CENSYS_API_SECRET'))
    
    # File paths
    config_dir: Path = field(default_factory=lambda: Path.home() / '.gridland')
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / 'data')
    temp_dir: Path = field(default_factory=lambda: Path('/tmp/gridland'))
    output: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_config()
        self._ensure_directories()
    
    def _validate_config(self):
        """Validate configuration values."""
        if self.scan_timeout < 1 or self.scan_timeout > 300:
            raise ValueError("scan_timeout must be between 1 and 300 seconds")
        
        if self.max_threads < 1 or self.max_threads > 1000:
            raise ValueError("max_threads must be between 1 and 1000")
        
        if self.masscan_rate < 1 or self.masscan_rate > 1000000:
            raise ValueError("masscan_rate must be between 1 and 1,000,000")
        
        if self.output_format not in ['table', 'json', 'csv', 'xml', 'summary']:
            raise ValueError("output_format must be one of: table, json, csv, xml, summary")
        
        if self.auth_delay < 0 or self.auth_delay > 60:
            raise ValueError("auth_delay must be between 0 and 60 seconds")
    
    def _ensure_directories(self):
        """Create necessary directories if they don't exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
    
    def load_user_config(self, config_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load user configuration from JSON file."""
        if config_path is None:
            config_path = self.config_dir / 'config.json'
        
        if not config_path.exists():
            return {}
        
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            
            # Update configuration with user values
            for key, value in user_config.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            
            return user_config
        except (json.JSONDecodeError, IOError) as e:
            raise ValueError(f"Failed to load user configuration: {e}")
    
    def save_user_config(self, config_path: Optional[Path] = None):
        """Save current configuration to JSON file."""
        if config_path is None:
            config_path = self.config_dir / 'config.json'
        
        config_dict = {
            'scan_timeout': self.scan_timeout,
            'max_threads': self.max_threads,
            'connect_timeout': self.connect_timeout,
            'masscan_rate': self.masscan_rate,
            'default_ports': self.default_ports,
            'output_format': self.output_format,
            'verbose': self.verbose,
            'color_output': self.color_output,
            'test_default_creds': self.test_default_creds,
            'auth_delay': self.auth_delay,
            'max_auth_attempts': self.max_auth_attempts
        }
        
        try:
            with open(config_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
        except IOError as e:
            raise ValueError(f"Failed to save user configuration: {e}")
    
    def get_ports_list(self) -> list[int]:
        """Convert default_ports string to list of integers."""
        if not self.default_ports:
            return []
        try:
            return sorted(list(set(int(port.strip()) for port in self.default_ports.split(','))))
        except ValueError as e:
            raise ValueError(f"Invalid port specification: {self.default_ports}") from e
    
    def has_shodan_api(self) -> bool:
        """Check if Shodan API key is configured."""
        return self.shodan_api_key is not None and len(self.shodan_api_key.strip()) > 0
    
    def has_censys_api(self) -> bool:
        """Check if Censys API credentials are configured."""
        return (self.censys_api_id is not None and len(self.censys_api_id.strip()) > 0 and
                self.censys_api_secret is not None and len(self.censys_api_secret.strip()) > 0)


# Global configuration instance
_config_instance = None

def get_config() -> GridlandConfig:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = GridlandConfig()
        # Try to load user configuration
        try:
            _config_instance.load_user_config()
        except ValueError:
            # Continue with defaults if user config fails
            pass
    return _config_instance

def reset_config():
    """Reset the global configuration instance (mainly for testing)."""
    global _config_instance
    _config_instance = None


# Comprehensive camera port categorization based on CamXploit.py analysis
CAMERA_PORT_CATEGORIES = {
    'standard_web': [
        # Standard web ports from CamXploit.py lines 60-61
        80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
        8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099
    ],
    'rtsp_ecosystem': [
        # RTSP ports from CamXploit.py lines 63-64
        554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554
    ],
    'custom_camera': [
        # Custom camera ports from CamXploit.py lines 70-71 (Dahua/similar)
        37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
        37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800
    ],
    'onvif_discovery': [
        # ONVIF ports from CamXploit.py lines 73-74
        3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710
    ],
    'streaming_protocols': [
        # RTMP ports from CamXploit.py lines 66-67
        1935, 1936, 1937, 1938, 1939,
        # MMS ports from CamXploit.py lines 89-90
        1755, 1756, 1757, 1758, 1759, 1760,
        # VLC streaming ports from CamXploit.py lines 76-77
        8100, 8110, 8120, 8130, 8140, 8150, 8160, 8170, 8180, 8190
    ],
    'common_alternatives': [
        # Common alternative ports from CamXploit.py lines 80-83
        5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010,
        6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010,
        7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
        9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010
    ],
    'additional_common': [
        # Additional common ports from CamXploit.py lines 85-87
        8888, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896, 8897, 8898, 8899,
        9999, 9998, 9997, 9996, 9995, 9994, 9993, 9992, 9991, 9990
    ],
    'enterprise_ranges': [
        # Custom ranges from CamXploit.py lines 92-98 (10k-15k)
        10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010,
        11000, 11001, 11002, 11003, 11004, 11005, 11006, 11007, 11008, 11009, 11010,
        12000, 12001, 12002, 12003, 12004, 12005, 12006, 12007, 12008, 12009, 12010,
        13000, 13001, 13002, 13003, 13004, 13005, 13006, 13007, 13008, 13009, 13010,
        14000, 14001, 14002, 14003, 14004, 14005, 14006, 14007, 14008, 14009, 14010,
        15000, 15001, 15002, 15003, 15004, 15005, 15006, 15007, 15008, 15009, 15010
    ],
    'enterprise_high': [
        # High ports commonly used by cameras from CamXploit.py lines 100-106
        20000, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010,
        21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010,
        22000, 22001, 22002, 22003, 22004, 22005, 22006, 22007, 22008, 22009, 22010,
        23000, 23001, 23002, 23003, 23004, 23005, 23006, 23007, 23008, 23009, 23010,
        24000, 24001, 24002, 24003, 24004, 24005, 24006, 24007, 24008, 24009, 24010,
        25000, 25001, 25002, 25003, 25004, 25005, 25006, 25007, 25008, 25009, 25010
    ],
    'enterprise_custom': [
        # Additional custom ranges from CamXploit.py lines 108-144 (30k-65k)
        30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009, 30010,
        31000, 31001, 31002, 31003, 31004, 31005, 31006, 31007, 31008, 31009, 31010,
        32000, 32001, 32002, 32003, 32004, 32005, 32006, 32007, 32008, 32009, 32010,
        33000, 33001, 33002, 33003, 33004, 33005, 33006, 33007, 33008, 33009, 33010,
        34000, 34001, 34002, 34003, 34004, 34005, 34006, 34007, 34008, 34009, 34010,
        35000, 35001, 35002, 35003, 35004, 35005, 35006, 35007, 35008, 35009, 35010,
        36000, 36001, 36002, 36003, 36004, 36005, 36006, 36007, 36008, 36009, 36010,
        37000, 37001, 37002, 37003, 37004, 37005, 37006, 37007, 37008, 37009, 37010,
        38000, 38001, 38002, 38003, 38004, 38005, 38006, 38007, 38008, 38009, 38010,
        39000, 39001, 39002, 39003, 39004, 39005, 39006, 39007, 39008, 39009, 39010,
        40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009, 40010,
        41000, 41001, 41002, 41003, 41004, 41005, 41006, 41007, 41008, 41009, 41010,
        42000, 42001, 42002, 42003, 42004, 42005, 42006, 42007, 42008, 42009, 42010,
        43000, 43001, 43002, 43003, 43004, 43005, 43006, 43007, 43008, 43009, 43010,
        44000, 44001, 44002, 44003, 44004, 44005, 44006, 44007, 44008, 44009, 44010,
        45000, 45001, 45002, 45003, 45004, 45005, 45006, 45007, 45008, 45009, 45010,
        46000, 46001, 46002, 46003, 46004, 46005, 46006, 46007, 46008, 46009, 46010,
        47000, 47001, 47002, 47003, 47004, 47005, 47006, 47007, 47008, 47009, 47010,
        48000, 48001, 48002, 48003, 48004, 48005, 48006, 48007, 48008, 48009, 48010,
        49000, 49001, 49002, 49003, 49004, 49005, 49006, 49007, 49008, 49009, 49010,
        50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010,
        51000, 51001, 51002, 51003, 51004, 51005, 51006, 51007, 51008, 51009, 51010,
        52000, 52001, 52002, 52003, 52004, 52005, 52006, 52007, 52008, 52009, 52010,
        53000, 53001, 53002, 53003, 53004, 53005, 53006, 53007, 53008, 53009, 53010,
        54000, 54001, 54002, 54003, 54004, 54005, 54006, 54007, 54008, 54009, 54010,
        55000, 55001, 55002, 55003, 55004, 55005, 55006, 55007, 55008, 55009, 55010,
        56000, 56001, 56002, 56003, 56004, 56005, 56006, 56007, 56008, 56009, 56010,
        57000, 57001, 57002, 57003, 57004, 57005, 57006, 57007, 57008, 57009, 57010,
        58000, 58001, 58002, 58003, 58004, 58005, 58006, 58007, 58008, 58009, 58010,
        59000, 59001, 59002, 59003, 59004, 59005, 59006, 59007, 59008, 59009, 59010,
        60000, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010,
        61000, 61001, 61002, 61003, 61004, 61005, 61006, 61007, 61008, 61009, 61010,
        62000, 62001, 62002, 62003, 62004, 62005, 62006, 62007, 62008, 62009, 62010,
        63000, 63001, 63002, 63003, 63004, 63005, 63006, 63007, 63008, 63009, 63010,
        64000, 64001, 64002, 64003, 64004, 64005, 64006, 64007, 64008, 64009, 64010,
        65000, 65001, 65002, 65003, 65004, 65005, 65006, 65007, 65008, 65009, 65010
    ]
}


class CameraPortManager:
    """Intelligent port management with category-based selection for camera reconnaissance."""
    
    def __init__(self):
        self.all_ports = self._compile_comprehensive_ports()
        self.priority_ports = self._get_priority_ports()
        self.category_map = CAMERA_PORT_CATEGORIES
    
    def _compile_comprehensive_ports(self) -> List[int]:
        """Compile all camera-relevant ports from CamXploit.py analysis."""
        ports = set()
        
        # Add all categorized ports
        for category, port_list in CAMERA_PORT_CATEGORIES.items():
            ports.update(port_list)
        
        return sorted(list(ports))
    
    def _get_priority_ports(self) -> List[int]:
        """High-probability camera ports for fast scanning."""
        return [
            # Core camera ports
            80, 443, 554, 8080, 8443, 8554,
            # Brand-specific high-probability
            37777, 37778, 37779,  # Dahua
            3702,  # ONVIF
            1935,  # RTMP
            8000, 8001, 8081,  # Common alternates
            10554, 1554, 2554,  # Additional RTSP
            8888, 9999, 5000  # Popular alternatives
        ]
    
    def get_ports_for_scan_mode(self, mode: str) -> List[int]:
        """Return appropriate ports based on scan intensity."""
        if mode == "FAST":
            return self.priority_ports
        elif mode == "BALANCED":
            # Priority ports + standard web + RTSP ecosystem
            balanced_ports = set(self.priority_ports)
            balanced_ports.update(CAMERA_PORT_CATEGORIES['standard_web'])
            balanced_ports.update(CAMERA_PORT_CATEGORIES['rtsp_ecosystem'])
            balanced_ports.update(CAMERA_PORT_CATEGORIES['streaming_protocols'])
            return sorted(list(balanced_ports))
        elif mode == "COMPREHENSIVE":
            return self.all_ports
        else:
            return self.priority_ports
    
    def get_ports_for_categories(self, categories: List[str]) -> List[int]:
        """Get ports for specific categories."""
        ports = set()
        for category in categories:
            if category in self.category_map:
                ports.update(self.category_map[category])
        return sorted(list(ports))
    
    def get_available_categories(self) -> List[str]:
        """Get list of available port categories."""
        return list(self.category_map.keys())
    
    def summarize_port_ranges(self, ports: List[int]) -> str:
        """Summarize port list for display purposes."""
        if not ports:
            return "none"
        
        ranges = []
        start = ports[0]
        end = start
        
        for port in ports[1:]:
            if port == end + 1:
                end = port
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = end = port
        
        # Add final range
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
        
        return ", ".join(ranges)
    
    def get_port_statistics(self) -> Dict[str, int]:
        """Get statistics about port coverage."""
        stats = {
            'total_ports': len(self.all_ports),
            'priority_ports': len(self.priority_ports),
            'categories': len(self.category_map)
        }
        
        for category, port_list in self.category_map.items():
            stats[f'{category}_count'] = len(port_list)
        
        return stats


# Global port manager instance
_port_manager_instance = None

def get_port_manager() -> CameraPortManager:
    """Get the global port manager instance."""
    global _port_manager_instance
    if _port_manager_instance is None:
        _port_manager_instance = CameraPortManager()
    return _port_manager_instance