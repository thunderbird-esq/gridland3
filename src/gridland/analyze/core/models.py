"""
Core models and base classes for GRIDLAND analysis engine.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

@dataclass
class PluginMetadata:
    """Metadata for analysis plugins."""
    name: str
    version: str
    author: str
    description: str
    plugin_type: str = "vulnerability"
    supported_ports: List[int] = field(default_factory=list)
    supported_services: List[str] = field(default_factory=list)

@dataclass 
class StreamResult:
    """Result from stream detection analysis."""
    url: str
    protocol: str
    status: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VulnerabilityResult:
    """Result from vulnerability analysis."""
    id: str
    severity: str
    confidence: float
    description: str
    exploit_available: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeviceFingerprint:
    """Device fingerprint information."""
    brand: str
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    hardware_version: Optional[str] = None
    serial_number: Optional[str] = None
    device_type: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    authentication_methods: List[str] = field(default_factory=list)
    configuration_access: bool = False
    vulnerability_indicators: List[str] = field(default_factory=list)

class Plugin(ABC):
    """Base plugin class."""
    
    def __init__(self):
        self.metadata = None
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        pass

class VulnerabilityPlugin(Plugin):
    """Base class for vulnerability detection plugins."""
    
    @abstractmethod
    async def analyze_vulnerabilities(self, target_ip: str, target_port: int, 
                                    banner: Optional[str] = None) -> List[VulnerabilityResult]:
        """Analyze target for vulnerabilities."""
        pass

class StreamPlugin(Plugin):
    """Base class for stream detection plugins."""
    
    @abstractmethod
    async def analyze_streams(self, target_ip: str, target_port: int,
                            banner: Optional[str] = None) -> List[StreamResult]:
        """Analyze target for streams."""
        pass
