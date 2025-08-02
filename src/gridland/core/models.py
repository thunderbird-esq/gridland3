from abc import ABC, abstractmethod
from typing import List, Any

from dataclasses import dataclass, field
from typing import Optional, List, Any
from abc import ABC, abstractmethod


class BasePlugin(ABC):
    """Base class for all plugins."""

    def __init__(self, scheduler, memory_pool):
        self.scheduler = scheduler
        self.memory_pool = memory_pool

    @abstractmethod
    async def analyze(self, target: dict) -> List[Any]:
        """Run the plugin."""
        pass

@dataclass
class DeviceFingerprint:
    """Comprehensive device fingerprint information"""
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


@dataclass
class VulnerabilityResult:
    """Standardized vulnerability result."""
    vulnerability_id: str
    severity: str
    confidence: float
    description: str
    ip: str
    port: int
    details: dict = field(default_factory=dict)

@dataclass
class CameraIndicator:
    """Camera detection indicator with confidence scoring"""
    indicator_type: str
    value: str
    confidence: float
    brand_match: Optional[str] = None

@dataclass
class StreamEndpoint:
    """Enhanced stream endpoint with comprehensive metadata"""
    url: str
    protocol: str
    brand: Optional[str]
    content_type: Optional[str]
    response_size: Optional[int]
    authentication_required: bool
    confidence: float
    response_time: float
    quality_score: float
    metadata: dict
