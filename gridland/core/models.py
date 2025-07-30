from abc import ABC, abstractmethod
from typing import List, Any

from dataclasses import dataclass, field
from typing import Optional, List

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
