"""
Plugin base classes and structures for Gridland
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Any, Optional
from .core import ScanTarget


@dataclass
class Finding:
    """Represents a security finding from a plugin"""
    category: str  # e.g., "credential", "stream", "vulnerability"
    description: str
    severity: str = "medium"  # low, medium, high, critical
    port: Optional[int] = None
    url: Optional[str] = None
    data: Optional[dict] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}


class ScannerPlugin(ABC):
    """Base class for all scanner plugins"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.enabled = True

    @abstractmethod
    def can_scan(self, target: ScanTarget) -> bool:
        """
        Determine if this plugin can scan the given target
        
        Args:
            target: ScanTarget to evaluate
            
        Returns:
            bool: True if plugin can scan this target
        """
        pass

    @abstractmethod
    def scan(self, target: ScanTarget, progress_callback=None) -> List[Finding]:
        """
        Perform the scan and return findings
        
        Args:
            target: ScanTarget to scan
            progress_callback: Optional callback for progress reporting
            
        Returns:
            List[Finding]: List of security findings
        """
        pass

    def get_description(self) -> str:
        """Get plugin description"""
        return f"{self.name} scanner plugin"

    def set_enabled(self, enabled: bool):
        """Enable or disable the plugin"""
        self.enabled = enabled

    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled