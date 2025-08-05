"""
Core data structures for Gridland security scanner
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
import json


@dataclass
class PortResult:
    """Represents the result of scanning a single port"""
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None

    def __str__(self):
        return f"{self.port} ({self.service or 'unknown'})"


@dataclass
class ScanTarget:
    """Represents a scan target with its results"""
    ip: str
    open_ports: List[PortResult] = None
    device_type: Optional[str] = None
    brand: Optional[str] = None
    credentials: Dict[str, str] = None
    streams: List[str] = None
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.credentials is None:
            self.credentials = {}
        if self.streams is None:
            self.streams = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'ip': self.ip,
            'open_ports': [{'port': p.port, 'service': p.service, 'banner': p.banner} for p in self.open_ports],
            'device_type': self.device_type,
            'brand': self.brand,
            'credentials': self.credentials,
            'streams': self.streams,
            'vulnerabilities': self.vulnerabilities
        }

    def to_json(self):
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Job:
    """Represents a scan job for the web interface"""
    id: str
    target: str
    status: str = "pending"  # pending, running, completed, failed
    logs: List[str] = None
    results: List[ScanTarget] = None
    analysis: Optional[str] = None # Add a dedicated field for the analysis
    
    def __post_init__(self):
        if self.logs is None:
            self.logs = []
        if self.results is None:
            self.results = []

    def add_log(self, message: str):
        """Add a log message with timestamp"""
        import time
        timestamp = time.strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'target': self.target,
            'status': self.status,
            'logs': self.logs,
            'results': [r.to_dict() for r in self.results],
            'analysis': self.analysis,
        }