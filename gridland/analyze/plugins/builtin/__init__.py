"""
Built-in Security Plugins for GRIDLAND

This module contains production-ready security plugins for comprehensive
camera and network device vulnerability assessment.
"""

from .hikvision_scanner import hikvision_scanner
from .dahua_scanner import dahua_scanner
from .axis_scanner import axis_scanner
from .banner_grabber import banner_grabber
from .ip_context_scanner import ip_context_scanner
from .enhanced_camera_detector import EnhancedCameraDetector
from .cp_plus_scanner import CPPlusScanner
from .advanced_fingerprinting_scanner import AdvancedFingerprintingScanner
from .cve_correlation_scanner import CVECorrelationScanner
from .enhanced_credential_scanner import EnhancedCredentialScanner
from .multi_protocol_stream_scanner import MultiProtocolStreamScanner

# Export all built-in plugins for automatic discovery
__all__ = [
    'hikvision_scanner',
    'dahua_scanner', 
    'axis_scanner',
    'banner_grabber',
    'ip_context_scanner',
    'EnhancedCameraDetector',
    'CPPlusScanner',
    'AdvancedFingerprintingScanner',
    'CVECorrelationScanner',
    'EnhancedCredentialScanner',
    'MultiProtocolStreamScanner'
]

# Plugin registry for automatic loading
BUILTIN_PLUGINS = [
    hikvision_scanner,
    dahua_scanner,
    axis_scanner,
    banner_grabber,
    ip_context_scanner,
    EnhancedCameraDetector(),
    CPPlusScanner(),
    AdvancedFingerprintingScanner(),
    CVECorrelationScanner(),
    EnhancedCredentialScanner(),
    MultiProtocolStreamScanner()
]