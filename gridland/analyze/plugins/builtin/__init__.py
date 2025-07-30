"""
Built-in Security Plugins for GRIDLAND

This module contains production-ready security plugins for comprehensive
camera and network device vulnerability assessment.
"""

from . import hikvision_scanner
from . import dahua_scanner
from . import axis_scanner
from . import banner_grabber
from . import ip_context_scanner
from . import enhanced_camera_detector
from . import cp_plus_scanner
from . import advanced_fingerprinting_scanner
from . import cve_correlation_scanner
from . import enhanced_credential_scanner
from . import multi_protocol_stream_scanner

# Export all built-in plugins for automatic discovery
__all__ = [
    'hikvision_scanner',
    'dahua_scanner',
    'axis_scanner',
    'banner_grabber',
    'ip_context_scanner',
    'enhanced_camera_detector',
    'cp_plus_scanner',
    'advanced_fingerprinting_scanner',
    'cve_correlation_scanner',
    'enhanced_credential_scanner',
    'multi_protocol_stream_scanner'
]

# Plugin registry for automatic loading
BUILTIN_PLUGINS = [
    hikvision_scanner.hikvision_scanner,
    dahua_scanner.dahua_scanner,
    axis_scanner.axis_scanner,
    banner_grabber.banner_grabber,
    ip_context_scanner.ip_context_scanner,
    enhanced_camera_detector.EnhancedCameraDetector(),
    cp_plus_scanner.CPPlusScanner(),
    advanced_fingerprinting_scanner.AdvancedFingerprintingScanner(None, None),
    cve_correlation_scanner.CVECorrelationScanner(),
    enhanced_credential_scanner.EnhancedCredentialScanner(),
    multi_protocol_stream_scanner.MultiProtocolStreamScanner()
]