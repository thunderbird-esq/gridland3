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

# In gridland/analyze/plugins/builtin/__init__.py

# This file serves as the registry for all built-in plugins.
# The PluginManager will discover and instantiate the classes listed here.

from .enhanced_camera_detector import EnhancedCameraDetector
from .advanced_fingerprinting_scanner import AdvancedFingerprintingScanner
# Import other plugin classes here as they are created

# --- THIS IS THE FIX ---
# We provide a list of the plugin CLASSES, not instances.
# The PluginManager will handle creating instances of these classes at runtime.
available_plugins = [
    EnhancedCameraDetector,
    AdvancedFingerprintingScanner,
]
# --- END OF FIX ---