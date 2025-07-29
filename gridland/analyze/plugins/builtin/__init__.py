"""
Built-in Security Plugins for GRIDLAND

This module contains production-ready security plugins for comprehensive
camera and network device vulnerability assessment.
"""

from .hikvision_scanner import hikvision_scanner
from .dahua_scanner import dahua_scanner
from .axis_scanner import axis_scanner
from .generic_camera_scanner import generic_camera_scanner
from .banner_grabber import banner_grabber
from .ip_context_scanner import ip_context_scanner
from .enhanced_stream_scanner import enhanced_stream_scanner

# Export all built-in plugins for automatic discovery
__all__ = [
    'hikvision_scanner',
    'dahua_scanner', 
    'axis_scanner',
    'generic_camera_scanner',
    'banner_grabber',
    'ip_context_scanner',
    'enhanced_stream_scanner'
]

# Plugin registry for automatic loading
BUILTIN_PLUGINS = [
    hikvision_scanner,
    dahua_scanner,
    axis_scanner,
    generic_camera_scanner,
    banner_grabber,
    ip_context_scanner,
    enhanced_stream_scanner
]