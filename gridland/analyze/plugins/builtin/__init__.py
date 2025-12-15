"""
Built-in Security Plugins for GRIDLAND

This module contains production-ready security plugins for comprehensive
camera and network device vulnerability assessment.
"""

from .axis_scanner import axis_scanner
from .banner_grabber import banner_grabber
from .cpplus_scanner import cpplus_scanner
from .dahua_scanner import dahua_scanner
from .generic_camera_scanner import generic_camera_scanner
from .hikvision_scanner import hikvision_scanner
from .ip_context_scanner import ip_context_scanner
from .osint_integration_scanner import osint_integration_scanner
from .rtsp_stream_scanner import rtsp_stream_scanner
from .stream_discovery import StreamDiscoveryPlugin, stream_discovery_plugin

# Export all built-in plugins for automatic discovery
__all__ = [
    "hikvision_scanner",
    "dahua_scanner",
    "axis_scanner",
    "cpplus_scanner",
    "rtsp_stream_scanner",
    "generic_camera_scanner",
    "banner_grabber",
    "ip_context_scanner",
    "osint_integration_scanner",
    "stream_discovery_plugin",
    "StreamDiscoveryPlugin",
]

# Plugin registry for automatic loading
BUILTIN_PLUGINS = [
    hikvision_scanner,
    dahua_scanner,
    axis_scanner,
    cpplus_scanner,
    rtsp_stream_scanner,
    generic_camera_scanner,
    banner_grabber,
    ip_context_scanner,
    osint_integration_scanner,
    stream_discovery_plugin,
]

