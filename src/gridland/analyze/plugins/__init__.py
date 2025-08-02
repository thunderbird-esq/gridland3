"""
Plugin system for GRIDLAND analysis extensions.

Provides a flexible plugin architecture for extending vulnerability
scanning and analysis capabilities with custom tools and scanners.
"""

from .manager import (
    PluginManager,
    PluginRegistry,
    AnalysisPlugin,
    VulnerabilityPlugin,
    StreamPlugin,
    get_plugin_manager,
    initialize_plugin_manager
)

__all__ = [
    'PluginManager',
    'PluginRegistry', 
    'AnalysisPlugin',
    'VulnerabilityPlugin',
    'StreamPlugin',
    'get_plugin_manager',
    'initialize_plugin_manager'
]