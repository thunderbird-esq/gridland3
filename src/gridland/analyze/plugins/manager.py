"""
Plugin manager for runtime-loadable analysis scanners.

Provides a flexible plugin architecture for extending GRIDLAND's
analysis capabilities with custom vulnerability scanners and tools.
"""

import importlib
import importlib.util
import inspect
import threading
from abc import ABC, abstractmethod  
from pathlib import Path
from typing import Dict, List, Optional, Type, Any, Callable
from dataclasses import dataclass
from uuid import uuid4

from gridland.core.logger import get_logger
from gridland.core.config import get_config
from ..memory import VulnerabilityResult, StreamResult, AnalysisResult

logger = get_logger(__name__)


class AnalysisPlugin(ABC):
    """Base class for analysis plugins."""
    
    def __init__(self):
        self.plugin_id = str(uuid4())
        self.enabled = True
    
    @property
    @abstractmethod
    def metadata(self) -> dict:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    async def analyze(self, target_ip: str, target_port: int, 
                     service: str = "", banner: str = "") -> List[Any]:
        """
        Perform analysis on target.
        
        Args:
            target_ip: Target IP address
            target_port: Target port number
            service: Detected service type
            banner: Service banner
            
        Returns:
            List of results (VulnerabilityResult, StreamResult, or custom)
        """
        pass
    
    def initialize(self) -> bool:
        """Initialize plugin. Return True if successful."""
        return True
    
    def cleanup(self):
        """Cleanup plugin resources."""
        pass
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get plugin configuration options."""
        return {}
    
    def set_configuration(self, config: Dict[str, Any]):
        """Set plugin configuration."""
        pass


class VulnerabilityPlugin(AnalysisPlugin):
    """Base class for vulnerability scanning plugins."""
    
    @abstractmethod
    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                  service: str = "", banner: str = "") -> List[VulnerabilityResult]:
        """Scan for vulnerabilities. Must be implemented by subclasses."""
        pass
    
    async def analyze(self, target_ip: str, target_port: int, 
                     service: str = "", banner: str = "") -> List[VulnerabilityResult]:
        """Wrapper for vulnerability scanning."""
        return await self.scan_vulnerabilities(target_ip, target_port, service, banner)


class StreamPlugin(AnalysisPlugin):
    """Base class for stream analysis plugins."""
    
    @abstractmethod
    async def analyze_streams(self, target_ip: str, target_port: int,
                             service: str = "", banner: str = "") -> List[StreamResult]:
        """Analyze streams. Must be implemented by subclasses."""
        pass
    
    async def analyze(self, target_ip: str, target_port: int,
                     service: str = "", banner: str = "") -> List[StreamResult]:
        """Wrapper for stream analysis."""
        return await self.analyze_streams(target_ip, target_port, service, banner)


class PluginRegistry:
    """Registry for managing loaded plugins."""
    
    def __init__(self):
        self.plugins: Dict[str, AnalysisPlugin] = {}
        self.plugins_by_type: Dict[str, List[AnalysisPlugin]] = {
            'vulnerability': [],
            'stream': [],
            'banner': [],
            'custom': [],
            'enrichment': []
        }
        self.plugins_by_port: Dict[int, List[AnalysisPlugin]] = {}
        self.plugins_by_service: Dict[str, List[AnalysisPlugin]] = {}
        self._lock = threading.RLock()
    
    def register_plugin(self, plugin: AnalysisPlugin) -> bool:
        """Register a plugin in the registry."""
        try:
            metadata = plugin.metadata
            with self._lock:
                # Add to main registry
                self.plugins[plugin.plugin_id] = plugin
                
                # Add to type index
                plugin_type = metadata.get("plugin_type", "custom").lower()
                if plugin_type not in self.plugins_by_type:
                    self.plugins_by_type[plugin_type] = []
                self.plugins_by_type[plugin_type].append(plugin)
                
                # Add to port index
                for port in metadata.get("supported_ports", []):
                    if port not in self.plugins_by_port:
                        self.plugins_by_port[port] = []
                    self.plugins_by_port[port].append(plugin)
                
                # Add to service index
                for service in metadata.get("supported_services", []):
                    service_key = service.lower()
                    if service_key not in self.plugins_by_service:
                        self.plugins_by_service[service_key] = []
                    self.plugins_by_service[service_key].append(plugin)
            
            logger.info(f"Registered plugin: {metadata.get('name', 'Unknown')} v{metadata.get('version', '0.0.0')}")
            return True
            
        except Exception as e:
            plugin_name = "Unknown Plugin"
            try:
                plugin_name = plugin.metadata.get("name", "Unknown")
            except Exception:
                pass
            logger.error(f"Failed to register plugin {plugin_name}: {e}")
            return False
    
    def unregister_plugin(self, plugin_id: str) -> bool:
        """Unregister a plugin."""
        try:
            with self._lock:
                if plugin_id not in self.plugins:
                    return False
                
                plugin = self.plugins[plugin_id]
                metadata = plugin.metadata
                
                # Remove from type index
                plugin_type = metadata.get("plugin_type", "custom").lower()
                if plugin_type in self.plugins_by_type:
                    self.plugins_by_type[plugin_type] = [
                        p for p in self.plugins_by_type[plugin_type] 
                        if p.plugin_id != plugin_id
                    ]
                
                # Remove from port index
                for port in metadata.get("supported_ports", []):
                    if port in self.plugins_by_port:
                        self.plugins_by_port[port] = [
                            p for p in self.plugins_by_port[port]
                            if p.plugin_id != plugin_id
                        ]
                
                # Remove from service index
                for service in metadata.get("supported_services", []):
                    service_key = service.lower()
                    if service_key in self.plugins_by_service:
                        self.plugins_by_service[service_key] = [
                            p for p in self.plugins_by_service[service_key]
                            if p.plugin_id != plugin_id
                        ]
                
                # Cleanup plugin
                plugin.cleanup()
                
                # Remove from main registry
                del self.plugins[plugin_id]
            
            logger.info(f"Unregistered plugin: {metadata.get('name', 'Unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister plugin {plugin_id}: {e}")
            return False
    
    def get_plugins_for_target(self, port: int, service: str = "") -> List[AnalysisPlugin]:
        """Get plugins applicable to a target."""
        applicable_plugins = set()
        
        with self._lock:
            # Add plugins matching port
            if port in self.plugins_by_port:
                applicable_plugins.update(self.plugins_by_port[port])
            
            # Add plugins matching service
            if service:
                service_key = service.lower()
                if service_key in self.plugins_by_service:
                    applicable_plugins.update(self.plugins_by_service[service_key])
            
            # Filter enabled plugins and sort by priority
            enabled_plugins = [p for p in applicable_plugins if p.enabled]
            return sorted(enabled_plugins, key=lambda p: p.metadata.get("priority", 100))
    
    def get_plugins_by_type(self, plugin_type: str) -> List[AnalysisPlugin]:
        """Get plugins by type."""
        with self._lock:
            return self.plugins_by_type.get(plugin_type.lower(), []).copy()
    
    def get_all_plugins(self) -> List[AnalysisPlugin]:
        """Get all registered plugins."""
        with self._lock:
            return list(self.plugins.values())


class PluginManager:
    """
    Runtime-loadable plugin manager for analysis extensions.
    
    Provides dynamic loading, unloading, and management of analysis plugins
    for extending GRIDLAND's scanning capabilities.
    """
    
    def __init__(self, plugin_directories: Optional[List[Path]] = None):
        self.config = get_config()
        self.plugin_directories = plugin_directories or [
            self.config.data_dir / "plugins",
            Path(__file__).parent / "builtin"
        ]
        
        self.registry = PluginRegistry()
        self._loaded_modules: Dict[str, Any] = {}
        self._lock = threading.RLock()
        
        # Ensure plugin directories exist
        for plugin_dir in self.plugin_directories:
            plugin_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"PluginManager initialized with {len(self.plugin_directories)} plugin directories")
    
    def load_plugins_from_directory(self, directory: Path) -> int:
        """Load all plugins from a directory."""
        if not directory.exists():
            logger.warning(f"Plugin directory does not exist: {directory}")
            return 0
        
        loaded_count = 0
        
        # Look for Python files
        for plugin_file in directory.glob("*.py"):
            if plugin_file.name.startswith("_") or plugin_file.name == "__init__.py":
                continue  # Skip private files and __init__.py
            
            try:
                if self.load_plugin_from_file(plugin_file):
                    loaded_count += 1
            except Exception as e:
                logger.error(f"Failed to load plugin from {plugin_file}: {e}")
        
        return loaded_count
    
    def load_plugin_from_file(self, plugin_file: Path) -> bool:
        """Load a plugin from a Python file."""
        try:
            module_name = f"gridland_plugin_{plugin_file.stem}_{uuid4().hex[:8]}"
            
            # Load module
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if not spec or not spec.loader:
                logger.error(f"Could not load plugin spec from {plugin_file}")
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            plugin_classes = []
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, AnalysisPlugin) and 
                    obj != AnalysisPlugin and
                    not inspect.isabstract(obj)):
                    plugin_classes.append(obj)
            
            if not plugin_classes:
                return False
            
            # Instantiate and register plugins
            for plugin_class in plugin_classes:
                try:
                    plugin_instance = plugin_class()
                    
                    # Initialize plugin
                    if not plugin_instance.initialize():
                        logger.error(f"Plugin initialization failed: {plugin_class.__name__}")
                        continue
                    
                    # Register plugin
                    if self.registry.register_plugin(plugin_instance):
                        with self._lock:
                            self._loaded_modules[plugin_instance.plugin_id] = module
                        logger.info(f"Loaded plugin: {plugin_instance.metadata.name}")
                    
                except Exception as e:
                    logger.error(f"Failed to instantiate plugin {plugin_class.__name__}: {e}")
            
            return len(plugin_classes) > 0
            
        except Exception as e:
            logger.error(f"Error loading plugin from {plugin_file}: {e}")
            return False
    
    def load_all_plugins(self) -> int:
        """Load plugins from all configured directories."""
        total_loaded = 0
        
        for directory in self.plugin_directories:
            try:
                loaded = self.load_plugins_from_directory(directory)
                total_loaded += loaded
                logger.info(f"Loaded {loaded} plugins from {directory}")
            except Exception as e:
                logger.error(f"Error loading plugins from {directory}: {e}")
        
        logger.info(f"Total plugins loaded: {total_loaded}")
        return total_loaded
    
    def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a specific plugin."""
        try:
            # Unregister from registry
            success = self.registry.unregister_plugin(plugin_id)
            
            # Remove loaded module
            with self._lock:
                if plugin_id in self._loaded_modules:
                    del self._loaded_modules[plugin_id]
            
            return success
            
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_id}: {e}")
            return False
    
    def reload_plugin(self, plugin_id: str) -> bool:
        """Reload a specific plugin."""
        # Note: Full plugin reloading is complex due to Python's import system
        # For now, we unload and would need to reload from file
        logger.warning("Plugin reloading not fully implemented")
        return self.unload_plugin(plugin_id)
    
    def get_applicable_plugins(self, target_port: int, service: str = "") -> List[AnalysisPlugin]:
        """Get plugins applicable to a target."""
        return self.registry.get_plugins_for_target(target_port, service)
    
    def get_vulnerability_plugins(self) -> List[VulnerabilityPlugin]:
        """Get all vulnerability scanning plugins."""
        plugins = self.registry.get_plugins_by_type('vulnerability')
        return [p for p in plugins if isinstance(p, VulnerabilityPlugin)]
    
    def get_stream_plugins(self) -> List[StreamPlugin]:
        """Get all stream analysis plugins."""
        plugins = self.registry.get_plugins_by_type('stream')
        return [p for p in plugins if isinstance(p, StreamPlugin)]
    
    def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin."""
        if plugin_id in self.registry.plugins:
            self.registry.plugins[plugin_id].enabled = True
            logger.info(f"Enabled plugin: {plugin_id}")
            return True
        return False
    
    def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin."""
        if plugin_id in self.registry.plugins:
            self.registry.plugins[plugin_id].enabled = False
            logger.info(f"Disabled plugin: {plugin_id}")
            return True
        return False
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get plugin manager statistics."""
        all_plugins = self.registry.get_all_plugins()
        
        stats = {
            'total_plugins': len(all_plugins),
            'enabled_plugins': len([p for p in all_plugins if p.enabled]),
            'plugins_by_type': {
                plugin_type: len(plugins) 
                for plugin_type, plugins in self.registry.plugins_by_type.items()
            },
            'plugin_details': [
                {
                    'id': plugin.plugin_id,
                    'name': plugin.metadata.get("name", "Unknown"),
                    'version': plugin.metadata.get("version", "0.0.0"),
                    'type': plugin.metadata.get("plugin_type", "custom"),
                    'enabled': plugin.enabled,
                    'priority': plugin.metadata.get("priority", 100)
                }
                for plugin in all_plugins
            ]
        }
        
        return stats
    
    def shutdown(self):
        """Shutdown plugin manager and cleanup all plugins."""
        logger.info("Shutting down PluginManager")
        
        all_plugins = self.registry.get_all_plugins()
        for plugin in all_plugins:
            try:
                self.unload_plugin(plugin.plugin_id)
            except Exception as e:
                logger.error(f"Error during plugin cleanup: {e}")
        
        with self._lock:
            self._loaded_modules.clear()


# Global plugin manager instance
_global_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Get global plugin manager instance."""
    global _global_plugin_manager
    if _global_plugin_manager is None:
        _global_plugin_manager = PluginManager()
        _global_plugin_manager.load_all_plugins()
    return _global_plugin_manager


def initialize_plugin_manager(plugin_directories: Optional[List[Path]] = None) -> PluginManager:
    """Initialize global plugin manager with custom directories."""
    global _global_plugin_manager
    if _global_plugin_manager is not None:
        _global_plugin_manager.shutdown()
    
    _global_plugin_manager = PluginManager(plugin_directories)
    _global_plugin_manager.load_all_plugins()
    return _global_plugin_manager