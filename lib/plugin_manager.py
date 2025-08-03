"""
Plugin management system for Gridland
"""
import os
import importlib.util
import logging
from typing import List, Dict, Any
from .plugins import ScannerPlugin, Finding
from .core import ScanTarget


class PluginManager:
    """Manages loading and executing scanner plugins"""
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.plugins: List[ScannerPlugin] = []
        self.plugin_dirs = plugin_dirs or ['plugins']
        self.logger = logging.getLogger('gridland.plugins')
        self._load_plugins()

    def _load_plugins(self):
        """Load all plugins from plugin directories"""
        self.logger.debug(f"Loading plugins from directories: {self.plugin_dirs}")
        
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                self.logger.warning(f"Plugin directory {plugin_dir} does not exist")
                continue
                
            self.logger.debug(f"Scanning plugin directory: {plugin_dir}")
            for filename in os.listdir(plugin_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    self._load_plugin_file(os.path.join(plugin_dir, filename))
        
        self.logger.info(f"Loaded {len(self.plugins)} plugins: {[type(p).__name__ for p in self.plugins]}")

    def _load_plugin_file(self, filepath: str):
        """Load a single plugin file"""
        try:
            module_name = os.path.splitext(os.path.basename(filepath))[0]
            self.logger.debug(f"Loading plugin file: {filepath}")
            
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find plugin classes in the module
                plugins_found = 0
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, ScannerPlugin) and 
                        attr != ScannerPlugin):
                        
                        # Instantiate the plugin
                        plugin_instance = attr()
                        self.plugins.append(plugin_instance)
                        plugins_found += 1
                        self.logger.debug(f"Loaded plugin: {attr.__name__} from {filepath}")
                
                if plugins_found == 0:
                    self.logger.warning(f"No plugin classes found in {filepath}")
                        
        except Exception as e:
            self.logger.error(f"Failed to load plugin {filepath}: {e}")
            self.logger.debug(f"Plugin loading exception details", exc_info=True)

    def get_plugins(self) -> List[ScannerPlugin]:
        """Get all loaded plugins"""
        return self.plugins

    def get_enabled_plugins(self) -> List[ScannerPlugin]:
        """Get only enabled plugins"""
        return [p for p in self.plugins if p.is_enabled()]

    def run_all_plugins(self, target: ScanTarget) -> List[Finding]:
        """
        Run all applicable plugins against a target
        
        Args:
            target: ScanTarget to scan
            
        Returns:
            List[Finding]: Combined findings from all plugins
        """
        all_findings = []
        enabled_plugins = self.get_enabled_plugins()
        
        self.logger.info(f"Running {len(enabled_plugins)} enabled plugins against {target.ip}")
        
        for plugin in enabled_plugins:
            plugin_name = type(plugin).__name__
            try:
                self.logger.debug(f"Checking if {plugin_name} can scan {target.ip}")
                
                if plugin.can_scan(target):
                    self.logger.info(f"Running {plugin_name} against {target.ip}")
                    findings = plugin.scan(target)
                    
                    self.logger.debug(f"{plugin_name} found {len(findings)} findings")
                    for finding in findings:
                        self.logger.debug(f"{plugin_name} finding: {finding.category} - {finding.description}")
                    
                    all_findings.extend(findings)
                else:
                    self.logger.debug(f"{plugin_name} cannot scan {target.ip} (no applicable ports)")
                    
            except Exception as e:
                self.logger.error(f"Plugin {plugin_name} failed: {e}")
                self.logger.debug(f"Plugin {plugin_name} exception details", exc_info=True)
                continue
        
        self.logger.info(f"Plugin execution completed. Total findings: {len(all_findings)}")
        return all_findings

    def run_plugin_by_name(self, plugin_name: str, target: ScanTarget) -> List[Finding]:
        """
        Run a specific plugin by name
        
        Args:
            plugin_name: Name of plugin to run
            target: ScanTarget to scan
            
        Returns:
            List[Finding]: Findings from the plugin
        """
        for plugin in self.plugins:
            if plugin.name == plugin_name and plugin.is_enabled():
                if plugin.can_scan(target):
                    return plugin.scan(target)
                break
        
        return []

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin by name"""
        for plugin in self.plugins:
            if plugin.name == plugin_name:
                plugin.set_enabled(True)
                return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin by name"""
        for plugin in self.plugins:
            if plugin.name == plugin_name:
                plugin.set_enabled(False)
                return True
        return False

    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        """List all plugins with their status"""
        plugin_list = {}
        for plugin in self.plugins:
            plugin_list[plugin.name] = {
                'enabled': plugin.is_enabled(),
                'description': plugin.get_description()
            }
        return plugin_list