import os
import importlib.util
import logging
import json
import hashlib
from typing import List, Dict, Any
from .plugins import ScannerPlugin, Finding
from .core import ScanTarget


class PluginManager:
    """Manages loading and executing scanner plugins"""
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.plugins: List[ScannerPlugin] = []
        self.plugin_dirs = plugin_dirs or ['plugins']
        self.logger = logging.getLogger('gridland.plugins')
        self.hashes = self._load_hashes()
        self._load_plugins()

    def _load_hashes(self) -> Dict[str, str]:
        """Load known-good hashes from the integrity file."""
        hashes_file = 'data/integrity.json'
        if not os.path.exists(hashes_file):
            self.logger.warning(f"Integrity file not found at '{hashes_file}'. Skipping plugin integrity checks.")
            return {}
        try:
            with open(hashes_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Failed to load or parse integrity file '{hashes_file}': {e}. No integrity checks will be performed.")
            return {}

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

    def _verify_integrity(self, filepath: str) -> bool:
        """Verify the integrity of a plugin file against the known hash."""
        if not self.hashes:
            return True # Skip check if hashes aren't loaded

        filename = os.path.basename(filepath)
        known_hash = self.hashes.get(filename)

        if not known_hash:
            self.logger.warning(f"SECURITY: No hash found for plugin '{filename}'. Cannot verify integrity. Skipping load.")
            return False

        try:
            with open(filepath, 'rb') as f:
                file_content = f.read()
                current_hash = hashlib.sha256(file_content).hexdigest()

            if current_hash != known_hash:
                self.logger.critical(f"SECURITY ALERT: Plugin '{filename}' has been modified! Hash mismatch.")
                self.logger.critical(f"Expected hash: {known_hash}")
                self.logger.critical(f"Current hash:  {current_hash}")
                self.logger.critical("This plugin will NOT be loaded. Investigate this unauthorized change immediately.")
                return False

            self.logger.debug(f"Integrity check passed for {filename}")
            return True

        except IOError as e:
            self.logger.error(f"Error reading plugin file {filepath} for integrity check: {e}")
            return False

    def _load_plugin_file(self, filepath: str):
        """Load a single plugin file after verifying its integrity."""
        # Step 1: Verify integrity
        if not self._verify_integrity(filepath):
            return # Do not load the plugin if integrity check fails

        # Step 2: Load the plugin if verification passes
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

    def run_all_plugins(self, target: ScanTarget, fingerprint: Dict = None) -> List[Finding]:
        """
        Run all applicable plugins against a target, informed by fingerprint data.
        
        Args:
            target: ScanTarget to scan
            fingerprint: Fingerprint data from the intelligence gathering phase
            
        Returns:
            List[Finding]: Combined findings from all plugins
        """
        all_findings = []
        # In the new workflow, the fingerprint scanner is run separately first.
        enabled_plugins = [p for p in self.get_enabled_plugins() if type(p).__name__ != 'FingerprintScannerPlugin']
        
        self.logger.info(f"Running {len(enabled_plugins)} intelligence-led plugins against {target.ip}")
        
        for plugin in enabled_plugins:
            plugin_name = type(plugin).__name__
            try:
                if plugin.can_scan(target):
                    self.logger.info(f"Running {plugin_name} against {target.ip} with fingerprint context")
                    findings = plugin.scan(target, fingerprint=fingerprint or {})
                    
                    self.logger.debug(f"{plugin_name} found {len(findings)} findings")
                    all_findings.extend(findings)
                else:
                    self.logger.debug(f"{plugin_name} cannot scan {target.ip} (no applicable ports)")
                    
            except Exception as e:
                self.logger.error(f"Plugin {plugin_name} failed: {e}")
                self.logger.debug(f"Plugin {plugin_name} exception details", exc_info=True)
                continue
        
        self.logger.info(f"Plugin execution completed. Total findings: {len(all_findings)}")
        return all_findings

    def run_plugin_by_name(self, plugin_name: str, target: ScanTarget, fingerprint: Dict = None) -> List[Finding]:
        """
        Run a specific plugin by name, informed by fingerprint data.
        
        Args:
            plugin_name: Name of the plugin class to run
            target: ScanTarget to scan
            fingerprint: Optional fingerprint data
            
        Returns:
            List[Finding]: Findings from the plugin
        """
        for plugin in self.plugins:
            if type(plugin).__name__ == plugin_name and plugin.is_enabled():
                if plugin.can_scan(target):
                    # The base 'scan' method in the abstract class does not have the fingerprint arg.
                    # We rely on concrete implementations to have it.
                    if fingerprint is not None:
                        return plugin.scan(target, fingerprint=fingerprint)
                    else:
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