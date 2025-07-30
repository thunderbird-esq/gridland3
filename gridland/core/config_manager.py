import yaml
from pathlib import Path
from threading import Lock
from ..core.logger import logger

class ConfigManager:
    _instance = None
    _lock = Lock()
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, config_path: Path = None):
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return

            if config_path is None:
                # Default path is in the project root
                config_path = Path(__file__).parent.parent.parent / 'config.yaml'

            try:
                with open(config_path, 'r') as f:
                    self._config = yaml.safe_load(f)
                logger.info(f"Configuration loaded successfully from {config_path}")
            except (FileNotFoundError, yaml.YAMLError) as e:
                logger.error(f"Failed to load configuration from {config_path}: {e}")
                self._config = {} # Default to empty config on error

            self._initialized = True

    def get(self, *keys, default=None):
        """
        Retrieves a nested configuration value.
        Example: get('network', 'timeout', default=10)
        """
        value = self._config
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

# Create a single, globally accessible instance
config_manager = ConfigManager()
