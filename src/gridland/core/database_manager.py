import json
import os
from pathlib import Path
from threading import Lock
from gridland.core.logger import get_logger

logger = get_logger(__name__)

class DatabaseManager:
    _instance = None
    _lock = Lock()
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self, data_directory: Path = None):
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return

            self._databases = {}
            if data_directory is None:
                # Default path relative to this file's location
                data_directory = Path(__file__).parent.parent / 'data'

            self._load_all_databases(data_directory)
            self._initialized = True
            logger.info("DatabaseManager initialized and all data loaded into memory.")

            # --- ADD THIS VERIFICATION STEP ---
            # Check for the presence of critical databases after loading.
            # This provides a clear, early warning if a key file is missing.
            critical_dbs = ['fingerprinting_database', 'stream_paths']
            for db_name in critical_dbs:
                if db_name not in self._databases:
                    logger.critical(
                        f"CRITICAL: The '{db_name}.json' database was not found! "
                        "Core functionality will be impaired."
                    )

    def _load_all_databases(self, data_directory: Path):
        """Loads all .json files from the specified data directory."""
        if not data_directory.is_dir():
            logger.error(f"Data directory not found: {data_directory}")
            return

        for json_file in data_directory.glob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    # Use the filename without extension as the key
                    db_name = json_file.stem
                    self._databases[db_name] = json.load(f)
                    logger.debug(f"Loaded database: {db_name}")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Failed to load database {json_file.name}: {e}")

    def get_db(self, name: str) -> dict:
        """
        Retrieves a loaded database by its name (filename without .json).

        Args:
            name: The name of the database to retrieve.

        Returns:
            A dictionary containing the database content, or an empty dict if not found.
        """
        return self._databases.get(name, {})

# Create a single, globally accessible instance
db_manager = DatabaseManager()
