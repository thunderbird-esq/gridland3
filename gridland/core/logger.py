"""
Professional logging system for GRIDLAND.

Provides colored output, structured logging, and multiple output formats
optimized for security tool usage.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class GridlandFormatter(logging.Formatter):
    """Custom formatter with color support and security-focused formatting."""
    
    # Color mappings for different log levels
    COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT
    }
    
    # Symbols for different log levels
    SYMBOLS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '💀'
    }
    
    def __init__(self, use_color: bool = True, use_symbols: bool = True):
        self.use_color = use_color
        self.use_symbols = use_symbols
        
        # Base format without color
        base_format = '[%(asctime)s] %(levelname)s: %(message)s'
        super().__init__(base_format, datefmt='%H:%M:%S')
    
    def format(self, record):
        """Format log record with colors and symbols."""
        # Get base formatted message
        formatted = super().format(record)
        
        level_name = record.levelname
        
        # Add symbol if enabled
        if self.use_symbols and level_name in self.SYMBOLS:
            symbol = self.SYMBOLS[level_name]
            formatted = f"{symbol} {formatted}"
        
        # Add color if enabled and outputting to TTY
        if self.use_color and sys.stderr.isatty() and level_name in self.COLORS:
            color = self.COLORS[level_name]
            formatted = f"{color}{formatted}{Style.RESET_ALL}"
        
        return formatted


class SecurityLogger:
    """Security-focused logger with operational awareness."""
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Set up console and file handlers."""
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_formatter = GridlandFormatter(use_color=True, use_symbols=True)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
    
    def add_file_handler(self, log_file: Path, level: int = logging.DEBUG):
        """Add file handler for persistent logging."""
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = GridlandFormatter(use_color=False, use_symbols=False)
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
    
    def set_level(self, level: int):
        """Set logging level for all handlers."""
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)
    
    # Convenience methods with security context
    def debug(self, msg: str, **kwargs):
        """Debug level logging."""
        self.logger.debug(msg, **kwargs)
    
    def info(self, msg: str, **kwargs):
        """Info level logging."""
        self.logger.info(msg, **kwargs)
    
    def warning(self, msg: str, **kwargs):
        """Warning level logging."""
        self.logger.warning(msg, **kwargs)
    
    def error(self, msg: str, **kwargs):
        """Error level logging."""
        self.logger.error(msg, **kwargs)
    
    def critical(self, msg: str, **kwargs):
        """Critical level logging."""
        self.logger.critical(msg, **kwargs)
    
    # Security-specific logging methods
    def scan_start(self, target: str, scan_type: str):
        """Log start of scanning operation."""
        self.info(f"Starting {scan_type} scan of {target}")
    
    def scan_complete(self, target: str, scan_type: str, duration: float, results_count: int = 0):
        """Log completion of scanning operation."""
        self.info(f"Completed {scan_type} scan of {target} in {duration:.2f}s ({results_count} results)")
    
    def target_found(self, target: str, service: str, details: str = ""):
        """Log discovery of target service."""
        msg = f"Target found: {service} on {target}"
        if details:
            msg += f" - {details}"
        self.info(msg)
    
    def vulnerability_found(self, target: str, vuln_type: str, severity: str = "medium"):
        """Log discovery of vulnerability."""
        severity_colors = {
            'low': Fore.YELLOW,
            'medium': Fore.LIGHTYELLOW_EX,
            'high': Fore.RED,
            'critical': Fore.MAGENTA + Style.BRIGHT
        }
        
        symbol = "🔓" if severity in ['high', 'critical'] else "⚠️"
        msg = f"{symbol} Vulnerability found on {target}: {vuln_type} (severity: {severity})"
        
        if severity in ['high', 'critical']:
            self.warning(msg)
        else:
            self.info(msg)
    
    def auth_attempt(self, target: str, username: str, success: bool):
        """Log authentication attempt."""
        if success:
            self.warning(f"🔓 Successful login to {target} with {username}")
        else:
            self.debug(f"Failed login attempt to {target} with {username}")
    
    def stream_found(self, target: str, stream_url: str, stream_type: str = "RTSP"):
        """Log discovery of video stream."""
        self.info(f"📹 {stream_type} stream found: {stream_url}")
    
    def rate_limit(self, target: str, delay: float):
        """Log rate limiting action."""
        self.debug(f"Rate limiting {target} - waiting {delay:.1f}s")
    
    def error_with_context(self, operation: str, target: str, error: Exception):
        """Log error with operational context."""
        self.error(f"Failed {operation} on {target}: {type(error).__name__}: {error}")


class OperationLogger:
    """Context manager for logging operations with timing."""
    
    def __init__(self, logger: SecurityLogger, operation: str, target: str):
        self.logger = logger
        self.operation = operation
        self.target = target
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.scan_start(self.target, self.operation)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            if exc_type is None:
                self.logger.scan_complete(self.target, self.operation, duration)
            else:
                self.logger.error(f"Failed {self.operation} on {self.target} after {duration:.2f}s: {exc_val}")


# Global logger instances
_loggers = {}

def get_logger(name: str = "gridland", level: Optional[int] = None) -> SecurityLogger:
    """Get or create a logger instance."""
    if name not in _loggers:
        if level is None:
            # Import here to avoid circular imports
            from .config import get_config
            config = get_config()
            level = logging.DEBUG if config.verbose else logging.INFO
        
        _loggers[name] = SecurityLogger(name, level)
    
    return _loggers[name]

def setup_file_logging(log_file: Path, level: int = logging.DEBUG):
    """Set up file logging for all loggers."""
    for logger in _loggers.values():
        logger.add_file_handler(log_file, level)

def set_verbose(verbose: bool):
    """Enable or disable verbose logging for all loggers."""
    level = logging.DEBUG if verbose else logging.INFO
    for logger in _loggers.values():
        logger.set_level(level)