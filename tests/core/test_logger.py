"""
Comprehensive test suite for logger.py.

Tests cover:
- GridlandFormatter colors and symbols
- SecurityLogger initialization and methods
- OperationLogger context manager
- Module-level functions
"""

import logging
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from io import StringIO

from gridland.core.logger import (
    GridlandFormatter,
    SecurityLogger,
    OperationLogger,
    get_logger,
    setup_file_logging,
    set_verbose,
)


class TestGridlandFormatter:
    """Test GridlandFormatter class."""

    def test_initialization(self):
        """Test formatter initialization."""
        formatter = GridlandFormatter()
        assert formatter is not None

    def test_initialization_no_color(self):
        """Test formatter without color."""
        formatter = GridlandFormatter(use_color=False)
        assert formatter.use_color is False

    def test_initialization_no_symbols(self):
        """Test formatter without symbols."""
        formatter = GridlandFormatter(use_symbols=False)
        assert formatter.use_symbols is False

    def test_has_colors_dict(self):
        """Test formatter has colors dictionary."""
        assert hasattr(GridlandFormatter, 'COLORS')
        assert "INFO" in GridlandFormatter.COLORS

    def test_has_symbols_dict(self):
        """Test formatter has symbols dictionary."""
        assert hasattr(GridlandFormatter, 'SYMBOLS')
        assert "INFO" in GridlandFormatter.SYMBOLS

    def test_format_info_record(self):
        """Test formatting INFO record."""
        formatter = GridlandFormatter(use_color=False, use_symbols=True)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None
        )
        result = formatter.format(record)
        assert "Test message" in result


class TestSecurityLogger:
    """Test SecurityLogger class."""

    def test_initialization(self):
        """Test logger initialization."""
        logger = SecurityLogger("test_logger")
        assert logger is not None

    def test_initialization_with_level(self):
        """Test logger initialization with level."""
        logger = SecurityLogger("test_logger_level", level=logging.DEBUG)
        assert logger.logger.level == logging.DEBUG

    def test_debug(self):
        """Test debug logging."""
        logger = SecurityLogger("test_debug")
        logger.debug("Debug message")  # Should not raise

    def test_info(self):
        """Test info logging."""
        logger = SecurityLogger("test_info")
        logger.info("Info message")  # Should not raise

    def test_warning(self):
        """Test warning logging."""
        logger = SecurityLogger("test_warning")
        logger.warning("Warning message")  # Should not raise

    def test_error(self):
        """Test error logging."""
        logger = SecurityLogger("test_error")
        logger.error("Error message")  # Should not raise

    def test_critical(self):
        """Test critical logging."""
        logger = SecurityLogger("test_critical")
        logger.critical("Critical message")  # Should not raise

    def test_scan_start(self):
        """Test scan_start logging."""
        logger = SecurityLogger("test_scan_start")
        logger.scan_start("192.168.1.1", "vulnerability scan")  # Should not raise

    def test_scan_complete(self):
        """Test scan_complete logging."""
        logger = SecurityLogger("test_scan_complete")
        logger.scan_complete("192.168.1.1", "vulnerability scan", 5.0, results_count=10)

    def test_target_found(self):
        """Test target_found logging."""
        logger = SecurityLogger("test_target_found")
        logger.target_found("192.168.1.1", "RTSP", "Stream active")

    def test_vulnerability_found(self):
        """Test vulnerability_found logging."""
        logger = SecurityLogger("test_vuln_found")
        logger.vulnerability_found("192.168.1.1", "Default credentials", "high")

    def test_auth_attempt_success(self):
        """Test auth_attempt success logging."""
        logger = SecurityLogger("test_auth_success")
        logger.auth_attempt("192.168.1.1", "admin", success=True)

    def test_auth_attempt_failure(self):
        """Test auth_attempt failure logging."""
        logger = SecurityLogger("test_auth_failure")
        logger.auth_attempt("192.168.1.1", "admin", success=False)

    def test_stream_found(self):
        """Test stream_found logging."""
        logger = SecurityLogger("test_stream_found")
        logger.stream_found("192.168.1.1", "rtsp://camera/stream", "RTSP")

    def test_rate_limit(self):
        """Test rate_limit logging."""
        logger = SecurityLogger("test_rate_limit")
        logger.rate_limit("192.168.1.1", 2.5)

    def test_error_with_context(self):
        """Test error_with_context logging."""
        logger = SecurityLogger("test_error_context")
        logger.error_with_context("scan", "192.168.1.1", Exception("Test error"))


class TestOperationLogger:
    """Test OperationLogger context manager."""

    def test_context_manager_enter(self):
        """Test entering context."""
        base_logger = SecurityLogger("test_op_enter")
        op_logger = OperationLogger(base_logger, "scan", "192.168.1.1")
        with op_logger as ctx:
            assert ctx.start_time is not None

    def test_context_manager_exit_success(self):
        """Test exiting context successfully."""
        base_logger = SecurityLogger("test_op_exit")
        op_logger = OperationLogger(base_logger, "scan", "192.168.1.1")
        with op_logger:
            pass  # Simulate successful operation

    def test_context_manager_exit_error(self):
        """Test exiting context with error."""
        base_logger = SecurityLogger("test_op_error")
        op_logger = OperationLogger(base_logger, "scan", "192.168.1.1")
        try:
            with op_logger:
                raise ValueError("Test error")
        except ValueError:
            pass  # Expected


class TestModuleFunctions:
    """Test module-level functions."""

    def test_get_logger_returns_logger(self):
        """Test get_logger returns SecurityLogger."""
        logger = get_logger("test_module")
        assert isinstance(logger, SecurityLogger)

    def test_get_logger_same_name(self):
        """Test get_logger returns same instance."""
        logger1 = get_logger("same_test")
        logger2 = get_logger("same_test")
        assert logger1 is logger2

    def test_set_verbose(self):
        """Test set_verbose changes log levels."""
        logger = get_logger("verbose_test")
        set_verbose(True)
        # Should have set level to DEBUG for existing loggers
        set_verbose(False)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
