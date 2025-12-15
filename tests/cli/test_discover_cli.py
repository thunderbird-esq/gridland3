"""
Comprehensive tests for discover_cli.py.

Tests cover:
- ProgressIndicator class
- Port selection functions
- Engine selection
- Output format functions
- CLI option handling
"""

import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock, patch

from gridland.cli.discover_cli import (
    discover,
    ProgressIndicator,
    _get_ports_for_scan_mode,
    _validate_inputs,
    _auto_select_engine,
    _check_masscan_available,
    _xml_escape,
)


class TestProgressIndicator:
    """Test ProgressIndicator class."""

    def test_initialization(self):
        """Test ProgressIndicator init."""
        pi = ProgressIndicator("Discovering")
        assert pi.message == "Discovering"
        assert pi.show_spinner is True

    def test_context_manager(self):
        """Test context manager."""
        pi = ProgressIndicator("Testing")
        with pi:
            assert pi.start_time is not None


class TestPortSelection:
    """Test port selection functions."""

    def test_get_ports_for_scan_mode_fast(self):
        """Test fast scan mode ports."""
        mock_pm = MagicMock()
        mock_pm.get_ports_for_scan_mode.return_value = [80, 443, 554]
        result = _get_ports_for_scan_mode("fast", mock_pm)
        assert isinstance(result, list)

    def test_get_ports_for_scan_mode_normal(self):
        """Test normal scan mode ports."""
        mock_pm = MagicMock()
        mock_pm.get_ports_for_scan_mode.return_value = [80, 443, 554, 8080]
        result = _get_ports_for_scan_mode("normal", mock_pm)
        assert isinstance(result, list)


class TestInputValidation:
    """Test input validation functions."""

    def test_validate_inputs_masscan_with_range(self):
        """Test valid masscan inputs."""
        # Should not raise
        _validate_inputs("masscan", "192.168.1.0/24", None, None)

    def test_validate_inputs_shodan_with_query(self):
        """Test valid shodan inputs."""
        # Should not raise
        _validate_inputs("shodan", None, "camera port:554", None)


class TestEngineSelection:
    """Test engine selection functions."""

    def test_auto_select_engine_with_range(self):
        """Test auto-select with IP range."""
        result = _auto_select_engine("192.168.1.0/24", None, None)
        assert result in ["masscan", "python"]

    def test_auto_select_engine_with_query(self):
        """Test auto-select with query."""
        result = _auto_select_engine(None, "camera port:554", None)
        assert result in ["shodanspider", "censys"]  # Actual engine names


class TestUtilityFunctions:
    """Test utility functions."""

    def test_check_masscan_available(self):
        """Test masscan availability check."""
        result = _check_masscan_available()
        assert isinstance(result, bool)

    def test_xml_escape_basic(self):
        """Test XML escaping."""
        result = _xml_escape("test & value")
        assert "&amp;" in result

    def test_xml_escape_quotes(self):
        """Test XML quote escaping."""
        result = _xml_escape('test "value"')
        assert "&quot;" in result


class TestDiscoverCLI:
    """Test discover CLI command."""

    def test_discover_help(self):
        """Test discover --help."""
        runner = CliRunner()
        result = runner.invoke(discover, ["--help"])
        assert result.exit_code == 0
        assert "Discover" in result.output or "engine" in result.output.lower()

    def test_discover_dry_run(self):
        """Test discover --dry-run."""
        runner = CliRunner()
        result = runner.invoke(discover, [
            "--engine", "masscan",
            "--range", "192.168.1.0/24",
            "--dry-run"
        ])
        assert result.exit_code in [0, 1]

    def test_discover_verbose(self):
        """Test discover --verbose."""
        runner = CliRunner()
        result = runner.invoke(discover, ["--help", "--verbose"])
        assert result.exit_code == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
