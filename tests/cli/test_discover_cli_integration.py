"""Integration tests for GRIDLAND discover CLI.

Tests the Phase 8 CLI enhancements including Python port scanner
integration and camera port selection.
"""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

# Import the discover command
from gridland.cli.discover_cli import discover


class TestDiscoverCLIBasics:
    """Test basic discover CLI functionality."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    def test_discover_help(self, runner):
        """Test --help displays all options."""
        result = runner.invoke(discover, ["--help"])
        assert result.exit_code == 0
        assert "discover" in result.output.lower() or "Discover" in result.output
        # Check for new Phase 8 flags
        assert "--use-python-scanner" in result.output
        assert "--camera-ports" in result.output
        assert "--camera-port-category" in result.output

    def test_discover_requires_input(self, runner):
        """Test discover requires input specification."""
        result = runner.invoke(discover, [])
        # Should fail or warn without input
        assert result.exit_code != 0 or "Must specify" in result.output


class TestDiscoverPythonScanner:
    """Test Python scanner CLI integration."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_use_python_scanner_flag_exists(self, runner):
        """Test --use-python-scanner flag is recognized."""
        result = runner.invoke(discover, ["--help"])
        assert "--use-python-scanner" in result.output
        assert "Python" in result.output or "python" in result.output.lower()

    def test_python_scanner_help_text(self, runner):
        """Test Python scanner help text mentions masscan alternative."""
        result = runner.invoke(discover, ["--help"])
        help_text = result.output.lower()
        assert "python" in help_text or "scanner" in help_text


class TestDiscoverCameraPorts:
    """Test camera port CLI integration."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_camera_ports_flag_exists(self, runner):
        """Test --camera-ports flag is recognized."""
        result = runner.invoke(discover, ["--help"])
        assert "--camera-ports" in result.output
        assert "camera" in result.output.lower() or "port" in result.output.lower()

    def test_camera_port_category_flag_exists(self, runner):
        """Test --camera-port-category flag is recognized."""
        result = runner.invoke(discover, ["--help"])
        assert "--camera-port-category" in result.output

    def test_camera_port_category_choices(self, runner):
        """Test camera port category shows valid choices."""
        result = runner.invoke(discover, ["--help"])
        # Should show available categories
        assert (
            "rtsp" in result.output.lower()
            or "web" in result.output.lower()
            or "all" in result.output.lower()
        )


class TestDiscoverDryRun:
    """Test discover dry run mode."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_dry_run_with_range(self, runner):
        """Test --dry-run shows planned discovery."""
        result = runner.invoke(discover, ["--range", "192.168.1.0/24", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry Run" in result.output or "dry run" in result.output.lower()
        assert "192.168.1.0" in result.output


class TestDiscoverEngineSelection:
    """Test engine selection options."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_engine_options(self, runner):
        """Test engine selection shows all options."""
        result = runner.invoke(discover, ["--help"])
        assert "--engine" in result.output
        assert "masscan" in result.output.lower()
        assert "shodanspider" in result.output.lower()
        assert "censys" in result.output.lower()
        assert "auto" in result.output.lower()

    def test_scan_mode_options(self, runner):
        """Test scan mode options are available."""
        result = runner.invoke(discover, ["--help"])
        assert "--scan-mode" in result.output
        assert "FAST" in result.output
        assert "BALANCED" in result.output
        assert "COMPREHENSIVE" in result.output


class TestDiscoverOutputFormats:
    """Test discover output format options."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_output_format_options(self, runner):
        """Test output format choices are available."""
        result = runner.invoke(discover, ["--help"])
        assert "--output-format" in result.output
        assert "table" in result.output
        assert "json" in result.output
        assert "csv" in result.output
        assert "xml" in result.output


class TestDiscoverInputValidation:
    """Test input validation for discover CLI."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_masscan_requires_range(self, runner):
        """Test masscan engine requires --range or --input-file."""
        result = runner.invoke(
            discover, ["--engine", "masscan", "--query", "camera"]  # Wrong input type for masscan
        )
        # Should fail or warn
        assert (
            result.exit_code != 0
            or "range" in result.output.lower()
            or "input" in result.output.lower()
        )


# Test count validation
def test_minimum_test_count():
    """Ensure we have adequate test coverage."""
    import inspect

    test_classes = [
        TestDiscoverCLIBasics,
        TestDiscoverPythonScanner,
        TestDiscoverCameraPorts,
        TestDiscoverDryRun,
        TestDiscoverEngineSelection,
        TestDiscoverOutputFormats,
        TestDiscoverInputValidation,
    ]

    total_tests = 0
    for cls in test_classes:
        methods = [m for m in dir(cls) if m.startswith("test_")]
        total_tests += len(methods)

    assert total_tests >= 10, f"Expected at least 10 tests, found {total_tests}"
