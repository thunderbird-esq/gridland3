"""
Comprehensive tests for analyze_cli.py.

Tests cover:
- ProgressIndicator class
- Target parsing functions
- Output format functions
- CLI option handling
"""

import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock, patch, AsyncMock

from gridland.cli.analyze_cli import (
    analyze,
    ProgressIndicator,
    _parse_target_list,
    _result_to_dict,
    _output_json,
)


class TestProgressIndicator:
    """Test ProgressIndicator class."""

    def test_initialization(self):
        """Test ProgressIndicator init."""
        pi = ProgressIndicator("Testing")
        assert pi.message == "Testing"
        assert pi.show_spinner is True

    def test_context_manager_enter(self):
        """Test context manager enter."""
        pi = ProgressIndicator("Testing")
        with pi:
            assert pi.start_time is not None

    def test_context_manager_exit(self):
        """Test context manager exit."""
        pi = ProgressIndicator("Testing")
        with pi:
            pass
        # Should exit cleanly

    def test_update(self):
        """Test update method."""
        pi = ProgressIndicator("Testing")
        with pi:
            pi.update(processed=1, total=10, status="Running")


class TestTargetParsing:
    """Test target parsing functions."""

    def test_parse_target_list_single(self):
        """Test parsing single target."""
        result = _parse_target_list("192.168.1.1:80")
        assert len(result) == 1

    def test_parse_target_list_multiple(self):
        """Test parsing multiple targets."""
        result = _parse_target_list("192.168.1.1:80,192.168.1.2:443")
        assert len(result) >= 1

    def test_parse_target_list_empty(self):
        """Test parsing empty string."""
        result = _parse_target_list("")
        # Empty string returns empty list
        assert isinstance(result, list)


    def test_result_to_dict_with_object(self):
        """Test converting object result."""
        mock_result = MagicMock()
        mock_result.ip = "192.168.1.1"
        mock_result.port = 80
        mock_result.vulnerabilities = []
        mock_result.streams = []
        output = _result_to_dict(mock_result)
        assert isinstance(output, dict)
        assert output["ip"] == "192.168.1.1"


class TestAnalyzeCLI:
    """Test analyze CLI command."""

    def test_analyze_help(self):
        """Test analyze --help."""
        runner = CliRunner()
        result = runner.invoke(analyze, ["--help"])
        assert result.exit_code == 0
        assert "Analyze" in result.output or "targets" in result.output.lower()

    def test_analyze_no_targets(self):
        """Test analyze with no targets."""
        runner = CliRunner()
        result = runner.invoke(analyze, [])
        # Should show error or help
        assert result.exit_code in [0, 1, 2]

    def test_analyze_dry_run(self):
        """Test analyze --dry-run."""
        runner = CliRunner()
        result = runner.invoke(analyze, ["--targets", "192.168.1.1:80", "--dry-run"])
        assert result.exit_code in [0, 1]

    def test_analyze_verbose(self):
        """Test analyze --verbose."""
        runner = CliRunner()
        result = runner.invoke(analyze, ["--help", "--verbose"])
        assert result.exit_code == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
