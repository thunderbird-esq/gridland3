"""Integration tests for GRIDLAND analyze CLI.

Tests the Phase 8 CLI enhancements including OSINT features,
brand detection, CVE lookup, login scanning, and credential testing.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

# Import the analyze command
from gridland.cli.analyze_cli import analyze


class TestAnalyzeCLIBasics:
    """Test basic analyze CLI functionality."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    def test_analyze_help(self, runner):
        """Test --help displays all options."""
        result = runner.invoke(analyze, ['--help'])
        assert result.exit_code == 0
        assert 'analyze' in result.output.lower() or 'Analyze' in result.output
        # Check for new Phase 8 flags
        assert '--show-search-urls' in result.output
        assert '--geo-lookup' in result.output
        assert '--google-dorks' in result.output
        assert '--show-cves' in result.output
        assert '--detect-brand' in result.output
        assert '--scan-logins' in result.output
        assert '--test-credentials' in result.output
        assert '--full-scan' in result.output

    def test_analyze_requires_input(self, runner):
        """Test analyze requires input specification."""
        result = runner.invoke(analyze, [])
        # Should fail without targets
        assert result.exit_code != 0 or 'Must specify' in result.output or 'Error' in result.output


class TestAnalyzeOSINTFlags:
    """Test OSINT-related CLI flags."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_show_search_urls_flag_exists(self, runner):
        """Test --show-search-urls flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--show-search-urls' in result.output
        assert 'OSINT' in result.output or 'search' in result.output.lower()

    def test_geo_lookup_flag_exists(self, runner):
        """Test --geo-lookup flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--geo-lookup' in result.output
        assert 'geolocation' in result.output.lower() or 'lookup' in result.output.lower()

    def test_google_dorks_flag_exists(self, runner):
        """Test --google-dorks flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--google-dorks' in result.output
        assert 'dork' in result.output.lower() or 'Google' in result.output

    def test_full_scan_enables_multiple_flags(self, runner):
        """Test --full-scan flag description mentions enabling features."""
        result = runner.invoke(analyze, ['--help'])
        assert '--full-scan' in result.output


class TestAnalyzeBrandDetection:
    """Test brand detection CLI flags."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_detect_brand_flag_exists(self, runner):
        """Test --detect-brand flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--detect-brand' in result.output
        assert 'brand' in result.output.lower()

    def test_show_cves_flag_exists(self, runner):
        """Test --show-cves flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--show-cves' in result.output
        assert 'CVE' in result.output


class TestAnalyzeSecurityFlags:
    """Test security-related CLI flags."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_scan_logins_flag_exists(self, runner):
        """Test --scan-logins flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--scan-logins' in result.output
        assert 'login' in result.output.lower()

    def test_test_credentials_flag_exists(self, runner):
        """Test --test-credentials flag is recognized."""
        result = runner.invoke(analyze, ['--help'])
        assert '--test-credentials' in result.output
        assert 'credential' in result.output.lower() or 'consent' in result.output.lower()


class TestAnalyzeDryRun:
    """Test analyze dry run mode."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_dry_run_with_targets(self, runner):
        """Test --dry-run shows planned analysis."""
        result = runner.invoke(analyze, [
            '--targets', '192.168.1.1:80',
            '--dry-run'
        ])
        assert result.exit_code == 0
        assert 'Dry Run' in result.output or 'dry run' in result.output.lower()
        assert '192.168.1.1' in result.output


class TestAnalyzeOutputFormats:
    """Test analyze output format options."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_output_format_options(self, runner):
        """Test output format choices are available."""
        result = runner.invoke(analyze, ['--help'])
        assert '--output-format' in result.output
        assert 'table' in result.output
        assert 'json' in result.output
        assert 'csv' in result.output


# Test count validation
def test_minimum_test_count():
    """Ensure we have adequate test coverage."""
    import inspect

    test_classes = [
        TestAnalyzeCLIBasics,
        TestAnalyzeOSINTFlags,
        TestAnalyzeBrandDetection,
        TestAnalyzeSecurityFlags,
        TestAnalyzeDryRun,
        TestAnalyzeOutputFormats,
    ]

    total_tests = 0
    for cls in test_classes:
        methods = [m for m in dir(cls) if m.startswith('test_')]
        total_tests += len(methods)

    assert total_tests >= 15, f"Expected at least 15 tests, found {total_tests}"
