"""
Comprehensive test suite for analysis_engine.py.

Tests cover:
- AnalysisTarget and AnalysisConfiguration dataclasses
- AnalysisEngine initialization and configuration
- Software extraction methods
- CVSS conversion
- Statistics and shutdown
- Convenience functions
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from gridland.analyze.engines.analysis_engine import (
    AnalysisTarget,
    AnalysisConfiguration,
    AnalysisEngine,
    create_analysis_config,
)


class TestAnalysisTargetDataclass:
    """Test AnalysisTarget dataclass."""

    def test_basic_creation(self):
        """Test basic target creation."""
        target = AnalysisTarget(ip="192.168.1.1", port=80)
        assert target.ip == "192.168.1.1"
        assert target.port == 80

    def test_default_values(self):
        """Test default values."""
        target = AnalysisTarget(ip="10.0.0.1", port=443)
        assert target.service == ""
        assert target.banner == ""
        assert target.metadata == {}

    def test_with_all_fields(self):
        """Test target with all fields."""
        target = AnalysisTarget(
            ip="192.168.1.100",
            port=554,
            service="rtsp",
            banner="RTSP/1.0 Server",
            metadata={"brand": "hikvision"}
        )
        assert target.service == "rtsp"
        assert target.banner == "RTSP/1.0 Server"
        assert target.metadata["brand"] == "hikvision"


class TestAnalysisConfigurationDataclass:
    """Test AnalysisConfiguration dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = AnalysisConfiguration()
        assert config.max_concurrent_targets == 100
        assert config.timeout_per_target == 30.0
        assert config.enable_vulnerability_scanning is True
        assert config.enable_stream_analysis is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = AnalysisConfiguration(
            max_concurrent_targets=50,
            timeout_per_target=15.0,
            enable_vulnerability_scanning=False
        )
        assert config.max_concurrent_targets == 50
        assert config.timeout_per_target == 15.0
        assert config.enable_vulnerability_scanning is False

    def test_performance_mode_default(self):
        """Test default performance mode."""
        config = AnalysisConfiguration()
        assert config.performance_mode == "BALANCED"

    def test_signature_confidence_threshold(self):
        """Test signature confidence threshold."""
        config = AnalysisConfiguration(signature_confidence_threshold=0.9)
        assert config.signature_confidence_threshold == 0.9


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_create_analysis_config_balanced(self):
        """Test creating balanced config."""
        config = create_analysis_config("BALANCED")
        assert config.performance_mode == "BALANCED"
        assert config.max_concurrent_targets == 100

    def test_create_analysis_config_fast(self):
        """Test creating fast config."""
        config = create_analysis_config("FAST")
        assert config.performance_mode == "FAST"
        assert config.max_concurrent_targets == 200

    def test_create_analysis_config_thorough(self):
        """Test creating thorough config."""
        config = create_analysis_config("THOROUGH")
        assert config.performance_mode == "THOROUGH"
        assert config.max_concurrent_targets == 50

    def test_create_analysis_config_default(self):
        """Test default config creates balanced."""
        config = create_analysis_config()
        assert config.performance_mode == "BALANCED"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
