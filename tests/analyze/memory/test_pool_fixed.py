"""
Comprehensive test suite for memory/pool.py - FIXED VERSION.

Tests cover:
- AnalysisMemoryPool initialization
- Object acquisition and release
- Pool statistics (using correct method name: get_pool_statistics)
- Cleanup
"""

import pytest
from unittest.mock import MagicMock, patch

from gridland.analyze.memory.pool import (
    get_memory_pool,
    AnalysisMemoryPool,
    VulnerabilityResult,
    StreamResult,
    AnalysisResult,
    PoolStats,
)


class TestPoolStatsDataclass:
    """Test PoolStats dataclass."""

    def test_creation(self):
        """Test PoolStats creation."""
        stats = PoolStats()
        assert stats.allocations == 0
        assert stats.pool_hits == 0

    def test_fields(self):
        """Test PoolStats has expected fields."""
        stats = PoolStats()
        assert hasattr(stats, 'allocations')
        assert hasattr(stats, 'deallocations')
        assert hasattr(stats, 'pool_hits')
        assert hasattr(stats, 'pool_misses')
        assert hasattr(stats, 'current_active')


class TestVulnerabilityResult:
    """Test VulnerabilityResult pooled object."""

    def test_creation(self):
        """Test VulnerabilityResult creation."""
        result = VulnerabilityResult()
        assert result.ip == ""
        assert result.port == 0

    def test_reset(self):
        """Test VulnerabilityResult reset."""
        result = VulnerabilityResult()
        result.ip = "192.168.1.1"
        result.port = 80
        result.reset()
        assert result.ip == ""
        assert result.port == 0


class TestStreamResult:
    """Test StreamResult pooled object."""

    def test_creation(self):
        """Test StreamResult creation."""
        result = StreamResult()
        assert result.ip == ""
        assert result.stream_url == ""

    def test_reset(self):
        """Test StreamResult reset."""
        result = StreamResult()
        result.ip = "192.168.1.1"
        result.stream_url = "rtsp://test"
        result.reset()
        assert result.ip == ""


class TestAnalysisMemoryPoolInit:
    """Test AnalysisMemoryPool initialization."""

    def test_initialization(self):
        """Test pool initialization."""
        pool = AnalysisMemoryPool()
        assert pool is not None

    def test_singleton_pattern(self):
        """Test singleton pattern."""
        pool1 = get_memory_pool()
        pool2 = get_memory_pool()
        assert pool1 is pool2


class TestAnalysisMemoryPoolAcquisition:
    """Test AnalysisMemoryPool object acquisition."""

    def test_acquire_vulnerability_result(self):
        """Test acquiring vulnerability result."""
        pool = get_memory_pool()
        result = pool.acquire_vulnerability_result()
        assert result is not None
        assert isinstance(result, VulnerabilityResult)

    def test_acquire_stream_result(self):
        """Test acquiring stream result."""
        pool = get_memory_pool()
        result = pool.acquire_stream_result()
        assert result is not None
        assert isinstance(result, StreamResult)

    def test_acquire_analysis_result(self):
        """Test acquiring analysis result."""
        pool = get_memory_pool()
        result = pool.acquire_analysis_result()
        assert result is not None
        assert isinstance(result, AnalysisResult)


class TestAnalysisMemoryPoolRelease:
    """Test AnalysisMemoryPool object release."""

    def test_release_vulnerability_result(self):
        """Test releasing vulnerability result."""
        pool = get_memory_pool()
        result = pool.acquire_vulnerability_result()
        pool.release_vulnerability_result(result)  # Should not raise

    def test_release_stream_result(self):
        """Test releasing stream result."""
        pool = get_memory_pool()
        result = pool.acquire_stream_result()
        pool.release_stream_result(result)  # Should not raise


class TestAnalysisMemoryPoolStatistics:
    """Test AnalysisMemoryPool statistics - FIXED."""

    def test_get_pool_statistics(self):
        """Test getting pool statistics - CORRECT METHOD NAME."""
        pool = get_memory_pool()
        stats = pool.get_pool_statistics()  # Correct: get_pool_statistics not get_statistics
        assert isinstance(stats, dict)

    def test_statistics_has_pool_keys(self):
        """Test statistics has pool type keys."""
        pool = get_memory_pool()
        stats = pool.get_pool_statistics()
        # Should have keys for different pool types
        assert len(stats) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
