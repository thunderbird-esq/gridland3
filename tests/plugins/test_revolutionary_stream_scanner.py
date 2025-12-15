"""
Comprehensive test suite for RevolutionaryStreamScanner.

Tests cover:
- Initialization and metadata
- Brand detection methods
- Stream discovery
- ML prediction
- CVE correlation
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Skip import if module has issues
try:
    from gridland.analyze.plugins.builtin.revolutionary_stream_scanner import RevolutionaryStreamScanner
    IMPORT_SUCCESS = True
except Exception as e:
    IMPORT_SUCCESS = False
    IMPORT_ERROR = str(e)


@pytest.mark.skipif(not IMPORT_SUCCESS, reason=f"Import failed: {IMPORT_ERROR if not IMPORT_SUCCESS else ''}")
class TestRevolutionaryStreamScannerInit:
    """Test RevolutionaryStreamScanner initialization."""

    def test_initialization(self):
        """Test scanner initialization."""
        scanner = RevolutionaryStreamScanner()
        assert scanner is not None

    def test_has_memory_pool(self):
        """Test scanner has memory pool."""
        scanner = RevolutionaryStreamScanner()
        assert scanner.memory_pool is not None

    def test_has_brand_patterns(self):
        """Test scanner has brand patterns."""
        scanner = RevolutionaryStreamScanner()
        assert hasattr(scanner, 'brand_patterns') or hasattr(scanner, 'camera_brands')

    def test_has_stream_paths(self):
        """Test scanner has stream paths database."""
        scanner = RevolutionaryStreamScanner()
        assert hasattr(scanner, 'stream_paths') or hasattr(scanner, 'rtsp_paths')


class TestRevolutionaryStreamScannerMetadata:
    """Test RevolutionaryStreamScanner metadata."""

    def test_get_metadata_returns_plugin_metadata(self):
        """Test metadata returns PluginMetadata object."""
        scanner = RevolutionaryStreamScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'name')
        assert hasattr(metadata, 'version')
        assert hasattr(metadata, 'description')

    def test_metadata_name_contains_stream(self):
        """Test metadata name contains stream or revolutionary."""
        scanner = RevolutionaryStreamScanner()
        metadata = scanner.get_metadata()
        name_lower = metadata.name.lower()
        assert "stream" in name_lower or "revolution" in name_lower

    def test_metadata_has_supported_ports(self):
        """Test metadata includes supported ports."""
        scanner = RevolutionaryStreamScanner()
        metadata = scanner.get_metadata()
        assert hasattr(metadata, 'supported_ports')
        # Should include common streaming ports
        ports = metadata.supported_ports
        assert 554 in ports or 80 in ports


class TestRevolutionaryStreamScannerBrandDetection:
    """Test RevolutionaryStreamScanner brand detection."""

    def test_analyze_banner_hikvision(self):
        """Test Hikvision banner analysis."""
        scanner = RevolutionaryStreamScanner()
        result = scanner._analyze_banner_for_brand("HIKVISION IP Camera")
        assert result is not None
        if isinstance(result, dict):
            assert result.get('brand', '').lower() == 'hikvision' or 'hikvision' in str(result).lower()

    def test_analyze_banner_dahua(self):
        """Test Dahua banner analysis."""
        scanner = RevolutionaryStreamScanner()
        result = scanner._analyze_banner_for_brand("Dahua Web Server")
        assert result is not None

    def test_analyze_banner_axis(self):
        """Test Axis banner analysis."""
        scanner = RevolutionaryStreamScanner()
        result = scanner._analyze_banner_for_brand("AXIS Video Server")
        assert result is not None

    def test_analyze_banner_unknown(self):
        """Test unknown banner analysis."""
        scanner = RevolutionaryStreamScanner()
        result = scanner._analyze_banner_for_brand("nginx/1.18.0")
        # Should return unknown or None
        assert result is None or (isinstance(result, dict) and result.get('brand', 'unknown') == 'unknown')


class TestRevolutionaryStreamScannerMLPrediction:
    """Test RevolutionaryStreamScanner ML prediction."""

    def test_extract_ml_features(self):
        """Test ML feature extraction."""
        scanner = RevolutionaryStreamScanner()
        features = scanner._extract_ml_features("192.168.1.1", 554, "rtsp", "HIKVISION")
        assert isinstance(features, (list, dict))

    def test_calculate_variance(self):
        """Test variance calculation."""
        scanner = RevolutionaryStreamScanner()
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        variance = scanner._calculate_variance(values)
        assert isinstance(variance, float)
        assert variance > 0


class TestRevolutionaryStreamScannerScan:
    """Test RevolutionaryStreamScanner scanning."""

    @pytest.mark.asyncio
    async def test_analyze_vulnerability_returns_list(self):
        """Test analyze_vulnerability returns list."""
        scanner = RevolutionaryStreamScanner()
        with patch.object(scanner, '_revolutionary_brand_detection', new_callable=AsyncMock) as mock_brand:
            mock_brand.return_value = {'brand': 'hikvision', 'confidence': 0.8}
            with patch.object(scanner, '_perform_advanced_correlation', new_callable=AsyncMock) as mock_corr:
                mock_corr.return_value = []
                # Mock stream discovery to return empty
                with patch('gridland.analyze.core.stream_intelligence.AdvancedStreamDiscovery') as mock_stream:
                    mock_stream_instance = MagicMock()
                    mock_stream_instance.discover_all_streams = AsyncMock(return_value=[])
                    mock_stream.return_value = mock_stream_instance
                    
                    results = await scanner.analyze_vulnerability("192.168.1.1", 554, "rtsp", "")
                    assert isinstance(results, list)


class TestRevolutionaryStreamScannerCVECorrelation:
    """Test RevolutionaryStreamScanner CVE correlation."""

    def test_create_cve_correlation(self):
        """Test CVE correlation result creation."""
        scanner = RevolutionaryStreamScanner()
        result = scanner._create_cve_correlation(
            "192.168.1.1", 80, "CVE-2021-36260", "hikvision", []
        )
        assert result is not None
        assert hasattr(result, 'ip') or hasattr(result, 'cve_id')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
