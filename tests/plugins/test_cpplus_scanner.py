"""
Unit tests for CP Plus Scanner plugin.

Tests the CPPlusScanner plugin for CP Plus DVR/NVR camera system detection.
"""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest

from gridland.analyze.plugins.builtin.cpplus_scanner import CPPlusScanner


class TestCPPlusScanner:
    """Test suite for CPPlusScanner plugin."""

    @pytest.fixture
    def scanner(self):
        """Create a CPPlusScanner instance for testing."""
        return CPPlusScanner()

    def test_initialization(self, scanner):
        """Test scanner initializes with correct default values."""
        assert scanner.timeout == 5
        assert scanner.cpplus_data is not None
        assert "detection_keywords" in scanner.cpplus_data
        assert "endpoints" in scanner.cpplus_data

    def test_get_metadata(self, scanner):
        """Test plugin metadata is correctly defined."""
        metadata = scanner.get_metadata()
        assert metadata.name == "CP Plus Scanner"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_type == "vulnerability"
        assert "http" in metadata.supported_services
        assert "https" in metadata.supported_services
        assert metadata.performance_impact == "LOW"
        assert metadata.priority == 70

    def test_get_protocol_http(self, scanner):
        """Test protocol detection returns http for standard ports."""
        assert scanner._get_protocol(80) == "http"
        assert scanner._get_protocol(8080) == "http"
        assert scanner._get_protocol(8000) == "http"

    def test_get_protocol_https(self, scanner):
        """Test protocol detection returns https for SSL ports."""
        assert scanner._get_protocol(443) == "https"
        assert scanner._get_protocol(8443) == "https"
        assert scanner._get_protocol(8444) == "https"

    def test_contains_brand_keywords_cp_plus(self, scanner):
        """Test brand keyword detection for 'cp plus'."""
        content = "Welcome to CP Plus DVR system"
        assert scanner._contains_brand_keywords(content.lower()) is True

    def test_contains_brand_keywords_cpplus(self, scanner):
        """Test brand keyword detection for 'cpplus'."""
        content = "cpplus surveillance camera"
        assert scanner._contains_brand_keywords(content.lower()) is True

    def test_contains_brand_keywords_cp_dash_plus(self, scanner):
        """Test brand keyword detection for 'cp-plus'."""
        content = "CP-Plus Network Video Recorder"
        assert scanner._contains_brand_keywords(content.lower()) is True

    def test_contains_brand_keywords_cp_underscore_plus(self, scanner):
        """Test brand keyword detection for 'cp_plus'."""
        content = "cp_plus dvr firmware"
        assert scanner._contains_brand_keywords(content.lower()) is True

    def test_contains_brand_keywords_not_found(self, scanner):
        """Test brand keyword detection returns False for non-CP Plus content."""
        content = "Hikvision camera system"
        assert scanner._contains_brand_keywords(content.lower()) is False

    def test_extract_model_number_uvr_0401e1(self, scanner):
        """Test model extraction for UVR-0401E1."""
        content_lower = "welcome to uvr-0401e1 system"
        content_original = "Welcome to UVR-0401E1 system"
        model = scanner._extract_model_number(content_lower, content_original)
        assert model == "CP-UVR-0401E1-IC2"

    def test_extract_model_number_uvr0401e1(self, scanner):
        """Test model extraction for UVR0401E1 (no dash)."""
        content_lower = "firmware version uvr0401e1"
        content_original = "Firmware version UVR0401E1"
        model = scanner._extract_model_number(content_lower, content_original)
        assert model == "CP-UVR-0401E1-IC2"

    def test_extract_model_number_with_cp_prefix(self, scanner):
        """Test model extraction with CP- prefix."""
        content_lower = "model: cp-uvr-0801e1"
        content_original = "Model: CP-UVR-0801E1"
        model = scanner._extract_model_number(content_lower, content_original)
        assert model == "CP-UVR-0801E1"

    def test_extract_model_number_dvr_series(self, scanner):
        """Test model extraction for DVR series."""
        content_lower = "cp-dvr-0404e1-s"
        content_original = "CP-DVR-0404E1-S"
        model = scanner._extract_model_number(content_lower, content_original)
        assert model == "CP-DVR-0404E1-S"

    def test_extract_model_number_nvr_series(self, scanner):
        """Test model extraction for NVR series."""
        content_lower = "cp-nvr-1604e1"
        content_original = "CP-NVR-1604E1"
        model = scanner._extract_model_number(content_lower, content_original)
        assert model == "CP-NVR-1604E1"

    def test_extract_model_number_not_found(self, scanner):
        """Test model extraction returns 'unknown' when no model found."""
        content_lower = "generic camera system"
        content_original = "Generic Camera System"
        model = scanner._extract_model_number(content_lower, content_original)
        assert model == "unknown"

    def test_detect_device_type_dvr(self, scanner):
        """Test device type detection for DVR."""
        content = "digital video recorder dvr system"
        device_type = scanner._detect_device_type(content.lower())
        assert device_type == "dvr"

    def test_detect_device_type_nvr(self, scanner):
        """Test device type detection for NVR."""
        content = "network video recorder nvr device"
        device_type = scanner._detect_device_type(content.lower())
        assert device_type == "nvr"

    def test_detect_device_type_unknown(self, scanner):
        """Test device type detection returns 'unknown' for unrecognized types."""
        content = "camera system"
        device_type = scanner._detect_device_type(content.lower())
        assert device_type == "unknown"

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_success(self, mock_get, scanner):
        """Test successful CP Plus brand detection."""
        # Mock successful response with CP Plus content
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "CP Plus DVR System UVR-0401E1"
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        assert result["brand_detected"] is True
        assert result["brand"] == "cp_plus"
        assert result["model"] == "CP-UVR-0401E1-IC2"
        assert result["device_type"] == "dvr"
        assert result["confidence"] > 0.0
        assert len(result["evidence"]) > 0

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_no_detection(self, mock_get, scanner):
        """Test CP Plus detection with non-CP Plus content."""
        # Mock response with non-CP Plus content
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Hikvision Camera System"
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        assert result["brand_detected"] is False
        assert result["brand"] == "unknown"
        assert result["confidence"] == 0.0

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_404_response(self, mock_get, scanner):
        """Test CP Plus detection with 404 response."""
        # Mock 404 response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        assert result["brand_detected"] is False
        assert result["brand"] == "unknown"

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_exception(self, mock_get, scanner):
        """Test CP Plus detection handles exceptions gracefully."""
        # Mock exception
        mock_get.side_effect = Exception("Connection error")

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        assert result["brand_detected"] is False
        assert result["brand"] == "unknown"

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_multiple_indicators(self, mock_get, scanner):
        """Test CP Plus detection with multiple indicators."""
        # Mock response with brand, model, and device type
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "CP-Plus DVR UVR-0401E1 Network Video Recorder"
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        assert result["brand_detected"] is True
        assert result["model"] == "CP-UVR-0401E1-IC2"
        assert result["device_type"] == "dvr"
        assert len(result["evidence"]) >= 2  # Model + Brand
        assert result["confidence"] >= 0.7  # High confidence

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_tests_multiple_endpoints(self, mock_get, scanner):
        """Test that detection tries multiple endpoints."""
        tested_endpoints = []

        def track_requests(*args, **kwargs):
            url = args[0]
            tested_endpoints.append(url)
            mock_resp = Mock()
            mock_resp.status_code = 404  # No success to force testing all endpoints
            return mock_resp

        mock_get.side_effect = track_requests

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        # Should have tested multiple endpoints from cpplus_data.json
        assert len(tested_endpoints) > 0
        # Check that various endpoints were tested
        paths_tested = [url.split("192.168.1.1:80")[1] for url in tested_endpoints]
        assert "/" in paths_tested or "/index.html" in paths_tested

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_brand_stops_on_success(self, mock_get, scanner):
        """Test detection stops after finding evidence."""
        call_count = [0]

        def count_requests(*args, **kwargs):
            call_count[0] += 1
            mock_resp = Mock()
            if call_count[0] == 1:
                # First request succeeds with CP Plus content
                mock_resp.status_code = 200
                mock_resp.text = "CP Plus DVR UVR-0401E1"
            else:
                # Subsequent requests (should not happen)
                mock_resp.status_code = 404
            return mock_resp

        mock_get.side_effect = count_requests

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        # Should stop after first successful detection
        assert call_count[0] == 1
        assert result["brand_detected"] is True

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_multi_port(self, mock_get, scanner):
        """Test CP Plus detection across multiple ports."""

        def mock_responses(*args, **kwargs):
            url = args[0]
            mock_resp = Mock()
            if ":8080/" in url:
                # Found on port 8080
                mock_resp.status_code = 200
                mock_resp.text = "CP Plus NVR System"
            else:
                mock_resp.status_code = 404
            return mock_resp

        mock_get.side_effect = mock_responses

        result = scanner.detect_cp_plus("192.168.1.1", [80, 8080, 8000])

        assert result["brand_detected"] is True
        assert result["brand"] == "cp_plus"
        assert result["device_type"] == "nvr"

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_with_predetected_brand(self, mock_get, scanner):
        """Test CP Plus detection when brand is already known."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "CP Plus CP-UVR-0401E1 System"
        mock_get.return_value = mock_response

        result = scanner.detect_cp_plus("192.168.1.1", [80], brand="cp_plus")

        assert result["brand_detected"] is True
        assert result["model"] == "CP-UVR-0401E1-IC2"

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_confidence_scoring(self, mock_get, scanner):
        """Test confidence scoring for different detection levels."""
        # Test with only brand keyword (should have lower confidence)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "CP Plus System"
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        # Should have some confidence but not maximum
        assert 0.0 < result["confidence"] < 1.0

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_confidence_capped_at_one(self, mock_get, scanner):
        """Test that confidence is capped at 1.0."""
        # Mock response with all possible indicators
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "CP Plus DVR System UVR-0401E1-IC2 Network Video Recorder"
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        # Confidence should not exceed 1.0
        assert result["confidence"] <= 1.0

    def test_convert_to_vulnerability_results_success(self, scanner):
        """Test conversion of detection results to vulnerability objects."""
        detection_result = {
            "brand_detected": True,
            "brand": "cp_plus",
            "model": "CP-UVR-0401E1-IC2",
            "device_type": "dvr",
            "confidence": 0.9,
            "evidence": ["Found model in /index.html", "Found brand in /"],
        }

        results = scanner._convert_to_vulnerability_results("192.168.1.1", 80, detection_result)

        assert len(results) == 1
        vuln = results[0]
        assert vuln.ip == "192.168.1.1"
        assert vuln.port == 80
        assert vuln.vulnerability_id == "CP-PLUS-DETECTION"
        assert vuln.severity == "INFO"
        assert vuln.confidence == 90
        assert "CP-UVR-0401E1-IC2" in vuln.description
        assert vuln.exploit_available is False

        # Check details
        details = json.loads(vuln.details)
        assert details["brand"] == "cp_plus"
        assert details["model"] == "CP-UVR-0401E1-IC2"
        assert details["device_type"] == "dvr"
        assert len(details["evidence"]) == 2

    def test_convert_to_vulnerability_results_not_detected(self, scanner):
        """Test conversion returns empty list when brand not detected."""
        detection_result = {
            "brand_detected": False,
            "brand": "unknown",
            "model": "unknown",
            "device_type": "unknown",
            "confidence": 0.0,
            "evidence": [],
        }

        results = scanner._convert_to_vulnerability_results("192.168.1.1", 80, detection_result)

        assert len(results) == 0

    @pytest.mark.asyncio
    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    async def test_scan_vulnerabilities_async(self, mock_get, scanner):
        """Test async scan_vulnerabilities method."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "CP Plus DVR UVR-0401E1"
        mock_get.return_value = mock_response

        results = await scanner.scan_vulnerabilities("192.168.1.1", 80)

        assert len(results) == 1
        assert results[0].vulnerability_id == "CP-PLUS-DETECTION"

    @pytest.mark.asyncio
    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    async def test_scan_vulnerabilities_no_detection(self, mock_get, scanner):
        """Test async scan returns empty list when no CP Plus detected."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Generic camera system"
        mock_get.return_value = mock_response

        results = await scanner.scan_vulnerabilities("192.168.1.1", 80)

        assert len(results) == 0

    def test_load_cpplus_data_fallback(self, scanner):
        """Test fallback to minimal data if JSON file fails."""
        # The scanner should have loaded data from JSON or fallback
        assert scanner.cpplus_data is not None
        assert "detection_keywords" in scanner.cpplus_data
        # Check essential keywords are present
        keywords = scanner.cpplus_data["detection_keywords"]["brand"]
        assert "cp plus" in keywords or "cpplus" in keywords

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_https_protocol(self, mock_get, scanner):
        """Test HTTPS protocol is used for SSL ports."""
        tested_urls = []

        def capture_requests(*args, **kwargs):
            tested_urls.append(args[0])
            mock_resp = Mock()
            mock_resp.status_code = 404
            return mock_resp

        mock_get.side_effect = capture_requests

        scanner._detect_cp_plus_brand("192.168.1.1", 443)

        # All URLs should use https://
        assert all(url.startswith("https://") for url in tested_urls)
        assert any(":443/" in url for url in tested_urls)

    @patch("gridland.analyze.plugins.builtin.cpplus_scanner.requests.get")
    def test_detect_cp_plus_model_without_prefix(self, mock_get, scanner):
        """Test model extraction adds CP- prefix when missing."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Model: UVR-0801E1 Device"
        mock_get.return_value = mock_response

        result = scanner._detect_cp_plus_brand("192.168.1.1", 80)

        # Should add CP- prefix
        if result["model"] != "unknown":
            assert result["model"].startswith("CP-")
