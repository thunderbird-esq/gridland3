"""Unit tests for Brand Detector.

Tests camera brand detection from HTTP response data including server headers,
content types, and response bodies.
"""

from gridland.analyze.core.brand_detector import BrandDetector


class TestBrandDetector:
    """Tests for BrandDetector class."""

    def test_camera_servers_dict_exists(self):
        """Test that CAMERA_SERVERS dictionary is properly defined."""
        detector = BrandDetector()
        assert hasattr(detector, "CAMERA_SERVERS")
        assert isinstance(detector.CAMERA_SERVERS, dict)
        assert len(detector.CAMERA_SERVERS) == 10  # 9 brands + generic

    def test_camera_content_types_list_exists(self):
        """Test that CAMERA_CONTENT_TYPES list is properly defined."""
        detector = BrandDetector()
        assert hasattr(detector, "CAMERA_CONTENT_TYPES")
        assert isinstance(detector.CAMERA_CONTENT_TYPES, list)
        assert len(detector.CAMERA_CONTENT_TYPES) == 10

    def test_detect_brand_hikvision_server_header(self):
        """Test Hikvision detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "hikvision-webs",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "hikvision"
        assert result["confidence"] == 1.0
        assert any("server_header" in e for e in result["evidence"])

    def test_detect_brand_dahua_server_header(self):
        """Test Dahua detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Dahua-HTTP/1.0",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "dahua"
        assert result["confidence"] == 1.0
        assert any("server_header" in e for e in result["evidence"])

    def test_detect_brand_axis_server_header(self):
        """Test Axis detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Axis/2.0",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "axis"
        assert result["confidence"] == 1.0
        assert any("server_header" in e for e in result["evidence"])

    def test_detect_brand_axis_communications(self):
        """Test Axis Communications detection via full name."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Axis Communications AB",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "axis"
        assert result["confidence"] == 1.0

    def test_detect_brand_sony_server_header(self):
        """Test Sony detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Sony IPELA Engine",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "sony"
        assert result["confidence"] == 1.0

    def test_detect_brand_bosch_server_header(self):
        """Test Bosch detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Bosch Security Systems",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "bosch"
        assert result["confidence"] == 1.0

    def test_detect_brand_samsung_server_header(self):
        """Test Samsung detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Samsung Techwin",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "samsung"
        assert result["confidence"] == 1.0

    def test_detect_brand_panasonic_server_header(self):
        """Test Panasonic detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Panasonic Network Camera",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "panasonic"
        assert result["confidence"] == 1.0

    def test_detect_brand_vivotek_server_header(self):
        """Test Vivotek detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "Vivotek-HTTP/1.0",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "vivotek"
        assert result["confidence"] == 1.0

    def test_detect_brand_cp_plus_server_header(self):
        """Test CP Plus detection via server header."""
        detector = BrandDetector()
        port_data = {
            "server_header": "CP-Plus-WebServer/1.0",
            "content_type": "text/html",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "cp plus"
        assert result["confidence"] == 1.0

    def test_detect_brand_cp_plus_body_cpplus(self):
        """Test CP Plus detection via body with 'cpplus' indicator."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "text/html",
            "response_body": "<html>Welcome to CPPLUS DVR System</html>",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "cp plus"
        assert result["confidence"] == 1.0
        assert any("cp_plus_indicators" in e for e in result["evidence"])

    def test_detect_brand_cp_plus_body_uvr(self):
        """Test CP Plus detection via body with 'uvr' indicator."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "text/html",
            "response_body": "<html>UVR Login Page</html>",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "cp plus"
        assert result["confidence"] == 1.0

    def test_detect_brand_cp_plus_body_0401e1(self):
        """Test CP Plus detection via body with '0401e1' indicator."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "text/html",
            "response_body": "var model = '0401e1';",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "cp plus"
        assert result["confidence"] == 1.0

    def test_detect_brand_generic_camera_content_type(self):
        """Test generic camera detection via content type."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "image/jpeg",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "generic"
        assert result["confidence"] == 0.5
        assert any("content_type" in e for e in result["evidence"])

    def test_detect_brand_generic_mjpeg_content_type(self):
        """Test generic camera detection via MJPEG content type."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "image/mjpeg",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "generic"
        assert result["confidence"] == 0.5

    def test_detect_brand_generic_video_content_type(self):
        """Test generic camera detection via video content type."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "video/mp4",
            "response_body": "",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "generic"
        assert result["confidence"] == 0.5

    def test_detect_brand_generic_body_keywords(self):
        """Test generic camera detection via body keywords."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "text/html",
            "response_body": "<html><title>Surveillance Camera</title></html>",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "generic"
        assert result["confidence"] == 0.7  # 2 evidence sources: content_type + body_keywords
        assert any("body_keywords" in e for e in result["evidence"])

    def test_detect_brand_generic_dvr_keyword(self):
        """Test generic camera detection with DVR keyword."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "text/html",
            "response_body": "Digital Video Recorder Login",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "generic"
        assert result["confidence"] == 0.7  # 2 evidence sources: content_type + body_keywords

    def test_detect_brand_generic_cctv_keyword(self):
        """Test generic camera detection with CCTV keyword."""
        detector = BrandDetector()
        port_data = {
            "server_header": "",
            "content_type": "text/html",
            "response_body": "CCTV Monitoring System",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "generic"
        assert result["confidence"] == 0.7  # 2 evidence sources: content_type + body_keywords

    def test_detect_brand_unknown_no_evidence(self):
        """Test unknown brand when no evidence is found."""
        detector = BrandDetector()
        port_data = {
            "server_header": "nginx/1.18",
            "content_type": "text/plain",
            "response_body": "Hello World",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["evidence"] == []

    def test_detect_brand_empty_port_data(self):
        """Test brand detection with empty port data."""
        detector = BrandDetector()
        port_data = {}
        result = detector.detect_brand(port_data)

        assert result["brand"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["evidence"] == []

    def test_detect_brand_case_insensitive(self):
        """Test that brand detection is case-insensitive."""
        detector = BrandDetector()
        port_data = {
            "server_header": "HIKVISION-WEBS",
            "content_type": "TEXT/HTML",
            "response_body": "<HTML>DVR SYSTEM</HTML>",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "hikvision"
        assert result["confidence"] == 1.0

    def test_detect_brand_multiple_evidence_sources(self):
        """Test brand detection with multiple evidence sources."""
        detector = BrandDetector()
        port_data = {
            "server_header": "hikvision-webs",
            "content_type": "image/jpeg",
            "response_body": "<html>Camera Surveillance System</html>",
        }
        result = detector.detect_brand(port_data)

        assert result["brand"] == "hikvision"
        assert result["confidence"] == 1.0
        assert len(result["evidence"]) >= 2

    def test_analyze_all_ports_empty_list(self):
        """Test analyze_all_ports with empty port list."""
        detector = BrandDetector()
        result = detector.analyze_all_ports([])

        assert result["brand"] == "unknown"
        assert result["confidence"] == 0.0
        assert result["evidence"] == []
        assert result["all_detections"] == []

    def test_analyze_all_ports_single_port(self):
        """Test analyze_all_ports with single port."""
        detector = BrandDetector()
        ports_data = [
            {
                "server_header": "hikvision-webs",
                "content_type": "text/html",
                "response_body": "",
                "port": 80,
            }
        ]
        result = detector.analyze_all_ports(ports_data)

        assert result["brand"] == "hikvision"
        assert result["confidence"] == 1.0
        assert len(result["all_detections"]) == 1
        assert "port 80" in result["evidence"][0]

    def test_analyze_all_ports_consistent_brand(self):
        """Test analyze_all_ports with consistent brand across ports."""
        detector = BrandDetector()
        ports_data = [
            {"server_header": "hikvision-webs", "port": 80},
            {"response_body": "hikvision dvr system", "port": 8080},
        ]
        result = detector.analyze_all_ports(ports_data)

        assert result["brand"] == "hikvision"
        assert result["confidence"] == 1.0
        assert len(result["all_detections"]) == 2

    def test_analyze_all_ports_conflict_resolution(self):
        """Test conflict resolution when different brands detected."""
        detector = BrandDetector()
        ports_data = [
            {"server_header": "hikvision-webs", "port": 80},
            {"server_header": "DNVRS-Webs", "port": 8080},
        ]
        result = detector.analyze_all_ports(ports_data)

        # Should pick one of the brands with confidence 1.0
        assert result["brand"] in ["hikvision", "dahua"]
        assert result["confidence"] == 1.0
        assert len(result["all_detections"]) == 2

    def test_analyze_all_ports_generic_vs_specific(self):
        """Test that specific brands are preferred over generic."""
        detector = BrandDetector()
        ports_data = [
            {"response_body": "camera surveillance", "port": 80},  # generic
            {"server_header": "axis/2.0", "port": 8080},  # specific
        ]
        result = detector.analyze_all_ports(ports_data)

        assert result["brand"] == "axis"
        assert result["confidence"] == 1.0

    def test_analyze_all_ports_all_generic(self):
        """Test analyze_all_ports when all ports indicate generic."""
        detector = BrandDetector()
        ports_data = [
            {"response_body": "camera system", "port": 80},
            {"content_type": "image/jpeg", "port": 8080},
        ]
        result = detector.analyze_all_ports(ports_data)

        assert result["brand"] == "generic"
        assert result["confidence"] > 0.0

    def test_analyze_all_ports_mixed_confidence(self):
        """Test analyze_all_ports with mixed confidence levels."""
        detector = BrandDetector()
        ports_data = [
            {"server_header": "hikvision-webs", "port": 80},  # confidence 1.0
            {"content_type": "image/jpeg", "port": 8080},  # confidence 0.5
        ]
        result = detector.analyze_all_ports(ports_data)

        # Should choose hikvision with higher confidence
        assert result["brand"] == "hikvision"
        assert result["confidence"] == 1.0

    def test_analyze_all_ports_aggregates_evidence(self):
        """Test that evidence from all ports is aggregated."""
        detector = BrandDetector()
        ports_data = [
            {"server_header": "hikvision-webs", "port": 80},
            {"response_body": "dvr camera", "port": 8080},
        ]
        result = detector.analyze_all_ports(ports_data)

        assert len(result["evidence"]) >= 2
        assert any("port 80" in e for e in result["evidence"])
        assert any("port 8080" in e for e in result["evidence"])

    def test_analyze_all_ports_no_port_number(self):
        """Test analyze_all_ports when port number is not provided."""
        detector = BrandDetector()
        ports_data = [{"server_header": "axis/2.0"}]
        result = detector.analyze_all_ports(ports_data)

        assert result["brand"] == "axis"
        assert "port unknown" in result["evidence"][0]

    def test_detect_brand_dvr_in_server_header_hikvision(self):
        """Test that DVR in header can detect Hikvision."""
        detector = BrandDetector()
        port_data = {"server_header": "DVR-Webs hikvision"}
        result = detector.detect_brand(port_data)

        assert result["brand"] == "hikvision"

    def test_detect_brand_nvr_in_server_header_dahua(self):
        """Test that Dahua keyword in header detects Dahua."""
        detector = BrandDetector()
        port_data = {"server_header": "Dahua NVR-Webs"}
        result = detector.detect_brand(port_data)

        assert result["brand"] == "dahua"

    def test_evidence_list_structure(self):
        """Test that evidence list contains properly formatted strings."""
        detector = BrandDetector()
        port_data = {
            "server_header": "hikvision-webs",
            "content_type": "image/jpeg",
            "response_body": "camera dvr",
        }
        result = detector.detect_brand(port_data)

        assert isinstance(result["evidence"], list)
        assert all(isinstance(e, str) for e in result["evidence"])
        assert len(result["evidence"]) >= 1

    def test_confidence_range(self):
        """Test that confidence scores are always in valid range [0.0, 1.0]."""
        detector = BrandDetector()
        test_cases = [
            {"server_header": "hikvision-webs"},
            {"content_type": "image/jpeg"},
            {"response_body": "camera"},
            {"server_header": "nginx"},
            {},
        ]

        for port_data in test_cases:
            result = detector.detect_brand(port_data)
            assert 0.0 <= result["confidence"] <= 1.0
