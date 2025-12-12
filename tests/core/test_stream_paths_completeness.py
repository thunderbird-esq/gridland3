#!/usr/bin/env python3
"""
Test stream paths completeness against CamXploit.py baseline.

This test ensures that GRIDLAND's stream_paths.json contains all paths
from the original CamXploit.py implementation (lines 1579-1683) plus
enhancements for modern camera systems.

TASKS 033-042: Stream Paths Verification
"""

import json
from pathlib import Path

import pytest


class TestStreamPathsCompleteness:
    """Verify stream_paths.json completeness against CamXploit.py baseline."""

    @pytest.fixture(scope="class")
    def stream_paths_data(self):
        """Load stream_paths.json data."""
        stream_paths_file = (
            Path(__file__).parent.parent.parent / "gridland" / "data" / "stream_paths.json"
        )
        with open(stream_paths_file) as f:
            return json.load(f)

    @pytest.fixture(scope="class")
    def camxploit_baseline(self):
        """
        CamXploit.py baseline paths from lines 1579-1683.

        These are the canonical paths that must be present in GRIDLAND's
        implementation to ensure feature parity with the original tool.
        """
        return {
            "rtsp": [
                # Generic RTSP paths
                "/live.sdp",
                "/h264.sdp",
                "/stream1",
                "/stream2",
                "/main",
                "/sub",
                "/video",
                "/cam/realmonitor",
                "/Streaming/Channels/1",
                "/Streaming/Channels/101",
                # Brand-specific paths (ONVIF, Axis, Hikvision, etc.)
                "/onvif/streaming/channels/1",
                "/axis-media/media.amp",
                "/axis-cgi/mjpg/video.cgi",
                "/cgi-bin/mjpg/video.cgi",
                "/cgi-bin/hi3510/snap.cgi",
                "/cgi-bin/snapshot.cgi",
                "/cgi-bin/viewer/video.jpg",
                "/img/snapshot.cgi",
                "/snapshot.jpg",
                "/video/mjpg.cgi",
                "/video.cgi",
                "/videostream.cgi",
                "/mjpg/video.mjpg",
                "/mjpg.cgi",
                "/stream.cgi",
                "/live.cgi",
                # ONVIF standard paths
                "/live/0/onvif.sdp",
                "/live/0/h264.sdp",
                "/live/0/mpeg4.sdp",
                "/live/0/audio.sdp",
                "/live/1/onvif.sdp",
                "/live/1/h264.sdp",
                "/live/1/mpeg4.sdp",
                "/live/1/audio.sdp",
            ],
            "rtmp": [
                "/live",
                "/stream",
                "/hls",
                "/flv",
                "/rtmp",
                "/live/stream",
                "/live/stream1",
                "/live/stream2",
                "/live/main",
                "/live/sub",
                "/live/video",
                "/live/audio",
                "/live/av",
                "/live/rtmp",
                "/live/rtmps",
            ],
            "http": [
                # Generic HTTP paths
                "/video",
                "/stream",
                "/mjpg/video.mjpg",
                "/cgi-bin/mjpg/video.cgi",
                "/axis-cgi/mjpg/video.cgi",
                "/cgi-bin/viewer/video.jpg",
                "/snapshot.jpg",
                "/img/snapshot.cgi",
                # ONVIF HTTP endpoints
                "/onvif/device_service",
                "/onvif/streaming",
                # Axis control endpoints
                "/axis-cgi/com/ptz.cgi",
                "/axis-cgi/param.cgi",
                # CGI endpoints
                "/cgi-bin/snapshot.cgi",
                "/cgi-bin/hi3510/snap.cgi",
                "/video/mjpg.cgi",
                "/video.cgi",
                "/videostream.cgi",
                "/mjpg.cgi",
                "/stream.cgi",
                "/live.cgi",
                # API endpoints
                "/api/video",
                "/api/stream",
                "/api/live",
                "/api/video/live",
                "/api/stream/live",
                "/api/camera/live",
                "/api/camera/stream",
                "/api/camera/video",
                "/api/camera/snapshot",
                "/api/camera/image",
                "/api/camera/feed",
                "/api/camera/feed/live",
                "/api/camera/feed/stream",
                "/api/camera/feed/video",
                # CP Plus specific
                "/cgi-bin/video.cgi",
                "/cgi-bin/stream.cgi",
                "/cgi-bin/live.cgi",
            ],
        }

    def flatten_protocol_paths(self, protocol_data):
        """
        Flatten nested protocol paths into a single list.

        Args:
            protocol_data: Dictionary or list of paths, potentially nested

        Returns:
            List of all paths found in the structure
        """
        paths = []
        if isinstance(protocol_data, dict):
            for key, value in protocol_data.items():
                if isinstance(value, list):
                    paths.extend(value)
                elif isinstance(value, dict):
                    paths.extend(self.flatten_protocol_paths(value))
        elif isinstance(protocol_data, list):
            paths.extend(protocol_data)
        return paths

    def test_rtsp_paths_completeness(self, stream_paths_data, camxploit_baseline):
        """Verify all CamXploit.py RTSP paths are present in GRIDLAND."""
        gridland_rtsp = set(self.flatten_protocol_paths(stream_paths_data["protocols"]["rtsp"]))
        baseline_rtsp = set(camxploit_baseline["rtsp"])

        missing = baseline_rtsp - gridland_rtsp

        assert (
            not missing
        ), f"Missing {len(missing)} RTSP paths from CamXploit.py baseline:\n" + "\n".join(
            f"  - {path}" for path in sorted(missing)
        )

        # Also verify we have a good number of enhanced paths
        assert len(gridland_rtsp) >= len(
            baseline_rtsp
        ), "GRIDLAND should have at least as many RTSP paths as CamXploit.py baseline"

    def test_rtmp_paths_completeness(self, stream_paths_data, camxploit_baseline):
        """Verify all CamXploit.py RTMP paths are present in GRIDLAND."""
        gridland_rtmp = set(self.flatten_protocol_paths(stream_paths_data["protocols"]["rtmp"]))
        baseline_rtmp = set(camxploit_baseline["rtmp"])

        missing = baseline_rtmp - gridland_rtmp

        assert (
            not missing
        ), f"Missing {len(missing)} RTMP paths from CamXploit.py baseline:\n" + "\n".join(
            f"  - {path}" for path in sorted(missing)
        )

    def test_http_paths_completeness(self, stream_paths_data, camxploit_baseline):
        """Verify all CamXploit.py HTTP paths are present in GRIDLAND."""
        gridland_http = set(self.flatten_protocol_paths(stream_paths_data["protocols"]["http"]))
        baseline_http = set(camxploit_baseline["http"])

        missing = baseline_http - gridland_http

        assert (
            not missing
        ), f"Missing {len(missing)} HTTP paths from CamXploit.py baseline:\n" + "\n".join(
            f"  - {path}" for path in sorted(missing)
        )

    def test_minimum_path_count(self, stream_paths_data):
        """Verify GRIDLAND has at least 138 stream paths (CamXploit.py requirement)."""
        total_paths = 0
        for protocol in ["rtsp", "rtmp", "http"]:
            paths = self.flatten_protocol_paths(stream_paths_data["protocols"][protocol])
            total_paths += len(paths)

        assert total_paths >= 138, (
            f"GRIDLAND must have at least 138 stream paths (CamXploit.py baseline + enhancements). "
            f"Found {total_paths}"
        )

    def test_total_path_count_exceeds_baseline(self, stream_paths_data, camxploit_baseline):
        """Verify GRIDLAND has more paths than the baseline (enhancements present)."""
        gridland_total = sum(
            len(self.flatten_protocol_paths(stream_paths_data["protocols"][proto]))
            for proto in ["rtsp", "rtmp", "http"]
        )

        baseline_total = sum(len(camxploit_baseline[proto]) for proto in ["rtsp", "rtmp", "http"])

        assert gridland_total > baseline_total, (
            f"GRIDLAND should have MORE paths than CamXploit.py baseline (enhancements). "
            f"GRIDLAND: {gridland_total}, Baseline: {baseline_total}"
        )

    def test_protocol_categorization(self, stream_paths_data):
        """Verify protocols are properly categorized by type."""
        protocols = stream_paths_data["protocols"]

        # RTSP should have brand-specific categories
        assert "rtsp" in protocols
        assert isinstance(protocols["rtsp"], dict)
        assert "generic" in protocols["rtsp"]
        assert "hikvision" in protocols["rtsp"]
        assert "dahua" in protocols["rtsp"]
        assert "axis" in protocols["rtsp"]
        assert "onvif" in protocols["rtsp"]

        # RTMP should have categories
        assert "rtmp" in protocols
        assert isinstance(protocols["rtmp"], dict)
        assert "generic" in protocols["rtmp"]

        # HTTP should have functional categories
        assert "http" in protocols
        assert isinstance(protocols["http"], dict)
        assert "snapshots" in protocols["http"]
        assert "mjpeg_streams" in protocols["http"]
        assert "api_endpoints" in protocols["http"]
        assert "brand_specific" in protocols["http"]

    def test_brand_specific_paths(self, stream_paths_data):
        """Verify brand-specific paths are documented."""
        rtsp_brands = stream_paths_data["protocols"]["rtsp"]
        http_brands = stream_paths_data["protocols"]["http"]["brand_specific"]

        # RTSP brands
        required_rtsp_brands = ["hikvision", "dahua", "axis", "sony", "foscam"]
        for brand in required_rtsp_brands:
            assert brand in rtsp_brands, f"Missing {brand} in RTSP paths"
            assert len(rtsp_brands[brand]) > 0, f"No paths for {brand} in RTSP"

        # HTTP brands
        required_http_brands = ["hikvision", "dahua", "axis", "foscam", "onvif"]
        for brand in required_http_brands:
            assert brand in http_brands, f"Missing {brand} in HTTP brand_specific paths"
            assert len(http_brands[brand]) > 0, f"No paths for {brand} in HTTP"

    def test_onvif_standard_compliance(self, stream_paths_data):
        """Verify ONVIF standard paths are present."""
        rtsp_onvif = stream_paths_data["protocols"]["rtsp"]["onvif"]
        http_onvif = stream_paths_data["protocols"]["http"]["brand_specific"]["onvif"]

        # RTSP ONVIF paths
        assert "/onvif/streaming/channels/1" in rtsp_onvif
        assert "/live/0/onvif.sdp" in rtsp_onvif
        assert "/live/1/onvif.sdp" in rtsp_onvif

        # HTTP ONVIF paths
        assert "/onvif/device_service" in http_onvif
        assert "/onvif/streaming" in http_onvif

    def test_high_success_paths_documented(self, stream_paths_data):
        """Verify high-success paths are documented for optimization."""
        assert "optimization" in stream_paths_data
        assert "high_success_paths" in stream_paths_data["optimization"]

        high_success = stream_paths_data["optimization"]["high_success_paths"]
        assert len(high_success) > 0, "No high-success paths documented"

        # Verify common high-success paths
        assert "/snapshot.jpg" in high_success
        assert "/live.sdp" in high_success

    def test_content_types_defined(self, stream_paths_data):
        """Verify content types are defined for stream detection."""
        assert "content_types" in stream_paths_data

        content_types = stream_paths_data["content_types"]
        assert "video" in content_types
        assert "image" in content_types
        assert "stream" in content_types

        # Verify common MIME types
        assert "image/jpeg" in content_types["image"]
        assert "video/h264" in content_types["video"]
        assert "multipart/x-mixed-replace" in content_types["stream"]

    def test_detection_patterns_defined(self, stream_paths_data):
        """Verify detection patterns are defined for protocol identification."""
        assert "detection_patterns" in stream_paths_data

        patterns = stream_paths_data["detection_patterns"]
        assert "rtsp_success" in patterns
        assert "http_stream_indicators" in patterns
        assert "authentication_challenges" in patterns

        # Verify key patterns
        assert "RTSP/1.0 200 OK" in patterns["rtsp_success"]
        assert "WWW-Authenticate" in patterns["authentication_challenges"]

    def test_port_protocols_mapping(self, stream_paths_data):
        """Verify port-to-protocol mappings are defined."""
        assert "port_protocols" in stream_paths_data

        port_protocols = stream_paths_data["port_protocols"]
        assert "rtsp" in port_protocols
        assert "rtmp" in port_protocols
        assert "http" in port_protocols
        assert "https" in port_protocols

        # Verify standard ports
        assert 554 in port_protocols["rtsp"]
        assert 1935 in port_protocols["rtmp"]
        assert 80 in port_protocols["http"]
        assert 443 in port_protocols["https"]

    def test_metadata_version_tracking(self, stream_paths_data):
        """Verify metadata is properly tracked."""
        assert "version" in stream_paths_data
        assert "last_updated" in stream_paths_data
        assert "source" in stream_paths_data

        # Version should be 2.1 or higher after our updates
        version = float(stream_paths_data["version"])
        assert version >= 2.1, f"Expected version >= 2.1, got {version}"


class TestStreamPathsStructure:
    """Test the structure and organization of stream_paths.json."""

    @pytest.fixture(scope="class")
    def stream_paths_data(self):
        """Load stream_paths.json data."""
        stream_paths_file = (
            Path(__file__).parent.parent.parent / "gridland" / "data" / "stream_paths.json"
        )
        with open(stream_paths_file) as f:
            return json.load(f)

    def test_json_validity(self, stream_paths_data):
        """Verify JSON is valid and can be loaded."""
        assert stream_paths_data is not None
        assert isinstance(stream_paths_data, dict)

    def test_no_duplicate_paths_within_protocol(self, stream_paths_data):
        """Verify no duplicate paths within each brand section of a protocol.

        Note: Duplicates across different brands are allowed since common paths
        like /live.sdp can be used by multiple camera manufacturers.
        """
        for protocol_name, protocol_data in stream_paths_data["protocols"].items():
            if isinstance(protocol_data, dict):
                # Check for duplicates within each brand section
                for brand_name, brand_paths in protocol_data.items():
                    if isinstance(brand_paths, list):
                        duplicates = [
                            path for path in set(brand_paths) if brand_paths.count(path) > 1
                        ]
                        assert (
                            not duplicates
                        ), f"Duplicate paths found in {protocol_name}/{brand_name}:\n" + "\n".join(
                            f"  - {path}" for path in duplicates
                        )

    def test_all_paths_start_with_slash(self, stream_paths_data):
        """Verify all paths start with forward slash."""

        def check_paths(data, protocol_name):
            if isinstance(data, dict):
                for value in data.values():
                    check_paths(value, protocol_name)
            elif isinstance(data, list):
                for path in data:
                    assert path.startswith(
                        "/"
                    ), f"Path '{path}' in {protocol_name} does not start with '/'"

        for protocol_name, protocol_data in stream_paths_data["protocols"].items():
            check_paths(protocol_data, protocol_name)

    def test_websocket_protocol_present(self, stream_paths_data):
        """Verify WebSocket protocol support (enhancement beyond CamXploit.py)."""
        assert "websocket" in stream_paths_data["protocols"]
        ws_paths = stream_paths_data["protocols"]["websocket"]
        assert len(ws_paths) > 0, "No WebSocket paths defined"

    def test_webrtc_protocol_present(self, stream_paths_data):
        """Verify WebRTC protocol support (enhancement beyond CamXploit.py)."""
        assert "webrtc" in stream_paths_data["protocols"]
        webrtc_paths = stream_paths_data["protocols"]["webrtc"]
        assert len(webrtc_paths) > 0, "No WebRTC paths defined"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
