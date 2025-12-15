"""
Comprehensive test suite for stream_intelligence.py module.

Tests cover:
- StreamProtocol and StreamQuality enums
- StreamEndpoint and StreamTopology dataclasses
- StreamPathDatabase initialization and path retrieval
- AdvancedStreamDiscovery methods with mocked HTTP
- StreamQualityAssessor, StreamTopologyMapper, VulnerabilityCorrelator
"""

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from gridland.analyze.core.stream_intelligence import (
    StreamProtocol,
    StreamQuality,
    StreamEndpoint,
    StreamTopology,
    StreamPathDatabase,
    AdvancedStreamDiscovery,
    StreamQualityAssessor,
    StreamTopologyMapper,
    VulnerabilityCorrelator,
)


class TestStreamProtocolEnum:
    """Test StreamProtocol enumeration."""

    def test_rtsp_value(self):
        """Test RTSP protocol value."""
        assert StreamProtocol.RTSP.value == "rtsp"

    def test_rtmp_value(self):
        """Test RTMP protocol value."""
        assert StreamProtocol.RTMP.value == "rtmp"

    def test_http_value(self):
        """Test HTTP protocol value."""
        assert StreamProtocol.HTTP.value == "http"

    def test_https_value(self):
        """Test HTTPS protocol value."""
        assert StreamProtocol.HTTPS.value == "https"

    def test_mms_value(self):
        """Test MMS protocol value."""
        assert StreamProtocol.MMS.value == "mms"

    def test_rtp_value(self):
        """Test RTP protocol value."""
        assert StreamProtocol.RTP.value == "rtp"

    def test_onvif_value(self):
        """Test ONVIF protocol value."""
        assert StreamProtocol.ONVIF.value == "onvif"

    def test_hls_value(self):
        """Test HLS protocol value."""
        assert StreamProtocol.HLS.value == "hls"

    def test_dash_value(self):
        """Test DASH protocol value."""
        assert StreamProtocol.DASH.value == "dash"

    def test_webrtc_value(self):
        """Test WebRTC protocol value."""
        assert StreamProtocol.WEBRTC.value == "webrtc"

    def test_all_protocols_count(self):
        """Test total number of protocols."""
        assert len(StreamProtocol) == 13


class TestStreamQualityEnum:
    """Test StreamQuality enumeration."""

    def test_excellent_value(self):
        """Test EXCELLENT quality value."""
        assert StreamQuality.EXCELLENT.value == "excellent"

    def test_good_value(self):
        """Test GOOD quality value."""
        assert StreamQuality.GOOD.value == "good"

    def test_poor_value(self):
        """Test POOR quality value."""
        assert StreamQuality.POOR.value == "poor"

    def test_failed_value(self):
        """Test FAILED quality value."""
        assert StreamQuality.FAILED.value == "failed"

    def test_unknown_value(self):
        """Test UNKNOWN quality value."""
        assert StreamQuality.UNKNOWN.value == "unknown"

    def test_all_qualities_count(self):
        """Test total number of quality levels."""
        assert len(StreamQuality) == 5


class TestStreamEndpointDataclass:
    """Test StreamEndpoint dataclass."""

    def test_basic_creation(self):
        """Test basic endpoint creation."""
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1/stream",
            protocol=StreamProtocol.RTSP
        )
        assert endpoint.url == "rtsp://192.168.1.1/stream"
        assert endpoint.protocol == StreamProtocol.RTSP

    def test_default_values(self):
        """Test default values are set correctly."""
        endpoint = StreamEndpoint(
            url="http://example.com/video",
            protocol=StreamProtocol.HTTP
        )
        assert endpoint.brand is None
        assert endpoint.model is None
        assert endpoint.resolution is None
        assert endpoint.fps is None
        assert endpoint.codec is None
        assert endpoint.quality == StreamQuality.UNKNOWN
        assert endpoint.response_time is None
        assert endpoint.content_type is None
        assert endpoint.content_length is None
        assert endpoint.authentication_required is False
        assert endpoint.vulnerability_indicators == []
        assert endpoint.metadata == {}
        assert endpoint.confidence_score == 0.0

    def test_full_creation(self):
        """Test endpoint with all fields."""
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1:554/Streaming/Channels/1",
            protocol=StreamProtocol.RTSP,
            brand="hikvision",
            model="DS-2CD2142FWD-I",
            resolution=(1920, 1080),
            fps=30.0,
            codec="h264",
            quality=StreamQuality.EXCELLENT,
            response_time=45.5,
            content_type="video/h264",
            content_length=1024,
            authentication_required=True,
            vulnerability_indicators=["CVE-2021-36260"],
            metadata={"firmware": "V5.5.0"},
            confidence_score=0.95
        )
        assert endpoint.brand == "hikvision"
        assert endpoint.resolution == (1920, 1080)
        assert endpoint.fps == 30.0
        assert endpoint.authentication_required is True
        assert "CVE-2021-36260" in endpoint.vulnerability_indicators

    def test_timestamp_auto_generated(self):
        """Test discovery timestamp is auto-generated."""
        before = time.time()
        endpoint = StreamEndpoint(
            url="http://test.com/stream",
            protocol=StreamProtocol.HTTP
        )
        after = time.time()
        assert before <= endpoint.discovery_timestamp <= after


class TestStreamTopologyDataclass:
    """Test StreamTopology dataclass."""

    def test_basic_creation(self):
        """Test basic topology creation."""
        primary = StreamEndpoint(url="rtsp://1.1.1.1/stream", protocol=StreamProtocol.RTSP)
        backup = StreamEndpoint(url="rtsp://1.1.1.2/stream", protocol=StreamProtocol.RTSP)
        
        topology = StreamTopology(
            primary_streams=[primary],
            backup_streams=[backup],
            multicast_groups=["239.0.0.1"],
            bandwidth_estimates={"primary": 5000.0},
            network_latency={"1.1.1.1": 25.0},
            redundancy_paths=[[primary, backup]],
            quality_correlation_matrix=None
        )
        
        assert len(topology.primary_streams) == 1
        assert len(topology.backup_streams) == 1
        assert "239.0.0.1" in topology.multicast_groups
        assert topology.bandwidth_estimates["primary"] == 5000.0


class TestStreamPathDatabase:
    """Test StreamPathDatabase class."""

    def test_initialization(self):
        """Test database initialization."""
        db = StreamPathDatabase()
        assert db.stream_paths is not None
        assert db.brand_signatures is not None
        assert db.vulnerability_patterns is not None

    def test_rtsp_paths_initialized(self):
        """Test RTSP paths are initialized."""
        db = StreamPathDatabase()
        assert StreamProtocol.RTSP in db.stream_paths
        rtsp_paths = db.stream_paths[StreamProtocol.RTSP]
        assert "generic" in rtsp_paths
        assert len(rtsp_paths["generic"]) > 0

    def test_http_paths_initialized(self):
        """Test HTTP paths are initialized."""
        db = StreamPathDatabase()
        assert StreamProtocol.HTTP in db.stream_paths
        http_paths = db.stream_paths[StreamProtocol.HTTP]
        assert "generic" in http_paths

    def test_rtmp_paths_initialized(self):
        """Test RTMP paths are initialized."""
        db = StreamPathDatabase()
        assert StreamProtocol.RTMP in db.stream_paths

    def test_hikvision_rtsp_paths(self):
        """Test Hikvision-specific RTSP paths."""
        db = StreamPathDatabase()
        rtsp_paths = db.stream_paths[StreamProtocol.RTSP]
        assert "hikvision" in rtsp_paths
        hik_paths = rtsp_paths["hikvision"]
        assert "/Streaming/Channels/1" in hik_paths

    def test_dahua_rtsp_paths(self):
        """Test Dahua-specific RTSP paths."""
        db = StreamPathDatabase()
        rtsp_paths = db.stream_paths[StreamProtocol.RTSP]
        assert "dahua" in rtsp_paths

    def test_axis_rtsp_paths(self):
        """Test Axis-specific RTSP paths."""
        db = StreamPathDatabase()
        rtsp_paths = db.stream_paths[StreamProtocol.RTSP]
        assert "axis" in rtsp_paths

    def test_brand_signatures_initialized(self):
        """Test brand signatures database."""
        db = StreamPathDatabase()
        assert "hikvision" in db.brand_signatures
        assert "dahua" in db.brand_signatures
        assert "axis" in db.brand_signatures

    def test_hikvision_signature_structure(self):
        """Test Hikvision signature has required fields."""
        db = StreamPathDatabase()
        hik = db.brand_signatures["hikvision"]
        assert "http_headers" in hik
        assert "html_patterns" in hik
        assert "url_patterns" in hik
        assert "behavioral_signatures" in hik

    def test_vulnerability_patterns_initialized(self):
        """Test vulnerability patterns database."""
        db = StreamPathDatabase()
        assert "cve_indicators" in db.vulnerability_patterns
        assert "auth_bypass_patterns" in db.vulnerability_patterns
        assert "info_disclosure" in db.vulnerability_patterns

    def test_discovery_history_empty_on_init(self):
        """Test discovery history is empty on init."""
        db = StreamPathDatabase()
        assert db.discovery_history == []

    def test_adaptive_patterns_empty_on_init(self):
        """Test adaptive patterns is empty on init."""
        db = StreamPathDatabase()
        assert db.adaptive_patterns == {}


class TestStreamQualityAssessor:
    """Test StreamQualityAssessor class."""

    def test_initialization(self):
        """Test assessor initialization."""
        assessor = StreamQualityAssessor()
        assert assessor is not None

    @pytest.mark.asyncio
    async def test_assess_stream_returns_quality(self):
        """Test stream assessment returns quality."""
        assessor = StreamQualityAssessor()
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1/stream",
            protocol=StreamProtocol.RTSP
        )
        # Call the assess method directly - it should return a StreamQuality
        quality = await assessor.assess_stream(endpoint)
        assert isinstance(quality, StreamQuality)


class TestStreamTopologyMapper:
    """Test StreamTopologyMapper class."""

    def test_initialization(self):
        """Test mapper initialization."""
        mapper = StreamTopologyMapper()
        assert mapper is not None

    @pytest.mark.asyncio
    async def test_map_stream_topology_empty_list(self):
        """Test mapping empty stream list."""
        mapper = StreamTopologyMapper()
        topology = await mapper.map_stream_topology([])
        assert isinstance(topology, StreamTopology)
        assert len(topology.primary_streams) == 0

    @pytest.mark.asyncio
    async def test_map_stream_topology_single_stream(self):
        """Test mapping single stream."""
        mapper = StreamTopologyMapper()
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1/stream",
            protocol=StreamProtocol.RTSP,
            quality=StreamQuality.GOOD
        )
        topology = await mapper.map_stream_topology([endpoint])
        assert isinstance(topology, StreamTopology)


class TestVulnerabilityCorrelator:
    """Test VulnerabilityCorrelator class."""

    def test_initialization(self):
        """Test correlator initialization."""
        correlator = VulnerabilityCorrelator()
        assert correlator is not None

    @pytest.mark.asyncio
    async def test_correlate_vulnerabilities_basic(self):
        """Test basic vulnerability correlation."""
        correlator = VulnerabilityCorrelator()
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1/stream",
            protocol=StreamProtocol.RTSP,
            brand="hikvision"
        )
        vulnerabilities = await correlator.correlate_vulnerabilities(endpoint)
        assert isinstance(vulnerabilities, list)

    @pytest.mark.asyncio
    async def test_correlate_vulnerabilities_unknown_brand(self):
        """Test vulnerability correlation with unknown brand."""
        correlator = VulnerabilityCorrelator()
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1/stream",
            protocol=StreamProtocol.RTSP,
            brand=None
        )
        vulnerabilities = await correlator.correlate_vulnerabilities(endpoint)
        assert isinstance(vulnerabilities, list)


class TestAdvancedStreamDiscovery:
    """Test AdvancedStreamDiscovery class."""

    def test_initialization(self):
        """Test discovery engine initialization."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        assert discovery.database is db
        assert discovery.session_pool is None

    def test_has_quality_assessor(self):
        """Test discovery has quality assessor."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        assert hasattr(discovery, 'quality_assessor')
        assert isinstance(discovery.quality_assessor, StreamQualityAssessor)

    def test_has_topology_mapper(self):
        """Test discovery has topology mapper."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        assert hasattr(discovery, 'topology_mapper')
        assert isinstance(discovery.topology_mapper, StreamTopologyMapper)

    def test_has_vulnerability_correlator(self):
        """Test discovery has vulnerability correlator."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        assert hasattr(discovery, 'vulnerability_correlator')
        assert isinstance(discovery.vulnerability_correlator, VulnerabilityCorrelator)

    @pytest.mark.asyncio
    async def test_ensure_session_pool(self):
        """Test session pool is created on demand."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        assert discovery.session_pool is None
        await discovery._ensure_session_pool()
        assert discovery.session_pool is not None
        # Cleanup
        await discovery.session_pool.close()

    @pytest.mark.asyncio
    async def test_discover_streams_comprehensive_empty_ports(self):
        """Test comprehensive discovery with no open ports."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        streams = await discovery.discover_streams_comprehensive("192.168.1.1", [])
        assert isinstance(streams, list)
        # Cleanup session if created
        if discovery.session_pool:
            await discovery.session_pool.close()

    def test_generate_intelligent_variations(self):
        """Test intelligent URL variation generation."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1:554/stream1",
            protocol=StreamProtocol.RTSP
        )
        variations = discovery._generate_intelligent_variations([endpoint])
        assert isinstance(variations, list)

    def test_detect_protocol_from_url_rtsp(self):
        """Test protocol detection from RTSP URL."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        protocol = discovery._detect_protocol_from_url("rtsp://192.168.1.1/stream")
        assert protocol == StreamProtocol.RTSP

    def test_detect_protocol_from_url_http(self):
        """Test protocol detection from HTTP URL."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        protocol = discovery._detect_protocol_from_url("http://192.168.1.1/video")
        assert protocol == StreamProtocol.HTTP

    def test_detect_protocol_from_url_https(self):
        """Test protocol detection from HTTPS URL."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        protocol = discovery._detect_protocol_from_url("https://192.168.1.1/video")
        assert protocol == StreamProtocol.HTTPS

    def test_detect_protocol_from_url_rtmp(self):
        """Test protocol detection from RTMP URL."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        protocol = discovery._detect_protocol_from_url("rtmp://192.168.1.1/live")
        assert protocol == StreamProtocol.RTMP

    def test_calculate_confidence_score(self):
        """Test confidence score calculation."""
        db = StreamPathDatabase()
        discovery = AdvancedStreamDiscovery(db)
        
        endpoint = StreamEndpoint(
            url="rtsp://192.168.1.1/stream",
            protocol=StreamProtocol.RTSP,
            quality=StreamQuality.EXCELLENT,
            response_time=50.0
        )
        score = discovery._calculate_confidence_score(endpoint)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
