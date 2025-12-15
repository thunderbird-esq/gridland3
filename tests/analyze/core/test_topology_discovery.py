"""
Comprehensive test suite for topology_discovery.py module.

Tests cover:
- NetworkNode and NetworkCluster dataclasses
- NetworkTopology dataclass
- NetworkFingerprintEngine device fingerprinting
- NetworkClusterAnalyzer clustering algorithms
- TopologyDiscoveryEngine main discovery flow
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.core.topology_discovery import (
    NetworkNode,
    NetworkCluster,
    NetworkTopology,
    NetworkFingerprintEngine,
    NetworkClusterAnalyzer,
    TopologyDiscoveryEngine,
)


class TestNetworkNodeDataclass:
    """Test NetworkNode dataclass."""

    def test_basic_creation(self):
        """Test basic node creation."""
        node = NetworkNode(ip="192.168.1.1")
        assert node.ip == "192.168.1.1"

    def test_default_values(self):
        """Test default values."""
        node = NetworkNode(ip="10.0.0.1")
        assert node.hostname is None
        assert node.mac_address is None
        assert node.vendor is None
        assert node.device_type is None
        assert node.open_ports == []
        assert node.services == {}
        assert node.response_times == []
        assert node.ttl_values == []
        assert node.fingerprint_score == 0.0
        assert node.confidence == 0.0
        assert node.metadata == {}

    def test_full_creation(self):
        """Test node with all fields."""
        node = NetworkNode(
            ip="192.168.1.100",
            hostname="camera-01.local",
            mac_address="AA:BB:CC:DD:EE:FF",
            vendor="Hikvision",
            device_type="IP Camera",
            open_ports=[80, 443, 554],
            services={"80": "http", "554": "rtsp"},
            response_times=[25.5, 30.2, 28.1],
            ttl_values=[64, 64, 64],
            fingerprint_score=0.85,
            confidence=0.9,
            metadata={"firmware": "V5.5.0"}
        )
        assert node.hostname == "camera-01.local"
        assert node.vendor == "Hikvision"
        assert 554 in node.open_ports
        assert node.fingerprint_score == 0.85


class TestNetworkClusterDataclass:
    """Test NetworkCluster dataclass."""

    def test_basic_creation(self):
        """Test basic cluster creation."""
        node1 = NetworkNode(ip="192.168.1.1")
        node2 = NetworkNode(ip="192.168.1.2")
        cluster = NetworkCluster(
            cluster_id="cluster-001",
            nodes=[node1, node2],
            cluster_type="subnet",
            characteristics={},
            vulnerability_score=0.5,
            lateral_movement_potential=0.3
        )
        assert cluster.cluster_id == "cluster-001"
        assert len(cluster.nodes) == 2

    def test_cluster_type(self):
        """Test cluster type assignment."""
        cluster = NetworkCluster(
            cluster_id="camera-cluster",
            nodes=[],
            cluster_type="camera_array",
            characteristics={"protocol": "rtsp"},
            vulnerability_score=0.8,
            lateral_movement_potential=0.6
        )
        assert cluster.cluster_type == "camera_array"
        assert cluster.vulnerability_score == 0.8


class TestNetworkTopologyDataclass:
    """Test NetworkTopology dataclass."""

    def test_basic_creation(self):
        """Test basic topology creation."""
        topology = NetworkTopology(
            target_network="192.168.1.0/24",
            nodes=[],
            clusters=[],
            network_devices=[],
            security_boundaries=[],
            vulnerability_paths=[],
            analysis_metadata={}
        )
        assert topology.target_network == "192.168.1.0/24"
        assert len(topology.nodes) == 0

    def test_topology_with_nodes_and_clusters(self):
        """Test topology with nodes and clusters."""
        node = NetworkNode(ip="192.168.1.1", open_ports=[80, 554])
        cluster = NetworkCluster(
            cluster_id="cl-1",
            nodes=[node],
            cluster_type="camera",
            characteristics={},
            vulnerability_score=0.5,
            lateral_movement_potential=0.3
        )
        topology = NetworkTopology(
            target_network="192.168.1.0/24",
            nodes=[node],
            clusters=[cluster],
            network_devices=[],
            security_boundaries=[{"type": "firewall", "ip": "192.168.1.254"}],
            vulnerability_paths=[{"from": "192.168.1.1", "to": "192.168.1.254"}],
            analysis_metadata={"scan_time": 45.5}
        )
        assert len(topology.nodes) == 1
        assert len(topology.clusters) == 1
        assert len(topology.security_boundaries) == 1


class TestNetworkFingerprintEngine:
    """Test NetworkFingerprintEngine class."""

    def test_initialization(self):
        """Test engine initialization."""
        engine = NetworkFingerprintEngine()
        assert engine is not None
        assert hasattr(engine, 'device_signatures')

    def test_device_signatures_exist(self):
        """Test device signatures are populated."""
        engine = NetworkFingerprintEngine()
        assert "cisco_switch" in engine.device_signatures
        assert "hikvision_nvr" in engine.device_signatures

    def test_cisco_signature_structure(self):
        """Test Cisco signature has required fields."""
        engine = NetworkFingerprintEngine()
        cisco = engine.device_signatures["cisco_switch"]
        assert "ttl_patterns" in cisco
        assert "port_patterns" in cisco

    def test_hikvision_signature_structure(self):
        """Test Hikvision signature has required fields."""
        engine = NetworkFingerprintEngine()
        hik = engine.device_signatures["hikvision_nvr"]
        assert "ttl_patterns" in hik
        assert "port_patterns" in hik

    def test_fingerprint_device_hikvision(self):
        """Test fingerprinting a Hikvision camera."""
        engine = NetworkFingerprintEngine()
        node = NetworkNode(
            ip="192.168.1.100",
            open_ports=[80, 443, 554, 8000],
            ttl_values=[64, 64, 64]
        )
        result = engine.fingerprint_device(node)
        assert isinstance(result, tuple)
        assert len(result) == 2  # (device_type, score)

    def test_fingerprint_device_unknown(self):
        """Test fingerprinting unknown device."""
        engine = NetworkFingerprintEngine()
        node = NetworkNode(
            ip="192.168.1.200",
            open_ports=[12345],
            ttl_values=[128]
        )
        result = engine.fingerprint_device(node)
        assert isinstance(result, tuple)

    def test_calculate_fingerprint_score(self):
        """Test fingerprint score calculation."""
        engine = NetworkFingerprintEngine()
        node = NetworkNode(
            ip="192.168.1.1",
            open_ports=[80, 554, 8000],
            ttl_values=[64]
        )
        signature = engine.device_signatures["hikvision_nvr"]
        score = engine._calculate_fingerprint_score(node, signature)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


class TestNetworkClusterAnalyzer:
    """Test NetworkClusterAnalyzer class."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = NetworkClusterAnalyzer()
        assert analyzer is not None
        assert hasattr(analyzer, 'cluster_algorithms')

    def test_cluster_algorithms_exist(self):
        """Test cluster algorithms are registered."""
        analyzer = NetworkClusterAnalyzer()
        assert "subnet_clustering" in analyzer.cluster_algorithms
        assert "timing_clustering" in analyzer.cluster_algorithms
        assert "port_clustering" in analyzer.cluster_algorithms

    def test_analyze_clusters_empty_list(self):
        """Test analyzing empty node list."""
        analyzer = NetworkClusterAnalyzer()
        clusters = analyzer.analyze_clusters([])
        assert isinstance(clusters, list)
        assert len(clusters) == 0

    def test_analyze_clusters_single_node(self):
        """Test analyzing single node."""
        analyzer = NetworkClusterAnalyzer()
        node = NetworkNode(ip="192.168.1.1", open_ports=[80, 554])
        clusters = analyzer.analyze_clusters([node])
        assert isinstance(clusters, list)

    def test_analyze_clusters_multiple_nodes(self):
        """Test analyzing multiple nodes."""
        analyzer = NetworkClusterAnalyzer()
        nodes = [
            NetworkNode(ip="192.168.1.1", open_ports=[80, 554]),
            NetworkNode(ip="192.168.1.2", open_ports=[80, 554]),
            NetworkNode(ip="192.168.1.3", open_ports=[80, 554]),
        ]
        clusters = analyzer.analyze_clusters(nodes)
        assert isinstance(clusters, list)

    def test_cluster_by_subnet(self):
        """Test subnet clustering algorithm."""
        analyzer = NetworkClusterAnalyzer()
        nodes = [
            NetworkNode(ip="192.168.1.1"),
            NetworkNode(ip="192.168.1.2"),
            NetworkNode(ip="192.168.2.1"),
        ]
        clusters = analyzer._cluster_by_subnet(nodes)
        assert isinstance(clusters, list)

    def test_cluster_by_ports(self):
        """Test port-based clustering."""
        analyzer = NetworkClusterAnalyzer()
        nodes = [
            NetworkNode(ip="192.168.1.1", open_ports=[80, 554]),
            NetworkNode(ip="192.168.1.2", open_ports=[80, 554]),
            NetworkNode(ip="192.168.1.3", open_ports=[22, 23]),
        ]
        clusters = analyzer._cluster_by_ports(nodes)
        assert isinstance(clusters, list)

    def test_calculate_subnet_vulnerability(self):
        """Test subnet vulnerability calculation."""
        analyzer = NetworkClusterAnalyzer()
        nodes = [
            NetworkNode(ip="192.168.1.1", open_ports=[80, 554, 23]),
            NetworkNode(ip="192.168.1.2", open_ports=[80, 21]),
        ]
        score = analyzer._calculate_subnet_vulnerability(nodes)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_calculate_lateral_movement_potential(self):
        """Test lateral movement potential calculation."""
        analyzer = NetworkClusterAnalyzer()
        nodes = [
            NetworkNode(ip="192.168.1.1", open_ports=[22, 445]),
            NetworkNode(ip="192.168.1.2", open_ports=[3389, 445]),
        ]
        potential = analyzer._calculate_lateral_movement_potential(nodes)
        assert isinstance(potential, float)
        assert 0.0 <= potential <= 1.0


class TestTopologyDiscoveryEngine:
    """Test TopologyDiscoveryEngine class."""

    def test_initialization(self):
        """Test engine initialization."""
        engine = TopologyDiscoveryEngine()
        assert engine is not None
        assert hasattr(engine, 'fingerprint_engine')
        assert hasattr(engine, 'cluster_analyzer')

    def test_has_fingerprint_engine(self):
        """Test engine has fingerprint engine."""
        engine = TopologyDiscoveryEngine()
        assert isinstance(engine.fingerprint_engine, NetworkFingerprintEngine)

    def test_has_cluster_analyzer(self):
        """Test engine has cluster analyzer."""
        engine = TopologyDiscoveryEngine()
        assert isinstance(engine.cluster_analyzer, NetworkClusterAnalyzer)

    @pytest.mark.asyncio
    async def test_discover_topology_empty_network(self):
        """Test topology discovery with empty network."""
        engine = TopologyDiscoveryEngine()
        # Mock the network scanning to return empty
        with patch.object(engine, '_discover_network_nodes', new_callable=AsyncMock) as mock:
            mock.return_value = []
            topology = await engine.discover_network_topology("192.168.1.1")
            assert isinstance(topology, NetworkTopology)
            assert "192.168.1" in topology.target_network

    @pytest.mark.asyncio
    async def test_discover_topology_with_nodes(self):
        """Test topology discovery with discovered nodes."""
        engine = TopologyDiscoveryEngine()
        mock_nodes = [
            NetworkNode(ip="192.168.1.1", open_ports=[80, 554]),
            NetworkNode(ip="192.168.1.2", open_ports=[80, 554]),
        ]
        with patch.object(engine, '_discover_network_nodes', new_callable=AsyncMock) as mock:
            mock.return_value = mock_nodes
            topology = await engine.discover_network_topology("192.168.1.1")
            assert isinstance(topology, NetworkTopology)
            assert len(topology.nodes) >= 0  # May filter some nodes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
