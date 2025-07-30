"""
Advanced Network Topology Discovery Engine

This module implements revolutionary network topology mapping specifically designed
for camera reconnaissance operations. It goes far beyond traditional network scanning
by creating intelligent topology maps that reveal:

1. Network architecture patterns
2. Camera cluster relationships  
3. VLAN and subnet boundaries
4. Load balancer detection
5. Network device fingerprinting
6. Lateral movement paths
7. Infrastructure vulnerability patterns

This represents a breakthrough in reconnaissance methodology, providing
network intelligence never before available in security tools.
"""

import asyncio
import ipaddress
import json
import math
import socket
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union
import aiohttp
import struct

from gridland.core.logger import get_logger
from gridland.analyze.memory import get_memory_pool

logger = get_logger(__name__)


@dataclass
class NetworkNode:
    """Represents a discovered network node with comprehensive metadata"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    response_times: List[float] = field(default_factory=list)
    ttl_values: List[int] = field(default_factory=list)
    fingerprint_score: float = 0.0
    confidence: float = 0.0
    metadata: Dict[str, any] = field(default_factory=dict)


@dataclass
class NetworkCluster:
    """Represents a cluster of related network devices"""
    cluster_id: str
    nodes: List[NetworkNode]
    cluster_type: str  # "camera_bank", "switch_group", "vlan_segment", "load_balanced"
    characteristics: Dict[str, any]
    vulnerability_score: float
    lateral_movement_potential: float


@dataclass
class NetworkTopology:
    """Complete network topology representation"""
    target_network: str
    nodes: List[NetworkNode]
    clusters: List[NetworkCluster]
    network_devices: List[NetworkNode]
    security_boundaries: List[Dict[str, any]]
    vulnerability_paths: List[Dict[str, any]]
    analysis_metadata: Dict[str, any]


class NetworkFingerprintEngine:
    """Advanced network device fingerprinting based on behavioral patterns"""
    
    def __init__(self):
        self.device_signatures = {
            "cisco_switch": {
                "ttl_patterns": [64, 255],
                "port_patterns": [22, 23, 80, 443],
                "timing_signature": (10, 50),
                "response_patterns": ["cisco", "ios"]
            },
            "hikvision_nvr": {
                "ttl_patterns": [64],
                "port_patterns": [80, 554, 8000, 8080],
                "timing_signature": (50, 150),
                "response_patterns": ["hikvision", "webs"]
            },
            "dahua_nvr": {
                "ttl_patterns": [64],
                "port_patterns": [80, 554, 37777, 37778],
                "timing_signature": (80, 200),
                "response_patterns": ["dahua", "webs"]
            },
            "axis_camera": {
                "ttl_patterns": [64],
                "port_patterns": [80, 443, 554],
                "timing_signature": (30, 100),
                "response_patterns": ["axis", "vapix"]
            },
            "generic_router": {
                "ttl_patterns": [64, 255],
                "port_patterns": [22, 23, 53, 80, 443],
                "timing_signature": (5, 30),
                "response_patterns": ["router", "gateway"]
            },
            "linux_server": {
                "ttl_patterns": [64],
                "port_patterns": [22, 80, 443],
                "timing_signature": (1, 20),
                "response_patterns": ["apache", "nginx", "openssh"]
            },
            "windows_server": {
                "ttl_patterns": [128],
                "port_patterns": [135, 139, 445, 3389],
                "timing_signature": (20, 100),
                "response_patterns": ["microsoft", "windows"]
            }
        }
    
    def fingerprint_device(self, node: NetworkNode) -> Tuple[str, float]:
        """Fingerprint device type based on behavioral patterns"""
        best_match = "unknown"
        best_score = 0.0
        
        for device_type, signature in self.device_signatures.items():
            score = self._calculate_fingerprint_score(node, signature)
            if score > best_score:
                best_score = score
                best_match = device_type
        
        return best_match, best_score
    
    def _calculate_fingerprint_score(self, node: NetworkNode, signature: Dict) -> float:
        """Calculate fingerprint match score"""
        score = 0.0
        
        # TTL pattern matching
        if node.ttl_values and signature.get("ttl_patterns"):
            avg_ttl = sum(node.ttl_values) / len(node.ttl_values)
            ttl_match = any(abs(avg_ttl - expected) <= 2 for expected in signature["ttl_patterns"])
            if ttl_match:
                score += 0.3
        
        # Port pattern matching
        if node.open_ports and signature.get("port_patterns"):
            port_overlap = set(node.open_ports) & set(signature["port_patterns"])
            port_score = len(port_overlap) / len(signature["port_patterns"])
            score += port_score * 0.4
        
        # Timing pattern matching
        if node.response_times and signature.get("timing_signature"):
            avg_time = sum(node.response_times) / len(node.response_times)
            min_time, max_time = signature["timing_signature"]
            if min_time <= avg_time <= max_time:
                score += 0.2
        
        # Response pattern matching (if available in metadata)
        response_data = str(node.metadata.get("banners", "")).lower()
        if response_data and signature.get("response_patterns"):
            pattern_matches = sum(1 for pattern in signature["response_patterns"] 
                                if pattern in response_data)
            if pattern_matches > 0:
                score += 0.3
        
        return min(score, 1.0)


class NetworkClusterAnalyzer:
    """Analyze network nodes to identify clusters and relationships"""
    
    def __init__(self):
        self.cluster_algorithms = {
            "subnet_clustering": self._cluster_by_subnet,
            "timing_clustering": self._cluster_by_timing,
            "port_clustering": self._cluster_by_ports,
            "behavioral_clustering": self._cluster_by_behavior
        }
    
    def analyze_clusters(self, nodes: List[NetworkNode]) -> List[NetworkCluster]:
        """Comprehensive cluster analysis using multiple methodologies"""
        all_clusters = []
        
        for algorithm_name, algorithm_func in self.cluster_algorithms.items():
            try:
                clusters = algorithm_func(nodes)
                for cluster in clusters:
                    cluster.characteristics["algorithm"] = algorithm_name
                all_clusters.extend(clusters)
            except Exception as e:
                logger.debug(f"Cluster algorithm {algorithm_name} failed: {e}")
        
        # Merge overlapping clusters and rank by significance
        merged_clusters = self._merge_overlapping_clusters(all_clusters)
        significant_clusters = self._filter_significant_clusters(merged_clusters)
        
        return significant_clusters
    
    def _cluster_by_subnet(self, nodes: List[NetworkNode]) -> List[NetworkCluster]:
        """Cluster nodes by subnet relationships"""
        subnet_groups = defaultdict(list)
        
        for node in nodes:
            try:
                ip = ipaddress.ip_address(node.ip)
                # Group by /24 subnet
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                subnet_groups[subnet].append(node)
            except Exception:
                continue
        
        clusters = []
        for subnet, subnet_nodes in subnet_groups.items():
            if len(subnet_nodes) >= 2:  # At least 2 nodes to form cluster
                cluster = NetworkCluster(
                    cluster_id=f"subnet_{subnet.replace('/', '_')}",
                    nodes=subnet_nodes,
                    cluster_type="subnet_segment",
                    characteristics={
                        "subnet": subnet,
                        "node_count": len(subnet_nodes),
                        "density": len(subnet_nodes) / 254  # /24 subnet density
                    },
                    vulnerability_score=self._calculate_subnet_vulnerability(subnet_nodes),
                    lateral_movement_potential=self._calculate_lateral_movement_potential(subnet_nodes)
                )
                clusters.append(cluster)
        
        return clusters
    
    def _cluster_by_timing(self, nodes: List[NetworkNode]) -> List[NetworkCluster]:
        """Cluster nodes by response timing patterns (indicates load balancing)"""
        clusters = []
        
        # Group nodes with similar response time patterns
        timing_groups = defaultdict(list)
        
        for node in nodes:
            if node.response_times:
                avg_time = sum(node.response_times) / len(node.response_times)
                # Group by timing buckets (10ms intervals)
                timing_bucket = int(avg_time / 10) * 10
                timing_groups[timing_bucket].append(node)
        
        for timing_bucket, timing_nodes in timing_groups.items():
            if len(timing_nodes) >= 3:  # Multiple nodes with same timing = potential load balancer
                # Check if they're also on same subnet (stronger indicator)
                subnets = set()
                for node in timing_nodes:
                    try:
                        ip = ipaddress.ip_address(node.ip)
                        subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                        subnets.add(subnet)
                    except Exception:
                        continue
                
                if len(subnets) == 1:  # Same subnet + same timing = likely load balanced
                    cluster = NetworkCluster(
                        cluster_id=f"load_balanced_{timing_bucket}ms",
                        nodes=timing_nodes,
                        cluster_type="load_balanced",
                        characteristics={
                            "average_response_time": timing_bucket,
                            "timing_variance": self._calculate_timing_variance(timing_nodes),
                            "subnet": list(subnets)[0] if subnets else "unknown"
                        },
                        vulnerability_score=0.8,  # Load balancing often indicates important infrastructure
                        lateral_movement_potential=0.9  # High value for lateral movement
                    )
                    clusters.append(cluster)
        
        return clusters
    
    def _cluster_by_ports(self, nodes: List[NetworkNode]) -> List[NetworkCluster]:
        """Cluster nodes by port patterns (indicates device type clusters)"""
        clusters = []
        port_signatures = defaultdict(list)
        
        for node in nodes:
            if node.open_ports:
                # Create port signature (sorted tuple)
                port_sig = tuple(sorted(node.open_ports))
                port_signatures[port_sig].append(node)
        
        for port_pattern, pattern_nodes in port_signatures.items():
            if len(pattern_nodes) >= 2:
                # Determine cluster type based on port pattern
                cluster_type = self._determine_cluster_type_from_ports(port_pattern)
                
                cluster = NetworkCluster(
                    cluster_id=f"port_pattern_{hash(port_pattern)}",
                    nodes=pattern_nodes,
                    cluster_type=cluster_type,
                    characteristics={
                        "port_pattern": list(port_pattern),
                        "pattern_frequency": len(pattern_nodes),
                        "common_services": self._extract_common_services(pattern_nodes)
                    },
                    vulnerability_score=self._calculate_port_pattern_vulnerability(port_pattern),
                    lateral_movement_potential=self._calculate_port_pattern_lateral_potential(port_pattern)
                )
                clusters.append(cluster)
        
        return clusters
    
    def _cluster_by_behavior(self, nodes: List[NetworkNode]) -> List[NetworkCluster]:
        """Cluster nodes by behavioral fingerprints"""
        clusters = []
        behavioral_groups = defaultdict(list)
        
        fingerprinter = NetworkFingerprintEngine()
        
        for node in nodes:
            device_type, confidence = fingerprinter.fingerprint_device(node)
            if confidence > 0.5:  # Only cluster high-confidence fingerprints
                behavioral_groups[device_type].append((node, confidence))
        
        for device_type, device_nodes in behavioral_groups.items():
            if len(device_nodes) >= 2:
                nodes_only = [node for node, _ in device_nodes]
                avg_confidence = sum(conf for _, conf in device_nodes) / len(device_nodes)
                
                cluster = NetworkCluster(
                    cluster_id=f"behavioral_{device_type}",
                    nodes=nodes_only,
                    cluster_type="device_type_cluster",
                    characteristics={
                        "device_type": device_type,
                        "average_confidence": avg_confidence,
                        "fingerprint_consistency": self._calculate_fingerprint_consistency(device_nodes)
                    },
                    vulnerability_score=self._calculate_device_type_vulnerability(device_type),
                    lateral_movement_potential=self._calculate_device_type_lateral_potential(device_type)
                )
                clusters.append(cluster)
        
        return clusters
    
    def _calculate_subnet_vulnerability(self, nodes: List[NetworkNode]) -> float:
        """Calculate vulnerability score for subnet cluster"""
        score = 0.3  # Base score
        
        # More nodes = higher potential impact
        node_count = len(nodes)
        if node_count > 10:
            score += 0.3
        elif node_count > 5:
            score += 0.2
        
        # Open ports indicate attack surface
        total_ports = sum(len(node.open_ports) for node in nodes)
        avg_ports = total_ports / len(nodes) if nodes else 0
        if avg_ports > 5:
            score += 0.2
        
        # Camera devices are high-value targets
        camera_indicators = ["camera", "nvr", "dvr", "hikvision", "dahua", "axis"]
        camera_nodes = sum(1 for node in nodes 
                          if any(indicator in str(node.metadata).lower() 
                                for indicator in camera_indicators))
        if camera_nodes > len(nodes) * 0.5:  # > 50% camera devices
            score += 0.4
        
        return min(score, 1.0)
    
    def _calculate_lateral_movement_potential(self, nodes: List[NetworkNode]) -> float:
        """Calculate lateral movement potential for node cluster"""
        potential = 0.2  # Base potential
        
        # More nodes = more lateral movement opportunities
        node_count = len(nodes)
        potential += min(node_count * 0.05, 0.4)
        
        # Administrative services increase lateral movement potential
        admin_ports = [22, 23, 3389, 5900, 5901]  # SSH, Telnet, RDP, VNC
        admin_nodes = sum(1 for node in nodes 
                         if any(port in node.open_ports for port in admin_ports))
        if admin_nodes > 0:
            potential += 0.3
        
        # Trust relationships in same subnet
        potential += 0.2
        
        return min(potential, 1.0)
    
    def _calculate_timing_variance(self, nodes: List[NetworkNode]) -> float:
        """Calculate timing variance for load balancer detection"""
        all_times = []
        for node in nodes:
            all_times.extend(node.response_times)
        
        if len(all_times) < 2:
            return 0.0
        
        mean_time = sum(all_times) / len(all_times)
        variance = sum((t - mean_time) ** 2 for t in all_times) / len(all_times)
        return variance
    
    def _determine_cluster_type_from_ports(self, port_pattern: Tuple[int, ...]) -> str:
        """Determine cluster type based on port patterns"""
        port_set = set(port_pattern)
        
        # Camera/surveillance patterns
        camera_ports = {80, 554, 8080, 8000, 37777, 37778}
        if len(port_set & camera_ports) >= 2:
            return "camera_cluster"
        
        # Network infrastructure patterns
        network_ports = {22, 23, 53, 80, 443, 161}
        if len(port_set & network_ports) >= 3:
            return "network_infrastructure"
        
        # Server patterns
        server_ports = {80, 443, 22, 21, 25}
        if len(port_set & server_ports) >= 2:
            return "server_cluster"
        
        return "mixed_services"
    
    def _calculate_port_pattern_vulnerability(self, port_pattern: Tuple[int, ...]) -> float:
        """Calculate vulnerability based on port pattern"""
        port_set = set(port_pattern)
        score = 0.2
        
        # High-risk ports
        high_risk_ports = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432}
        risk_count = len(port_set & high_risk_ports)
        score += risk_count * 0.1
        
        # Common vulnerable services
        vulnerable_ports = {80, 443, 22, 554}  # Often misconfigured
        vuln_count = len(port_set & vulnerable_ports)
        score += vuln_count * 0.05
        
        # Many open ports = larger attack surface
        if len(port_pattern) > 10:
            score += 0.3
        elif len(port_pattern) > 5:
            score += 0.2
        
        return min(score, 1.0)
    
    def _calculate_port_pattern_lateral_potential(self, port_pattern: Tuple[int, ...]) -> float:
        """Calculate lateral movement potential from port pattern"""
        port_set = set(port_pattern)
        potential = 0.1
        
        # Administrative access ports
        admin_ports = {22, 23, 3389, 5900}
        if port_set & admin_ports:
            potential += 0.4
        
        # File sharing ports
        share_ports = {139, 445, 21, 22}
        if port_set & share_ports:
            potential += 0.3
        
        # Database ports (often contain credentials)
        db_ports = {1433, 3306, 5432, 1521}
        if port_set & db_ports:
            potential += 0.2
        
        return min(potential, 1.0)
    
    def _extract_common_services(self, nodes: List[NetworkNode]) -> Dict[int, str]:
        """Extract commonly seen services across nodes"""
        port_services = defaultdict(list)
        
        for node in nodes:
            for port, service in node.services.items():
                port_services[port].append(service)
        
        # Return most common service for each port
        common_services = {}
        for port, services in port_services.items():
            if services:
                most_common = max(set(services), key=services.count)
                common_services[port] = most_common
        
        return common_services
    
    def _calculate_device_type_vulnerability(self, device_type: str) -> float:
        """Calculate vulnerability score based on device type"""
        device_risk_scores = {
            "hikvision_nvr": 0.9,  # Known vulnerabilities
            "dahua_nvr": 0.8,
            "axis_camera": 0.6,
            "generic_router": 0.7,
            "cisco_switch": 0.5,
            "linux_server": 0.4,
            "windows_server": 0.6,
            "unknown": 0.3
        }
        
        return device_risk_scores.get(device_type, 0.3)
    
    def _calculate_device_type_lateral_potential(self, device_type: str) -> float:
        """Calculate lateral movement potential based on device type"""
        lateral_potential = {
            "hikvision_nvr": 0.8,  # Often part of larger networks
            "dahua_nvr": 0.8,
            "cisco_switch": 0.9,    # Network infrastructure = high lateral potential
            "generic_router": 0.9,
            "linux_server": 0.7,
            "windows_server": 0.8,
            "axis_camera": 0.5,
            "unknown": 0.3
        }
        
        return lateral_potential.get(device_type, 0.3)
    
    def _calculate_fingerprint_consistency(self, device_nodes: List[Tuple[NetworkNode, float]]) -> float:
        """Calculate how consistent fingerprinting is across nodes"""
        confidences = [conf for _, conf in device_nodes]
        if not confidences:
            return 0.0
        
        avg_confidence = sum(confidences) / len(confidences)
        variance = sum((c - avg_confidence) ** 2 for c in confidences) / len(confidences)
        
        # Lower variance = higher consistency
        consistency = max(0.0, 1.0 - variance)
        return consistency
    
    def _merge_overlapping_clusters(self, clusters: List[NetworkCluster]) -> List[NetworkCluster]:
        """Merge clusters with significant node overlap"""
        merged = []
        used_clusters = set()
        
        for i, cluster1 in enumerate(clusters):
            if i in used_clusters:
                continue
            
            merged_cluster = cluster1
            
            for j, cluster2 in enumerate(clusters[i+1:], i+1):
                if j in used_clusters:
                    continue
                
                # Calculate overlap
                nodes1 = set(node.ip for node in cluster1.nodes)
                nodes2 = set(node.ip for node in cluster2.nodes)
                overlap = len(nodes1 & nodes2) / min(len(nodes1), len(nodes2))
                
                if overlap > 0.6:  # 60% overlap threshold
                    # Merge clusters
                    all_nodes = {node.ip: node for node in merged_cluster.nodes + cluster2.nodes}
                    merged_cluster.nodes = list(all_nodes.values())
                    merged_cluster.cluster_type = "merged_cluster"
                    merged_cluster.characteristics.update(cluster2.characteristics)
                    used_clusters.add(j)
            
            merged.append(merged_cluster)
            used_clusters.add(i)
        
        return merged
    
    def _filter_significant_clusters(self, clusters: List[NetworkCluster]) -> List[NetworkCluster]:
        """Filter clusters by significance (size, vulnerability score, etc.)"""
        significant = []
        
        for cluster in clusters:
            # Significance criteria
            if (len(cluster.nodes) >= 2 and  # Minimum size
                (cluster.vulnerability_score >= 0.4 or  # High vulnerability
                 cluster.lateral_movement_potential >= 0.5 or  # High lateral potential
                 len(cluster.nodes) >= 5)):  # Large cluster
                significant.append(cluster)
        
        # Sort by combined significance score
        def significance_score(cluster):
            return (cluster.vulnerability_score * 0.4 + 
                   cluster.lateral_movement_potential * 0.3 + 
                   len(cluster.nodes) * 0.02)
        
        significant.sort(key=significance_score, reverse=True)
        return significant


class TopologyDiscoveryEngine:
    """Main engine for comprehensive network topology discovery"""
    
    def __init__(self):
        self.memory_pool = get_memory_pool()
        self.fingerprint_engine = NetworkFingerprintEngine()
        self.cluster_analyzer = NetworkClusterAnalyzer()
        self.discovery_stats = {
            "nodes_discovered": 0,
            "clusters_identified": 0,
            "vulnerability_paths_found": 0,
            "scan_start_time": 0.0
        }
    
    async def discover_network_topology(self, target_ip: str, 
                                      scope: str = "subnet") -> NetworkTopology:
        """
        Revolutionary network topology discovery.
        
        Args:
            target_ip: Primary target IP address
            scope: Discovery scope ("subnet", "class_c", "targeted")
        
        Returns:
            Comprehensive NetworkTopology object
        """
        self.discovery_stats["scan_start_time"] = time.time()
        
        logger.info(f"🌐 Starting advanced topology discovery for {target_ip} (scope: {scope})")
        
        try:
            # Phase 1: Target Network Determination
            target_network = self._determine_target_network(target_ip, scope)
            
            # Phase 2: Comprehensive Network Scanning
            nodes = await self._discover_network_nodes(target_network)
            
            # Phase 3: Advanced Device Fingerprinting
            nodes = await self._fingerprint_network_devices(nodes)
            
            # Phase 4: Network Cluster Analysis
            clusters = self.cluster_analyzer.analyze_clusters(nodes)
            
            # Phase 5: Security Boundary Detection
            security_boundaries = await self._detect_security_boundaries(nodes, clusters)
            
            # Phase 6: Vulnerability Path Analysis
            vulnerability_paths = await self._analyze_vulnerability_paths(nodes, clusters)
            
            # Phase 7: Network Device Classification
            network_devices = self._classify_network_devices(nodes)
            
            # Create comprehensive topology
            topology = NetworkTopology(
                target_network=target_network,
                nodes=nodes,
                clusters=clusters,
                network_devices=network_devices,
                security_boundaries=security_boundaries,
                vulnerability_paths=vulnerability_paths,
                analysis_metadata={
                    "scan_duration": time.time() - self.discovery_stats["scan_start_time"],
                    "discovery_stats": self.discovery_stats,
                    "scope": scope,
                    "methodology": "advanced_topology_discovery_v2"
                }
            )
            
            logger.info(f"✅ Topology discovery complete: {len(nodes)} nodes, {len(clusters)} clusters")
            return topology
            
        except Exception as e:
            logger.error(f"❌ Topology discovery failed: {e}")
            raise
    
    def _determine_target_network(self, target_ip: str, scope: str) -> str:
        """Determine target network range based on scope"""
        try:
            ip = ipaddress.ip_address(target_ip)
            
            if scope == "subnet":
                # /24 subnet
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
            elif scope == "class_c":
                # /24 network (same as subnet for most cases)
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
            elif scope == "targeted":
                # Smaller range around target
                # Create /28 network (16 addresses)
                network = ipaddress.ip_network(f"{ip}/28", strict=False)
            else:
                # Default to /24
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
            
            return str(network)
            
        except Exception as e:
            logger.warning(f"Network determination failed: {e}, using default /24")
            return f"{target_ip}/24"
    
    async def _discover_network_nodes(self, target_network: str) -> List[NetworkNode]:
        """Discover active nodes in target network"""
        nodes = []
        
        try:
            network = ipaddress.ip_network(target_network)
            
            # Limit scan size for performance
            max_hosts = min(100, network.num_addresses - 2)  # Exclude network/broadcast
            hosts_to_scan = list(network.hosts())[:max_hosts]
            
            logger.debug(f"Scanning {len(hosts_to_scan)} hosts in {target_network}")
            
            # Concurrent host discovery
            semaphore = asyncio.Semaphore(20)  # Limit concurrent scans
            tasks = []
            
            for host_ip in hosts_to_scan:
                task = self._discover_single_node(str(host_ip), semaphore)
                tasks.append(task)
            
            # Execute discovery tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, NetworkNode):
                    nodes.append(result)
                    self.discovery_stats["nodes_discovered"] += 1
                elif isinstance(result, Exception):
                    logger.debug(f"Host discovery error: {result}")
            
        except Exception as e:
            logger.error(f"Network node discovery failed: {e}")
        
        return nodes
    
    async def _discover_single_node(self, host_ip: str, semaphore: asyncio.Semaphore) -> Optional[NetworkNode]:
        """Discover single network node with comprehensive probing"""
        async with semaphore:
            try:
                # Quick ping-style connectivity check
                if not await self._check_host_alive(host_ip):
                    return None
                
                node = NetworkNode(ip=host_ip)
                
                # Port scanning for common ports
                common_ports = [22, 23, 25, 53, 80, 135, 139, 443, 445, 554, 993, 995, 
                               1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 37777, 37778]
                
                node.open_ports = await self._scan_ports(host_ip, common_ports)
                
                # Service detection for open ports
                if node.open_ports:
                    node.services = await self._detect_services(host_ip, node.open_ports[:5])  # Limit for performance
                
                # Response timing measurement
                node.response_times = await self._measure_response_times(host_ip)
                
                # TTL measurement
                node.ttl_values = await self._measure_ttl_values(host_ip)
                
                # Hostname resolution
                node.hostname = await self._resolve_hostname(host_ip)
                
                return node
                
            except Exception as e:
                logger.debug(f"Single node discovery failed for {host_ip}: {e}")
                return None
    
    async def _check_host_alive(self, host_ip: str) -> bool:
        """Quick host alive check using multiple methods"""
        try:
            # Method 1: TCP connect to common ports
            common_ports = [80, 443, 22, 23]
            
            for port in common_ports:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host_ip, port),
                        timeout=1.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except Exception:
                    continue
            
            # Method 2: HTTP request (for cameras/web devices)
            try:
                timeout = aiohttp.ClientTimeout(total=2)
                connector = aiohttp.TCPConnector(ssl=False)
                
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    async with session.get(f"http://{host_ip}") as response:
                        return True
            except Exception:
                pass
            
            return False
            
        except Exception:
            return False
    
    async def _scan_ports(self, host_ip: str, ports: List[int]) -> List[int]:
        """Scan ports on target host"""
        open_ports = []
        
        async def scan_port(port):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host_ip, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None
        
        # Concurrent port scanning
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, int):
                open_ports.append(result)
        
        return sorted(open_ports)
    
    async def _detect_services(self, host_ip: str, ports: List[int]) -> Dict[int, str]:
        """Detect services on open ports"""
        services = {}
        
        for port in ports:
            try:
                service = await self._identify_service(host_ip, port)
                if service:
                    services[port] = service
            except Exception as e:
                logger.debug(f"Service detection failed for {host_ip}:{port}: {e}")
        
        return services
    
    async def _identify_service(self, host_ip: str, port: int) -> Optional[str]:
        """Identify service on specific port"""
        try:
            if port == 80:
                return await self._identify_http_service(host_ip, port)
            elif port == 443:
                return "https"
            elif port == 22:
                return "ssh"
            elif port == 23:
                return "telnet"
            elif port == 554:
                return "rtsp"
            elif port in [37777, 37778]:
                return "dahua-tcp"
            else:
                # Generic banner grabbing
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host_ip, port),
                        timeout=3.0
                    )
                    
                    # Send generic probe
                    writer.write(b"\\r\\n")
                    await writer.drain()
                    
                    # Read response
                    data = await asyncio.wait_for(reader.read(512), timeout=2.0)
                    writer.close()
                    await writer.wait_closed()
                    
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                        return self._parse_service_from_banner(banner)
                    
                except Exception:
                    pass
            
            return f"tcp-{port}"
            
        except Exception:
            return None
    
    async def _identify_http_service(self, host_ip: str, port: int) -> str:
        """Identify HTTP-based service"""
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(f"http://{host_ip}:{port}") as response:
                    server_header = response.headers.get('Server', '').lower()
                    content = (await response.text())[:500].lower()
                    
                    # Identify camera web interfaces
                    if any(indicator in server_header + content 
                           for indicator in ['hikvision', 'webs']):
                        return "hikvision-http"
                    elif any(indicator in server_header + content 
                            for indicator in ['dahua', 'dh-']):
                        return "dahua-http"
                    elif 'axis' in server_header + content:
                        return "axis-http"
                    elif any(indicator in server_header + content 
                            for indicator in ['apache', 'nginx', 'lighttpd']):
                        return f"http-{server_header.split('/')[0] if '/' in server_header else 'generic'}"
                    else:
                        return "http"
        except Exception:
            return "http"
    
    def _parse_service_from_banner(self, banner: str) -> str:
        """Parse service type from banner"""
        banner_lower = banner.lower()
        
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower:
            return 'smtp'
        elif 'pop3' in banner_lower:
            return 'pop3'
        elif 'imap' in banner_lower:
            return 'imap'
        elif 'rtsp' in banner_lower:
            return 'rtsp'
        else:
            return 'unknown'
    
    async def _measure_response_times(self, host_ip: str) -> List[float]:
        """Measure response times for timing analysis"""
        times = []
        
        # Test multiple times for accuracy
        for _ in range(3):
            try:
                start_time = time.time()
                
                # Quick TCP connect to port 80
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host_ip, 80),
                        timeout=2.0
                    )
                    response_time = (time.time() - start_time) * 1000
                    times.append(response_time)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception:
                    # Try port 22 if 80 fails
                    try:
                        start_time = time.time()
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(host_ip, 22),
                            timeout=2.0
                        )
                        response_time = (time.time() - start_time) * 1000
                        times.append(response_time)
                        
                        writer.close()
                        await writer.wait_closed()
                        
                    except Exception:
                        continue
                        
            except Exception:
                continue
        
        return times
    
    async def _measure_ttl_values(self, host_ip: str) -> List[int]:
        """Measure TTL values for OS fingerprinting"""
        # TTL measurement requires raw sockets which are complex in async context
        # For now, return empty list - could be enhanced with external tools
        return []
    
    async def _resolve_hostname(self, host_ip: str) -> Optional[str]:
        """Resolve hostname for IP address"""
        try:
            hostname = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyaddr, host_ip
                ),
                timeout=2.0
            )
            return hostname[0] if hostname else None
        except Exception:
            return None
    
    async def _fingerprint_network_devices(self, nodes: List[NetworkNode]) -> List[NetworkNode]:
        """Apply advanced fingerprinting to all discovered nodes"""
        for node in nodes:
            try:
                device_type, confidence = self.fingerprint_engine.fingerprint_device(node)
                node.device_type = device_type
                node.fingerprint_score = confidence
                node.confidence = confidence
                
                # Store fingerprinting details
                node.metadata["device_type"] = device_type
                node.metadata["fingerprint_confidence"] = confidence
                
            except Exception as e:
                logger.debug(f"Fingerprinting failed for {node.ip}: {e}")
        
        return nodes
    
    async def _detect_security_boundaries(self, nodes: List[NetworkNode], 
                                        clusters: List[NetworkCluster]) -> List[Dict[str, any]]:
        """Detect security boundaries and network segmentation"""
        boundaries = []
        
        try:
            # Detect subnet boundaries
            subnets = set()
            for node in nodes:
                try:
                    ip = ipaddress.ip_address(node.ip)
                    subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                    subnets.add(subnet)
                except Exception:
                    continue
            
            if len(subnets) > 1:
                boundary = {
                    "type": "subnet_boundary",
                    "subnets": list(subnets),
                    "potential_firewall": True,
                    "segmentation_score": len(subnets) / len(nodes) if nodes else 0
                }
                boundaries.append(boundary)
            
            # Detect service boundaries (different service patterns)
            service_patterns = defaultdict(list)
            for node in nodes:
                pattern = tuple(sorted(node.open_ports))
                service_patterns[pattern].append(node.ip)
            
            if len(service_patterns) > 2:
                boundary = {
                    "type": "service_boundary",
                    "patterns": {str(k): v for k, v in service_patterns.items()},
                    "potential_segmentation": True,
                    "diversity_score": len(service_patterns) / len(nodes) if nodes else 0
                }
                boundaries.append(boundary)
            
        except Exception as e:
            logger.debug(f"Security boundary detection failed: {e}")
        
        return boundaries
    
    async def _analyze_vulnerability_paths(self, nodes: List[NetworkNode], 
                                         clusters: List[NetworkCluster]) -> List[Dict[str, any]]:
        """Analyze potential vulnerability exploitation paths"""
        vulnerability_paths = []
        
        try:
            # Path 1: High-value target clusters
            for cluster in clusters:
                if cluster.vulnerability_score > 0.7:
                    path = {
                        "type": "high_value_cluster",
                        "cluster_id": cluster.cluster_id,
                        "target_nodes": [node.ip for node in cluster.nodes],
                        "vulnerability_score": cluster.vulnerability_score,
                        "lateral_potential": cluster.lateral_movement_potential,
                        "attack_strategy": self._suggest_attack_strategy(cluster)
                    }
                    vulnerability_paths.append(path)
                    self.discovery_stats["vulnerability_paths_found"] += 1
            
            # Path 2: Administrative access vectors
            admin_nodes = [node for node in nodes 
                          if any(port in node.open_ports for port in [22, 23, 3389, 5900])]
            
            if admin_nodes:
                path = {
                    "type": "administrative_access",
                    "target_nodes": [node.ip for node in admin_nodes],
                    "access_methods": self._identify_access_methods(admin_nodes),
                    "risk_level": "high",
                    "lateral_potential": 0.9
                }
                vulnerability_paths.append(path)
                self.discovery_stats["vulnerability_paths_found"] += 1
            
            # Path 3: Camera-specific vulnerabilities
            camera_nodes = [node for node in nodes 
                           if node.device_type and 'camera' in node.device_type.lower()]
            
            if camera_nodes:
                path = {
                    "type": "camera_vulnerabilities",
                    "target_nodes": [node.ip for node in camera_nodes],
                    "vulnerability_types": ["default_credentials", "firmware_exploits", "stream_access"],
                    "risk_level": "high",
                    "business_impact": "surveillance_compromise"
                }
                vulnerability_paths.append(path)
                self.discovery_stats["vulnerability_paths_found"] += 1
            
        except Exception as e:
            logger.debug(f"Vulnerability path analysis failed: {e}")
        
        return vulnerability_paths
    
    def _suggest_attack_strategy(self, cluster: NetworkCluster) -> List[str]:
        """Suggest attack strategies based on cluster characteristics"""
        strategies = []
        
        if cluster.cluster_type == "camera_cluster":
            strategies.extend([
                "default_credential_testing",
                "firmware_vulnerability_exploitation",
                "stream_hijacking",
                "configuration_extraction"
            ])
        elif cluster.cluster_type == "network_infrastructure":
            strategies.extend([
                "snmp_enumeration",
                "configuration_backup_extraction",
                "privilege_escalation",
                "network_pivot"
            ])
        elif cluster.cluster_type == "load_balanced":
            strategies.extend([
                "load_balancer_bypass",
                "session_prediction",
                "backend_server_identification"
            ])
        else:
            strategies.extend([
                "service_enumeration",
                "vulnerability_scanning",
                "credential_brute_force"
            ])
        
        return strategies
    
    def _identify_access_methods(self, admin_nodes: List[NetworkNode]) -> Dict[str, List[str]]:
        """Identify administrative access methods"""
        access_methods = defaultdict(list)
        
        for node in admin_nodes:
            if 22 in node.open_ports:
                access_methods["ssh"].append(node.ip)
            if 23 in node.open_ports:
                access_methods["telnet"].append(node.ip)
            if 3389 in node.open_ports:
                access_methods["rdp"].append(node.ip)
            if 5900 in node.open_ports or 5901 in node.open_ports:
                access_methods["vnc"].append(node.ip)
        
        return dict(access_methods)
    
    def _classify_network_devices(self, nodes: List[NetworkNode]) -> List[NetworkNode]:
        """Classify network infrastructure devices"""
        network_devices = []
        
        for node in nodes:
            # Classify as network device if it has network infrastructure characteristics
            is_network_device = (
                node.device_type in ["cisco_switch", "generic_router"] or
                (22 in node.open_ports and 23 in node.open_ports and 80 in node.open_ports) or
                (161 in node.open_ports)  # SNMP
            )
            
            if is_network_device:
                network_devices.append(node)
        
        return network_devices


# Main interface function
async def discover_network_topology(target_ip: str, scope: str = "subnet") -> NetworkTopology:
    """
    Main interface for network topology discovery.
    
    Args:
        target_ip: Primary target IP address
        scope: Discovery scope ("subnet", "class_c", "targeted")
    
    Returns:
        Comprehensive NetworkTopology object
    """
    engine = TopologyDiscoveryEngine()
    return await engine.discover_network_topology(target_ip, scope)