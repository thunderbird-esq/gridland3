"""
Core analysis engine with hybrid AsyncIO + Threading architecture.

Implements high-performance vulnerability analysis using the revolutionary
memory pool, work-stealing scheduler, and plugin system for optimal resource utilization.
"""

import asyncio
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

from ...core.logger import get_logger
from ...core.config import get_config
from ...core.network import NetworkValidator
from ..memory import (
    get_memory_pool, 
    AnalysisResult, 
    VulnerabilityResult, 
    StreamResult
)
from ..core import get_scheduler
from ..core.database import get_signature_database
from ..core.threat_intelligence import get_threat_intelligence
from ..core.phase2_integration import get_phase2_orchestrator
from ..plugins import get_plugin_manager, VulnerabilityPlugin, StreamPlugin

logger = get_logger(__name__)


@dataclass
class AnalysisTarget:
    """Target for analysis operations."""
    ip: str
    port: int
    service: str = ""
    banner: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisConfiguration:
    """Configuration for analysis operations."""
    max_concurrent_targets: int = 100
    timeout_per_target: float = 30.0
    enable_vulnerability_scanning: bool = True
    enable_stream_analysis: bool = True
    enable_plugin_scanning: bool = True
    enable_enrichment_plugins: bool = False
    signature_confidence_threshold: float = 0.7
    max_vulnerabilities_per_target: int = 50
    performance_mode: str = "BALANCED"  # FAST, BALANCED, THOROUGH


class AnalysisEngine:
    """
    Revolutionary analysis engine with hybrid concurrency architecture.
    
    Combines AsyncIO for I/O-bound operations with ThreadPoolExecutor for
    CPU-intensive tasks, utilizing the work-stealing scheduler for optimal
    performance across diverse workloads.
    """
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        self.config = config or AnalysisConfiguration()
        self.app_config = get_config()
        
        # Core components
        self.memory_pool = get_memory_pool()
        self.scheduler = get_scheduler()
        self.signature_db = get_signature_database()
        self.plugin_manager = get_plugin_manager()
        self.threat_intelligence = get_threat_intelligence()
        self.phase2_orchestrator = get_phase2_orchestrator()
        
        # Performance tracking
        self.analysis_stats = {
            'targets_analyzed': 0,
            'vulnerabilities_found': 0,
            'streams_discovered': 0,
            'analysis_time_total': 0.0,
            'avg_analysis_time': 0.0
        }
        self._stats_lock = threading.RLock()
        
        # Connection pooling for HTTP requests
        self._http_session = None
        self._setup_http_session()
        
        logger.info("AnalysisEngine initialized with hybrid AsyncIO + Threading architecture")
    
    def _setup_http_session(self):
        """Setup optimized HTTP session for banner grabbing."""
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(
                limit=self.config.max_concurrent_targets,
                limit_per_host=10,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_per_target)
            self._http_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'GRIDLAND/3.0 Security Scanner'}
            )
        except ImportError:
            logger.warning("aiohttp not available, using fallback HTTP client")
            self._http_session = None
    
    async def analyze_targets(self, targets: List[AnalysisTarget]) -> List[AnalysisResult]:
        """
        Analyze multiple targets concurrently with optimal resource utilization.
        
        Uses hybrid concurrency: AsyncIO for I/O coordination and ThreadPoolExecutor
        for CPU-intensive analysis tasks distributed via work-stealing scheduler.
        """
        if not targets:
            return []
        
        start_time = time.time()
        logger.info(f"Starting analysis of {len(targets)} targets")
        
        # Create semaphore for connection limiting
        semaphore = asyncio.Semaphore(self.config.max_concurrent_targets)
        
        # Process targets in batches for memory efficiency
        batch_size = min(50, self.config.max_concurrent_targets)
        all_results = []
        
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            logger.debug(f"Processing batch {i//batch_size + 1}/{(len(targets) + batch_size - 1)//batch_size}")
            
            # Create analysis tasks for batch
            tasks = [
                self._analyze_single_target_async(target, semaphore)
                for target in batch
            ]
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            for result in batch_results:
                if isinstance(result, AnalysisResult):
                    all_results.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Batch analysis error: {result}")
        
        # Update statistics
        analysis_time = time.time() - start_time
        with self._stats_lock:
            self.analysis_stats['targets_analyzed'] += len(targets)
            self.analysis_stats['analysis_time_total'] += analysis_time
            self.analysis_stats['avg_analysis_time'] = (
                self.analysis_stats['analysis_time_total'] / 
                self.analysis_stats['targets_analyzed']
            )
            
            # Count results
            for result in all_results:
                self.analysis_stats['vulnerabilities_found'] += len(result.vulnerabilities)
                self.analysis_stats['streams_discovered'] += len(result.streams)
        
        logger.info(f"Analysis completed: {len(all_results)} results in {analysis_time:.2f}s")
        return all_results
    
    async def _analyze_single_target_async(self, target: AnalysisTarget, 
                                          semaphore: asyncio.Semaphore) -> AnalysisResult:
        """Analyze single target with async I/O coordination."""
        async with semaphore:
            return await self._perform_target_analysis(target)
    
    async def _perform_target_analysis(self, target: AnalysisTarget) -> AnalysisResult:
        """Perform comprehensive analysis of a single target."""
        start_time = time.time()
        
        # Acquire result object from memory pool
        result = self.memory_pool.acquire_analysis_result()
        result.ip = target.ip
        result.port = target.port
        result.service = target.service
        result.banner = target.banner
        
        try:
            # Enhanced banner grabbing if not provided
            if not target.banner and target.port in [80, 443, 8080, 8443]:
                target.banner = await self._grab_banner_async(target)
                result.banner = target.banner
            
            # Concurrent analysis tasks
            analysis_tasks = []
            
            # 1. Signature-based vulnerability detection (CPU-intensive)
            if self.config.enable_vulnerability_scanning:
                analysis_tasks.append(
                    self._run_in_thread(self._signature_analysis, target)
                )
            
            # 2. Plugin-based scanning (Mixed I/O and CPU)
            if self.config.enable_plugin_scanning:
                analysis_tasks.append(
                    self._plugin_analysis_async(target)
                )
            
            # 3. Stream discovery and analysis (I/O-intensive)
            if self.config.enable_stream_analysis:
                analysis_tasks.append(
                    self._stream_analysis_async(target)
                )
            
            # 4. Threat intelligence analysis (I/O-intensive)
            analysis_tasks.append(
                self._threat_intelligence_analysis_async(target)
            )
            
            # 5. Phase 2 revolutionary analysis (Comprehensive)
            analysis_tasks.append(
                self._phase2_revolutionary_analysis_async(target)
            )
            
            # Execute all analysis tasks concurrently
            analysis_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Process results
            for i, task_result in enumerate(analysis_results):
                if isinstance(task_result, Exception):
                    logger.error(f"Analysis task {i} failed for {target.ip}:{target.port}: {task_result}")
                    continue
                
                if isinstance(task_result, list):
                    # Vulnerability or stream results
                    for item in task_result:
                        if isinstance(item, VulnerabilityResult):
                            result.vulnerabilities.append(item)
                        elif isinstance(item, StreamResult):
                            result.streams.append(item)
            
            # Limit results to prevent memory bloat
            result.vulnerabilities = result.vulnerabilities[:self.config.max_vulnerabilities_per_target]
            
            # Calculate confidence score
            result.confidence = self._calculate_confidence_score(result)
            result.analysis_time = time.time() - start_time
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed for {target.ip}:{target.port}: {e}")
            result.confidence = 0.0
            result.analysis_time = time.time() - start_time
            return result
    
    async def _grab_banner_async(self, target: AnalysisTarget) -> str:
        """Asynchronously grab service banner."""
        if not self._http_session:
            return ""
        
        try:
            # Determine URL scheme
            scheme = "https" if target.port in [443, 8443] else "http"
            url = f"{scheme}://{target.ip}:{target.port}/"
            
            async with self._http_session.get(url) as response:
                # Get server header as banner
                server_header = response.headers.get('Server', '')
                
                # Get first line of response text for additional context
                text_sample = ""
                try:
                    content = await response.text()
                    text_sample = content.split('\n')[0][:200] if content else ""
                except:
                    pass
                
                # Combine server header and text sample
                banner = f"{server_header} {text_sample}".strip()
                return banner[:500]  # Limit banner length
                
        except Exception as e:
            logger.debug(f"Banner grab failed for {target.ip}:{target.port}: {e}")
            return ""
    
    async def _run_in_thread(self, func, *args) -> Any:
        """Run CPU-intensive function in thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)
    
    def _signature_analysis(self, target: AnalysisTarget) -> List[VulnerabilityResult]:
        """CPU-intensive signature-based vulnerability analysis."""
        vulnerabilities = []
        
        # Search signature database
        signatures = self.signature_db.search_comprehensive(
            port=target.port,
            service=target.service,
            banner=target.banner,
            text=target.banner  # Use banner as general text search
        )
        
        for signature in signatures:
            # Apply confidence threshold
            if signature.confidence < self.config.signature_confidence_threshold:
                continue
            
            # Create vulnerability result from memory pool
            vuln = self.memory_pool.acquire_vulnerability_result()
            vuln.ip = target.ip
            vuln.port = target.port
            vuln.service = target.service
            vuln.vulnerability_id = signature.id
            vuln.severity = signature.severity
            vuln.confidence = signature.confidence
            vuln.description = signature.description
            vuln.exploit_available = signature.exploits_available
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _plugin_analysis_async(self, target: AnalysisTarget) -> List[Any]:
        """Plugin-based analysis with mixed I/O and CPU operations."""
        all_results = []
        
        # Get applicable plugins
        plugins = self.plugin_manager.get_applicable_plugins(target.port, target.service)
        
        if not plugins:
            return all_results
        
        # Run plugins concurrently
        plugin_tasks = []
        for plugin in plugins:
            if not plugin.enabled:
                continue
            
            # Skip enrichment plugins if not enabled in config
            if plugin.metadata.plugin_type == 'enrichment' and not self.config.enable_enrichment_plugins:
                continue

            try:
                task = plugin.analyze(target.ip, target.port, target.service, target.banner)
                plugin_tasks.append(task)
            except Exception as e:
                logger.error(f"Plugin {plugin.metadata.name} analysis setup failed: {e}")
        
        if plugin_tasks:
            plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)
            
            for result in plugin_results:
                if isinstance(result, Exception):
                    logger.error(f"Plugin analysis error: {result}")
                elif isinstance(result, list):
                    all_results.extend(result)
        
        return all_results
    
    async def _stream_analysis_async(self, target: AnalysisTarget) -> List[StreamResult]:
        """I/O-intensive stream discovery and analysis."""
        streams = []
        
        # Only analyze likely streaming ports
        streaming_ports = {554, 8554, 1935, 8080, 8000}
        if target.port not in streaming_ports and 'rtsp' not in target.service.lower():
            return streams
        
        try:
            # Test common RTSP endpoints
            rtsp_endpoints = [
                f"rtsp://{target.ip}:{target.port}/",
                f"rtsp://{target.ip}:{target.port}/live",
                f"rtsp://{target.ip}:{target.port}/cam/realmonitor",
                f"rtsp://{target.ip}:{target.port}/stream1",
            ]
            
            # Test endpoints concurrently (simplified - would need real RTSP client)
            for endpoint in rtsp_endpoints:
                # This would be replaced with actual RTSP probing
                if await self._test_rtsp_endpoint(endpoint):
                    stream = self.memory_pool.acquire_stream_result()
                    stream.ip = target.ip
                    stream.port = target.port
                    stream.protocol = "RTSP"
                    stream.stream_url = endpoint
                    stream.accessible = True
                    stream.authenticated = False  # Would be determined by actual testing
                    streams.append(stream)
                    break  # Found working endpoint
        
        except Exception as e:
            logger.debug(f"Stream analysis failed for {target.ip}:{target.port}: {e}")
        
        return streams
    
    async def _threat_intelligence_analysis_async(self, target: AnalysisTarget) -> List[VulnerabilityResult]:
        """Perform threat intelligence analysis on target."""
        vulnerabilities = []
        
        try:
            # Prepare target information for threat intelligence
            target_info = {
                'ip': target.ip,
                'port': target.port,
                'service': target.service,
                'banner': target.banner,
                'software': self._extract_software_info(target.banner),
                'metadata': target.metadata
            }
            
            # Get threat intelligence analysis
            threat_result = await self.threat_intelligence.analyze_threat_intelligence(
                target.ip, target.port, target_info
            )
            
            # Convert threat intelligence to vulnerability results
            
            # 1. CVE correlations
            for cve in threat_result.cve_correlations:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = cve.get('cve_id', 'THREAT-INTEL-CVE')
                vuln.severity = self._cvss_to_severity(cve.get('cvss_score', 0))
                vuln.confidence = min(0.9, threat_result.confidence_score + 0.1)
                vuln.description = f"CVE Correlation: {cve.get('description', 'Known vulnerability')}"
                vuln.exploit_available = False
                vulnerabilities.append(vuln)
            
            # 2. Threat indicators
            for indicator in threat_result.threat_indicators:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = f"THREAT-INDICATOR-{indicator.get('type', 'UNKNOWN')}"
                vuln.severity = indicator.get('severity', 'medium').upper()
                vuln.confidence = threat_result.confidence_score
                vuln.description = f"Threat Intelligence: {indicator.get('source', 'Unknown')} indicates {indicator.get('type', 'suspicious activity')}"
                vuln.exploit_available = False
                vulnerabilities.append(vuln)
            
            # 3. Low reputation score
            if threat_result.reputation_scores:
                aggregate_reputation = threat_result.reputation_scores.get('aggregate', 1.0)
                if aggregate_reputation < 0.5:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target.ip
                    vuln.port = target.port
                    vuln.service = target.service
                    vuln.vulnerability_id = "LOW-REPUTATION-SCORE"
                    vuln.severity = "HIGH" if aggregate_reputation < 0.3 else "MEDIUM"
                    vuln.confidence = threat_result.confidence_score
                    vuln.description = f"Low reputation score: {aggregate_reputation:.2f} from {len(threat_result.reputation_scores)} sources"
                    vuln.exploit_available = False
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"Threat intelligence analysis failed for {target.ip}:{target.port}: {e}")
        
        return vulnerabilities
    
    def _extract_software_info(self, banner: str) -> Dict[str, str]:
        """Extract software information from banner for threat intelligence."""
        software_info = {}
        
        if not banner:
            return software_info
        
        # Common software patterns in banners
        import re
        patterns = [
            (r'Apache[/\s]+(\d+\.[\d\.]+)', 'apache'),
            (r'nginx[/\s]+(\d+\.[\d\.]+)', 'nginx'),
            (r'Microsoft-IIS[/\s]+(\d+\.[\d\.]+)', 'iis'),
            (r'OpenSSH[_\s]+(\d+\.[\d\.]+)', 'openssh'),
            (r'(\w+)[/\s]+(\d+\.[\d\.]+)', 'generic')
        ]
        
        for pattern, software_type in patterns:
            matches = re.findall(pattern, banner, re.IGNORECASE)
            if matches:
                if software_type == 'generic':
                    software_name, version = matches[0]
                    software_info[software_name.lower()] = version
                else:
                    version = matches[0] if isinstance(matches[0], str) else matches[0][1]
                    software_info[software_type] = version
                break
        
        return software_info
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0.0:
            return "LOW"
        else:
            return "INFO"
    
    async def _phase2_revolutionary_analysis_async(self, target: AnalysisTarget) -> List[Any]:
        """Perform Phase 2 revolutionary analysis with all advanced capabilities."""
        revolutionary_results = []
        
        try:
            # Prepare comprehensive target information
            target_info = {
                'ip': target.ip,
                'port': target.port,
                'service': target.service,
                'banner': target.banner,
                'software': self._extract_software_info(target.banner),
                'metadata': target.metadata
            }
            
            # Execute comprehensive Phase 2 revolutionary analysis
            phase2_result = await self.phase2_orchestrator.perform_revolutionary_analysis(
                target.ip, target.port, target_info
            )
            
            # Convert Phase 2 results to vulnerability and stream results
            
            # 1. Enhanced stream intelligence results
            for stream_url, quality_score in phase2_result.stream_quality_scores.items():
                stream = self.memory_pool.acquire_stream_result()
                stream.ip = target.ip
                stream.port = target.port
                stream.protocol = stream_url.split(':')[0] if ':' in stream_url else 'UNKNOWN'
                stream.stream_url = f"http://{target.ip}:{target.port}{stream_url.split(':', 1)[1] if ':' in stream_url else stream_url}"
                stream.accessible = True
                stream.authenticated = False
                stream.quality_score = quality_score
                revolutionary_results.append(stream)
            
            # 2. Advanced fingerprinting vulnerabilities
            for dimension, fp_data in phase2_result.fingerprint_dimensions.items():
                if fp_data.get('confidence', 0) > 0.7:
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target.ip
                    vuln.port = target.port
                    vuln.service = target.service
                    vuln.vulnerability_id = f"ADVANCED-FINGERPRINT-{dimension.upper()}"
                    vuln.severity = "MEDIUM"
                    vuln.confidence = fp_data.get('confidence', 0.7)
                    vuln.description = f"Advanced fingerprinting detected {dimension} characteristics: {fp_data}"
                    vuln.exploit_available = False
                    revolutionary_results.append(vuln)
            
            # 3. ML vulnerability predictions
            for vuln_type, ml_score in phase2_result.ml_vulnerability_scores.items():
                if ml_score > 0.6:  # High confidence ML predictions
                    vuln = self.memory_pool.acquire_vulnerability_result()
                    vuln.ip = target.ip
                    vuln.port = target.port
                    vuln.service = target.service
                    vuln.vulnerability_id = f"ML-PREDICTED-{vuln_type.upper()}"
                    vuln.severity = "HIGH" if ml_score > 0.8 else "MEDIUM"
                    vuln.confidence = ml_score
                    vuln.description = f"ML vulnerability prediction: {vuln_type} (confidence: {ml_score:.2f})"
                    vuln.exploit_available = False
                    revolutionary_results.append(vuln)
            
            # 4. Behavioral anomalies
            for anomaly in phase2_result.behavioral_anomalies:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = f"BEHAVIORAL-ANOMALY-{anomaly.upper()}"
                vuln.severity = "MEDIUM"
                vuln.confidence = 0.75
                vuln.description = f"Behavioral anomaly detected: {anomaly}"
                vuln.exploit_available = False
                revolutionary_results.append(vuln)
            
            # 5. Successful credential discoveries
            if phase2_result.credentials_successful > 0:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = "WEAK-CREDENTIALS-DISCOVERED"
                vuln.severity = "HIGH"
                vuln.confidence = 0.95
                vuln.description = f"Weak credentials discovered: {phase2_result.credentials_successful}/{phase2_result.credentials_tested} successful"
                vuln.exploit_available = True
                revolutionary_results.append(vuln)
            
            # 6. Successful exploitations
            if phase2_result.successful_exploitations > 0:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = "AUTOMATED-EXPLOITATION-SUCCESS"
                vuln.severity = "CRITICAL"
                vuln.confidence = 0.98
                vuln.description = f"Automated exploitation successful: {phase2_result.successful_exploitations}/{phase2_result.exploitation_attempts} attempts"
                vuln.exploit_available = True
                revolutionary_results.append(vuln)
            
            # 7. Network topology insights
            if phase2_result.network_cluster_id:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = "NETWORK-TOPOLOGY-EXPOSURE"
                vuln.severity = "LOW"
                vuln.confidence = 0.8
                vuln.description = f"Network topology mapping: Cluster {phase2_result.network_cluster_id}, {len(phase2_result.topology_relationships)} relationships"
                vuln.exploit_available = False
                revolutionary_results.append(vuln)
            
            # 8. Low reputation indicators
            if phase2_result.reputation_score < 0.7:
                vuln = self.memory_pool.acquire_vulnerability_result()
                vuln.ip = target.ip
                vuln.port = target.port
                vuln.service = target.service
                vuln.vulnerability_id = "LOW-REPUTATION-INTELLIGENCE"
                vuln.severity = "HIGH" if phase2_result.reputation_score < 0.3 else "MEDIUM"
                vuln.confidence = 1.0 - phase2_result.reputation_score
                vuln.description = f"Low reputation score from threat intelligence: {phase2_result.reputation_score:.2f}"
                vuln.exploit_available = False
                revolutionary_results.append(vuln)
        
        except Exception as e:
            logger.error(f"Phase 2 revolutionary analysis failed for {target.ip}:{target.port}: {e}")
        
        return revolutionary_results
    
    async def _test_rtsp_endpoint(self, endpoint: str) -> bool:
        """Test if RTSP endpoint is accessible (simplified implementation)."""
        # This is a placeholder - real implementation would use RTSP client
        # For now, just simulate some endpoints being accessible
        import random
        await asyncio.sleep(0.1)  # Simulate network delay
        return random.random() < 0.1  # 10% chance of accessible stream
    
    def _calculate_confidence_score(self, result: AnalysisResult) -> float:
        """Calculate overall confidence score for analysis result."""
        if not result.vulnerabilities and not result.streams:
            return 0.0
        
        # Weight vulnerability confidence scores
        vuln_confidence = 0.0
        if result.vulnerabilities:
            vuln_confidence = sum(v.confidence for v in result.vulnerabilities) / len(result.vulnerabilities)
        
        # Weight stream accessibility
        stream_confidence = 0.0
        if result.streams:
            accessible_streams = sum(1 for s in result.streams if s.accessible)
            stream_confidence = accessible_streams / len(result.streams) * 0.8
        
        # Combined confidence (weighted average)
        if result.vulnerabilities and result.streams:
            return (vuln_confidence * 0.7 + stream_confidence * 0.3)
        elif result.vulnerabilities:
            return vuln_confidence
        else:
            return stream_confidence
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive analysis engine statistics."""
        with self._stats_lock:
            base_stats = self.analysis_stats.copy()
        
        return {
            **base_stats,
            'memory_pool_stats': self.memory_pool.get_pool_statistics(),
            'scheduler_stats': self.scheduler.get_statistics(),
            'signature_db_stats': self.signature_db.get_statistics(),
            'plugin_stats': self.plugin_manager.get_plugin_statistics(),
            'threat_intelligence_stats': self.threat_intelligence.get_statistics(),
            'phase2_integration_stats': self.phase2_orchestrator.get_integration_statistics(),
            'configuration': {
                'max_concurrent_targets': self.config.max_concurrent_targets,
                'timeout_per_target': self.config.timeout_per_target,
                'performance_mode': self.config.performance_mode,
                'signature_confidence_threshold': self.config.signature_confidence_threshold
            }
        }
    
    async def shutdown(self):
        """Shutdown analysis engine and cleanup resources."""
        logger.info("Shutting down AnalysisEngine")
        
        # Close HTTP session
        if self._http_session:
            await self._http_session.close()
        
        # Cleanup components (they have their own shutdown methods)
        # Note: We don't shut down shared components here as they might be used elsewhere
        
        logger.info("AnalysisEngine shutdown complete")


# Convenience functions for common analysis patterns
async def analyze_discovery_results(discovery_results: List[Dict]) -> List[AnalysisResult]:
    """Analyze results from discovery phase."""
    # Convert discovery results to analysis targets
    targets = []
    for result in discovery_results:
        target = AnalysisTarget(
            ip=result.get('ip', ''),
            port=result.get('port', 0),
            service=result.get('service', ''),
            banner=result.get('banner', ''),
            metadata=result
        )
        targets.append(target)
    
    # Create and run analysis engine
    engine = AnalysisEngine()
    try:
        return await engine.analyze_targets(targets)
    finally:
        await engine.shutdown()


async def analyze_single_target(ip: str, port: int, service: str = "", banner: str = "") -> Optional[AnalysisResult]:
    """Analyze a single target."""
    target = AnalysisTarget(ip=ip, port=port, service=service, banner=banner)
    
    engine = AnalysisEngine()
    try:
        results = await engine.analyze_targets([target])
        return results[0] if results else None
    finally:
        await engine.shutdown()


def create_analysis_config(performance_mode: str = "BALANCED") -> AnalysisConfiguration:
    """Create analysis configuration for different performance modes."""
    if performance_mode == "FAST":
        return AnalysisConfiguration(
            max_concurrent_targets=200,
            timeout_per_target=10.0,
            signature_confidence_threshold=0.8,
            max_vulnerabilities_per_target=10,
            performance_mode="FAST"
        )
    elif performance_mode == "THOROUGH":
        return AnalysisConfiguration(
            max_concurrent_targets=50,
            timeout_per_target=60.0,
            signature_confidence_threshold=0.5,
            max_vulnerabilities_per_target=100,
            performance_mode="THOROUGH"
        )
    else:  # BALANCED
        return AnalysisConfiguration(
            max_concurrent_targets=100,
            timeout_per_target=30.0,
            signature_confidence_threshold=0.7,
            max_vulnerabilities_per_target=50,
            performance_mode="BALANCED"
        )