"""
Masscan integration for GRIDLAND discovery operations.

Provides high-speed port scanning capabilities using the masscan tool,
with intelligent rate limiting, result parsing, and error handling.
"""

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from uuid import uuid4

from ..core.config import get_config, get_port_manager
from ..core.logger import get_logger
from ..core.network import NetworkValidator, IPRangeGenerator
from .adaptive_scanner import AdaptivePortScanner

logger = get_logger(__name__)


@dataclass
class MasscanResult:
    """Result from masscan operation."""
    ip: str
    port: int
    protocol: str
    timestamp: str
    status: str = "open"


class MasscanEngine:
    """High-performance port scanner using masscan."""
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.masscan_path = self._find_masscan()
        self.temp_dir = self.config.temp_dir
        
        # Common camera ports for focused scanning
        self.camera_ports = [
            80, 443,           # HTTP/HTTPS
            554,               # RTSP
            8080, 8081, 8000,  # HTTP alternatives
            8443, 8888, 9000,  # HTTPS alternatives
            81, 82, 83,        # HTTP alternatives
            5000, 5001,        # Camera management
            37777, 37778,      # Dahua
            8899,              # Hikvision
            4567,              # Axis
            1024, 1025,        # Various camera systems
        ]
    
    def _find_masscan(self) -> Optional[str]:
        """Locate masscan executable."""
        common_paths = [
            '/usr/local/bin/masscan',  # Homebrew default on macOS
            '/usr/bin/masscan',
            '/opt/homebrew/bin/masscan',  # Homebrew on Apple Silicon
            'masscan'  # In PATH
        ]
        
        for path in common_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                # Masscan outputs version to stderr, but exits with code 0
                if result.returncode == 0 or 'Masscan version' in (result.stdout + result.stderr):
                    logger.debug(f"Found masscan at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        logger.warning("Masscan not found. Install with: apt install masscan")
        return None
    
    def is_available(self) -> bool:
        """Check if masscan is available."""
        return self.masscan_path is not None
    
    def scan_range(self, ip_range: str, ports: Optional[List[int]] = None, 
                   rate: Optional[int] = None) -> List[MasscanResult]:
        """
        Scan IP range for open ports using masscan.
        
        Args:
            ip_range: CIDR notation, IP range, or single IP
            ports: List of ports to scan (default: camera ports)
            rate: Scan rate in packets/second (default: from config)
            
        Returns:
            List of MasscanResult objects
        """
        if not self.is_available():
            logger.error("Masscan not available - falling back to internal scanner")
            return self._fallback_scan(ip_range, ports)
        
        # Validate inputs
        if not self._validate_range(ip_range):
            logger.error(f"Invalid IP range: {ip_range}")
            return []
        
        ports = ports or self.camera_ports
        rate = rate or self.config.masscan_rate
        
        # Generate unique output file
        output_file = self.temp_dir / f"masscan_{uuid4().hex}.json"
        
        try:
            # Build masscan command
            cmd = self._build_command(ip_range, ports, rate, output_file)
            
            # Execute scan with monitoring
            logger.info(f"Starting masscan scan of {ip_range} ({len(ports)} ports, rate: {rate} pps)")
            start_time = time.time()
            
            result = self._execute_masscan(cmd)
            
            duration = time.time() - start_time
            logger.info(f"Masscan completed in {duration:.2f}s")
            
            # Parse results
            results = self._parse_results(output_file)
            logger.info(f"Found {len(results)} open ports")
            
            return results
            
        except Exception as e:
            logger.error(f"Masscan scan failed: {e}")
            return []
        finally:
            # Cleanup
            if output_file.exists():
                output_file.unlink()
    
    def _validate_range(self, ip_range: str) -> bool:
        """Validate IP range format."""
        # Single IP
        if NetworkValidator.validate_ip(ip_range):
            return True
        
        # CIDR notation
        if NetworkValidator.validate_cidr(ip_range):
            return True
        
        # IP range (192.168.1.1-192.168.1.100)
        if '-' in ip_range and len(ip_range.split('-')) == 2:
            start_ip, end_ip = ip_range.split('-')
            return (NetworkValidator.validate_ip(start_ip.strip()) and 
                   NetworkValidator.validate_ip(end_ip.strip()))
        
        return False
    
    def _build_command(self, ip_range: str, ports: List[int], 
                      rate: int, output_file: Path) -> List[str]:
        """Build masscan command arguments."""
        cmd = [
            self.masscan_path,
            ip_range,
            '-p', ','.join(map(str, ports)),
            '--rate', str(rate),
            '--output-format', 'json',
            '--output-filename', str(output_file),
            '--open-only',  # Only report open ports
            '--banners',    # Grab banners when possible
        ]
        
        # Add additional options based on configuration
        if self.config.verbose:
            cmd.append('--verbose')
        
        # Reduce retries for speed
        cmd.extend(['--retries', '1'])
        
        return cmd
    
    def _execute_masscan(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Execute masscan command with proper error handling."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                check=False   # Don't raise on non-zero exit
            )
            
            if result.returncode != 0:
                logger.warning(f"Masscan returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    logger.warning(f"Masscan stderr: {result.stderr}")
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error("Masscan scan timed out (5 minutes)")
            raise
        except Exception as e:
            logger.error(f"Failed to execute masscan: {e}")
            raise
    
    def _parse_results(self, output_file: Path) -> List[MasscanResult]:
        """Parse masscan JSON output."""
        results = []
        
        if not output_file.exists():
            logger.warning("Masscan output file not found")
            return results
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        # Parse masscan JSON format
                        if 'ports' in data:
                            ip = data.get('ip', '')
                            timestamp = data.get('timestamp', '')
                            
                            for port_info in data['ports']:
                                port = port_info.get('port', 0)
                                proto = port_info.get('proto', 'tcp')
                                status = port_info.get('status', 'open')
                                
                                if port > 0:
                                    results.append(MasscanResult(
                                        ip=ip,
                                        port=port,
                                        protocol=proto,
                                        timestamp=timestamp,
                                        status=status
                                    ))
                    
                    except json.JSONDecodeError as e:
                        logger.debug(f"Failed to parse JSON line: {line[:100]}... Error: {e}")
                        continue
        
        except IOError as e:
            logger.error(f"Failed to read masscan output: {e}")
        
        return results
    
    def _fallback_scan(self, ip_range: str, ports: Optional[List[int]]) -> List[MasscanResult]:
        """Fallback to internal port scanner when masscan unavailable."""
        from ..core.network import PortScanner
        
        logger.info("Using internal port scanner (slower than masscan)")
        
        ports = ports or self.camera_ports
        scanner = PortScanner(
            timeout=self.config.connect_timeout,
            max_threads=self.config.max_threads
        )
        
        results = []
        
        # Generate IPs from range
        if NetworkValidator.validate_ip(ip_range):
            ips = [ip_range]
        elif NetworkValidator.validate_cidr(ip_range):
            ips = list(IPRangeGenerator.from_cidr(ip_range))
        elif '-' in ip_range:
            ips = list(IPRangeGenerator.from_range(ip_range))
        else:
            logger.error(f"Unsupported IP range format: {ip_range}")
            return results
        
        # Scan each IP
        for ip in ips:
            scan_results = scanner.scan_ports(ip, ports)
            
            for result in scan_results:
                if result.is_open:
                    results.append(MasscanResult(
                        ip=result.ip,
                        port=result.port,
                        protocol='tcp',
                        timestamp=str(int(time.time())),
                        status='open'
                    ))
        
        return results
    
    def scan_targets_file(self, file_path: str, ports: Optional[List[int]] = None) -> List[MasscanResult]:
        """Scan targets from file (one IP/range per line)."""
        all_results = []
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    target = line.strip()
                    
                    # Skip empty lines and comments
                    if not target or target.startswith('#'):
                        continue
                    
                    logger.info(f"Scanning target {line_num}: {target}")
                    
                    try:
                        results = self.scan_range(target, ports)
                        all_results.extend(results)
                    except Exception as e:
                        logger.error(f"Failed to scan {target}: {e}")
                        continue
        
        except IOError as e:
            logger.error(f"Failed to read targets file {file_path}: {e}")
            return []
        
        return all_results
    
    def get_camera_candidates(self, results: List[MasscanResult]) -> List[MasscanResult]:
        """Filter results for likely camera candidates."""
        camera_candidates = []
        
        # Ports that strongly indicate camera systems
        strong_camera_ports = {554, 37777, 37778, 8899, 4567}
        
        # Ports that might indicate cameras
        possible_camera_ports = {80, 443, 8080, 8081, 8000, 8443, 8888, 9000, 81, 5000, 5001}
        
        for result in results:
            if result.port in strong_camera_ports:
                camera_candidates.append(result)
            elif result.port in possible_camera_ports:
                # These need further analysis to confirm camera presence
                camera_candidates.append(result)
        
        return camera_candidates
    
    def get_unique_ips(self, results: List[MasscanResult]) -> List[str]:
        """Extract unique IP addresses from results."""
        return list(set(result.ip for result in results))
    
    def results_to_dict(self, results: List[MasscanResult]) -> List[Dict]:
        """Convert results to dictionary format for JSON output."""
        return [
            {
                'ip': r.ip,
                'port': r.port,
                'protocol': r.protocol,
                'timestamp': r.timestamp,
                'status': r.status
            }
            for r in results
        ]


class EnhancedMasscanEngine(MasscanEngine):
    """Masscan engine with comprehensive camera port intelligence."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.port_manager = get_port_manager()
        self.adaptive_scanner = AdaptivePortScanner()

    def scan_range_comprehensive(self, ip_range: str,
                               scan_mode: str = "BALANCED",
                               custom_categories: Optional[List[str]] = None) -> List[MasscanResult]:
        """Enhanced scanning with category-based port selection."""

        # Get appropriate ports for scan mode
        if custom_categories:
            ports = self.port_manager.get_ports_for_categories(custom_categories)
        elif scan_mode == "ADAPTIVE":
            ports = self.adaptive_scanner.get_adaptive_port_list()
        else:
            ports = self.port_manager.get_ports_for_scan_mode(scan_mode)

        # Log scan scope for visibility
        logger.info(f"Comprehensive scan: {len(ports)} ports in {scan_mode} mode")
        logger.debug(f"Port ranges: {self._summarize_port_ranges(ports)}")

        return self.scan_range(ip_range, ports=ports)

    def _summarize_port_ranges(self, ports: List[int]) -> str:
        """Summarize port list for logging."""
        if not ports:
            return "none"

        return self.port_manager.summarize_port_ranges(ports)