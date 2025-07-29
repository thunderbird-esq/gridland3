"""
Network utilities for GRIDLAND.

Provides IP address validation, port scanning utilities, and network-related
helper functions optimized for security reconnaissance.
"""

import socket
import ipaddress
import threading
import time
from typing import List, Tuple, Generator, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Result of a port scan operation."""
    ip: str
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time: float = 0.0


class NetworkValidator:
    """Network input validation utilities."""
    
    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Validate if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_cidr(cidr_str: str) -> bool:
        """Validate if string is a valid CIDR network."""
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate if port number is valid."""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        """Validate port range string like '80-443' or '80,443,8080'."""
        try:
            if '-' in port_range:
                start, end = port_range.split('-', 1)
                start_port, end_port = int(start), int(end)
                return (NetworkValidator.validate_port(start_port) and 
                       NetworkValidator.validate_port(end_port) and 
                       start_port <= end_port)
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
                return all(NetworkValidator.validate_port(p) for p in ports)
            else:
                return NetworkValidator.validate_port(int(port_range))
        except (ValueError, AttributeError):
            return False


class IPRangeGenerator:
    """Generate IP addresses from various input formats."""
    
    @staticmethod
    def from_cidr(cidr: str) -> Generator[str, None, None]:
        """Generate IP addresses from CIDR notation."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():
                yield str(ip)
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Invalid CIDR {cidr}: {e}")
            return
    
    @staticmethod
    def from_range(ip_range: str) -> Generator[str, None, None]:
        """Generate IP addresses from range like '192.168.1.1-192.168.1.100'."""
        try:
            if '-' not in ip_range:
                yield ip_range
                return
            
            start_ip, end_ip = ip_range.split('-', 1)
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            if start.version != end.version:
                logger.error(f"IP version mismatch in range {ip_range}")
                return
            
            current = start
            while current <= end:
                yield str(current)
                current += 1
                
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Invalid IP range {ip_range}: {e}")
            return
    
    @staticmethod
    def from_file(file_path: str) -> Generator[str, None, None]:
        """Generate IP addresses from file (one per line)."""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        if NetworkValidator.validate_ip(ip):
                            yield ip
                        elif NetworkValidator.validate_cidr(ip):
                            yield from IPRangeGenerator.from_cidr(ip)
                        else:
                            logger.warning(f"Invalid IP/CIDR in file: {ip}")
        except IOError as e:
            logger.error(f"Failed to read IP file {file_path}: {e}")
    
    @staticmethod
    def chunk_ips(ip_generator: Generator[str, None, None], 
                  chunk_size: int = 1000) -> Generator[List[str], None, None]:
        """Split IP generator into chunks for batch processing."""
        chunk = []
        for ip in ip_generator:
            chunk.append(ip)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        
        if chunk:
            yield chunk


class PortScanner:
    """Fast, threaded port scanner optimized for reconnaissance."""
    
    def __init__(self, timeout: float = 3.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self._results_lock = threading.Lock()
    
    def scan_port(self, ip: str, port: int) -> ScanResult:
        """Scan a single port on target IP."""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            
            if result == 0:
                logger.debug(f"Port {port} open on {ip}")
                
                # Try to grab banner
                banner = self._grab_banner(sock)
                service = self._identify_service(port, banner)
                
                sock.close()
                return ScanResult(ip, port, True, service, banner, response_time)
            else:
                sock.close()
                return ScanResult(ip, port, False, response_time=response_time)
                
        except (socket.timeout, socket.error, OSError) as e:
            response_time = time.time() - start_time
            logger.debug(f"Port {port} connection failed on {ip}: {e}")
            return ScanResult(ip, port, False, response_time=response_time)
    
    def scan_ports(self, ip: str, ports: List[int]) -> List[ScanResult]:
        """Scan multiple ports on single IP using threading."""
        results = []
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                try:
                    result = future.result(timeout=self.timeout + 1)
                    results.append(result)
                except Exception as e:
                    port = future_to_port[future]
                    logger.error(f"Port scan failed for {ip}:{port}: {e}")
        
        return sorted(results, key=lambda x: x.port)
    
    def scan_multiple_targets(self, targets: List[Tuple[str, List[int]]]) -> List[ScanResult]:
        """Scan multiple IP/port combinations efficiently."""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit scan jobs for each target
            future_to_target = {
                executor.submit(self.scan_ports, ip, ports): (ip, ports)
                for ip, ports in targets
            }
            
            # Collect results
            for future in as_completed(future_to_target):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    ip, ports = future_to_target[future]
                    logger.error(f"Target scan failed for {ip}: {e}")
        
        return all_results
    
    def _grab_banner(self, sock: socket.socket, max_bytes: int = 1024) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            sock.settimeout(2.0)  # Short timeout for banner grab
            data = sock.recv(max_bytes)
            return data.decode('utf-8', errors='ignore').strip()
        except (socket.timeout, socket.error, UnicodeDecodeError):
            return None
    
    def _identify_service(self, port: int, banner: Optional[str] = None) -> Optional[str]:
        """Identify service based on port and banner."""
        # Common port/service mappings
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            554: 'RTSP',
            993: 'IMAPS',
            995: 'POP3S',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            8000: 'HTTP-Alt',
            8888: 'HTTP-Alt',
            9000: 'HTTP-Alt'
        }
        
        service = common_services.get(port)
        
        # Refine based on banner if available
        if banner:
            banner_lower = banner.lower()
            if 'http' in banner_lower:
                service = 'HTTP'
            elif 'ssh' in banner_lower:
                service = 'SSH'
            elif 'ftp' in banner_lower:
                service = 'FTP'
            elif 'rtsp' in banner_lower:
                service = 'RTSP'
        
        return service


class NetworkUtils:
    """General network utility functions."""
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is in private range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def is_local_ip(ip: str) -> bool:
        """Check if IP address is local/loopback."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback or ip_obj.is_link_local
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address (best guess)."""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    @staticmethod
    def reverse_dns(ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    @staticmethod
    def parse_ports(port_spec: str) -> List[int]:
        """Parse port specification into list of port numbers."""
        ports = []
        
        try:
            # Handle comma-separated ports
            if ',' in port_spec:
                for part in port_spec.split(','):
                    part = part.strip()
                    if '-' in part:
                        # Handle range within comma-separated list
                        start, end = map(int, part.split('-', 1))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(part))
            
            # Handle single range
            elif '-' in port_spec:
                start, end = map(int, port_spec.split('-', 1))
                ports.extend(range(start, end + 1))
            
            # Handle single port
            else:
                ports.append(int(port_spec))
            
            # Validate and deduplicate
            valid_ports = sorted(set(p for p in ports if NetworkValidator.validate_port(p)))
            return valid_ports
            
        except (ValueError, AttributeError) as e:
            logger.error(f"Invalid port specification '{port_spec}': {e}")
            return []