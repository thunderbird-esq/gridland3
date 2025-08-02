"""
Network scanning functions for Gridland
"""
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple
from .core import PortResult


def check_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """
    Check if a single port is open on the target IP
    
    Args:
        ip: Target IP address
        port: Port number to check
        timeout: Connection timeout in seconds
        
    Returns:
        PortResult: Object containing port status and basic info
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        is_open = result == 0
        service = None
        
        # Basic service identification
        if is_open:
            if port == 80:
                service = "http"
            elif port == 443:
                service = "https"
            elif port == 554:
                service = "rtsp"
            elif port == 8080:
                service = "http-alt"
            elif port == 8443:
                service = "https-alt"
            elif port in [37777, 37778, 37779]:
                service = "dvr"
            else:
                service = "unknown"
        
        return PortResult(port=port, is_open=is_open, service=service)
        
    except Exception:
        return PortResult(port=port, is_open=False)


def scan_ports(ip: str, ports: List[int], max_threads: int = 100, timeout: float = 2.0) -> List[PortResult]:
    """
    Scan multiple ports on a target IP using threading
    
    Args:
        ip: Target IP address
        ports: List of port numbers to scan
        max_threads: Maximum number of concurrent threads
        timeout: Connection timeout per port
        
    Returns:
        List[PortResult]: List of open ports with their details
    """
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all port checks
        future_to_port = {
            executor.submit(check_port, ip, port, timeout): port 
            for port in ports
        }
        
        # Collect results
        for future in as_completed(future_to_port):
            try:
                result = future.result()
                if result.is_open:
                    open_ports.append(result)
            except Exception:
                # Skip failed port checks
                pass
    
    # Sort by port number
    open_ports.sort(key=lambda x: x.port)
    return open_ports


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Attempt to grab a service banner from an open port
    
    Args:
        ip: Target IP address
        port: Port number
        timeout: Connection timeout
        
    Returns:
        Optional[str]: Banner string if available
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send basic HTTP request for web services
        if port in [80, 8080, 8081, 8082, 8083, 8084, 8085]:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port in [443, 8443]:
            # For HTTPS, we'd need SSL context - skip for now
            sock.close()
            return None
        
        # Try to receive data
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner if banner else None
        
    except Exception:
        return None


def is_camera_port(port: int) -> bool:
    """
    Check if a port is commonly used by IP cameras
    
    Args:
        port: Port number
        
    Returns:
        bool: True if it's a known camera port
    """
    # Common camera ports from the original CamXploit.py
    camera_ports = [
        80, 443, 554, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085,
        8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097,
        8098, 8099, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
        1935, 1936, 1937, 1938, 1939, 37777, 37778, 37779, 37780, 37781, 37782,
        37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790, 37791, 37792,
        37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800, 3702, 3703,
        3704, 3705, 3706, 3707, 3708, 3709, 3710, 5000, 5001, 5002, 5003,
        5004, 5005, 6000, 6001, 6002, 6003, 6004, 6005, 7000, 7001, 7002,
        7003, 7004, 7005, 9000, 9001, 9002, 9003, 9004, 9005, 8888, 8889,
        8890, 8891, 8892, 8893, 9999, 9998, 9997, 9996, 9995, 9994
    ]
    return port in camera_ports