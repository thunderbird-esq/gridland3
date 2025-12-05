"""Python-based port scanner for GRIDLAND.

This module provides a pure Python port scanner implementation that matches
the behavior of CamXploit.py's check_ports function. It uses threading for
concurrent scanning with configurable timeout and thread limits.
"""

import socket
import threading
from typing import Callable, List, Optional


class PythonPortScanner:
    """Thread-based port scanner using Python's socket library.

    This scanner replicates the functionality of CamXploit.py's check_ports
    function (lines 930-980), using threading for concurrent port scanning
    with configurable parameters and progress reporting.

    Attributes:
        max_threads: Maximum number of concurrent threads (default: 100).
        timeout: Socket connection timeout in seconds (default: 1.5).

    Example:
        >>> scanner = PythonPortScanner(max_threads=100, timeout=1.5)
        >>> open_ports = scanner.scan_ports("192.168.1.1", [80, 443, 554])
        >>> print(open_ports)
        [80, 443]
    """

    def __init__(self, max_threads: int = 100, timeout: float = 1.5):
        """Initialize the Python port scanner.

        Args:
            max_threads: Maximum number of concurrent scanning threads.
                         Default: 100 (matches CamXploit.py line 958).
            timeout: Socket connection timeout in seconds.
                     Default: 1.5 (matches CamXploit.py line 798).

        Raises:
            ValueError: If max_threads < 1 or timeout <= 0.
        """
        if max_threads < 1:
            raise ValueError("max_threads must be at least 1")
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        self.max_threads = max_threads
        self.timeout = timeout

    def scan_ports(
        self,
        ip: str,
        ports: List[int],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        termination_flag: Optional[threading.Event] = None,
    ) -> List[int]:
        """Scan a list of ports on a target IP address.

        This method replicates CamXploit.py's check_ports function behavior:
        - Uses socket.connect_ex() returning 0 for success (line 944)
        - Thread-safe result collection with locks (line 934)
        - Progress reporting every 50 ports (line 951)
        - Early termination support via flag (lines 939-940)
        - Returns sorted list of open ports (line 980)

        Args:
            ip: Target IP address to scan.
            ports: List of port numbers to scan (1-65535).
            progress_callback: Optional callback function called with
                               (scanned_count, total_ports) every 50 ports.
            termination_flag: Optional threading.Event() to signal early
                              termination. If set, scanning stops.

        Returns:
            List[int]: Sorted list of open port numbers.

        Raises:
            ValueError: If IP is invalid or ports contain invalid numbers.
            OSError: If socket operations fail critically.

        Example:
            >>> scanner = PythonPortScanner()
            >>> def progress(scanned, total):
            ...     print(f"Progress: {scanned}/{total}")
            >>> open_ports = scanner.scan_ports(
            ...     "192.168.1.1",
            ...     [80, 443, 8080],
            ...     progress_callback=progress
            ... )
            >>> print(open_ports)
            [80, 443]
        """
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            raise ValueError(f"Invalid IP address: {ip}")

        # Validate ports
        for port in ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"Invalid port number: {port}")

        open_ports = []
        lock = threading.Lock()
        scanned_count = 0
        total_ports = len(ports)

        def scan_port(port: int) -> None:
            """Scan a single port (inner function matching CamXploit.py line 937)."""
            nonlocal scanned_count

            # Check termination flag (matches line 939-940)
            if termination_flag and termination_flag.is_set():
                return

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    # connect_ex returns 0 on success (matches line 944)
                    if sock.connect_ex((ip, port)) == 0:
                        with lock:
                            open_ports.append(port)
                except Exception:
                    # Silently handle exceptions (matches line 953-955)
                    pass
                finally:
                    with lock:
                        scanned_count += 1
                        # Progress reporting every 50 ports (matches line 951)
                        if progress_callback and scanned_count % 50 == 0:
                            progress_callback(scanned_count, total_ports)

        # Thread pool management (matches lines 961-975)
        threads = []

        for port in ports:
            # Create and start thread
            thread = threading.Thread(target=scan_port, args=(port,))
            thread.daemon = True
            threads.append(thread)
            thread.start()

            # Limit concurrent threads (matches line 968)
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads = []

        # Wait for remaining threads (matches line 974-975)
        for thread in threads:
            thread.join()

        # Return sorted list (matches line 980)
        return sorted(open_ports)
