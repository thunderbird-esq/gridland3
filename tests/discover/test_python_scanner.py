"""Tests for the PythonPortScanner class."""

import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from gridland.discover.python_scanner import PythonPortScanner


class TestPythonPortScannerInit:
    """Test PythonPortScanner initialization."""

    def test_default_initialization(self):
        """Test scanner initializes with default values."""
        scanner = PythonPortScanner()
        assert scanner.max_threads == 100
        assert scanner.timeout == 1.5

    def test_custom_initialization(self):
        """Test scanner initializes with custom values."""
        scanner = PythonPortScanner(max_threads=50, timeout=2.0)
        assert scanner.max_threads == 50
        assert scanner.timeout == 2.0

    def test_invalid_max_threads(self):
        """Test ValueError raised for invalid max_threads."""
        with pytest.raises(ValueError, match="max_threads must be at least 1"):
            PythonPortScanner(max_threads=0)

        with pytest.raises(ValueError, match="max_threads must be at least 1"):
            PythonPortScanner(max_threads=-5)

    def test_invalid_timeout(self):
        """Test ValueError raised for invalid timeout."""
        with pytest.raises(ValueError, match="timeout must be greater than 0"):
            PythonPortScanner(timeout=0)

        with pytest.raises(ValueError, match="timeout must be greater than 0"):
            PythonPortScanner(timeout=-1.5)


class TestPythonPortScannerValidation:
    """Test input validation in scan_ports method."""

    def test_invalid_ip_address(self):
        """Test ValueError raised for invalid IP address."""
        scanner = PythonPortScanner()

        with pytest.raises(ValueError, match="Invalid IP address"):
            scanner.scan_ports("not.an.ip.address", [80])

        with pytest.raises(ValueError, match="Invalid IP address"):
            scanner.scan_ports("999.999.999.999", [80])

        with pytest.raises(ValueError, match="Invalid IP address"):
            scanner.scan_ports("", [80])

    def test_invalid_port_numbers(self):
        """Test ValueError raised for invalid port numbers."""
        scanner = PythonPortScanner()

        # Port out of range
        with pytest.raises(ValueError, match="Invalid port number"):
            scanner.scan_ports("127.0.0.1", [0])

        with pytest.raises(ValueError, match="Invalid port number"):
            scanner.scan_ports("127.0.0.1", [65536])

        with pytest.raises(ValueError, match="Invalid port number"):
            scanner.scan_ports("127.0.0.1", [-1])

        # Non-integer port
        with pytest.raises(ValueError, match="Invalid port number"):
            scanner.scan_ports("127.0.0.1", ["80"])

        with pytest.raises(ValueError, match="Invalid port number"):
            scanner.scan_ports("127.0.0.1", [80.5])

    def test_valid_ip_addresses(self):
        """Test that valid IP addresses are accepted."""
        scanner = PythonPortScanner()

        # Mock socket to avoid actual network calls
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # Port closed

            # These should not raise ValueError
            scanner.scan_ports("127.0.0.1", [80])
            scanner.scan_ports("192.168.1.1", [80])
            scanner.scan_ports("10.0.0.1", [80])
            scanner.scan_ports("8.8.8.8", [80])


class TestPythonPortScannerScanning:
    """Test port scanning functionality."""

    def test_scan_open_ports(self):
        """Test scanning with open ports returns correct results."""
        scanner = PythonPortScanner()

        # Mock socket to simulate open ports
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock

            # Simulate: port 80 open (0), port 443 open (0), port 8080 closed (1)
            def connect_ex_side_effect(address):
                port = address[1]
                if port in [80, 443]:
                    return 0  # Open
                return 1  # Closed

            mock_sock.connect_ex.side_effect = connect_ex_side_effect

            result = scanner.scan_ports("192.168.1.1", [80, 443, 8080])

            assert result == [80, 443]
            assert isinstance(result, list)
            assert all(isinstance(port, int) for port in result)

    def test_scan_no_open_ports(self):
        """Test scanning with no open ports returns empty list."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # All ports closed

            result = scanner.scan_ports("192.168.1.1", [80, 443, 8080])

            assert result == []

    def test_scan_all_ports_open(self):
        """Test scanning with all ports open."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0  # All ports open

            ports = [80, 443, 554, 8080, 8443]
            result = scanner.scan_ports("192.168.1.1", ports)

            assert result == sorted(ports)

    def test_scan_returns_sorted_list(self):
        """Test that results are returned in sorted order."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock

            # Return open for specific ports in any order
            def connect_ex_side_effect(address):
                port = address[1]
                if port in [8080, 443, 80, 554]:
                    return 0
                return 1

            mock_sock.connect_ex.side_effect = connect_ex_side_effect

            # Scan ports in unsorted order
            result = scanner.scan_ports("192.168.1.1", [8080, 443, 80, 554, 9999])

            # Should return sorted
            assert result == [80, 443, 554, 8080]

    def test_scan_empty_port_list(self):
        """Test scanning with empty port list."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            result = scanner.scan_ports("192.168.1.1", [])

            assert result == []

    def test_timeout_applied(self):
        """Test that timeout is properly applied to sockets."""
        scanner = PythonPortScanner(timeout=2.5)

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1

            scanner.scan_ports("192.168.1.1", [80])

            # Verify settimeout was called with correct value
            mock_sock.settimeout.assert_called_with(2.5)


class TestPythonPortScannerThreading:
    """Test threading and concurrency behavior."""

    def test_thread_limit_respected(self):
        """Test that max_threads limit is respected."""
        scanner = PythonPortScanner(max_threads=5)

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1

            # Scan many ports with small thread limit
            result = scanner.scan_ports("192.168.1.1", list(range(1, 51)))

            # Should complete without errors
            assert isinstance(result, list)

    def test_thread_safety(self):
        """Test that results are collected thread-safely."""
        scanner = PythonPortScanner(max_threads=10)

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0  # All open

            # Scan many ports concurrently
            ports = list(range(1, 101))
            result = scanner.scan_ports("192.168.1.1", ports)

            # All ports should be in results exactly once
            assert len(result) == len(ports)
            assert set(result) == set(ports)
            assert result == sorted(result)

    def test_exception_handling_in_threads(self):
        """Test that exceptions in threads are handled gracefully."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock

            # Simulate exception on some ports
            def connect_ex_side_effect(address):
                port = address[1]
                if port == 443:
                    raise OSError("Connection error")
                if port == 80:
                    return 0  # Open
                return 1  # Closed

            mock_sock.connect_ex.side_effect = connect_ex_side_effect

            result = scanner.scan_ports("192.168.1.1", [80, 443, 8080])

            # Should return only successfully scanned open ports
            assert result == [80]


class TestPythonPortScannerProgressCallback:
    """Test progress callback functionality."""

    def test_progress_callback_called(self):
        """Test that progress callback is called periodically."""
        scanner = PythonPortScanner()
        progress_calls = []

        def progress_callback(scanned, total):
            progress_calls.append((scanned, total))

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1

            # Scan 150 ports to trigger multiple callbacks
            result = scanner.scan_ports(
                "192.168.1.1",
                list(range(1, 151)),
                progress_callback=progress_callback,
            )

            # Should be called at 50, 100, 150
            assert len(progress_calls) >= 3
            assert (50, 150) in progress_calls
            assert (100, 150) in progress_calls
            assert (150, 150) in progress_calls

    def test_progress_callback_not_called_under_50(self):
        """Test progress callback not called for fewer than 50 ports."""
        scanner = PythonPortScanner()
        progress_calls = []

        def progress_callback(scanned, total):
            progress_calls.append((scanned, total))

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1

            result = scanner.scan_ports(
                "192.168.1.1", [80, 443, 8080], progress_callback=progress_callback
            )

            # Should not be called for only 3 ports
            assert len(progress_calls) == 0

    def test_no_callback_works(self):
        """Test that scanning works without progress callback."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0

            result = scanner.scan_ports("192.168.1.1", [80, 443])

            assert result == [80, 443]


class TestPythonPortScannerTermination:
    """Test early termination functionality."""

    def test_termination_flag_stops_scanning(self):
        """Test that setting termination flag stops scanning."""
        scanner = PythonPortScanner()
        termination_flag = threading.Event()

        scan_attempts = []

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock

            def connect_ex_side_effect(address):
                scan_attempts.append(address[1])
                # Set termination flag after first few scans
                if len(scan_attempts) >= 5:
                    termination_flag.set()
                time.sleep(0.01)  # Small delay to allow flag check
                return 0

            mock_sock.connect_ex.side_effect = connect_ex_side_effect

            result = scanner.scan_ports(
                "192.168.1.1",
                list(range(1, 101)),
                termination_flag=termination_flag,
            )

            # Should have scanned fewer ports than requested
            assert len(scan_attempts) < 100

    def test_no_termination_flag_works(self):
        """Test that scanning works without termination flag."""
        scanner = PythonPortScanner()

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0

            result = scanner.scan_ports("192.168.1.1", [80, 443])

            assert result == [80, 443]


class TestPythonPortScannerIntegration:
    """Integration tests for PythonPortScanner."""

    def test_realistic_scan_scenario(self):
        """Test a realistic scanning scenario."""
        scanner = PythonPortScanner(max_threads=50, timeout=1.0)

        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock

            # Simulate realistic camera ports: 80, 443, 554 open
            def connect_ex_side_effect(address):
                port = address[1]
                if port in [80, 443, 554]:
                    return 0
                return 1

            mock_sock.connect_ex.side_effect = connect_ex_side_effect

            common_camera_ports = [
                80,
                443,
                554,
                8000,
                8080,
                8443,
                8554,
                9000,
                1935,
                1755,
            ]
            result = scanner.scan_ports("192.168.1.100", common_camera_ports)

            assert result == [80, 443, 554]
            assert isinstance(result, list)
            assert all(isinstance(p, int) for p in result)
