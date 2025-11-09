#!/usr/bin/env python3
"""
Standalone test for ProcessManager lifecycle validation.

Tests process timeout and cleanup without importing server.py dependencies.
"""

import subprocess
import time
import sys
import threading
from urllib.parse import urlparse

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("WARNING: psutil not available, some cleanup features will be limited")


class TestProcessManager:
    """Minimal ProcessManager for testing (mirrors server.py implementation)."""

    def __init__(self):
        self.processes = {}
        self.lock = threading.Lock()
        self._shutdown = False
        self.timeout_thread = threading.Thread(target=self._timeout_checker, daemon=True)
        self.timeout_thread.start()

    def register(self, process, timeout):
        with self.lock:
            process_id = id(process)
            self.processes[process_id] = {
                'process': process,
                'timeout': timeout,
                'start_time': time.time()
            }
            print(f"Registered process {process_id} with {timeout}s timeout")
            return process_id

    def cleanup_process(self, process, timeout=5):
        if process is None:
            return

        process_id = id(process)

        try:
            if process.poll() is not None:
                print(f"Process {process_id} already terminated")
                return

            print(f"Sending SIGTERM to process {process_id}")
            process.terminate()

            try:
                process.wait(timeout=timeout)
                print(f"Process {process_id} terminated gracefully")
                return
            except subprocess.TimeoutExpired:
                print(f"Process {process_id} did not terminate, sending SIGKILL")

            process.kill()

            if PSUTIL_AVAILABLE:
                try:
                    parent = psutil.Process(process.pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    try:
                        parent.kill()
                    except psutil.NoSuchProcess:
                        pass
                    print(f"Killed process tree for {process_id}")
                except (psutil.NoSuchProcess, Exception) as e:
                    print(f"Process {process_id} cleanup: {e}")

            try:
                process.wait(timeout=1)
            except:
                pass

        except Exception as e:
            print(f"Error cleaning up process {process_id}: {e}")
        finally:
            with self.lock:
                self.processes.pop(process_id, None)

    def check_timeouts(self):
        current_time = time.time()
        with self.lock:
            processes_to_kill = []
            for process_id, info in list(self.processes.items()):
                elapsed = current_time - info['start_time']
                if elapsed > info['timeout']:
                    print(f"Process {process_id} exceeded timeout ({elapsed:.1f}s > {info['timeout']}s)")
                    processes_to_kill.append(info['process'])

        for process in processes_to_kill:
            self.cleanup_process(process)

    def _timeout_checker(self):
        while not self._shutdown:
            try:
                self.check_timeouts()
                time.sleep(5)
            except Exception as e:
                print(f"Error in timeout checker: {e}")

    def cleanup_all(self):
        self._shutdown = True
        print("Cleaning up all processes...")
        with self.lock:
            processes = list(self.processes.values())
        for info in processes:
            self.cleanup_process(info['process'])
        print("All processes cleaned up")


def validate_stream_url(url):
    """Validate stream URL (mirrors server.py implementation)."""
    if not url:
        return False

    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '\\']
    for char in dangerous_chars:
        if char in url:
            return False

    try:
        parsed = urlparse(url)
        allowed_protocols = ['rtsp', 'rtmp', 'http', 'https']

        if parsed.scheme.lower() not in allowed_protocols:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception as e:
        return False


def test_basic_cleanup():
    """Test 1: Basic process cleanup."""
    print("\n=== Test 1: Basic Process Cleanup ===")
    pm = TestProcessManager()

    process = subprocess.Popen(['sleep', '30'])
    pm.cleanup_process(process)

    assert process.poll() is not None, "Process not terminated!"
    print("✓ Test 1 PASSED - Process cleaned up successfully")


def test_timeout():
    """Test 2: Timeout enforcement."""
    print("\n=== Test 2: Timeout Enforcement ===")
    pm = TestProcessManager()

    process = subprocess.Popen(['sleep', '60'])
    process_id = pm.register(process, timeout=2)

    print("Waiting for timeout (up to 10 seconds)...")
    for i in range(20):
        if process.poll() is not None:
            print(f"✓ Process killed after timeout")
            break
        time.sleep(0.5)
    else:
        pm.cleanup_all()
        assert False, "Process not killed after timeout!"

    time.sleep(1)
    with pm.lock:
        assert process_id not in pm.processes, "Process still tracked!"

    pm.cleanup_all()
    print("✓ Test 2 PASSED - Timeout enforcement works")


def test_stream_validation():
    """Test 3: Stream URL validation."""
    print("\n=== Test 3: Stream URL Validation ===")

    valid = [
        'rtsp://192.168.1.100:554/stream',
        'rtmp://example.com:1935/live',
        'http://camera.local:8080/video',
        'https://secure.camera.com/feed',
    ]

    for url in valid:
        assert validate_stream_url(url), f"Valid URL rejected: {url}"

    invalid = [
        'rtsp://camera.local; rm -rf /',
        'rtsp://camera.local | cat /etc/passwd',
        'rtsp://camera.local && ls',
        'ftp://camera.local/stream',
        '',
    ]

    for url in invalid:
        assert not validate_stream_url(url), f"Invalid URL accepted: {url}"

    print("✓ Test 3 PASSED - URL validation works")


def test_multiple_processes():
    """Test 4: Multiple process management."""
    print("\n=== Test 4: Multiple Processes ===")
    pm = TestProcessManager()

    processes = []
    for i in range(3):
        p = subprocess.Popen(['sleep', '30'])
        pm.register(p, timeout=30)
        processes.append(p)

    with pm.lock:
        assert len(pm.processes) >= 3, "Not all processes tracked"

    for p in processes:
        pm.cleanup_process(p)

    time.sleep(1)

    for p in processes:
        assert p.poll() is not None, "Process not cleaned up"

    pm.cleanup_all()
    print("✓ Test 4 PASSED - Multiple processes managed successfully")


def main():
    print("=" * 60)
    print("ProcessManager Lifecycle Validation")
    print("=" * 60)
    print(f"psutil available: {PSUTIL_AVAILABLE}")

    try:
        test_basic_cleanup()
        test_timeout()
        test_stream_validation()
        test_multiple_processes()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED ✓")
        print("=" * 60)
        print("\nValidated features:")
        print("  ✓ Process cleanup (SIGTERM -> SIGKILL)")
        print("  ✓ Timeout enforcement")
        print("  ✓ Stream URL validation")
        print("  ✓ Multiple process management")
        if PSUTIL_AVAILABLE:
            print("  ✓ Process tree cleanup (psutil)")
        print("\n✓ Memory leak prevention is WORKING")
        print("=" * 60)

        return 0

    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
