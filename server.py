import sys
import subprocess
import ipaddress
import base64
import os
import re
import time
import threading
import atexit
from urllib.parse import urlparse
from flask import Flask, request, Response, stream_with_context, jsonify

try:
    import psutil
except ImportError:
    psutil = None
    print("⚠️  Warning: psutil not installed. Process cleanup will be limited.")

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    shodan = None
    print("⚠️  Warning: shodan not installed. Discovery endpoint will be disabled.")

app = Flask(__name__, static_folder='static', static_url_path='')

# --- Ethical Use Disclaimer ---
# This server provides access to security analysis tools. It is intended for
# educational, artistic (sousveillance), and authorized security auditing
# purposes ONLY. By using this tool, you are solely responsible
# for ensuring your actions comply with all applicable laws and ethical guidelines.
# Unauthorized use against systems you do not own or have explicit permission
# to test is illegal, unethical, and strictly prohibited.


# ============================================================================
# INPUT VALIDATION & SANITIZATION
# ============================================================================

class InputValidator:
    """
    Comprehensive input validation for all user-controlled inputs.
    Prevents command injection, XSS, and other injection attacks.
    """

    # Dangerous characters that could be used for command injection
    DANGEROUS_CHARS = [';', '|', '&', '$', '`', '\n', '\r', '>', '<', '\\', '(', ')']

    # Whitelisted stream protocols
    ALLOWED_PROTOCOLS = ['rtsp', 'rtmp', 'http', 'https']

    @staticmethod
    def validate_ip(ip_str, allow_private=True):
        """
        Validate IP address format and optionally reject private IPs.

        Args:
            ip_str: IP address string to validate
            allow_private: If False, reject private IP addresses

        Returns:
            str: Validated IP address

        Raises:
            ValueError: If IP is invalid or private (when not allowed)
        """
        if not ip_str:
            raise ValueError("IP address is required")

        # Remove whitespace
        ip_str = ip_str.strip()

        # Check for dangerous characters
        for char in InputValidator.DANGEROUS_CHARS:
            if char in ip_str:
                raise ValueError(f"Invalid IP address: contains dangerous character '{char}'")

        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise ValueError(f"Invalid IP address format: {str(e)}")

        # Check if private IP (optionally reject)
        if not allow_private and ip_obj.is_private:
            raise ValueError("Private IP addresses are not allowed")

        return str(ip_obj)

    @staticmethod
    def validate_stream_url(url_str):
        """
        Validate stream URL for safe subprocess execution.

        Args:
            url_str: Stream URL to validate

        Returns:
            str: Validated URL

        Raises:
            ValueError: If URL is invalid or contains dangerous patterns
        """
        if not url_str:
            raise ValueError("Stream URL is required")

        # Remove whitespace
        url_str = url_str.strip()

        # Length limit
        if len(url_str) > 500:
            raise ValueError("Stream URL exceeds maximum length of 500 characters")

        if len(url_str) < 10:
            raise ValueError("Stream URL is too short")

        # Check for dangerous characters
        for char in InputValidator.DANGEROUS_CHARS:
            if char in url_str:
                raise ValueError(f"Invalid stream URL: contains dangerous character '{char}'")

        # Parse URL to validate structure
        try:
            parsed = urlparse(url_str)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")

        # Validate protocol
        if not parsed.scheme:
            raise ValueError("Stream URL must include a protocol (rtsp://, http://, etc.)")

        if parsed.scheme.lower() not in InputValidator.ALLOWED_PROTOCOLS:
            raise ValueError(
                f"Invalid protocol '{parsed.scheme}'. "
                f"Allowed protocols: {', '.join(InputValidator.ALLOWED_PROTOCOLS)}"
            )

        # Validate hostname exists
        if not parsed.netloc:
            raise ValueError("Stream URL must include a hostname")

        # Additional checks for command injection patterns
        dangerous_patterns = [
            r'\$\(',  # Command substitution
            r'\`',    # Backticks
            r'\|\|',  # OR operator
            r'&&',    # AND operator
            r'\bsh\b',    # Shell invocation
            r'\bbash\b',  # Bash invocation
            r'\bexec\b',  # Exec command
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, url_str, re.IGNORECASE):
                raise ValueError(f"Invalid stream URL: contains dangerous pattern")

        return url_str

    @staticmethod
    def validate_shodan_query(query_str):
        """
        Validate Shodan search query.

        Args:
            query_str: Query string to validate

        Returns:
            str: Validated query string

        Raises:
            ValueError: If query is invalid
        """
        if not query_str:
            raise ValueError("Search query is required")

        # Strip whitespace
        query_str = query_str.strip()

        # Length limits
        if len(query_str) < 2:
            raise ValueError("Search query must be at least 2 characters")

        if len(query_str) > 500:
            raise ValueError("Search query exceeds maximum length of 500 characters")

        return query_str


# ============================================================================
# PROCESS MANAGEMENT
# ============================================================================

class ProcessManager:
    """
    Manages subprocess lifecycle with timeout enforcement and guaranteed cleanup.

    Prevents memory leaks and orphaned processes by:
    - Tracking all active processes with timeouts
    - Forcefully terminating processes that exceed timeout
    - Providing guaranteed cleanup on shutdown
    - Using psutil for comprehensive process tree cleanup
    """

    def __init__(self):
        self.processes = {}  # {process_id: {'process': subprocess.Popen, 'timeout': float, 'start_time': float}}
        self.lock = threading.Lock()
        self._shutdown = False

        # Start background timeout checker thread
        self.timeout_thread = threading.Thread(target=self._timeout_checker, daemon=True)
        self.timeout_thread.start()

    def register(self, process, timeout):
        """
        Register a process for tracking with specified timeout.

        Args:
            process: subprocess.Popen instance
            timeout: Maximum execution time in seconds

        Returns:
            Process ID for tracking
        """
        with self.lock:
            process_id = id(process)
            self.processes[process_id] = {
                'process': process,
                'timeout': timeout,
                'start_time': time.time()
            }
            print(f"ProcessManager: Registered process {process_id} with {timeout}s timeout")
            return process_id

    def cleanup_process(self, process, timeout=5):
        """
        Forcefully terminate a process with escalating signals.

        Strategy:
        1. Send SIGTERM (graceful shutdown)
        2. Wait up to timeout seconds
        3. Send SIGKILL (forced termination)
        4. Kill entire process tree if psutil available

        Args:
            process: subprocess.Popen instance to terminate
            timeout: Seconds to wait for graceful termination
        """
        if process is None:
            return

        process_id = id(process)

        try:
            # Check if process is already terminated
            if process.poll() is not None:
                print(f"ProcessManager: Process {process_id} already terminated")
                return

            # Try graceful termination first
            print(f"ProcessManager: Sending SIGTERM to process {process_id}")
            process.terminate()

            # Wait for graceful shutdown
            try:
                process.wait(timeout=timeout)
                print(f"ProcessManager: Process {process_id} terminated gracefully")
                return
            except subprocess.TimeoutExpired:
                print(f"ProcessManager: Process {process_id} did not terminate, sending SIGKILL")

            # Force kill if still running
            process.kill()

            # If psutil available, kill entire process tree
            if psutil:
                try:
                    parent = psutil.Process(process.pid)
                    children = parent.children(recursive=True)

                    # Kill all children
                    for child in children:
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass

                    # Kill parent
                    try:
                        parent.kill()
                    except psutil.NoSuchProcess:
                        pass

                    print(f"ProcessManager: Killed process tree for {process_id}")
                except psutil.NoSuchProcess:
                    print(f"ProcessManager: Process {process_id} already gone")
                except Exception as e:
                    print(f"ProcessManager: Error killing process tree: {e}")

            # Final wait to reap zombie process
            try:
                process.wait(timeout=1)
            except:
                pass

        except Exception as e:
            print(f"ProcessManager: Error cleaning up process {process_id}: {e}")
        finally:
            # Remove from tracking
            with self.lock:
                self.processes.pop(process_id, None)

    def check_timeouts(self):
        """
        Check all tracked processes and kill those exceeding timeout.
        Called periodically by background thread.
        """
        current_time = time.time()

        with self.lock:
            processes_to_kill = []

            for process_id, info in list(self.processes.items()):
                elapsed = current_time - info['start_time']

                if elapsed > info['timeout']:
                    print(f"ProcessManager: Process {process_id} exceeded timeout ({elapsed:.1f}s > {info['timeout']}s)")
                    processes_to_kill.append(info['process'])

        # Kill processes outside the lock to avoid blocking
        for process in processes_to_kill:
            self.cleanup_process(process)

    def _timeout_checker(self):
        """Background thread that periodically checks for timed-out processes."""
        while not self._shutdown:
            try:
                self.check_timeouts()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"ProcessManager: Error in timeout checker: {e}")

    def cleanup_all(self):
        """
        Clean up all tracked processes.
        Called on shutdown via atexit.
        """
        self._shutdown = True
        print("ProcessManager: Cleaning up all processes...")

        with self.lock:
            processes = list(self.processes.values())

        for info in processes:
            self.cleanup_process(info['process'])

        print("ProcessManager: All processes cleaned up")


# Initialize Shodan API client
api = None
if SHODAN_AVAILABLE:
    try:
        SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
        if not SHODAN_API_KEY:
            print("⚠️  Warning: SHODAN_API_KEY environment variable not set. Discovery will be disabled.")
        else:
            api = shodan.Shodan(SHODAN_API_KEY)
            print("✅ Shodan API initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing Shodan API: {e}")
        api = None

# Initialize global ProcessManager
process_manager = ProcessManager()

# Register cleanup on shutdown
atexit.register(process_manager.cleanup_all)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/discover', methods=['POST'])
def discover():
    """
    Shodan discovery endpoint with input validation.
    """
    if not api:
        return jsonify({"error": "Shodan API is not configured on the server."}), 500

    data = request.get_json(silent=True) or {}
    query = data.get('query')

    # Validate query input
    try:
        query = InputValidator.validate_shodan_query(query)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        results = api.search(query, limit=50)
        ips = [result['ip_str'] for result in results['matches']]
        return jsonify(ips)
    except AttributeError as e:
        # Shodan not available
        print(f"ERROR: Shodan module not available: {e}")
        return jsonify({"error": "Shodan API is not available. Install 'shodan' package."}), 500
    except Exception as e:
        # Handle both shodan.APIError and other exceptions
        error_msg = str(e)
        print(f"ERROR: Error in /discover: {error_msg}")
        return jsonify({"error": f"Discovery error: {error_msg}"}), 500


@app.route('/scan', methods=['POST'])
def scan():
    """
    Scan endpoint with comprehensive input validation and secure subprocess handling.
    """
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')

    # Validate IP input
    try:
        validated_ip = InputValidator.validate_ip(ip, allow_private=True)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    def generate_scan_output():
        process = None
        try:
            # SECURITY FIX: Pass IP as command-line argument instead of stdin
            # This prevents command injection via stdin
            process = subprocess.Popen(
                [sys.executable, '-u', os.path.abspath('CamXploit.py'), '--ip', validated_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env={'PATH': '/usr/bin:/bin'}  # Limited PATH to prevent command injection
            )

            # Register process with 300 second (5 minute) timeout
            process_manager.register(process, timeout=300)

            # Stream output with timeout checking
            for line in iter(process.stdout.readline, ''):
                # Check if process was killed by timeout
                if process.poll() is not None:
                    break
                yield f'data: {line.rstrip()}\\n\\n'

            process.stdout.close()
            process.wait()

        except Exception as e:
            yield f'data: Error: Scanner process failed: {e}\n\n'
        finally:
            # Guaranteed cleanup in finally block
            if process:
                process_manager.cleanup_process(process)

    return Response(stream_with_context(generate_scan_output()), mimetype='text/event-stream')


@app.route('/stream/<path:stream_url_b64>')
def stream(stream_url_b64):
    """
    Stream endpoint with comprehensive URL validation to prevent command injection.
    """
    try:
        stream_url = base64.urlsafe_b64decode(stream_url_b64).decode('utf-8')
    except Exception:
        return "Invalid stream URL format.", 400

    # SECURITY FIX: Validate stream URL BEFORE subprocess
    try:
        validated_url = InputValidator.validate_stream_url(stream_url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    def generate_gstreamer_stream():
        process = None
        try:
            # SECURITY FIX: Never use shell=True, use array of arguments
            gst_command = [
                'gst-launch-1.0',
                'rtspsrc',
                f'location={validated_url}',  # Using validated URL
                'latency=0',
                '!',
                'rtph264depay',
                '!',
                'h264parse',
                '!',
                'mpegtsmux',
                '!',
                'fdsink',
                'fd=1'
            ]

            # SECURITY FIX: Set limited PATH environment
            process = subprocess.Popen(
                gst_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={'PATH': '/usr/bin:/bin'}
            )

            # Register process with 600 second (10 minute) timeout
            process_manager.register(process, timeout=600)

            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                yield chunk

        except Exception as e:
            print(f"Stream error: {e}")
        finally:
            # Guaranteed cleanup in finally block
            if process:
                process_manager.cleanup_process(process)

    return Response(generate_gstreamer_stream(), mimetype='video/MP2T')


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/ui/')
def ui_interface():
    """Serve the Macintosh Plus native interface."""
    return app.send_static_file('gridland-ui/index.html')


@app.route('/ui/<path:filename>')
def ui_assets(filename):
    """Serve UI assets from gridland-ui directory."""
    return app.send_from_directory('gridland-ui', filename)


if __name__ == '__main__':
    # SECURITY NOTE: Debug mode should be disabled in production
    # Set debug=False and use proper WSGI server (gunicorn, uWSGI) for production
    app.run(host='0.0.0.0', port=8080, threaded=True, debug=True, use_reloader=False)
