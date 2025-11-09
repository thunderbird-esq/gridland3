import sys
import subprocess
import ipaddress
import base64
import os
import shodan
import time
import threading
import atexit
import signal
from urllib.parse import urlparse
from flask import Flask, request, Response, stream_with_context, jsonify
from werkzeug.utils import secure_filename

try:
    import psutil
except ImportError:
    psutil = None
    print("Warning: psutil not installed. Process cleanup will be limited.")

app = Flask(__name__, static_folder='static', static_url_path='')

# --- Ethical Use Disclaimer ---
# This server provides access to security analysis tools. It is intended for
# educational, artistic (sousveillance), and authorized security auditing
# purposes ONLY. By using this tool, you agree that you are solely responsible
# for ensuring your actions comply with all applicable laws and ethical guidelines.
# Unauthorized use against systems you do not own or have explicit permission
# to test is illegal, unethical, and strictly prohibited.

# Initialize Shodan API client
try:
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    if not SHODAN_API_KEY:
        print("Warning: SHODAN_API_KEY environment variable not set. Discovery will be disabled.")
        api = None
    else:
        api = shodan.Shodan(SHODAN_API_KEY)
except Exception as e:
    print(f"FATAL: Error initializing Shodan API: {e}")
    api = None


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


def validate_stream_url(url):
    """
    Validate stream URL to prevent command injection.

    Security checks:
    1. Whitelist allowed protocols (rtsp, rtmp, http, https)
    2. Reject dangerous shell characters
    3. Validate URL structure

    Args:
        url: Stream URL to validate

    Returns:
        True if valid, False otherwise
    """
    if not url:
        return False

    # Check for dangerous characters that could enable command injection
    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '\\']
    for char in dangerous_chars:
        if char in url:
            print(f"ProcessManager: Rejected stream URL with dangerous character: {char}")
            return False

    # Validate URL structure and protocol
    try:
        parsed = urlparse(url)

        # Whitelist allowed protocols
        allowed_protocols = ['rtsp', 'rtmp', 'http', 'https']

        if parsed.scheme.lower() not in allowed_protocols:
            print(f"ProcessManager: Rejected stream URL with invalid protocol: {parsed.scheme}")
            return False

        # Basic sanity check: must have a network location (host)
        if not parsed.netloc:
            print(f"ProcessManager: Rejected stream URL with no host")
            return False

        return True

    except Exception as e:
        print(f"ProcessManager: Error validating stream URL: {e}")
        return False


# Initialize global ProcessManager
process_manager = ProcessManager()

# Register cleanup on shutdown
atexit.register(process_manager.cleanup_all)

@app.route('/discover', methods=['POST'])
def discover():
    if not api:
        return jsonify({"error": "Shodan API is not configured on the server."}), 500

    query = request.json.get('query')
    if not query:
        return jsonify({"error": "A search query is required."}), 400

    try:
        results = api.search(query, limit=50)
        ips = [result['ip_str'] for result in results['matches']]
        return jsonify(ips)
    except shodan.APIError as e:
        print(f"ERROR: Shodan API error: {e}")
        return jsonify({"error": f"Shodan API error: {e}"}), 500
    except Exception as e:
        print(f"ERROR: An unexpected error occurred in /discover: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')

    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({'error': 'A valid IP address is required'}), 400

    safe_ip = secure_filename(ip)

    def generate_scan_output():
        process = None
        try:
            process = subprocess.Popen(
                [sys.executable, '-u', 'CamXploit.py'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Register process with 300 second (5 minute) timeout
            process_manager.register(process, timeout=300)

            try:
                process.stdin.write(safe_ip + '\n')
                process.stdin.flush()
            except Exception as e:
                yield f'data: Error: Failed to send input to scanner: {e}\n\n'
                return

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
    try:
        stream_url = base64.urlsafe_b64decode(stream_url_b64).decode('utf-8')
    except:
        return "Invalid stream URL format.", 400

    # Validate stream URL to prevent command injection
    if not validate_stream_url(stream_url):
        return "Invalid or unsafe stream URL.", 400

    def generate_gstreamer_stream():
        process = None
        try:
            gst_command = [
                'gst-launch-1.0',
                'rtspsrc', f'location={stream_url}', 'latency=0', '!',
                'rtph264depay', '!',
                'h264parse', '!',
                'mpegtsmux', '!',
                'fdsink', 'fd=1'
            ]
            process = subprocess.Popen(gst_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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

if __name__ == '__main__':
    # Environment configuration for production safety
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't', 'yes')
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', '8080'))

    # Security: Debug mode disabled by default
    # Set FLASK_DEBUG=true environment variable only for development
    print(f"Starting GRIDLAND server on {host}:{port} (debug={debug_mode})")
    app.run(host=host, port=port, threaded=True, debug=debug_mode, use_reloader=False)

