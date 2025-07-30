import sys
import subprocess
import ipaddress
import base64
import os
import shodan
from flask import Flask, request, Response, stream_with_context, jsonify
from werkzeug.utils import secure_filename

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
        process = subprocess.Popen(
            [sys.executable, '-u', 'CamXploit.py'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        try:
            process.stdin.write(safe_ip + '\n')
            process.stdin.flush()
        except Exception as e:
            yield f'data: Error: Failed to send input to scanner: {e}\n\n'
            process.kill()
            return
        for line in iter(process.stdout.readline, ''):
            yield f'data: {line.rstrip()}\\n\\n'
        process.stdout.close()
        process.wait()

    return Response(stream_with_context(generate_scan_output()), mimetype='text/event-stream')

@app.route('/stream/<path:stream_url_b64>')
def stream(stream_url_b64):
    try:
        stream_url = base64.urlsafe_b64decode(stream_url_b64).decode('utf-8')
    except:
        return "Invalid stream URL format.", 400

    def generate_gstreamer_stream():
        gst_command = [
            'gst-launch-1.0',
            'rtspsrc', f'location={stream_url}', 'latency=0', '!',
            'rtph264depay', '!',
            'h264parse', '!',
            'mpegtsmux', '!',
            'fdsink', 'fd=1'
        ]
        process = subprocess.Popen(gst_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            process.terminate()
            process.wait()

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
    # **FIXED:** Enabled debug mode but DISABLED the reloader to guarantee traceback visibility.
    app.run(host='0.0.0.0', port=8080, threaded=True, debug=True, use_reloader=False)

