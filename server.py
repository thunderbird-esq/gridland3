"""
GRIDLAND v3.0 - Security Reconnaissance Server

Flask backend providing API endpoints for the GRIDLAND UI.
Integrates with CamXploit.py for camera analysis and GRIDLAND modules.

⚠️ ETHICAL USE ONLY: This server provides access to security analysis tools.
It is intended for educational, artistic (sousveillance), and authorized
security auditing purposes ONLY. Unauthorized use is prohibited.
"""

import base64
import ipaddress
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

# Optional Shodan import
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    shodan = None
    SHODAN_AVAILABLE = False
    print("Warning: shodan module not available. Discovery features will be disabled.")

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename

# Initialize Flask app - serve gridland-ui assets from root path
app = Flask(__name__, static_folder="gridland-ui", static_url_path="")

# Configuration storage (in-memory, can be extended to file-based)
_config = {
    "scan_timeout": 10,
    "max_threads": 100,
    "default_ports": "80,443,554,8080,8443,8554,37777,37778,34567",
    "performance_mode": "BALANCED",
    "enable_credential_testing": True,
    "enable_stream_discovery": True,
    "rate_limit_delay": 0.1,
    "max_attempts_per_target": 100,
}
_config_lock = threading.Lock()

# Initialize Shodan API client
shodan_api = None
if SHODAN_AVAILABLE:
    try:
        SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
        if not SHODAN_API_KEY:
            print("Warning: SHODAN_API_KEY environment variable not set. Discovery will be disabled.")
        else:
            shodan_api = shodan.Shodan(SHODAN_API_KEY)
    except Exception as e:
        print(f"Warning: Error initializing Shodan API: {e}")


# =============================================================================
# Main UI Routes
# =============================================================================


@app.route("/")
def index():
    """Serve the main GRIDLAND UI."""
    return send_from_directory("gridland-ui", "index.html")


@app.route("/ui/")
def ui_index():
    """Alternate path to main UI."""
    return send_from_directory("gridland-ui", "index.html")


@app.route("/ui/<path:filename>")
def ui_assets(filename):
    """Serve UI assets from gridland-ui directory."""
    return send_from_directory("gridland-ui", filename)


@app.route("/legacy/")
def legacy_index():
    """Serve the legacy HelloBird UI."""
    return send_from_directory("static", "index.html")


@app.route("/legacy/<path:filename>")
def legacy_assets(filename):
    """Serve legacy UI assets."""
    return send_from_directory("static", filename)


# =============================================================================
# Discovery API
# =============================================================================


@app.route("/discover", methods=["POST"])
def discover():
    """
    Discover targets using Shodan API.

    Request Body:
        query (str): Shodan search query (e.g., "port:554 country:US")
        limit (int, optional): Maximum results to return (default: 50)

    Returns:
        List of IP addresses matching the query.
    """
    if not shodan_api:
        return jsonify({"error": "Shodan API is not configured. Set SHODAN_API_KEY environment variable."}), 500

    data = request.get_json(silent=True) or {}
    query = data.get("query")
    limit = data.get("limit", 50)

    if not query:
        return jsonify({"error": "A search query is required."}), 400

    try:
        results = shodan_api.search(query, limit=limit)
        ips = [result["ip_str"] for result in results["matches"]]
        return jsonify(ips)
    except shodan.APIError as e:
        print(f"ERROR: Shodan API error: {e}")
        return jsonify({"error": f"Shodan API error: {e}"}), 500
    except Exception as e:
        print(f"ERROR: An unexpected error occurred in /discover: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


# =============================================================================
# Scan/Analysis API
# =============================================================================


@app.route("/scan", methods=["POST", "GET"])
def scan():
    """
    Perform security analysis on a target IP using CamXploit.py.

    Supports both POST (with JSON body) and GET (with query params) for SSE compatibility.

    Request:
        ip (str): Target IP address to analyze

    Returns:
        Server-Sent Events stream with analysis output.
    """
    # Handle both POST body and GET query params
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        ip = data.get("ip")
    else:
        ip = request.args.get("ip")

    # Validate IP address
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "A valid IP address is required"}), 400

    safe_ip = secure_filename(ip)

    def generate_scan_output():
        """Stream CamXploit.py output as Server-Sent Events."""
        # Check if CamXploit.py exists
        camxploit_path = Path("CamXploit.py")
        if not camxploit_path.exists():
            camxploit_path = Path("legacy/CamXploit.py")

        if not camxploit_path.exists():
            yield f"data: Error: CamXploit.py not found\n\n"
            return

        process = subprocess.Popen(
            [sys.executable, "-u", str(camxploit_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        try:
            process.stdin.write(safe_ip + "\n")
            process.stdin.flush()
        except Exception as e:
            yield f"data: Error: Failed to send input to scanner: {e}\n\n"
            process.kill()
            return

        for line in iter(process.stdout.readline, ""):
            # Format as SSE
            yield f"data: {line.rstrip()}\n\n"

        process.stdout.close()
        return_code = process.wait()
        yield f"data: [Scan completed with exit code {return_code}]\n\n"

    return Response(
        stream_with_context(generate_scan_output()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


# =============================================================================
# SSE Streaming API
# =============================================================================


@app.route("/api/osint/stream/<ip>", methods=["GET"])
def osint_stream(ip):
    """
    Stream OSINT gathering as Server-Sent Events.

    Provides real-time progress updates as each OSINT phase completes.

    Args:
        ip: Target IP address

    Returns:
        Server-Sent Events stream with OSINT data.
    """
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    def generate_osint_stream():
        """Stream OSINT gathering phases as SSE events."""
        import time
        
        # Phase 1: Start
        yield f"data: {json.dumps({'phase': 'start', 'ip': ip, 'status': 'Starting OSINT gathering', 'progress': 0})}\n\n"
        
        # Phase 2: Search URLs
        try:
            from gridland.core.osint import get_search_urls
            
            yield f"data: {json.dumps({'phase': 'search_urls', 'status': 'Generating search engine URLs', 'progress': 20})}\n\n"
            
            urls = get_search_urls(ip)
            yield f"data: {json.dumps({'phase': 'search_urls', 'status': 'complete', 'progress': 25, 'data': {'urls': urls, 'count': len(urls)}})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'phase': 'search_urls', 'status': 'error', 'error': str(e)})}\n\n"
        
        # Phase 3: Google Dorks
        try:
            from gridland.core.osint import get_google_dork_urls
            
            yield f"data: {json.dumps({'phase': 'google_dorks', 'status': 'Generating Google dork queries', 'progress': 40})}\n\n"
            
            dorks = get_google_dork_urls(ip)
            dork_list = [{"query": q, "url": u} for q, u in dorks.items()]
            yield f"data: {json.dumps({'phase': 'google_dorks', 'status': 'complete', 'progress': 50, 'data': {'dorks': dork_list, 'count': len(dork_list)}})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'phase': 'google_dorks', 'status': 'error', 'error': str(e)})}\n\n"
        
        # Phase 4: Geolocation
        try:
            from gridland.core.osint import get_geolocation
            
            yield f"data: {json.dumps({'phase': 'geolocation', 'status': 'Looking up IP geolocation', 'progress': 65})}\n\n"
            
            geo = get_geolocation(ip)
            if geo:
                geo_data = geo.to_dict()
                yield f"data: {json.dumps({'phase': 'geolocation', 'status': 'complete', 'progress': 80, 'data': geo_data})}\n\n"
            else:
                yield f"data: {json.dumps({'phase': 'geolocation', 'status': 'not_found', 'progress': 80, 'data': None})}\n\n"
                
        except Exception as e:
            yield f"data: {json.dumps({'phase': 'geolocation', 'status': 'error', 'error': str(e)})}\n\n"
        
        # Phase 5: Complete
        try:
            from gridland.core.osint import osint_report
            
            yield f"data: {json.dumps({'phase': 'complete', 'status': 'Compiling final report', 'progress': 95})}\n\n"
            
            report = osint_report(ip)
            yield f"data: {json.dumps({'phase': 'complete', 'status': 'done', 'progress': 100, 'data': report})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'phase': 'complete', 'status': 'error', 'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate_osint_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/analyze/stream/<ip>", methods=["GET"])
def analyze_stream(ip):
    """
    Stream network analysis as Server-Sent Events.

    Provides real-time progress updates as each analysis phase completes.

    Args:
        ip: Target IP address

    Returns:
        Server-Sent Events stream with analysis data.
    """
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    def generate_analyze_stream():
        """Stream analysis phases as SSE events."""
        import socket
        import time
        
        # Phase 1: Start
        yield f"data: {json.dumps({'phase': 'start', 'ip': ip, 'status': 'Starting network analysis', 'progress': 0})}\n\n"
        
        # Phase 2: Port Scanning
        yield f"data: {json.dumps({'phase': 'port_scan', 'status': 'Scanning common camera ports', 'progress': 10})}\n\n"
        
        # Common camera ports to check
        common_ports = [80, 443, 554, 8080, 8443, 8554, 37777, 37778, 34567, 5000, 9000]
        open_ports = []
        
        for i, port in enumerate(common_ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
            
            # Report progress every few ports
            if (i + 1) % 3 == 0:
                progress = 10 + int((i / len(common_ports)) * 30)
                yield f"data: {json.dumps({'phase': 'port_scan', 'status': f'Scanning port {port}', 'progress': progress, 'ports_checked': i + 1})}\n\n"
        
        yield f"data: {json.dumps({'phase': 'port_scan', 'status': 'complete', 'progress': 40, 'data': {'open_ports': open_ports, 'count': len(open_ports)}})}\n\n"
        
        # Phase 3: Service Detection
        yield f"data: {json.dumps({'phase': 'service_detection', 'status': 'Detecting services on open ports', 'progress': 45})}\n\n"
        
        services = {}
        for port in open_ports:
            # Map ports to likely services
            port_services = {
                80: "HTTP",
                443: "HTTPS",
                554: "RTSP",
                8080: "HTTP-Proxy",
                8443: "HTTPS-Alt",
                8554: "RTSP-Alt",
                37777: "Dahua",
                37778: "Dahua-Config",
                34567: "Hikvision-DVR",
                5000: "ONVIF",
                9000: "Web-Interface",
            }
            services[port] = port_services.get(port, "Unknown")
        
        yield f"data: {json.dumps({'phase': 'service_detection', 'status': 'complete', 'progress': 60, 'data': {'services': services}})}\n\n"
        
        # Phase 4: Camera Detection
        yield f"data: {json.dumps({'phase': 'camera_detection', 'status': 'Detecting camera brand', 'progress': 65})}\n\n"
        
        camera_info = {"detected": False, "brand": None, "model": None}
        
        # Check for common camera indicators
        if 37777 in open_ports or 37778 in open_ports:
            camera_info = {"detected": True, "brand": "Dahua", "confidence": 0.9}
        elif 34567 in open_ports:
            camera_info = {"detected": True, "brand": "Hikvision-DVR", "confidence": 0.85}
        elif 554 in open_ports:
            camera_info = {"detected": True, "brand": "Generic RTSP", "confidence": 0.7}
        elif 80 in open_ports or 443 in open_ports:
            camera_info = {"detected": True, "brand": "Possible IP Camera", "confidence": 0.5}
        
        yield f"data: {json.dumps({'phase': 'camera_detection', 'status': 'complete', 'progress': 80, 'data': camera_info})}\n\n"
        
        # Phase 5: OSINT
        yield f"data: {json.dumps({'phase': 'osint', 'status': 'Gathering OSINT data', 'progress': 85})}\n\n"
        
        try:
            from gridland.core.osint import get_search_urls
            urls = get_search_urls(ip)
            yield f"data: {json.dumps({'phase': 'osint', 'status': 'complete', 'progress': 95, 'data': {'search_urls': urls}})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'phase': 'osint', 'status': 'error', 'error': str(e)})}\n\n"
        
        # Phase 6: Complete
        final_report = {
            "ip": ip,
            "open_ports": open_ports,
            "services": services,
            "camera": camera_info,
            "summary": {
                "ports_scanned": len(common_ports),
                "ports_open": len(open_ports),
                "camera_detected": camera_info.get("detected", False),
                "camera_brand": camera_info.get("brand"),
            }
        }
        
        yield f"data: {json.dumps({'phase': 'complete', 'status': 'done', 'progress': 100, 'data': final_report})}\n\n"

    return Response(
        stream_with_context(generate_analyze_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


# =============================================================================
# Stream API
# =============================================================================


@app.route("/stream/<path:stream_url_b64>")
def stream(stream_url_b64):
    """
    Transcode and stream RTSP/RTMP video to browser-compatible format.

    Args:
        stream_url_b64: Base64-encoded stream URL

    Returns:
        MPEG-TS video stream.
    """
    try:
        stream_url = base64.urlsafe_b64decode(stream_url_b64).decode("utf-8")
    except Exception:
        return jsonify({"error": "Invalid stream URL format."}), 400

    def generate_gstreamer_stream():
        """Stream video using GStreamer pipeline."""
        # Check if GStreamer is available
        import shutil
        if not shutil.which("gst-launch-1.0"):
            yield b"ERROR: GStreamer not installed. Install with: brew install gstreamer gst-plugins-base gst-plugins-good"
            return
            
        gst_command = [
            "gst-launch-1.0",
            "-q",
            "rtspsrc",
            f"location={stream_url}",
            "latency=0",
            "protocols=tcp",
            "!",
            "rtph264depay",
            "!",
            "h264parse",
            "!",
            "mpegtsmux",
            "!",
            "fdsink",
            "fd=1",
        ]

        process = subprocess.Popen(
            gst_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            process.terminate()
            process.wait()

    return Response(
        generate_gstreamer_stream(),
        mimetype="video/MP2T",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


# =============================================================================
# Configuration API
# =============================================================================


@app.route("/api/config", methods=["GET"])
def get_config():
    """
    Get current configuration.

    Returns:
        Current configuration object.
    """
    with _config_lock:
        return jsonify(_config)


@app.route("/api/config", methods=["POST"])
def set_config():
    """
    Update configuration.

    Request Body:
        Configuration key-value pairs to update.

    Returns:
        Updated configuration object.
    """
    data = request.get_json(silent=True) or {}

    with _config_lock:
        for key, value in data.items():
            if key in _config:
                _config[key] = value
        return jsonify(_config)


@app.route("/api/config/shodan", methods=["GET"])
def get_shodan_status():
    """Get Shodan API configuration status."""
    return jsonify({
        "available": SHODAN_AVAILABLE,
        "configured": shodan_api is not None,
        "message": "Shodan API ready" if shodan_api else "Shodan API not configured"
    })


@app.route("/api/config/shodan", methods=["POST"])
def set_shodan_key():
    """
    Configure Shodan API key at runtime.

    Request Body:
        api_key (str): Shodan API key

    Returns:
        Status of configuration.
    """
    global shodan_api

    if not SHODAN_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "Shodan module not installed. Run: pip install shodan"
        }), 400

    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key", "").strip()

    if not api_key:
        return jsonify({
            "success": False,
            "error": "API key is required"
        }), 400

    try:
        # Test the API key
        test_api = shodan.Shodan(api_key)
        test_api.info()  # This will fail if the key is invalid

        # Key is valid, save it
        shodan_api = test_api
        os.environ["SHODAN_API_KEY"] = api_key

        return jsonify({
            "success": True,
            "message": "Shodan API key configured successfully"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Invalid API key: {str(e)}"
        }), 400


# =============================================================================
# Plugin API
# =============================================================================


@app.route("/api/plugins", methods=["GET"])
def get_plugins():
    """
    Get information about available analysis plugins.

    Returns:
        Plugin information including names, versions, and status.
    """
    # Try to load from GRIDLAND plugin system
    plugins = []

    try:
        from gridland.analyze.plugins.manager import get_plugin_manager
        manager = get_plugin_manager()
        for plugin in manager.get_all_plugins():
            metadata = plugin.get_metadata()
            plugins.append({
                "name": metadata.name,
                "version": metadata.version,
                "description": metadata.description,
                "author": metadata.author,
                "enabled": True,
                "type": metadata.plugin_type,
            })
    except ImportError:
        # Fallback to hardcoded plugin list based on codebase
        plugins = [
            {"name": "Hikvision Scanner", "version": "3.0.0", "description": "Hikvision camera detection and analysis", "enabled": True, "type": "vulnerability"},
            {"name": "Dahua Scanner", "version": "3.0.0", "description": "Dahua camera detection and analysis", "enabled": True, "type": "vulnerability"},
            {"name": "Axis Scanner", "version": "3.0.0", "description": "Axis camera detection and analysis", "enabled": True, "type": "vulnerability"},
            {"name": "CP Plus Scanner", "version": "3.0.0", "description": "CP Plus DVR/NVR detection", "enabled": True, "type": "vulnerability"},
            {"name": "Generic Camera Scanner", "version": "3.0.0", "description": "Generic camera brand detection", "enabled": True, "type": "vulnerability"},
            {"name": "Login Page Scanner", "version": "3.0.0", "description": "Authentication endpoint discovery", "enabled": True, "type": "vulnerability"},
            {"name": "Credential Tester", "version": "3.0.0", "description": "Default credential testing", "enabled": True, "type": "vulnerability"},
            {"name": "RTSP Stream Scanner", "version": "3.0.0", "description": "RTSP stream discovery", "enabled": True, "type": "stream"},
            {"name": "Stream Discovery", "version": "3.0.0", "description": "Multi-protocol stream enumeration", "enabled": True, "type": "stream"},
            {"name": "Banner Grabber", "version": "3.0.0", "description": "Service banner analysis", "enabled": True, "type": "vulnerability"},
        ]

    return jsonify({
        "total_plugins": len(plugins),
        "enabled_plugins": sum(1 for p in plugins if p.get("enabled", True)),
        "plugins": plugins,
    })


# =============================================================================
# CLI API
# =============================================================================

# Map CLI commands to their module paths
CLI_MODULES = {
    "discover": "gridland.cli.discover_cli",
    "analyze": "gridland.cli.analyze_cli",
    "osint": "gridland.cli.osint_cli",
    "stream": "gridland.cli.stream_cli",
}


@app.route("/api/cli", methods=["POST"])
def invoke_cli():
    """
    Invoke GRIDLAND CLI commands programmatically.

    Request Body:
        command (str): CLI command to run ("discover", "analyze", "osint", "stream")
        subcommand (str, optional): Subcommand (e.g., "dorks", "geolocate")
        args (list): Command arguments

    Returns:
        Command output with stdout, stderr, and return code.
    """
    data = request.get_json(silent=True) or {}
    command = data.get("command")
    subcommand = data.get("subcommand")
    args = data.get("args", [])

    if not command:
        return jsonify({"error": "Command is required"}), 400

    if command not in CLI_MODULES:
        return jsonify({
            "error": f"Unknown command: {command}",
            "available_commands": list(CLI_MODULES.keys())
        }), 400

    try:
        cli_module = CLI_MODULES[command]
        
        # Build CLI command
        cmd = [sys.executable, "-m", cli_module]
        
        # Add subcommand if provided
        if subcommand:
            cmd.append(subcommand)
        
        # Add arguments
        cmd.extend([str(a) for a in args])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(Path(__file__).parent)
        )

        return jsonify({
            "success": result.returncode == 0,
            "command": command,
            "subcommand": subcommand,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cli/osint/<subcommand>/<ip>", methods=["GET"])
def invoke_osint_cli(subcommand, ip):
    """
    Direct OSINT CLI endpoint for quick access.

    Args:
        subcommand: One of "dorks", "geolocate", "search-urls", "full"
        ip: Target IP address

    Returns:
        OSINT command output as JSON.
    """
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    # Validate subcommand
    valid_subcommands = ["dorks", "geolocate", "search-urls", "full"]
    if subcommand not in valid_subcommands:
        return jsonify({
            "error": f"Unknown subcommand: {subcommand}",
            "valid_subcommands": valid_subcommands
        }), 400

    # Use native functions instead of subprocess for better performance
    try:
        from gridland.core.osint import (
            get_google_dork_urls,
            get_geolocation,
            get_search_urls,
            osint_report,
        )

        if subcommand == "dorks":
            dorks = get_google_dork_urls(ip)
            return jsonify({
                "ip": ip,
                "command": "osint dorks",
                "dorks": [{"query": q, "url": u} for q, u in dorks.items()],
                "count": len(dorks),
            })

        elif subcommand == "geolocate":
            geo = get_geolocation(ip)
            if geo is None:
                return jsonify({
                    "ip": ip,
                    "command": "osint geolocate",
                    "error": "Geolocation lookup failed",
                }), 404
            return jsonify({
                "ip": ip,
                "command": "osint geolocate",
                **geo.to_dict(),
            })

        elif subcommand == "search-urls":
            urls = get_search_urls(ip)
            return jsonify({
                "ip": ip,
                "command": "osint search-urls",
                "urls": urls,
                "count": len(urls),
            })

        elif subcommand == "full":
            report = osint_report(ip)
            return jsonify({
                "command": "osint full",
                **report,
            })

    except ImportError as e:
        return jsonify({"error": f"OSINT module not available: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cli/available", methods=["GET"])
def get_available_commands():
    """
    Get list of available CLI commands and their subcommands.

    Returns:
        Available commands with descriptions.
    """
    return jsonify({
        "commands": {
            "discover": {
                "description": "Discover camera targets using various sources",
                "subcommands": ["shodan", "censys", "local", "file"],
            },
            "analyze": {
                "description": "Analyze camera targets for vulnerabilities",
                "subcommands": ["target", "file", "network"],
            },
            "osint": {
                "description": "Open Source Intelligence gathering",
                "subcommands": ["dorks", "geolocate", "search-urls", "full"],
                "direct_endpoints": [
                    "/api/cli/osint/dorks/<ip>",
                    "/api/cli/osint/geolocate/<ip>",
                    "/api/cli/osint/search-urls/<ip>",
                    "/api/cli/osint/full/<ip>",
                ],
            },
            "stream": {
                "description": "Access and record video streams",
                "subcommands": ["view", "record"],
            },
        },
    })



# OSINT API
# =============================================================================


@app.route("/api/osint/urls/<ip>", methods=["GET"])
def get_osint_urls(ip):
    """
    Generate OSINT platform URLs for an IP address.

    Args:
        ip: Target IP address

    Returns:
        OSINT platform search URLs and Google dork queries.
    """
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        from gridland.core.osint import get_search_urls, get_google_dork_urls
        
        search_urls = get_search_urls(ip)
        dork_urls = get_google_dork_urls(ip)
        
        return jsonify({
            "ip": ip,
            "search_urls": search_urls,
            "google_dorks": [
                {"query": query, "url": url}
                for query, url in dork_urls.items()
            ],
        })
    except ImportError as e:
        return jsonify({"error": f"OSINT module not available: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/osint/geo/<ip>", methods=["GET"])
def get_geo_info(ip):
    """
    Get geolocation information for an IP address via ipinfo.io.

    Args:
        ip: Target IP address

    Returns:
        Geolocation data including city, region, country, coordinates, and map URLs.
    """
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        from gridland.core.osint import get_geolocation
        
        geo = get_geolocation(ip)
        
        if geo is None:
            return jsonify({
                "error": "Geolocation lookup failed",
                "ip": ip,
            }), 404
        
        return jsonify(geo.to_dict())
        
    except ImportError as e:
        return jsonify({"error": f"OSINT module not available: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/osint/full/<ip>", methods=["GET"])
def get_full_osint(ip):
    """
    Get complete OSINT report for an IP address.

    Combines geolocation, search engine URLs, and Google dork queries.

    Args:
        ip: Target IP address

    Returns:
        Complete OSINT intelligence report.
    """
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        from gridland.core.osint import osint_report
        
        report = osint_report(ip)
        return jsonify(report)
        
    except ImportError as e:
        return jsonify({"error": f"OSINT module not available: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# =============================================================================
# CVE API
# =============================================================================


@app.route("/api/cves/<brand>", methods=["GET"])
def get_cves(brand):
    """
    Get CVEs for a camera brand.

    Args:
        brand: Camera brand name (hikvision, dahua, axis, cp_plus)

    Returns:
        List of CVEs with details.
    """
    try:
        from gridland.analyze.core import CVELookup
        lookup = CVELookup()
        cves = lookup.get_cves(brand)
        return jsonify({
            "brand": brand,
            "count": len(cves),
            "cves": cves,
        })
    except ImportError:
        return jsonify({"error": "CVELookup module not available"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Health Check
# =============================================================================


@app.route("/api/health", methods=["GET"])
def health_check():
    """
    Health check endpoint.

    Returns:
        Server status and component availability.
    """
    components = {
        "server": True,
        "shodan_api": shodan_api is not None,
        "camxploit": Path("CamXploit.py").exists() or Path("legacy/CamXploit.py").exists(),
    }

    # Check GRIDLAND modules
    try:
        from gridland.core.data_loader import load_camera_ports
        load_camera_ports()
        components["gridland_core"] = True
    except Exception:
        components["gridland_core"] = False

    try:
        from gridland.analyze.plugins.manager import get_plugin_manager
        components["gridland_plugins"] = True
    except Exception:
        components["gridland_plugins"] = False

    all_healthy = all(components.values())

    return jsonify({
        "status": "healthy" if all_healthy else "degraded",
        "components": components,
    }), 200 if all_healthy else 503


# =============================================================================
# Error Handlers
# =============================================================================


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return jsonify({"error": "Internal server error"}), 500


# =============================================================================
# Main Entry Point
# =============================================================================


if __name__ == "__main__":
    print("=" * 60)
    print("GRIDLAND v3.0 - Security Reconnaissance Server")
    print("=" * 60)
    print(f"Shodan API: {'Configured' if shodan_api else 'NOT CONFIGURED'}")
    print(f"CamXploit: {'Available' if Path('CamXploit.py').exists() else 'Not found'}")
    print("=" * 60)
    print("Starting server on http://0.0.0.0:8080")
    print("UI available at: http://localhost:8080/")
    print("Legacy UI at: http://localhost:8080/legacy/")
    print("=" * 60)

    # Debug mode configurable via environment - default OFF for production
    debug_mode = os.environ.get("GRIDLAND_DEBUG", "false").lower() == "true"
    
    app.run(host="0.0.0.0", port=8080, threaded=True, debug=debug_mode, use_reloader=False)
