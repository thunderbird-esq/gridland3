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


@app.route("/api/cli", methods=["POST"])
def invoke_cli():
    """
    Invoke GRIDLAND CLI commands programmatically.

    Request Body:
        command (str): CLI command to run ("discover" or "analyze")
        args (list): Command arguments

    Returns:
        Command output.
    """
    data = request.get_json(silent=True) or {}
    command = data.get("command")
    args = data.get("args", [])

    if not command:
        return jsonify({"error": "Command is required"}), 400

    if command not in ["discover", "analyze"]:
        return jsonify({"error": f"Unknown command: {command}"}), 400

    try:
        # Build CLI command
        if command == "discover":
            cli_module = "gridland.cli.discover_cli"
        else:
            cli_module = "gridland.cli.analyze_cli"

        cmd = [sys.executable, "-m", cli_module] + [str(a) for a in args]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(Path(__file__).parent)
        )

        return jsonify({
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# OSINT API
# =============================================================================


@app.route("/api/osint/urls/<ip>", methods=["GET"])
def get_osint_urls(ip):
    """
    Generate OSINT platform URLs for an IP address.

    Args:
        ip: Target IP address

    Returns:
        OSINT platform search URLs.
    """
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        from gridland.analyze.core.osint import OSINTURLGenerator
        urls = OSINTURLGenerator.generate_search_urls(ip)
        dorks = OSINTURLGenerator.generate_google_dorks(ip)
        return jsonify({
            "search_urls": urls,
            "google_dorks": dorks,
        })
    except ImportError:
        # Fallback
        return jsonify({
            "search_urls": {
                "shodan": f"https://www.shodan.io/host/{ip}",
                "censys": f"https://search.censys.io/hosts/{ip}",
                "zoomeye": f"https://www.zoomeye.org/searchResult?q={ip}",
            },
            "google_dorks": [],
        })


@app.route("/api/osint/geo/<ip>", methods=["GET"])
def get_geo_info(ip):
    """
    Get geolocation information for an IP address.

    Args:
        ip: Target IP address

    Returns:
        Geolocation data.
    """
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        import asyncio
        from gridland.analyze.core.osint import GeoLookup

        async def lookup():
            geo = GeoLookup()
            return await geo.get_ip_info(ip)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            info = loop.run_until_complete(lookup())
            return jsonify(info)
        finally:
            loop.close()

    except ImportError:
        return jsonify({"error": "GeoLookup module not available"}), 500
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
    except:
        components["gridland_core"] = False

    try:
        from gridland.analyze.plugins.manager import get_plugin_manager
        components["gridland_plugins"] = True
    except:
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

    app.run(host="0.0.0.0", port=8080, threaded=True, debug=True, use_reloader=False)
