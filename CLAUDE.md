# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HelloBird is a web-based sousveillance console for educational security research and authorized auditing of publicly accessible camera feeds. The project consists of a Flask backend that wraps the CamXploit.py reconnaissance script with a web interface for discovery and analysis of camera endpoints.

**⚠️ IMPORTANT ETHICAL NOTICE**: This tool is designed for defensive security research, education, and authorized auditing ONLY. All usage must comply with applicable laws and ethical guidelines. Unauthorized scanning of systems you do not own is prohibited.

## Development Commands

### Running the Application

**Local Development:**
```bash
python server.py
```
- Runs Flask server on http://localhost:8080
- Requires SHODAN_API_KEY environment variable for discovery features

**Docker (Recommended):**
```bash
# Build the Docker image
docker build --build-arg SHODAN_API_KEY_ARG=your_api_key_here -t hellobird .

# Run the container
docker run -p 8080:8080 hellobird
```

### Dependencies
```bash
pip install -r requirements.txt
```

Required packages: requests, ipaddress, flask, shodan, python-dotenv

### Testing Individual Components
```bash
# Test the core scanning script directly
python CamXploit.py

# Test server endpoints manually via curl
curl -X POST http://localhost:8080/scan -H "Content-Type: application/json" -d '{"ip":"TARGET_IP"}'
```

## Architecture Overview

### Backend Structure (server.py)
- **Flask Web Server**: Main application server with three core endpoints
- **/discover**: Shodan API integration for target discovery (requires API key)
- **/scan**: Executes CamXploit.py via subprocess, streams output via Server-Sent Events
- **/stream**: GStreamer-based RTSP stream transcoding to MPEG-TS for browser playback
- **Static File Serving**: Serves frontend assets from /static directory

### Core Scanning Engine (CamXploit.py)
- Multi-threaded port scanner targeting common camera ports (80, 443, 554, 8080, etc.)
- Camera brand detection (Hikvision, Dahua, Axis, Sony, Bosch, etc.)
- Default credential testing and authentication bypass detection
- Live stream discovery (RTSP, HTTP, RTMP, MMS protocols)
- ONVIF protocol support for standardized camera communication

### Frontend Architecture
- **Single Page Application**: index.html with vanilla JavaScript
- **Real-time Communication**: Server-Sent Events for live scan output streaming
- **Three Main Panels**:
  - "The Net": Shodan-based target discovery interface
  - "The Scalpel": IP analysis and scanning interface  
  - Video player for stream viewing
- **Styling**: Uses system.css theme for retro computing aesthetic

### Docker Environment
- **Base Image**: python:3.9-slim
- **System Dependencies**: GStreamer multimedia framework with all plugin sets
- **Build Arguments**: SHODAN_API_KEY passed at build time
- **Port Exposure**: 8080 for web interface

## Key Implementation Details

### Stream Processing Pipeline
The /stream endpoint implements a GStreamer pipeline:
```
rtspsrc -> rtph264depay -> h264parse -> mpegtsmux -> fdsink
```
This converts RTSP H.264 streams to browser-compatible MPEG-TS format.

### Security Considerations
- Input validation using ipaddress.ip_address() for IP parameters
- Secure filename handling with werkzeug.utils.secure_filename()
- Subprocess isolation for CamXploit.py execution
- SSL certificate verification disabled for camera endpoints (common in embedded devices)

### Error Handling Patterns
- Graceful degradation when Shodan API is unavailable
- Process cleanup for long-running scans and streams
- Exception handling for network timeouts and malformed responses

## Development Workflows

### Adding New Camera Brand Detection
1. Update brand detection logic in CamXploit.py around line 200-300
2. Add corresponding HTTP headers/response patterns
3. Test against known camera models

### Extending Stream Protocol Support
1. Modify GStreamer pipeline in server.py /stream endpoint
2. Update frontend video player MIME type handling
3. Test codec compatibility across browsers

### API Integration Changes
1. Shodan query modifications in /discover endpoint
2. Update frontend discovery panel JavaScript
3. Handle new API response formats

## Project Status Notes

Based on DEVLOG.md, current implementation status:
- ✅ Core Flask server and frontend working
- ✅ Docker containerization complete
- ✅ CamXploit.py integration functional
- ⚠️ Shodan discovery limited by API tier restrictions
- ❓ Stream transcoding implemented but requires testing
- ❓ Analysis scanning needs validation with live targets

The next development phase focuses on testing the analysis and streaming features with legitimate test targets.