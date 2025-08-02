# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**GRIDLAND** is a production-grade network security scanner specifically designed for IP camera and IoT device penetration testing. The project has evolved from a simple wrapper around CamXploit.py into a comprehensive, modular security assessment platform with both CLI and web interfaces.

**ARCHITECTURE STATUS: COMPLETE OVERHAUL SUCCESSFUL**
- ✅ Modular lib/ system with proper separation of concerns
- ✅ Plugin-based scanning architecture (7 active plugins)
- ✅ Real-time web interface with job management
- ✅ Professional CLI for automation and scripting
- ✅ Enterprise-grade credential testing (247+ combinations)
- ✅ Comprehensive logging system for debugging and audit trails


## Development Commands

### Running the Application

**Web Interface (Recommended):**
```bash
flask --app server run --port 5001
# OR
python server.py
```
- Runs Flask server on http://localhost:5001
- Real-time browser interface with job management
- Live scan progress and results display

**Command Line Interface:**
```bash
# Quick aggressive scan
python gridland_clean.py quick <target_ip>

# Network range scan with full credential testing
python gridland_clean.py scan <network/cidr> --aggressive --threads 200

# Single target with JSON output
python gridland_clean.py scan <target_ip> --aggressive --output results.json
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
curl -X POST http://localhost:5001/api/jobs -H "Content-Type: application/json" -d '{"target":"TARGET_IP"}'
```

### Logging and Debugging
```bash
# All scans automatically generate detailed log files in logs/ directory

# CLI scans create target-specific logs
python gridland_clean.py quick 192.168.1.100
# Creates: logs/gridland_scan_192_168_1_100_{timestamp}.log

# Web interface creates session logs
python server.py
# Creates: logs/gridland_web_server_{timestamp}.log

# Log files contain:
# - Port scan details and timings
# - Device identification attempts  
# - Plugin execution and findings
# - Credential testing results
# - Stream discovery attempts
# - Error details with stack traces
# - Performance metrics
```

## Architecture Overview

### Modular Library System (lib/)
- **core.py**: Data structures (ScanTarget, PortResult, Job, Finding)
- **network.py**: Multi-threaded port scanning with 100+ camera ports
- **identify.py**: Device fingerprinting (15+ camera brands)
- **jobs.py**: Background job management for web interface
- **orchestrator.py**: Scan coordination and plugin integration
- **plugin_manager.py**: Plugin loading and execution system
- **plugins.py**: Base classes for scanner plugins

### Plugin Architecture (plugins/)
- **credential_scanner.py**: 247 credential combinations across 20 endpoints
- **stream_scanner.py**: RTSP and HTTP video stream discovery
- **vulnerability_scanner.py**: CVE detection and exploit identification
- **banner_grabber.py**: Service fingerprinting and version detection
- **onvif_scanner.py**: ONVIF protocol testing
- **web_interface_scanner.py**: Admin panel and debug interface discovery
- **config_scanner.py**: Configuration file and backup detection

### Web Interface (server.py)
- **REST API**: `/api/jobs` for scan submission and status polling
- **Job Management**: Background scanning with real-time progress
- **Live Updates**: Continuous polling for scan progress and results
- **Results Display**: Credentials, streams, vulnerabilities in structured table

### CLI Interface (gridland_clean.py)
- **Quick Scan**: `quick <target>` for rapid assessment
- **Network Scanning**: CIDR range support with threading
- **Aggressive Mode**: Full credential and vulnerability testing
- **JSON Output**: Professional reporting format

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

### Logging Architecture
- **Dual-output logging**: Console for user feedback + detailed file logging
- **Timestamped sessions**: Each scan/server session gets unique log file
- **Component-specific loggers**: CLI, web interface, plugins all log separately
- **Debug-level detail**: Function calls, parameters, exceptions with stack traces
- **Target-specific logs**: Individual log files per scan target

### Error Handling Patterns
- Graceful degradation when Shodan API is unavailable
- Process cleanup for long-running scans and streams
- Exception handling for network timeouts and malformed responses
- Comprehensive logging of all errors and exceptions for debugging

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

**PHASE 1 COMPLETE (August 2025)**
- ✅ Core Flask server and frontend working
- ✅ Plugin architecture with 7 active plugins
- ✅ Comprehensive logging system implemented
- ✅ CLI and web interfaces fully functional
- ✅ Git repository cleaned and organized
- ✅ Documentation updated and current

**Current Implementation Status:**
- ✅ Modular lib/ system fully operational
- ✅ Plugin-based scanning with detailed logging
- ✅ Real-time web interface with job management
- ✅ Professional CLI for automation and scripting
- ✅ Enterprise-grade credential testing (247+ combinations)
- ⚠️ Shodan discovery limited by API tier restrictions
- ❓ Stream transcoding implemented but requires live target testing
- ❓ All plugins require validation against live targets

**Next Development Phase:**
- Phase 2: Core stability testing with live targets
- Stream processing validation
- Plugin integration testing with real devices
- Performance optimization and error handling review
