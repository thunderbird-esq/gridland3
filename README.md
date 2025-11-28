# GRIDLAND v3.0

**Professional Camera Reconnaissance and Security Analysis Toolkit**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> ⚠️ **IMPORTANT**: This tool is designed for **defensive security research**, **education**, and **authorized auditing** ONLY. All usage must comply with applicable laws and ethical guidelines. Unauthorized scanning of systems you do not own or operate is prohibited and may be illegal.

---

## Overview

GRIDLAND is a next-generation reconnaissance toolkit for security researchers, penetration testers, and defensive security teams. Built from the ground up with a modular plugin architecture, GRIDLAND provides comprehensive camera system discovery, analysis, and stream intelligence capabilities.

### Key Features

- 🔍 **Multi-Engine Discovery** - Masscan, Shodan, Censys integration
- 🎯 **Advanced Fingerprinting** - Brand detection, firmware analysis, model identification
- 🔌 **Plugin Architecture** - Extensible vulnerability scanner system
- 🎬 **Stream Intelligence** - RTSP, HTTP, RTMP protocol analysis with validation
- 🧠 **Machine Learning** - Vulnerability prediction and pattern recognition
- ⚡ **High Performance** - Memory pooling, async I/O, work-stealing scheduler
- 🔐 **Security First** - Built-in secrets scanning, bandit integration, comprehensive testing
- 📊 **Rich Output** - JSON, markdown, and terminal-formatted results

---

## Architecture

```
gridland/
├── discover/          # Discovery engines (Masscan, Shodan, Censys)
├── analyze/           # Analysis framework
│   ├── core/          # Advanced fingerprinting, ML, topology
│   ├── engines/       # Analysis engine orchestration
│   ├── plugins/       # Vulnerability scanner plugins
│   └── memory/        # Memory pooling system
├── stream/            # Stream intelligence and validation
├── core/              # Shared utilities (logger, config, network)
└── cli/               # Command-line interface
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager
- (Optional) Docker for containerized deployment

### Quick Start

```bash
# Clone the repository
git clone https://github.com/thunderbird-esq/gridland3.git
cd gridland3

# Install dependencies
pip install -r requirements.txt

# Install development tools (optional)
pip install -r requirements-dev.txt

# Run validation tests
python validate_gridland.py
```

### Docker Deployment

```bash
# Build the Docker image
docker build --build-arg SHODAN_API_KEY_ARG=your_api_key_here -t gridland .

# Run the container
docker run -p 8080:8080 gridland
```

---

## Usage

### Command-Line Interface

```bash
# Discovery
python -m gridland.cli.discover_cli --engine masscan --target 192.168.1.0/24

# Analysis
python -m gridland.cli.analyze_cli --ip 192.168.1.100

# Stream intelligence
python -m gridland.cli.stream_cli --url rtsp://192.168.1.100:554/stream
```

### Web Interface

```bash
# Start the Flask server
python server.py

# Access at http://localhost:8080
```

### Programmatic Usage

```python
from gridland.discover.masscan_engine import MasscanEngine
from gridland.analyze.engines.analysis_engine import AnalysisEngine

# Discover targets
discovery = MasscanEngine()
targets = await discovery.discover(target="192.168.1.0/24", ports="80,443,554,8080")

# Analyze target
analysis = AnalysisEngine()
results = await analysis.analyze_target("192.168.1.100")
```

---

## Plugin System

GRIDLAND uses a modular plugin architecture for vulnerability scanning:

```python
from gridland.analyze.plugins.base import VulnerabilityPlugin

class CustomScanner(VulnerabilityPlugin):
    def get_metadata(self):
        return {"name": "custom-scanner", "version": "1.0"}

    async def scan_vulnerabilities(self, target_ip, scan_result):
        # Custom scanning logic
        return results
```

Built-in plugins:

- Hikvision scanner (CVE detection, auth bypass)
- Dahua scanner (credential testing, firmware checks)
- Axis scanner (VAPIX API analysis)
- Generic camera scanner (pattern matching)
- Banner grabber (service identification)
- RTSP stream scanner (protocol analysis)
- IP context scanner (geolocation, ASN lookup)

---

## Configuration

### Environment Variables

```bash
# API Keys (optional but recommended)
export SHODAN_API_KEY="your_shodan_key"  # pragma: allowlist secret
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"  # pragma: allowlist secret

# Logging
export GRIDLAND_LOG_LEVEL="INFO"
export GRIDLAND_LOG_FILE="gridland.log"
```

### Configuration File

Create `~/.gridland/config.json`:

```json
{
  "discovery": {
    "masscan_rate": 1000,
    "timeout": 30
  },
  "analysis": {
    "max_threads": 10,
    "plugin_timeout": 15
  }
}
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=gridland --cov-report=html

# Run specific test suite
pytest tests/discover/ -v
```

---

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run linting
black gridland/ tests/
flake8 gridland/ tests/
mypy gridland/

# Run security checks
bandit -r gridland/
```

### Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, development process, and how to submit pull requests.

---

## Performance

GRIDLAND is optimized for high-performance reconnaissance:

- **Memory Pooling**: Pre-allocated objects eliminate GC overhead
- **AsyncIO + Threading**: Hybrid concurrent execution model
- **Work-Stealing Scheduler**: Dynamic load balancing across cores
- **Trie-Based Pattern Matching**: O(m) lookup for brand detection
- **Zero-Copy Stream Validation**: Efficient protocol analysis

Benchmarks:

- Discovery: 1000 IPs/minute (masscan mode)
- Analysis: 50 targets/minute (all plugins)
- Fingerprinting: <500ms per target
- Stream validation: <2s per URL

---

## Security Considerations

- All API keys are encrypted at rest
- Secrets scanning enabled via detect-secrets
- Rate limiting prevents accidental DoS
- Comprehensive input validation
- No credential storage (memory-only)
- Audit logging for all operations

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Original CamXploit.py concept for camera reconnaissance
- Security research community for vulnerability databases
- Contributors to open-source security tools

---

## Support

- **Issues**: [GitHub Issues](https://github.com/thunderbird-esq/gridland3/issues)
- **Documentation**: See `CLAUDE.md` for development guides
- **Troubleshooting**: See `TROUBLESHOOTING.md` for common issues

---

## Responsible Disclosure

If you discover security vulnerabilities in GRIDLAND itself, please report them responsibly:

1. Do not open public issues
2. Email details to the maintainers
3. Allow reasonable time for patching
4. Coordinate public disclosure

---

**Built with ❤️ for the security research community**
