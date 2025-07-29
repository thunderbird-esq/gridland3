# GRIDLAND

**Professional Camera Reconnaissance Toolkit**

GRIDLAND is a modular, CLI-first security toolkit designed for authorized reconnaissance and vulnerability assessment of camera systems and IoT devices. Built for security researchers, penetration testers, and network administrators.

## ⚠️ Legal Notice

**This tool is for authorized security testing and educational purposes ONLY.**

- Only use against systems you own or have explicit written permission to test
- Unauthorized scanning of systems is illegal in most jurisdictions
- Users are solely responsible for compliance with all applicable laws
- The authors assume no liability for misuse of this software

## 🚀 Features

### Discovery Module (`gl-discover`)
- **Masscan Integration**: High-speed port scanning across large IP ranges
- **ShodanSpider v2**: Leverage Shodan data without API limitations
- **Censys Integration**: Professional search engine integration
- **Smart Rate Limiting**: Adaptive scanning to avoid detection
- **Multiple Input Formats**: CIDR, ranges, files, single IPs

### Analysis Module (`gl-analyze`)
- **Camera Brand Detection**: Identify Hikvision, Dahua, Axis, and 20+ brands
- **Vulnerability Assessment**: CVE database integration
- **Authentication Testing**: Smart credential testing with rate limiting
- **Service Fingerprinting**: Detailed service identification
- **Stream Discovery**: Automatic RTSP/HTTP stream detection

### Streaming Module (`gl-stream`)
- **Multi-Protocol Support**: RTSP, HTTP, RTMP stream handling
- **Player Integration**: VLC, FFplay, MPV support
- **Stream Recording**: Save streams to file
- **Real-time Validation**: Verify stream accessibility

## 📦 Installation

### Quick Install
```bash
git clone https://github.com/gridland/gridland.git
cd gridland
pip install -e .
```

### Development Install
```bash
git clone https://github.com/gridland/gridland.git
cd gridland
pip install -e .[dev]
```

### Dependencies
- **Python 3.8+**
- **Optional**: masscan (for high-speed discovery)
- **Optional**: VLC/FFplay (for stream viewing)

## 🎯 Quick Start

### Discover Targets
```bash
# Scan local network for cameras
gl-discover --range 192.168.1.0/24 --engine masscan

# Use ShodanSpider for internet-wide discovery
gl-discover --engine shodanspider --query "camera country:US"

# Scan specific ports on IP range
gl-discover --range 10.0.0.0/16 --ports 80,443,554,8080
```

### Analyze Targets
```bash
# Full analysis of single target
gl-analyze 192.168.1.100

# Fast scan without authentication testing
gl-analyze 192.168.1.100 --fast --no-auth

# Batch analysis from file
gl-analyze --batch targets.txt --output results.json
```

### View Streams
```bash
# Play discovered stream
gl-stream rtsp://192.168.1.100:554/live

# Record stream to file
gl-stream rtsp://192.168.1.100:554/live --record stream.mp4 --duration 30

# Use specific player
gl-stream rtsp://192.168.1.100:554/live --player vlc
```

## ⚙️ Configuration

### Environment Variables
```bash
export GL_SCAN_TIMEOUT=10          # Scan timeout in seconds
export GL_MAX_THREADS=100          # Maximum concurrent threads
export GL_MASSCAN_RATE=1000        # Masscan packets per second
export GL_VERBOSE=true             # Enable verbose logging
export GL_SHODAN_API_KEY=xxx       # Shodan API key (optional)
export GL_CENSYS_API_ID=xxx        # Censys API credentials (optional)
export GL_CENSYS_API_SECRET=xxx
```

### Configuration File
```bash
# Create config directory
mkdir ~/.gridland

# Edit configuration
gl-config --edit
```

## 🔧 Advanced Usage

### Pipeline Integration
```bash
# Discovery -> Analysis -> Streaming pipeline
gl-discover --range 192.168.1.0/24 --output targets.json | \
gl-analyze --batch --input targets.json --output results.json | \
jq '.[] | select(.streams | length > 0) | .streams[0]' | \
xargs -I {} gl-stream {}
```

### Custom Port Lists
```bash
# Common camera ports
gl-discover --range 192.168.1.0/24 --ports 80,443,554,8080,8081,8000,8888,81,8443

# Extended IoT device ports
gl-discover --range 192.168.1.0/24 --ports 1-1000,8000-9000
```

### Output Formats
```bash
# JSON output for automation
gl-analyze 192.168.1.100 --output-format json > results.json

# CSV for spreadsheet import
gl-analyze --batch targets.txt --output-format csv > results.csv

# Table format for human reading (default)
gl-analyze 192.168.1.100 --output-format table
```

## 🏗️ Architecture

```
gridland/
├── core/           # Configuration, logging, networking
├── discover/       # Target discovery engines
├── analyze/        # Analysis and vulnerability assessment
├── stream/         # Stream handling and playback
├── cli/           # Command-line interfaces
├── data/          # Signatures, credentials, CVE data
└── tests/         # Comprehensive test suite
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=gridland

# Run specific test module
pytest tests/test_discovery.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📖 Documentation

- **Full Documentation**: https://gridland.readthedocs.io/
- **API Reference**: https://gridland.readthedocs.io/api/
- **Examples**: https://github.com/gridland/gridland-examples

## 🔒 Security

Found a security vulnerability? Please report it responsibly:
- Email: security@gridland.dev
- Use GitHub's private vulnerability reporting
- Allow 90 days for coordinated disclosure

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original CamXploit project for inspiration
- Masscan and Nmap projects for scanning techniques
- Security research community for responsible disclosure practices

---

**Remember**: With great power comes great responsibility. Use GRIDLAND ethically and legally.