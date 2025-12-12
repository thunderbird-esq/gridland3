# Installation

This guide covers the installation of GRIDLAND v3.0 on various platforms.

## Requirements

### System Requirements

- **Python:** 3.8 or higher
- **Operating System:** Linux, macOS, or Windows
- **Memory:** 2GB RAM minimum (4GB recommended for large scans)
- **Disk Space:** 100MB for installation

### Optional Dependencies

- **masscan:** For high-speed port scanning (Linux only)
- **nmap:** Alternative port scanning backend
- **GStreamer:** For stream transcoding (server.py legacy features)

## Installation Methods

### Method 1: pip install (Recommended)

```bash
# Clone the repository
git clone https://github.com/thunderbird-esq/gridland3.git
cd gridland3

# Install in development mode
pip install -e .
```

This installs GRIDLAND with all required dependencies and makes the `gridland` command available system-wide.

### Method 2: Virtual Environment (Recommended for Development)

```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate  # On Linux/macOS
# OR
venv\Scripts\activate  # On Windows

# Install GRIDLAND
pip install -e .
```

### Method 3: Docker (Isolated Environment)

```bash
# Build the Docker image
docker build --build-arg SHODAN_API_KEY_ARG=your_api_key_here -t gridland:latest .

# Run GRIDLAND in a container
docker run -it --rm gridland:latest gridland --help
```

## Dependencies

### Core Dependencies

GRIDLAND requires the following Python packages (automatically installed with pip):

```
requests>=2.28.0      # HTTP client library
ipaddress>=1.0.23     # IP address validation (stdlib in Python 3.3+)
aiohttp>=3.8.0        # Async HTTP client for OSINT
python-dotenv>=0.19.0 # Environment variable management
```

### Optional Dependencies

For legacy server.py features:

```
flask>=2.0.0          # Web server framework
shodan>=1.25.0        # Shodan API integration
```

### Development Dependencies

For running tests and building documentation:

```
pytest>=7.0.0         # Testing framework
pytest-cov>=3.0.0     # Coverage reporting
pytest-asyncio>=0.18.0 # Async test support
mkdocs>=1.4.0         # Documentation generator
mkdocs-material>=8.5.0 # Material theme for MkDocs
mkdocstrings[python]>=0.19.0 # API documentation
```

Install all development dependencies:

```bash
pip install -r requirements-dev.txt
```

## Verifying Installation

### Check Installation

```bash
# Verify GRIDLAND is installed
gridland --version

# Check available commands
gridland --help

# Test discover command
gridland discover --help

# Test analyze command
gridland analyze --help
```

### Run Tests

```bash
# Run the full test suite
pytest

# Run with coverage
pytest --cov=gridland --cov-report=html

# Run specific test modules
pytest tests/test_data_loader.py -v
pytest tests/discover/ -v
pytest tests/analyze/ -v
```

### Validate Migration

```bash
# Run the migration validation script
python validate_migration.py

# Expected output:
# ✓ All 9 validation tests passed
```

## Platform-Specific Notes

### Linux

```bash
# Install system dependencies for full features
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv masscan

# Install GRIDLAND
pip install -e .
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python@3.11

# Install GRIDLAND
pip3 install -e .
```

### Windows

```powershell
# Ensure Python 3.8+ is installed
python --version

# Install GRIDLAND
pip install -e .

# Note: masscan is not available on Windows
# Use --use-python-scanner flag for port scanning
```

## Optional Tools

### Installing masscan (Linux Only)

masscan provides high-speed port scanning capabilities:

```bash
# Ubuntu/Debian
sudo apt-get install masscan

# From source
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

### Installing nmap

```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from: https://nmap.org/download.html
```

## Configuration

### Environment Variables

Create a `.env` file in the project root for optional configurations:

```bash
# Shodan API key (for legacy server.py features)
SHODAN_API_KEY=your_api_key_here

# IPinfo.io API key (optional, for enhanced geolocation)
IPINFO_API_KEY=your_api_key_here

# Custom data directory (optional)
GRIDLAND_DATA_DIR=/path/to/custom/data

# Audit log location (optional)
GRIDLAND_AUDIT_LOG=/path/to/audit.csv
```

### Data Directory Structure

GRIDLAND uses the following data files (automatically loaded):

```
gridland/data/
├── camera_ports.json       # 685 camera ports by category
├── login_paths.json        # 72 authentication endpoints
├── cve_database.json       # 39 CVEs with CVSS scores
├── stream_paths.json       # 138+ stream discovery paths
├── default_credentials.json # 30 default username/password pairs
└── cpplus_data.json        # CP Plus device detection data
```

## Troubleshooting

### Common Issues

#### ImportError: No module named 'gridland'

**Solution:** Install GRIDLAND in development mode:

```bash
pip install -e .
```

#### Command not found: gridland

**Solution:** Ensure pip's bin directory is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"

# Reload shell configuration
source ~/.bashrc
```

#### Permission denied errors

**Solution:** Use a virtual environment or install with --user flag:

```bash
pip install --user -e .
```

#### masscan not found

**Solution:** Either install masscan or use the Python scanner:

```bash
gridland discover --use-python-scanner --target 192.168.1.0/24
```

### Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](../troubleshooting.md)
2. Search [GitHub Issues](https://github.com/thunderbird-esq/gridland3/issues)
3. Open a new issue with:
   - Python version (`python --version`)
   - Operating system
   - Installation method
   - Full error message

## Next Steps

- [Quick Start Guide](quickstart.md) - Learn basic usage
- [Configuration Guide](configuration.md) - Customize GRIDLAND
- [CLI Reference](../cli/overview.md) - Explore all commands
