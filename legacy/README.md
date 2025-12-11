# Legacy CamXploit.py

## ⚠️ Deprecation Notice

**CamXploit.py has been deprecated** and replaced by GRIDLAND v3.0.

This directory contains the original CamXploit.py script for reference and backward compatibility. **No new features will be added to this script.**

## Migration to GRIDLAND v3.0

### Why Migrate?

| Feature | CamXploit.py | GRIDLAND v3.0 |
|---------|--------------|---------------|
| Architecture | Monolithic (1,853 lines) | Modular packages |
| Testing | None | 521+ unit tests |
| Data Storage | Hardcoded | JSON databases |
| CLI | Basic argparse | Rich Click CLI |
| Performance | Baseline | ~205K detections/sec |
| Maintenance | Deprecated | Active development |

### Command Equivalents

| CamXploit.py | GRIDLAND v3.0 |
|--------------|---------------|
| `python CamXploit.py` | `gridland analyze <IP> --full-scan` |
| Port scanning | `gridland discover --use-python-scanner` |
| Brand detection | `gridland analyze --detect-brand` |
| Stream discovery | `gridland analyze --full-scan` |

### Quick Migration

1. Install GRIDLAND: `pip install -e .`
2. Replace `python CamXploit.py` with `gridland analyze <IP>`
3. Use `gridland --help` for full CLI reference

## Running Legacy Script

If you must run the legacy script:

```bash
python legacy/CamXploit.py
```

**Note**: A deprecation warning will be displayed. This script may be removed in future versions.
