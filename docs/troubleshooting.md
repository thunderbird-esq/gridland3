# Troubleshooting

This guide helps resolve common issues encountered during development, testing, and deployment.

For the full troubleshooting guide, see the [TROUBLESHOOTING.md](https://github.com/thunderbird-esq/gridland3/blob/main/TROUBLESHOOTING.md) in the repository.

## Installation Issues

### `pip install` fails with dependency conflicts

**Solutions:**

1. Create fresh virtual environment:
   ```bash
   deactivate  # If in venv
   rm -rf venv
   python -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

2. Install package in editable mode:
   ```bash
   cd gridland
   pip install -e .
   ```

### Command `gl-discover` or `gl-analyze` not found

**Solutions:**

1. Install package in editable mode:
   ```bash
   cd gridland
   pip install -e .
   ```

2. Check if installed correctly:
   ```bash
   which gl-discover
   pip show gridland
   ```

## Testing Issues

### Tests fail with import errors

```
ModuleNotFoundError: No module named 'gridland'
```

**Solutions:**

1. Install package in development mode:
   ```bash
   cd gridland
   pip install -e .
   ```

2. Run tests from project root:
   ```bash
   cd /path/to/gridland3
   pytest tests/
   ```

### Async tests fail or hang

```
RuntimeError: Event loop is closed
```

**Solutions:**

1. Install pytest-asyncio:
   ```bash
   pip install pytest-asyncio
   ```

2. Mark async tests correctly:
   ```python
   @pytest.mark.asyncio
   async def test_async_function():
       result = await some_async_call()
       assert result
   ```

## Code Quality Issues

### Black and Flake8 conflict

Configure Flake8 to match Black:

```ini
# .flake8
[flake8]
max-line-length = 100
extend-ignore = E203, W503, E501
```

### Import order issues with isort/Black

Configure isort to use Black profile:

```toml
[tool.isort]
profile = "black"
line_length = 100
```

## Runtime Issues

### Scanner reports all ports closed

**Solutions:**

1. Verify target is reachable:
   ```bash
   ping 192.168.1.100
   ```

2. Increase timeout for slower networks:
   ```python
   from gridland.discover import PythonPortScanner
   scanner = PythonPortScanner(max_threads=100, timeout=5.0)
   ```

3. Use category-based scanning:
   ```bash
   gl-discover --camera-port-category rtsp 192.168.1.0/24
   ```

### Python scanner used instead of masscan

```
[INFO] masscan not found - falling back to Python scanner
```

Install masscan for faster scanning:

```bash
# Ubuntu/Debian
sudo apt-get install masscan

# macOS
brew install masscan
```

Or explicitly use Python scanner:

```bash
gl-discover --use-python-scanner 192.168.1.0/24
```

## Getting Help

If your issue isn't listed here:

1. **Search existing issues**: [GitHub Issues](https://github.com/thunderbird-esq/gridland3/issues)
2. **Check discussions**: [GitHub Discussions](https://github.com/thunderbird-esq/gridland3/discussions)
3. **Create new issue**: Use the bug report template
4. **Review logs**: Include full error messages and stack traces

## Debugging Tips

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Use Python Debugger

```python
import pdb; pdb.set_trace()  # Set breakpoint
```

### Profile Performance

```bash
python -m cProfile -o profile.stats script.py
python -m pstats profile.stats
```
