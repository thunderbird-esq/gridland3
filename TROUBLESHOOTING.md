# GRIDLAND v3.0 - Troubleshooting Guide

This guide helps resolve common issues encountered during development, testing, and deployment.

---

## 🔧 Installation Issues

### Issue: `pip install` fails with dependency conflicts

**Symptoms:**

```
ERROR: Cannot install gridland because these package versions have incompatible dependencies
```

**Solutions:**

1. **Create fresh virtual environment:**

   ```bash
   deactivate  # If in venv
   rm -rf venv
   python -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

2. **Use pip's dependency resolver:**

   ```bash
   pip install --use-feature=fast-deps -r requirements.txt
   ```

3. **Install dependencies one by one** to identify the conflict:

   ```bash
   pip install requests
   pip install aiohttp
   # ... etc
   ```

---

### Issue: Pre-commit hooks installation fails

**Symptoms:**

```
[ERROR] Cowardly refusing to install hooks with `core.hooksPath` set
```

**Solution:**

```bash
# Remove conflicting git hook configuration
git config --unset-all core.hooksPath

# Reinstall pre-commit
pre-commit clean
pre-commit install
```

---

### Issue: Command `gl-discover` or `gl-analyze` not found

**Symptoms:**

```bash
$ gl-discover
bash: gl-discover: command not found
```

**Solutions:**

1. **Install package in editable mode:**

   ```bash
   cd gridland
   pip install -e .
   ```

2. **Check if installed correctly:**

   ```bash
   which gl-discover
   pip show gridland
   ```

3. **Verify PATH includes pip's bin directory:**

   ```bash
   python -m site --user-base  # Shows user base
   # Add to PATH: export PATH="$PATH:/path/to/user/base/bin"
   ```

---

## 🧪 Testing Issues

### Issue: Tests fail with import errors

**Symptoms:**

```
ModuleNotFoundError: No module named 'gridland'
```

**Solutions:**

1. **Install package in development mode:**

   ```bash
   cd gridland
   pip install -e .
   ```

2. **Check PYTHONPATH:**

   ```bash
   export PYTHONPATH="${PYTHONPATH}:/path/to/gridland3"
   ```

3. **Run tests from project root:**

   ```bash
   cd /path/to/gridland3
   pytest tests/
   ```

---

### Issue: Async tests fail or hang

**Symptoms:**

```
RuntimeError: Event loop is closed
```

**Solutions:**

1. **Install pytest-asyncio:**

   ```bash
   pip install pytest-asyncio
   ```

2. **Mark async tests correctly:**

   ```python
   @pytest.mark.asyncio
   async def test_async_function():
       result = await some_async_call()
       assert result
   ```

3. **Use asyncio_mode in pytest.ini:**

   ```ini
   [pytest]
   asyncio_mode = auto
   ```

---

### Issue: HTTP mocking doesn't work

**Symptoms:**

```
Real HTTP request made during testing
```

**Solutions:**

1. **Use aioresponses for async HTTP:**

   ```python
   from aioresponses import aioresponses

   @aioresponses()
   async def test_http_call(mock_aiohttp):
       mock_aiohttp.get('http://test.com', payload={'result': 'ok'})
       # Test code
   ```

2. **Use responses for sync HTTP:**

   ```python
   import responses

   @responses.activate
   def test_sync_http():
       responses.get('http://test.com', json={'result': 'ok'})
       # Test code
   ```

---

### Issue: Coverage reports are inaccurate

**Symptoms:**

```
Coverage: 0%  (but code was definitely executed)
```

**Solutions:**

1. **Run coverage correctly:**

   ```bash
   pytest --cov=gridland --cov-report=term-missing tests/
   ```

2. **Check .coveragerc or pyproject.toml:**

   ```toml
   [tool.coverage.run]
   source = ["gridland"]
   ```

3. **Combine coverage from multiple runs:**

   ```bash
   coverage run -m pytest tests/
   coverage combine
   coverage report
   ```

---

## 🎨 Code Quality Issues

### Issue: Black and Flake8 conflict

**Symptoms:**

```
E501 line too long (105 > 100 characters)
```

(But Black formatted it that way)

**Solution:**

Configure Flake8 to match Black:

```ini
# .flake8
[flake8]
max-line-length = 100
extend-ignore = E203, W503, E501
```

---

### Issue: Import order issues with isort/Black

**Symptoms:**

```
Imports are incorrectly sorted
```

**Solution:**

Configure isort to use Black profile:

```toml
[tool.isort]
profile = "black"
line_length = 100
```

Or via command:

```bash
isort --profile black gridland/ tests/
```

---

### Issue: MyPy false positives

**Symptoms:**

```
error: Module has no attribute "..."
```

**Solutions:**

1. **Ignore specific errors:**

   ```python
   from typing import TYPE_CHECKING

   if TYPE_CHECKING:
       from optional_module import Something  # type: ignore
   ```

2. **Add to mypy.ini:**

   ```ini
   [mypy-problematic_module.*]
   ignore_errors = True
   ```

3. **Install type stubs:**

   ```bash
   pip install types-requests types-aiohttp
   ```

---

## 🔒 Security Scanning Issues

### Issue: Bandit false positives

**Symptoms:**

```
Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input
```

**Solutions:**

1. **Suppress specific warnings with comment:**

   ```python
   subprocess.run(cmd, shell=False)  # nosec B603
   ```

2. **Configure in pyproject.toml:**

   ```toml
   [tool.bandit]
   skips = ["B603"]
   ```

---

### Issue: detect-secrets finding false secrets

**Symptoms:**

```
Potential secret in file
```

**Solution:**

Create baseline:

```bash
detect-secrets scan --all-files --force-use-all-plugins > .secrets.baseline
```

Update baseline:

```bash
detect-secrets scan --baseline .secrets.baseline
```

---

## 🚀 GitHub Actions Issues

### Issue: CI workflow fails but passes locally

**Symptoms:**

```
Tests pass on local machine but fail in GitHub Actions
```

**Solutions:**

1. **Check Python version match:**

   ```yaml
   # .github/workflows/ci.yml
   - uses: actions/setup-python@v5
     with:
       python-version: '3.9'  # Match your local version
   ```

2. **Install system dependencies:**

   ```yaml
   - name: Install system dependencies
     run: |
       sudo apt-get update
       sudo apt-get install -y masscan
   ```

3. **Use cache to speed up:**

   ```yaml
   - uses: actions/setup-python@v5
     with:
       python-version: '3.9'
       cache: 'pip'
   ```

---

### Issue: GitHub Actions timeout

**Symptoms:**

```
Job exceeded maximum execution time
```

**Solutions:**

1. **Increase timeout:**

   ```yaml
   jobs:
     test:
       timeout-minutes: 30  # Default is 6 hours, but set explicitly
   ```

2. **Use pytest-timeout:**

   ```bash
   pytest --timeout=300  # 5 minutes per test
   ```

3. **Run tests in parallel:**

   ```bash
   pytest -n auto  # Requires pytest-xdist
   ```

---

### Issue: Coverage upload fails

**Symptoms:**

```
Error uploading to Codecov
```

**Solutions:**

1. **Check token (for private repos):**

   ```yaml
   - uses: codecov/codecov-action@v3
     with:
       token: ${{ secrets.CODECOV_TOKEN }}
   ```

2. **Verify coverage file exists:**

   ```yaml
   - name: Generate coverage
     run: pytest --cov=gridland --cov-report=xml

   - name: Upload coverage
     run: ls -la coverage.xml  # Verify file exists
   ```

---

## 🐛 Runtime Issues

### Issue: Memory pool exhaustion

**Symptoms:**

```
MemoryPool hit rate dropped below 50%
Dynamic allocation occurring
```

**Solutions:**

1. **Increase pool size:**

   ```python
   from gridland.analyze.memory import get_memory_pool

   pool = get_memory_pool()
   pool.resize_pool('vulnerability_pool', new_size=20000)
   ```

2. **Check for memory leaks:**

   ```python
   stats = pool.get_pool_statistics()
   for pool_name, stats_dict in stats.items():
       if stats_dict['active_objects'] > stats_dict['peak_objects']:
           print(f"Potential leak in {pool_name}")
   ```

---

### Issue: AsyncIO event loop errors

**Symptoms:**

```
RuntimeError: This event loop is already running
```

**Solutions:**

1. **Use asyncio.run() correctly:**

   ```python
   import asyncio

   async def main():
       result = await async_function()
       return result

   if __name__ == '__main__':
       result = asyncio.run(main())
   ```

2. **Don't create new loops:**

   ```python
   # Bad
   loop = asyncio.new_event_loop()

   # Good
   loop = asyncio.get_event_loop()
   ```

---

### Issue: Plugin not loading

**Symptoms:**

```
Plugin 'cp_plus_scanner' not found
```

**Solutions:**

1. **Check registration in **init**.py:**

   ```python
   # gridland/analyze/plugins/builtin/__init__.py
   from .cp_plus_scanner import cp_plus_scanner

   BUILTIN_PLUGINS = [
       ...,
       cp_plus_scanner,  # Must be added
   ]
   ```

2. **Verify plugin instance created:**

   ```python
   # At bottom of cp_plus_scanner.py
   cp_plus_scanner = CPPlusScanner()
   ```

3. **Check import errors:**

   ```python
   python -c "from gridland.analyze.plugins.builtin import cp_plus_scanner; print('OK')"
   ```

---

## 📊 Performance Issues

### Issue: Slow fingerprinting

**Symptoms:**

```
Fingerprinting takes >10 seconds per device
```

**Solutions:**

1. **Enable connection pooling:**

   ```python
   connector = aiohttp.TCPConnector(
       limit=100,
       limit_per_host=10,
       keepalive_timeout=60
   )
   session = aiohttp.ClientSession(connector=connector)
   ```

2. **Parallelize endpoint queries:**

   ```python
   tasks = [
       self._query_endpoint1(ip),
       self._query_endpoint2(ip),
       self._query_endpoint3(ip),
   ]
   results = await asyncio.gather(*tasks, return_exceptions=True)
   ```

3. **Reduce timeout:**

   ```python
   timeout = aiohttp.ClientTimeout(total=5)  # Reduce from 10s
   ```

---

## 📞 Getting Help

If your issue isn't listed here:

1. **Search existing issues**: <https://github.com/thunderbird-esq/gridland3/issues>
2. **Check discussions**: <https://github.com/thunderbird-esq/gridland3/discussions>
3. **Create new issue**: Use the bug report template
4. **Review logs**: Include full error messages and stack traces

---

## 🔍 Debugging Tips

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

### Memory Profiling

```bash
python -m memory_profiler script.py
```

---

**Last Updated**: 2025-11-28
**Version**: 3.0.0
