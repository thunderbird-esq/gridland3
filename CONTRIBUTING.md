# Contributing to GRIDLAND v3.0

Thank you for your interest in contributing to GRIDLAND! This document provides guidelines and setup instructions for contributors.

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- Git
- pip and virtualenv

### Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/thunderbird-esq/gridland3.git
   cd gridland3
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development tools
   ```

4. **Install pre-commit hooks**

   ```bash
   pip install pre-commit
   pre-commit install
   ```

5. **Install package in editable mode**

   ```bash
   cd gridland
   pip install -e .
   ```

6. **Verify installation**

   ```bash
   which gl-discover
   which gl-analyze
   python -c "from gridland.core.config import get_config; print('✅ Installation successful')"
   ```

---

## 📋 Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Your Changes

- Write clean, documented code
- Follow the code style guidelines (see below)
- Add tests for new functionality
- Update documentation as needed

### 3. Run Quality Checks

**Automatic (via pre-commit)**:

```bash
pre-commit run --all-files
```

**Manual checks**:

```bash
# Format code
black gridland/ tests/ --line-length=100
isort gridland/ tests/ --profile black

# Lint
flake8 gridland/ tests/
pylint gridland/ --max-line-length=100

# Type check
mypy gridland/ --ignore-missing-imports

# Security check
bandit -r gridland/

# Run tests
pytest tests/ -v --cov=gridland --cov-report=term-missing
```

### 4. Commit Your Changes

```bash
git add .
git commit -m "feat: add new fingerprinting module

- Implement Hikvision fingerprinting
- Add 50+ unit tests
- Update documentation
"
```

**Commit Message Format**:

```
<type>: <subject>

<body>

<footer>
```

**Types**:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `security`: Security fixes

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a PR on GitHub using the provided template.

---

## 🎨 Code Style Guidelines

### Python Code Standards

**Line Length**: 100 characters maximum

**Formatting**:

- Use Black for code formatting
- Use isort for import sorting
- Follow PEP 8 with Black modifications

**Naming Conventions**:

- `snake_case` for functions and variables
- `PascalCase` for classes
- `UPPER_SNAKE_CASE` for constants
- Descriptive names (avoid abbreviations unless standard)

**Docstrings**:

- All modules, classes, and public functions must have docstrings
- Use Google-style docstrings
- Include Args, Returns, Raises sections

**Example**:

```python
def fingerprint_device(ip: str, port: int, timeout: int = 10) -> FingerprintResult:
    """
    Extract device fingerprint from target camera.

    Args:
        ip: Target IP address (e.g., "192.168.1.100")
        port: Target port (e.g., 80)
        timeout: Connection timeout in seconds (default: 10)

    Returns:
        FingerprintResult with extracted device information

    Raises:
        ConnectionError: If unable to connect to target
        ValueError: If IP address is invalid

    Example:
        >>> result = fingerprint_device("192.168.1.100", 80)
        >>> print(result.model)
        'DS-2CD2032-I'
    """
    # Implementation
```

### Type Hints

- Use type hints for all function parameters and returns
- Use `Optional[T]` for values that can be None
- Use `List[T]`, `Dict[K, V]` for collections
- Use `typing` module for complex types

### Error Handling

- Never use bare `except:`
- Catch specific exceptions
- Log errors with context
- Use custom exceptions when appropriate

**Example**:

```python
try:
    response = await session.get(url, timeout=timeout)
except asyncio.TimeoutError:
    logger.warning(f"Timeout connecting to {url}")
    return None
except aiohttp.ClientError as e:
    logger.error(f"Connection error for {url}: {e}")
    return None
except Exception as e:
    logger.exception(f"Unexpected error querying {url}")
    raise
```

---

## 🧪 Testing Guidelines

### Test Requirements

- **All new features** must have tests
- **All bug fixes** must have regression tests
- **Minimum coverage**: 70% (aim for 90%+)
- **Test types**: Unit tests, integration tests, performance tests

### Writing Tests

**Test file structure**:

```
tests/
├── analyze/
│   ├── core/
│   │   ├── test_fingerprinting.py
│   │   ├── test_detection_aggregator.py
│   ├── plugins/
│   │   ├── builtin/
│   │   │   ├── test_cp_plus_scanner.py
```

**Test naming**:

```python
class TestFingerprinting:
    def test_hikvision_isapi_parsing(self):
        """Test Hikvision ISAPI XML response parsing."""
        # Arrange
        mock_response = """
        <DeviceInfo>
            <model>DS-2CD2032-I</model>
            <firmwareVersion>V5.6.5</firmwareVersion>
        </DeviceInfo>
        """

        # Act
        result = parse_hikvision_deviceinfo(mock_response)

        # Assert
        assert result.model == "DS-2CD2032-I"
        assert result.firmware == "V5.6.5"
```

**Mocking HTTP calls**:

```python
@pytest.fixture
def mock_http_response():
    return aiohttp.ClientResponse(
        method='GET',
        url='http://test.com',
        status=200,
        headers={'Content-Type': 'application/json'}
    )

@patch('aiohttp.ClientSession.get')
async def test_api_call(mock_get, mock_http_response):
    mock_get.return_value.__aenter__.return_value = mock_http_response
    # Test implementation
```

### Running Tests

**All tests**:

```bash
pytest tests/ -v
```

**With coverage**:

```bash
pytest tests/ --cov=gridland --cov-report=html
```

**Specific test file**:

```bash
pytest tests/analyze/core/test_fingerprinting.py -v
```

**Specific test**:

```bash
pytest tests/analyze/core/test_fingerprinting.py::TestFingerprinting::test_hikvision_parsing -v
```

**Mark-based selection**:

```bash
pytest -m unit          # Run only unit tests
pytest -m integration   # Run only integration tests
pytest -m "not slow"    # Skip slow tests
```

---

## 📦 Adding Dependencies

### Process

1. Add to appropriate requirements file:
   - `requirements.txt` - Core dependencies
   - `requirements-dev.txt` - Development tools
   - `requirements-test.txt` - Testing dependencies

2. Specify version constraints:

   ```
   requests>=2.28.0,<3.0.0
   aiohttp==3.9.1
   pytest>=7.0
   ```

3. Update `setup.py` if it's a core dependency

4. Document why the dependency is needed

### Approval Required

- Security-sensitive dependencies
- Large dependencies (>10MB)
- Dependencies with restrictive licenses

---

## 🐛 Bug Reports

### Before Reporting

1. Check existing issues
2. Verify it's reproducible
3. Test on latest version

### Bug Report Template

```markdown
**Description**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: Ubuntu 22.04
- Python: 3.9.7
- GRIDLAND: 3.0.0
- Installation method: pip

**Additional Context**
Logs, screenshots, etc.
```

---

## 🔒 Security

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Contact: [Security contact to be added]

### Security Best Practices

- Never commit API keys, credentials, or secrets
- Use environment variables for sensitive data
- Run `detect-secrets` before committing
- Follow OWASP security guidelines
- Sanitize all user inputs
- Use parameterized queries for databases

---

## 📚 Documentation

### Required Documentation

- **Code comments**: For complex logic
- **Docstrings**: For all public APIs
- **README updates**: For new features
- **CHANGELOG**: For user-facing changes

### Documentation Standards

- Clear and concise
- Include examples
- Keep up-to-date
- Test code examples

---

## ✅ Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code follows style guidelines
- [ ] All tests pass (`pytest tests/`)
- [ ] Coverage meets minimum (70%+)
- [ ] Pre-commit hooks pass
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)
- [ ] Commit messages follow convention
- [ ] PR description is clear and complete
- [ ] Related issues are referenced

---

## 🎯 Code Review Process

### What Reviewers Look For

1. **Correctness**: Does it work as intended?
2. **Tests**: Adequate test coverage?
3. **Style**: Follows guidelines?
4. **Performance**: Any performance concerns?
5. **Security**: Any security implications?
6. **Documentation**: Clear and complete?

### Response Time

- Initial review: Within 3 business days
- Follow-up reviews: Within 2 business days

### Approval Criteria

- At least 1 approval from maintainer
- All CI checks passing
- No unresolved review comments

---

## 🏆 Recognition

Contributors will be:

- Listed in CONTRIBUTORS.md
- Mentioned in release notes (for significant contributions)
- Credited in commit history

---

## 📞 Getting Help

- **Questions**: Open a GitHub discussion
- **Issues**: Create a GitHub issue
- **Chat**: [To be added]

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to GRIDLAND! 🚀
