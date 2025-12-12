# Contributing Guidelines

Thank you for your interest in contributing to GRIDLAND! This document provides guidelines for contributing to this security research project.

## Code of Conduct

- Be respectful and professional
- Follow ethical guidelines for security research
- Report security issues responsibly

## Getting Started

### Prerequisites

- Python 3.9+
- Git
- pre-commit (for local hooks)

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/thunderbird-esq/gridland3.git
cd gridland3

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=gridland --cov-report=html

# Run specific test file
pytest tests/test_data_loader.py -v
```

## Pull Request Process

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Write clean, documented code
- Add tests for new functionality
- Follow existing code style (enforced by pre-commit)

### 3. Run Pre-commit Hooks

```bash
pre-commit run --all-files
```

### 4. Submit PR

- Provide clear description of changes
- Reference any related issues
- Ensure CI passes

## Code Style

GRIDLAND uses these tools for code quality:

| Tool | Purpose | Config |
|------|---------|--------|
| Black | Code formatting | line-length=100 |
| isort | Import sorting | profile=black |
| Flake8 | Linting | max-line-length=100 |
| MyPy | Type checking | ignore-missing-imports |
| Bandit | Security scanning | -ll (low severity) |

## Security Guidelines

See the [Ethics Guide](ethics.md) for security research guidelines.

### Reporting Security Issues

- **DO NOT** open public issues for security vulnerabilities
- Email security concerns to the maintainers
- Include detailed reproduction steps
- Allow time for patch before disclosure

## Documentation

- Add docstrings to all public functions
- Update relevant docs when adding features
- Follow Google-style docstrings

```python
def example_function(param: str) -> bool:
    """Short description of function.

    Args:
        param: Description of parameter.

    Returns:
        Description of return value.

    Raises:
        ValueError: When param is invalid.
    """
    pass
```
