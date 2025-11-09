"""
Pytest configuration and fixtures for HelloBird test suite.

This module provides shared fixtures for testing the Flask application,
including app initialization, test clients, and common test data.
"""

import pytest
import os
import sys

# Add parent directory to path to import server module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock shodan module if not available
try:
    import shodan
except ImportError:
    # Create mock shodan module
    import importlib.util
    spec = importlib.util.spec_from_file_location("shodan", os.path.join(os.path.dirname(__file__), "mock_shodan.py"))
    shodan = importlib.util.module_from_spec(spec)
    sys.modules['shodan'] = shodan
    spec.loader.exec_module(shodan)

import server


@pytest.fixture
def app():
    """
    Create and configure a Flask app instance for testing.

    Returns:
        Flask: Configured Flask application in testing mode
    """
    # Store original API state
    original_api = server.api

    # Disable Shodan API for most tests to avoid external dependencies
    server.api = None

    # Configure app for testing
    server.app.config['TESTING'] = True
    server.app.config['DEBUG'] = False

    yield server.app

    # Restore original API state
    server.api = original_api


@pytest.fixture
def client(app):
    """
    Create a test client for the Flask application.

    Args:
        app: Flask application fixture

    Returns:
        FlaskClient: Test client for making requests
    """
    return app.test_client()


@pytest.fixture
def valid_ip():
    """
    Provide a valid IP address for testing.

    Returns:
        str: Valid IP address (Google DNS)
    """
    return "8.8.8.8"


@pytest.fixture
def invalid_ip():
    """
    Provide an invalid IP address for testing.

    Returns:
        str: Invalid IP address
    """
    return "999.999.999.999"


@pytest.fixture
def shodan_api_enabled(monkeypatch):
    """
    Enable Shodan API for specific tests.

    This fixture temporarily sets a mock Shodan API for tests that need it.
    """
    from unittest.mock import Mock

    mock_api = Mock()
    monkeypatch.setattr(server, 'api', mock_api)

    return mock_api


@pytest.fixture
def mock_subprocess(monkeypatch):
    """
    Mock subprocess.Popen for testing scan functionality.

    Returns:
        Mock: Mock Popen object
    """
    from unittest.mock import Mock, MagicMock
    import subprocess

    mock_process = MagicMock()
    mock_process.stdout.readline = Mock(side_effect=['Line 1\n', 'Line 2\n', ''])
    mock_process.wait = Mock(return_value=0)
    mock_process.kill = Mock()
    mock_process.stdin = MagicMock()

    mock_popen = Mock(return_value=mock_process)
    monkeypatch.setattr(subprocess, 'Popen', mock_popen)

    return mock_popen


@pytest.fixture
def valid_stream_url():
    """
    Provide a valid RTSP stream URL for testing.

    Returns:
        str: Valid RTSP URL
    """
    return "rtsp://example.com:554/stream"


@pytest.fixture
def invalid_stream_url():
    """
    Provide an invalid stream URL for testing.

    Returns:
        str: Invalid URL
    """
    return "http://malicious.com/../../etc/passwd"
