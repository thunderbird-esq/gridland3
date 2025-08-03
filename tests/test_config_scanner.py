import pytest
from unittest.mock import patch, MagicMock
from plugins.config_scanner import ConfigScannerPlugin
from lib.core import ScanTarget, PortResult

@patch('requests.get')
def test_scan_config_files_finds_file(mock_get):
    """A very simple test to see if _scan_config_files finds a file."""
    # Arrange
    plugin = ConfigScannerPlugin()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<configuration><api_key>AIzaSyABCDEFG123456789</api_key></configuration>"
    mock_get.return_value = mock_response

    # Act
    findings = plugin._scan_config_files("http://192.168.1.100:80", 80)

    # Assert
    assert len(findings) > 0
    assert mock_get.call_count > 0
