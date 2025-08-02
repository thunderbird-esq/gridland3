import pytest
from unittest.mock import patch, MagicMock
from lib.plugin_manager import PluginManager
from lib.core import ScanTarget, PortResult

@patch('requests.get')
def test_credential_scanner_plugin(mock_get):
    """
    Tests that the PluginManager can load and run the CredentialScannerPlugin,
    and that the plugin correctly identifies credentials.
    """
    # Arrange
    # Mock the response from requests.get to simulate a successful login
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    # Create a target for the scan
    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    # Act
    # The PluginManager will automatically discover and load plugins from the 'plugins' directory
    manager = PluginManager()
    all_findings = manager.run_all_plugins(target)

    # Assert
    assert len(manager.plugins) == 1
    assert manager.plugins[0].name == 'credential_scanner'

    assert len(all_findings) == 1
    finding = all_findings[0]
    assert finding.category == "Default Credentials"
    assert "admin:admin" in finding.description

    # Check that requests.get was called with the first credential combo
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    assert 'auth' in kwargs
    assert kwargs['auth'] == ('admin', 'admin')
