import pytest
from unittest.mock import patch, MagicMock
from plugins.web_interface_scanner import WebInterfaceScannerPlugin
from lib.core import ScanTarget, PortResult

@patch('requests.get')
def test_web_interface_scanner_finds_new_path(mock_get):
    """
    Tests that the web interface scanner can find one of the newly added admin paths.
    """
    # Arrange
    plugin = WebInterfaceScannerPlugin()
    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    # Mock requests.get to return a successful response for the new path
    def mock_get_side_effect(url, **kwargs):
        mock_response = MagicMock()
        if "/view/view.shtml" in url:
            mock_response.status_code = 200
            mock_response.text = "<html><title>Admin Login</title></html>"
        else:
            mock_response.status_code = 404
        return mock_response
    mock_get.side_effect = mock_get_side_effect

    # Act
    findings = plugin.scan(target)

    # Assert
    assert len(findings) > 0
    urls_found = [f.url for f in findings]
    assert any("/view/view.shtml" in url for url in urls_found)
