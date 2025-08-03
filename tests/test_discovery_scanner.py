import pytest
from unittest.mock import patch, MagicMock, call
from lib.core import ScanTarget, PortResult
from plugins.discovery_scanner import DiscoveryScannerPlugin
from lib.evasion import get_request_headers

@patch('requests.get')
def test_discovery_scanner_makes_requests(mock_get):
    """
    Tests that the DiscoveryScannerPlugin makes requests to paths defined in its data file.
    This verifies that the plugin is loading the external data and scanning for paths
    that were previously in both config_scanner and web_interface_scanner.
    """
    # Arrange
    # We don't need a successful response, just need to check the calls.
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mock_get.return_value = mock_response

    target = ScanTarget(
        ip='192.168.1.200',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    plugin = DiscoveryScannerPlugin()

    # Act
    findings = plugin.scan(target)

    # Assert
    # Check that the scanner attempted to access paths from both original scanners.
    # We are checking the `call_args_list` on the mock to see what URLs were requested.

    # Path from old config_scanner.py: /config.json
    expected_call_config = call(
        'http://192.168.1.200:80/config.json',
        timeout=5,
        verify=False,
        allow_redirects=True,
        headers=get_request_headers(),
        proxies=None
    )

    # Path from old web_interface_scanner.py: /admin
    expected_call_admin = call(
        'http://192.168.1.200:80/admin',
        timeout=5,
        verify=False,
        allow_redirects=True,
        headers=get_request_headers(),
        proxies=None
    )

    assert expected_call_config in mock_get.call_args_list
    assert expected_call_admin in mock_get.call_args_list

    # The scanner should not produce findings for 404 responses
    assert len(findings) == 0
