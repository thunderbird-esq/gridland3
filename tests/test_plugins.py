import pytest
from unittest.mock import patch, MagicMock
from lib.core import ScanTarget, PortResult
from plugins.credential_scanner import CredentialScannerPlugin

@patch('requests.get')
def test_credential_scanner_finds_multiple_credentials_on_different_ports(mock_get):
    """
    Tests that the CredentialScannerPlugin continues scanning other ports
    after finding a credential on one port.
    """
    # Arrange
    def side_effect(url, auth=None, **kwargs):
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Success on port 80's main page with admin:password
        if url == 'http://192.168.1.100:80/' and auth == ('admin', 'password'):
            mock_response.text = 'Welcome admin'
            return mock_response

        # Success on port 8080's main page with root:toor
        if url == 'http://192.168.1.100:8080/' and auth == ('root', 'toor'):
            mock_response.text = 'Welcome root'
            return mock_response

        # Any other combo is a login page, which should be skipped by the plugin's logic
        mock_response.text = 'please login'
        return mock_response

    mock_get.side_effect = side_effect

    scanner = CredentialScannerPlugin()
    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[
            PortResult(port=80, is_open=True),
            PortResult(port=8080, is_open=True)
        ]
    )

    # Act
    findings = scanner.scan(target)

    # Assert
    assert len(findings) == 2, f"Expected 2 findings, but got {len(findings)}"

    urls_found = {f.url for f in findings}
    descriptions_found = {f.description for f in findings}

    assert 'http://192.168.1.100:80/' in urls_found
    assert 'http://192.168.1.100:8080/' in urls_found

    assert any('admin:password' in d for d in descriptions_found)
    assert any('root:toor' in d for d in descriptions_found)

    # Check that scanning continued after the first find.
    calls = mock_get.call_args_list
    found_80_success = False
    found_8080_after_80_success = False
    for call in calls:
        url = call.args[0]
        auth = call.kwargs.get('auth')

        if url == 'http://192.168.1.100:80/' and auth == ('admin', 'password'):
            found_80_success = True

        if found_80_success and '192.168.1.100:8080' in url:
            found_8080_after_80_success = True
            break

    assert found_8080_after_80_success, "Scanner should have continued to port 8080 after finding creds on port 80"
