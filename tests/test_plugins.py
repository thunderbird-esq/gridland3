import pytest
from unittest.mock import patch, MagicMock
from plugins.credential_scanner import CredentialScannerPlugin
from lib.core import ScanTarget, PortResult
from lib.plugins import Finding

@patch('requests.get')
def test_credential_scanner_finds_credential(mock_get):
    """
    Tests that the CredentialScannerPlugin correctly identifies a credential on an endpoint.
    """
    # Arrange
    plugin = CredentialScannerPlugin()

    # Mock a successful response for a specific credential
    # This response should pass the _is_successful_login check
    success_response = MagicMock()
    success_response.status_code = 200
    success_response.text = "<html><body><h1>Welcome</h1></body></html>" # No failure indicators

    # Mock a failed response for all other attempts
    failed_response = MagicMock()
    failed_response.status_code = 401
    failed_response.text = "<html><body>Login Failed</body></html>"
    failed_response.raise_for_status = MagicMock()

    # Set the side_effect to return success only for 'admin:admin' on the first endpoint
    def side_effect(*args, **kwargs):
        auth = kwargs.get('auth')
        url = args[0]
        # The first endpoint in the list is the base URL
        if url == 'http://192.168.1.100:80/' and auth == ('admin', 'admin'):
            return success_response
        # For all other calls, return a failure, but not an exception
        return failed_response

    mock_get.side_effect = side_effect

    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    # Act
    findings = plugin.scan(target)

    # Assert
    # We expect to find exactly one credential because the other endpoints will all fail
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "credential"
    assert "Found default credentials 'admin:admin'" in finding.description
    assert finding.url == "http://192.168.1.100:80/"
    assert finding.data['username'] == 'admin'
    assert finding.data['password'] == 'admin'

    # Verify that the scanner stopped trying credentials for that endpoint after success
    # The successful credential is ('admin', 'admin')
    # The next password for 'admin' is 'password'. We should NOT see a call with this credential on the successful URL.
    calls = mock_get.call_args_list
    urls_called_with_next_password = [
        c.args[0] for c in calls if c.kwargs.get('auth') == ('admin', 'password')
    ]
    assert 'http://192.168.1.100:80/' not in urls_called_with_next_password


@patch('requests.get')
def test_credential_scanner_tries_all_endpoints(mock_get):
    """
    Tests that the CredentialScannerPlugin continues to scan other endpoints
    after finding a credential on one.
    """
    # Arrange
    plugin = CredentialScannerPlugin()

    success_response = MagicMock()
    success_response.status_code = 200
    success_response.text = "Welcome"

    failed_response = MagicMock()
    failed_response.status_code = 401
    failed_response.text = "Login Failed"

    def side_effect(*args, **kwargs):
        url = args[0]
        auth = kwargs.get('auth')
        # Succeed on the first endpoint with the first credential
        if url == 'http://192.168.1.100:80/' and auth == ('admin', ''):
            return success_response
        # Succeed on the second endpoint with a different credential
        if url == 'http://192.168.1.100:80/login' and auth == ('root', 'root'):
            return success_response
        return failed_response

    mock_get.side_effect = side_effect

    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    # Act
    findings = plugin.scan(target)

    # Assert
    assert len(findings) == 2

    finding_urls = {f.url for f in findings}
    assert 'http://192.168.1.100:80/' in finding_urls
    assert 'http://192.168.1.100:80/login' in finding_urls
