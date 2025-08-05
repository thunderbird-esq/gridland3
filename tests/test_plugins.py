import pytest
from unittest.mock import patch, MagicMock
from lib.core import ScanTarget, PortResult
from plugins.credential_scanner import CredentialScannerPlugin
from lib.evasion import get_request_headers

@patch('requests.get')
def test_credential_scanner_plugin_success(mock_get):
    """
    Tests that the CredentialScannerPlugin correctly identifies credentials
    when a valid login is found.
    """
    # Arrange
    # This response should not trigger the "failed login" indicators
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Welcome to the dashboard."
    mock_get.return_value = mock_response

    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    plugin = CredentialScannerPlugin()

    # Act
    findings = plugin.scan(target)

    # Assert
    # The plugin should find the first credential in its list and then stop.
    # The first credential for 'admin' is an empty password.
    assert len(findings) == 1

    finding = findings[0]
    assert finding.category == "credential"

    # The first endpoint checked is the base URL
    expected_endpoint = 'http://192.168.1.100:80/'
    expected_description = f"Found default credentials admin: on {expected_endpoint}"
    assert finding.description == expected_description

    assert finding.data['username'] == 'admin'
    assert finding.data['password'] == ''

    # Verify that the correct request was made
    mock_get.assert_any_call(
        expected_endpoint,
        auth=('admin', ''),
        headers=get_request_headers(),
        proxies=None,
        timeout=3,
        verify=False
    )

from plugins.fingerprint_scanner import FingerprintScannerPlugin

@patch('requests.get')
def test_fingerprint_scanner_confidence_scoring(mock_get):
    """
    Tests that the FingerprintScannerPlugin correctly uses confidence scoring
    to prioritize a high-confidence indicator (HTTP header) over a
    medium-confidence one (HTML content).
    """
    # Arrange
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {'Server': 'Apache'}
    mock_response.text = '<html><body>This is a page about Dahua devices.</body></html>'
    mock_response.url = 'http://192.168.1.101:80'
    mock_get.return_value = mock_response

    target = ScanTarget(
        ip='192.168.1.101',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    plugin = FingerprintScannerPlugin()

    # Act
    findings = plugin.scan(target)

    # Assert
    assert len(findings) == 1

    finding = findings[0]
    assert finding.category == "fingerprint"

    # Apache (header, score 3) should be chosen over Dahua (html_specific, score 2)
    assert finding.data['vendor'] == 'Apache'
    assert finding.data['confidence'] == 3

    # Verify that the evidence log contains both indicators
    assert len(finding.data['evidence']) == 2
    vendors_in_evidence = {e['vendor'] for e in finding.data['evidence']}
    assert 'Apache' in vendors_in_evidence
    assert 'Dahua' in vendors_in_evidence
