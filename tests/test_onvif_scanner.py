import pytest
from unittest.mock import patch, MagicMock
from plugins.onvif_scanner import ONVIFScannerPlugin
from lib.core import ScanTarget, PortResult

@patch('requests.post')
def test_onvif_scanner_unauthenticated_user_enum(mock_post):
    """
    Tests that the ONVIF scanner correctly identifies unauthenticated user enumeration.
    """
    # Arrange
    plugin = ONVIFScannerPlugin()
    # Temporarily modify the requests to only test GetUsers for this test
    plugin.ONVIF_REQUESTS = {"get_users": plugin.ONVIF_REQUESTS["get_users"]}

    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    # Mock the response for a successful GetUsers request
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = """
    <soap:Envelope>
        <soap:Body>
            <tds:GetUsersResponse>
                <tds:User>
                    <tt:Username>admin</tt:Username>
                    <tt:UserLevel>Administrator</tt:UserLevel>
                </tds:User>
            </tds:GetUsersResponse>
        </soap:Body>
    </soap:Envelope>
    """
    mock_post.return_value = mock_response

    # Act
    findings = plugin.scan(target)

    # Assert
    vuln_findings = [f for f in findings if f.severity == 'critical']
    assert len(vuln_findings) > 0

    finding = vuln_findings[0]
    assert finding.data.get('vulnerability_type') == 'unauthenticated_user_enumeration'
    assert 'admin' in str(finding.data.get('users'))
