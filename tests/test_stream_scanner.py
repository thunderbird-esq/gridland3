import pytest
from unittest.mock import patch, MagicMock
from plugins.stream_scanner import StreamScannerPlugin
from lib.core import ScanTarget, PortResult

@patch('requests.head')
@patch('socket.socket')
def test_stream_scanner_plugin(mock_socket, mock_head):
    """
    Tests that the StreamScannerPlugin can identify both RTSP and HTTP streams.
    """
    # Arrange
    # Mock the socket connection for RTSP
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect.return_value = None
    mock_socket.return_value.__enter__.return_value = mock_sock_instance

    # Mock the requests.head call for HTTP
    mock_head_response = MagicMock()
    mock_head_response.status_code = 200
    mock_head_response.headers = {'Content-Type': 'video/mjpeg'}
    mock_head.return_value = mock_head_response

    # Create a target with open RTSP and HTTP ports
    target = ScanTarget(
        ip='192.168.1.101',
        open_ports=[
            PortResult(port=554, is_open=True),
            PortResult(port=8080, is_open=True)
        ]
    )

    # Act
    plugin = StreamScannerPlugin()
    findings = plugin.scan(target)

    # Assert
    assert len(findings) == len(plugin.RTSP_PATHS) + 1 # All RTSP paths + one HTTP path

    # Check the RTSP finding
    rtsp_finding_urls = [f.raw_evidence for f in findings if f.raw_evidence.startswith('rtsp')]
    assert f"rtsp://192.168.1.101:554{plugin.RTSP_PATHS[0]}" in rtsp_finding_urls

    # Check the HTTP finding
    http_finding = next(f for f in findings if f.raw_evidence.startswith('http'))
    assert http_finding is not None
    assert http_finding.category == "Live Stream"
    assert "http://192.168.1.101:8080/video" in http_finding.description

    # Verify mocks were called
    mock_socket.assert_called()
    mock_head.assert_called()
