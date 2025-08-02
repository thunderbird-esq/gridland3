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
    def mock_head_side_effect(url, **kwargs):
        mock_response = MagicMock()
        if "192.168.1.101:8080/video" in url:
            mock_response.status_code = 200
            mock_response.headers = {'Content-Type': 'video/mjpeg'}
        else:
            mock_response.status_code = 404
            mock_response.headers = {'Content-Type': 'text/html'}
        return mock_response
    mock_head.side_effect = mock_head_side_effect

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
    assert len(findings) == len(plugin.RTSP_PATHS) + 1, f"Expected {len(plugin.RTSP_PATHS) + 1} findings, but got {len(findings)}"

    # Check the RTSP findings
    rtsp_finding_urls = [f.url for f in findings if f.url.startswith('rtsp')]
    assert len(rtsp_finding_urls) == len(plugin.RTSP_PATHS)
    assert f"rtsp://192.168.1.101:554{plugin.RTSP_PATHS[0]}" in rtsp_finding_urls

    # Check the HTTP finding
    http_findings = [f for f in findings if f.url.startswith('http')]
    assert len(http_findings) == 1
    http_finding = http_findings[0]

    assert http_finding.category == "stream"
    assert http_finding.url == "http://192.168.1.101:8080/video"

    # Verify mocks were called
    mock_socket.assert_called()
    mock_head.assert_called()
