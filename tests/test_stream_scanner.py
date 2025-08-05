import pytest
from unittest.mock import patch, MagicMock
from plugins.stream_scanner import StreamScannerPlugin
from lib.core import ScanTarget, PortResult
import requests

@patch('plugins.stream_scanner.get_proxies')
@patch('plugins.stream_scanner.get_request_headers')
@patch('requests.get')
@patch('socket.socket')
def test_stream_scanner_plugin(mock_socket, mock_get, mock_get_headers, mock_get_proxies):
    """
    Tests that the StreamScannerPlugin can identify both RTSP and HTTP streams.
    """
    # Arrange
    # Mock the helper functions from lib.evasion
    mock_get_headers.return_value = {'User-Agent': 'Test Scanner'}
    mock_get_proxies.return_value = None

    # Mock the socket connection for RTSP
    mock_sock_instance = MagicMock()
    mock_sock_instance.recv.return_value = b"RTSP/1.0 200 OK\r\n\r\n"
    mock_socket.return_value.__enter__.return_value = mock_sock_instance

    # Mock the requests.get call for HTTP
    mock_get_response = MagicMock()
    mock_get_response.status_code = 200
    mock_get_response.headers = {'Content-Type': 'video/mjpeg'}
    mock_get_response.iter_content.return_value = iter([b'fakedata'])
    mock_get.return_value = mock_get_response

    # Create a target with open RTSP and HTTP ports
    target = ScanTarget(
        ip='192.168.1.101',
        open_ports=[
            PortResult(port=554, is_open=True),
            PortResult(port=8080, is_open=True)
        ]
    )
    plugin = StreamScannerPlugin()

    # Act
    findings = plugin.scan(target)

    # Assert
    assert len(findings) > 0

    http_finding = next((f for f in findings if f.data.get("protocol") == "http"), None)
    assert http_finding is not None, "HTTP stream finding should be present"
    assert "http://192.168.1.101:8080/video" in http_finding.url

    rtsp_finding = next((f for f in findings if f.data.get("protocol") == "rtsp"), None)
    assert rtsp_finding is not None, "RTSP stream finding should be present"
    assert "rtsp://192.168.1.101:554/live.sdp" in rtsp_finding.url

    # Verify mocks were called
    mock_socket.assert_called()
    mock_get.assert_called()

def test_verify_http_stream_empty_content():
    """
    Tests that the stream verification handles empty content correctly.
    """
    # Arrange
    plugin = StreamScannerPlugin()
    url = "http://test.com/stream"

    # Mock requests.get to return a response with empty content
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'video/mjpeg'}
        # This will raise StopIteration when next() is called on it
        mock_response.iter_content.return_value = iter([])
        mock_get.return_value.__enter__.return_value = mock_response

        # Act
        result = plugin._verify_http_stream(url)

        # Assert
        assert result is False, "Stream with no content should not be verified"

    # Mock requests.get to simulate a ChunkedEncodingError
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'video/mjpeg'}
        mock_response.iter_content.side_effect = requests.exceptions.ChunkedEncodingError()
        mock_get.return_value.__enter__.return_value = mock_response

        # Act
        result = plugin._verify_http_stream(url)

        # Assert
        assert result is False, "Stream with ChunkedEncodingError should not be verified"
