import pytest
from unittest.mock import patch, MagicMock
from plugins.stream_scanner import StreamScannerPlugin
from lib.core import ScanTarget, PortResult

@patch('socket.socket')
def test_verify_rtsp_stream_success(mock_socket):
    """Tests that a valid RTSP stream is successfully verified."""
    # Arrange
    mock_sock_instance = MagicMock()
    mock_sock_instance.recv.return_value = b"RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\nm=video 554 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
    mock_socket.return_value = mock_sock_instance

    plugin = StreamScannerPlugin()
    url = "rtsp://192.168.1.101:554/stream1"

    # Act
    result = plugin._verify_rtsp_stream(url)

    # Assert
    assert result == "H.264"
    mock_sock_instance.connect.assert_called_once_with(('192.168.1.101', 554))
    mock_sock_instance.send.assert_called_once()

@patch('requests.get')
def test_verify_http_stream_success(mock_get):
    """Tests that a valid HTTP stream is successfully verified."""
    # Arrange
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {'Content-Type': 'video/mjpeg'}
    mock_response.iter_content.return_value = iter([b'fakedata'])
    mock_get.return_value = mock_response

    plugin = StreamScannerPlugin()
    url = "http://192.168.1.101:8080/video"

    # Act
    result = plugin._verify_http_stream(url)

    # Assert
    assert result == "MJPEG"
    mock_get.assert_called_once_with(url, timeout=3, verify=False, stream=True)

@patch('plugins.stream_scanner.StreamScannerPlugin._verify_rtsp_stream')
@patch('plugins.stream_scanner.StreamScannerPlugin._verify_http_stream')
def test_scan_calls_verification_methods(mock_verify_http, mock_verify_rtsp):
    """Tests that the main scan method calls the correct verification methods."""
    # Arrange
    mock_verify_rtsp.return_value = "H.264"
    mock_verify_http.return_value = "MJPEG"

    plugin = StreamScannerPlugin()
    target = ScanTarget(
        ip='192.168.1.101',
        open_ports=[
            PortResult(port=554, is_open=True),
            PortResult(port=8080, is_open=True)
        ]
    )

    # Act
    findings = plugin.scan(target)

    # Assert
    # It should call the verification methods for each path
    assert mock_verify_rtsp.call_count == len(plugin.RTSP_PATHS)
    assert mock_verify_http.call_count == len(plugin.HTTP_PATHS)

    # The number of findings should be the number of successful verifications
    assert len(findings) == len(plugin.RTSP_PATHS) + len(plugin.HTTP_PATHS)

    first_finding = findings[0]
    assert first_finding.category == "stream"
    assert first_finding.severity == "high"
    assert first_finding.data['format'] == "H.264"

    last_finding = findings[-1]
    assert last_finding.category == "stream"
    assert last_finding.severity == "high"
    assert last_finding.data['format'] == "MJPEG"
