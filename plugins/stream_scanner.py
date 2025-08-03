import requests
import socket
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.http import create_secure_session
import os

class StreamScannerPlugin(ScannerPlugin):
    """
    A plugin that discovers common RTSP and HTTP video streams.
    """
    
    def can_scan(self, target) -> bool:
        """Check if target has streaming ports"""
        stream_ports = [554, 8554, 80, 443, 8080, 8443, 5001]
        return any(p.port in stream_ports for p in target.open_ports)

    RTSP_PATHS = ['/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub']
    HTTP_PATHS = ['/video', '/stream', '/mjpg/video.mjpg', '/snapshot.jpg']
    HTTP_TIMEOUT = 3

    def _test_rtsp_stream(self, ip: str, port: int) -> bool:
        """
        Tests for a valid RTSP stream by sending an OPTIONS request.
        Returns True only if the server responds with RTSP/1.0 200 OK.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.HTTP_TIMEOUT)
                sock.connect((ip, port))

                # Send RTSP OPTIONS request
                rtsp_request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.sendall(rtsp_request.encode('utf-8'))

                # Read response
                response = sock.recv(1024).decode('utf-8', errors='ignore')

                # Check for a valid RTSP 200 OK response
                return "RTSP/1.0 200 OK" in response

        except (socket.error, socket.timeout):
            return False

    def _verify_http_stream(self, session: requests.Session, url: str) -> bool:
        """
        Verifies if a stream URL is active by reading a small chunk of the stream.
        """
        try:
            with session.get(url, timeout=self.HTTP_TIMEOUT, verify=False, stream=True) as response:
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'video' in content_type or 'image' in content_type:
                        # Attempt to read the first chunk to confirm it's a real stream
                        try:
                            next(response.iter_content(chunk_size=1024))
                            return True
                        except (requests.exceptions.ChunkedEncodingError, StopIteration):
                            # This can happen on empty or malformed streams, not a valid stream.
                            return False
        except requests.RequestException:
            return False
        return False

    def scan(self, target: ScanTarget) -> List[Finding]:
        findings = []
        proxy_url = os.environ.get('PROXY_URL')
        session = create_secure_session(proxy_url)

        try:
            for port_result in target.open_ports:
                # Check RTSP streams
                if port_result.port in [554, 8554]:
                    if self._test_rtsp_stream(target.ip, port_result.port):
                        # If the server responds correctly, we can assume standard paths might work
                        for path in self.RTSP_PATHS:
                            url = f"rtsp://{target.ip}:{port_result.port}{path}"
                            finding = Finding(
                                category="stream",
                                description=f"Verified RTSP service at {url}",
                                severity="medium",
                                url=url,
                                data={"protocol": "rtsp", "path": path}
                            )
                            findings.append(finding)
                        break # Move to next port after finding a valid RTSP server

                # Check and verify HTTP streams
                elif port_result.port in [80, 443, 8080, 8443]:
                    protocol = "https" if port_result.port in [443, 8443] else "http"
                    for path in self.HTTP_PATHS:
                        url = f"{protocol}://{target.ip}:{port_result.port}{path}"
                        if self._verify_http_stream(session, url):
                            finding = Finding(
                                category="stream",
                                description=f"Verified HTTP stream found at {url}",
                                severity="medium",
                                url=url,
                                data={"protocol": "http", "path": path}
                            )
                            findings.append(finding)
        finally:
            session.close()

        return findings
