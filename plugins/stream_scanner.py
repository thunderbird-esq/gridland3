import requests
import socket
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget

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
        """Tests for a listening socket on an RTSP port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.HTTP_TIMEOUT)
                sock.connect((ip, port))
                return True
        except socket.error:
            return False

    def _test_http_stream(self, url: str) -> bool:
        """Tests an HTTP URL for a valid video/image content type."""
        try:
            response = requests.head(url, timeout=self.HTTP_TIMEOUT, verify=False)
            content_type = response.headers.get('Content-Type', '').lower()
            return response.status_code == 200 and any(x in content_type for x in ['video', 'image', 'mjpeg'])
        except requests.RequestException:
            return False

    def scan(self, target: ScanTarget) -> List[Finding]:
        findings = []
        for port_result in target.open_ports:
            # Check RTSP streams
            if port_result.port in [554, 8554]:
                if self._test_rtsp_stream(target.ip, port_result.port):
                    for path in self.RTSP_PATHS:
                        url = f"rtsp://{target.ip}:{port_result.port}{path}"
                        # For RTSP, we assume any path on an open port is a potential stream
                        finding = Finding(
                            category="stream",
                            description=f"Potential RTSP stream found at {url}",
                            severity="medium",
                            url=url,
                            data={"protocol": "rtsp", "path": path}
                        )
                        findings.append(finding)
                    # NO break here. Let the loop continue to the elif.

            # Check HTTP streams
            elif port_result.port in [80, 443, 8080, 8443]:
                protocol = "https" if port_result.port in [443, 8443] else "http"
                for path in self.HTTP_PATHS:
                    url = f"{protocol}://{target.ip}:{port_result.port}{path}"
                    if self._test_http_stream(url):
                        finding = Finding(
                            category="stream",
                            description=f"Potential HTTP stream found at {url}",
                            severity="medium",
                            url=url,
                            data={"protocol": "http", "path": path}
                        )
                        findings.append(finding)
        return findings
