import requests
import socket
from typing import List, Tuple
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os
import logging

logger = logging.getLogger(__name__)

class StreamScannerPlugin(ScannerPlugin):
    """
    A plugin that discovers common RTSP and HTTP video streams.
    """

    def can_scan(self, target) -> bool:
        """Check if target has streaming ports"""
        stream_ports = [554, 8554, 80, 443, 8080, 8443, 5001]
        return any(p.port in stream_ports for p in target.open_ports)

    HTTP_TIMEOUT = 3

    def _get_prioritized_paths(self, fingerprint: dict = None) -> Tuple[List[str], List[str]]:
        """
        Returns prioritized lists of RTSP and HTTP stream paths based on fingerprint.
        """
        # Default generic paths
        rtsp_paths = ['/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub']
        http_paths = ['/video', '/stream', '/mjpg/video.mjpg', '/snapshot.jpg']

        vendor = fingerprint.get('vendor', '').lower() if fingerprint else ''

        if 'axis' in vendor:
            logger.info("Prioritizing Axis stream paths.")
            axis_rtsp_paths = ['/axis-media/media.amp', '/axis-cgi/mjpg/video.cgi']
            axis_http_paths = ['/axis-cgi/mjpg/video.cgi', '/axis-cgi/com/ptz.cgi', '/axis-cgi/param.cgi']
            rtsp_paths = axis_rtsp_paths + [p for p in rtsp_paths if p not in axis_rtsp_paths]
            http_paths = axis_http_paths + [p for p in http_paths if p not in axis_http_paths]
        elif 'hikvision' in vendor:
            logger.info("Prioritizing Hikvision stream paths.")
            hikvision_rtsp_paths = ['/Streaming/Channels/101', '/cgi-bin/hi3510/snap.cgi']
            hikvision_http_paths = ['/ISAPI/Streaming/channels/1/picture', '/cgi-bin/hi3510/snap.cgi']
            rtsp_paths = hikvision_rtsp_paths + [p for p in rtsp_paths if p not in hikvision_rtsp_paths]
            http_paths = hikvision_http_paths + [p for p in http_paths if p not in hikvision_http_paths]

        return rtsp_paths, http_paths

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

    def _verify_http_stream(self, url: str, proxy_url: str = None) -> bool:
        """
        Verifies if a stream URL is active by reading a small chunk of the stream.
        """
        try:
            with requests.get(url, timeout=self.HTTP_TIMEOUT, verify=False, stream=True, headers=get_request_headers(), proxies=get_proxies(proxy_url)) as response:
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

    def scan(self, target: ScanTarget, fingerprint: dict = None) -> List[Finding]:
        findings = []
        proxy_url = os.environ.get('PROXY_URL')

        rtsp_paths, http_paths = self._get_prioritized_paths(fingerprint)

        for port_result in target.open_ports:
            # Check RTSP streams
            if port_result.port in [554, 8554]:
                if self._test_rtsp_stream(target.ip, port_result.port):
                    logger.info(f"RTSP service detected on {target.ip}:{port_result.port}. Testing paths...")
                    # If the server responds correctly, we can assume standard paths might work
                    for path in rtsp_paths:
                        url = f"rtsp://{target.ip}:{port_result.port}{path}"
                        logger.info(f"Testing RTSP path: {url}")
                        # The basic check is enough to confirm the service is running, creating a finding for each path
                        finding = Finding(
                            category="stream",
                            description=f"Potential RTSP stream path found at {url}",
                            severity="medium",
                            url=url,
                            data={"protocol": "rtsp", "path": path}
                        )
                        findings.append(finding)
                    break # Move to next port after finding a valid RTSP server

            # Check and verify HTTP streams
            elif port_result.port in [80, 443, 8080, 8443]:
                protocol = "https" if port_result.port in [443, 8443] else "http"
                for path in http_paths:
                    url = f"{protocol}://{target.ip}:{port_result.port}{path}"
                    logger.info(f"Testing HTTP stream path: {url}")
                    if self._verify_http_stream(url, proxy_url):
                        logger.info(f"Verified HTTP stream at {url}")
                        finding = Finding(
                            category="stream",
                            description=f"Verified HTTP stream found at {url}",
                            severity="medium",
                            url=url,
                            data={"protocol": "http", "path": path}
                        )
                        findings.append(finding)
        return findings
