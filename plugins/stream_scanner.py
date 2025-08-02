import requests
import socket
from typing import List, Optional
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

    RTSP_PATHS = [
        # Generic paths from CamXploit
        '/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub',
        '/video', '/cam/realmonitor', '/Streaming/Channels/1', '/Streaming/Channels/101',
        # Brand-specific paths from CamXploit
        '/onvif/streaming/channels/1', '/axis-media/media.amp', '/axis-cgi/mjpg/video.cgi',
        '/cgi-bin/mjpg/video.cgi', '/cgi-bin/hi3510/snap.cgi', '/cgi-bin/snapshot.cgi',
        '/cgi-bin/viewer/video.jpg', '/img/snapshot.cgi', '/snapshot.jpg',
        '/video/mjpg.cgi', '/video.cgi', '/videostream.cgi', '/mjpg/video.mjpg',
        '/mjpg.cgi', '/stream.cgi', '/live.cgi', '/live/0/onvif.sdp',
        '/live/0/h264.sdp', '/live/0/mpeg4.sdp', '/live/0/audio.sdp',
        '/live/1/onvif.sdp', '/live/1/h264.sdp', '/live/1/mpeg4.sdp',
        '/live/1/audio.sdp'
    ]
    HTTP_PATHS = [
        # Generic paths from CamXploit
        '/video', '/stream', '/mjpg/video.mjpg', '/cgi-bin/mjpg/video.cgi',
        '/axis-cgi/mjpg/video.cgi', '/cgi-bin/viewer/video.jpg', '/snapshot.jpg',
        '/img/snapshot.cgi',
        # Brand-specific paths from CamXploit
        '/onvif/device_service', '/onvif/streaming', '/axis-cgi/com/ptz.cgi',
        '/axis-cgi/param.cgi', '/cgi-bin/snapshot.cgi', '/cgi-bin/hi3510/snap.cgi',
        '/video/mjpg.cgi', '/video.cgi', '/videostream.cgi', '/mjpg.cgi',
        '/stream.cgi', '/live.cgi',
        # Additional paths from CamXploit
        '/api/video', '/api/stream', '/api/live', '/api/video/live',
        '/api/stream/live', '/api/camera/live', '/api/camera/stream',
        '/api/camera/video', '/api/camera/snapshot', '/api/camera/image',
        '/api/camera/feed', '/api/camera/feed/live', '/api/camera/feed/stream',
        '/api/camera/feed/video',
        # CP Plus specific paths from CamXploit
        '/cgi-bin/video.cgi', '/cgi-bin/stream.cgi', '/cgi-bin/live.cgi'
    ]
    HTTP_TIMEOUT = 3

    def _verify_rtsp_stream(self, url: str) -> Optional[str]:
        """
        Verifies an RTSP stream by sending a DESCRIBE request.
        Returns the stream format if successful, otherwise None.
        """
        try:
            # Extract host and port from URL
            parsed_url = requests.utils.urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or 554

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.HTTP_TIMEOUT)
            sock.connect((host, port))

            # Send RTSP DESCRIBE request
            request = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Gridland Stream Verifier\r\n\r\n"
            sock.send(request.encode())

            response = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()

            if "RTSP/1.0 200 OK" in response and "Content-Type: application/sdp" in response:
                # Basic format detection from SDP
                if "m=video" in response:
                    if "H264" in response.upper():
                        return "H.264"
                    if "MJPEG" in response.upper():
                        return "MJPEG"
                    return "Unknown Video"
        except (socket.error, IndexError):
            return None
        return None

    def _verify_http_stream(self, url: str) -> Optional[str]:
        """
        Verifies an HTTP stream by checking headers and content.
        Returns the stream format if successful, otherwise None.
        """
        try:
            response = requests.get(url, timeout=self.HTTP_TIMEOUT, verify=False, stream=True)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if any(x in content_type for x in ['video', 'image', 'mjpeg']):
                    # Read a small chunk to confirm it's not an error page
                    first_chunk = next(response.iter_content(chunk_size=512), None)
                    if first_chunk and b'login' not in first_chunk.lower():
                        if 'mjpeg' in content_type:
                            return 'MJPEG'
                        if 'h264' in content_type:
                            return 'H.264'
                        return "Unknown Video"
        except requests.RequestException:
            return None
        return None

    def scan(self, target: ScanTarget, progress_callback=None) -> List[Finding]:
        findings = []

        # Create a combined list of all potential stream URLs to test
        urls_to_test = []
        for port_result in target.open_ports:
            if port_result.port in [554, 8554]:
                for path in self.RTSP_PATHS:
                    urls_to_test.append(f"rtsp://{target.ip}:{port_result.port}{path}")
            elif port_result.port in [80, 443, 8080, 8443]:
                protocol = "https" if port_result.port in [443, 8443] else "http"
                for path in self.HTTP_PATHS:
                    urls_to_test.append(f"{protocol}://{target.ip}:{port_result.port}{path}")

        # Scan all potential URLs
        for i, url in enumerate(urls_to_test):
            if progress_callback:
                progress = (i / len(urls_to_test)) * 100
                progress_callback(self.name, progress, f"Verifying stream {i+1}/{len(urls_to_test)}")

            stream_format = None
            protocol = "unknown"
            if url.startswith('rtsp://'):
                stream_format = self._verify_rtsp_stream(url)
                protocol = "rtsp"
            elif url.startswith('http'):
                stream_format = self._verify_http_stream(url)
                protocol = "http"

            if stream_format:
                finding = Finding(
                    category="stream",
                    description=f"Verified {stream_format} stream found at {url}",
                    severity="high", # Verified streams are high severity
                    url=url,
                    data={"protocol": protocol, "format": stream_format}
                )
                findings.append(finding)

        return findings
