"""
Device identification functions for Gridland
"""
import requests
import re
from typing import List, Tuple, Optional
from .core import PortResult, ScanTarget


# Disable SSL warnings for embedded devices
import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


def identify_device(ip: str, open_ports: List[PortResult], timeout: float = 5.0) -> Tuple[Optional[str], Optional[str]]:
    """
    Attempt to identify device type and brand based on HTTP responses
    
    Args:
        ip: Target IP address
        open_ports: List of open ports to check
        timeout: HTTP request timeout
        
    Returns:
        Tuple[device_type, brand]: Device type and brand if identified
    """
    device_type = None
    brand = None
    
    # Try HTTP ports first
    http_ports = [p for p in open_ports if p.port in [80, 8080, 8081, 8082, 8083, 8084, 8085, 8000, 8001]]
    
    for port_result in http_ports:
        port = port_result.port
        
        try:
            # Try HTTP first
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            device_type, brand = _analyze_response(response, ip, port)
            if device_type:
                return device_type, brand
                
        except requests.exceptions.RequestException:
            # Try HTTPS if HTTP fails
            try:
                url = f"https://{ip}:{port}"
                response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
                
                device_type, brand = _analyze_response(response, ip, port)
                if device_type:
                    return device_type, brand
                    
            except requests.exceptions.RequestException:
                continue
    
    # If no HTTP identification, check RTSP ports
    rtsp_ports = [p for p in open_ports if p.port in [554, 8554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554]]
    if rtsp_ports:
        # If RTSP is available, likely a camera
        device_type = "IP Camera"
    
    return device_type, brand


def _analyze_response(response: requests.Response, ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
    """
    Analyze HTTP response to identify device type and brand
    
    Args:
        response: HTTP response object
        ip: Target IP
        port: Target port
        
    Returns:
        Tuple[device_type, brand]: Identified device info
    """
    content = response.text.lower()
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    
    # Check headers first
    server_header = headers.get('server', '')
    www_auth = headers.get('www-authenticate', '')
    
    # Hikvision detection
    if 'hikvision' in server_header or 'hik' in server_header or any(x in content for x in ['hikvision', 'hik-connect', 'ivms', 'dss', 'isapi']):
        return "IP Camera", "Hikvision"
    
    # Dahua detection
    if 'dahua' in server_header or any(x in content for x in ['dahua', 'dss', 'smartpss', 'web service']):
        return "IP Camera", "Dahua"
    
    # Axis detection
    if 'axis' in server_header or any(x in content for x in ['axis', 'vapix', 'axis communications']):
        return "IP Camera", "Axis"

    # CP Plus detection (from CamXploit)
    if any(x in content for x in ['cp plus', 'cp-plus', 'cpplus', 'cp_plus', 'uvr', '0401e1']):
        return "IP Camera", "CP Plus"
    
    # Sony detection
    if any(x in content for x in ['sony', 'snc-', 'sony network camera']):
        return "IP Camera", "Sony"
    if 'sony' in server_header:
        return "IP Camera", "Sony"
    
    # Bosch detection
    if any(x in content for x in ['bosch', 'rcp+', 'video security']):
        return "IP Camera", "Bosch"
    if 'bosch' in server_header:
        return "IP Camera", "Bosch"
    
    # Panasonic detection
    if any(x in content for x in ['panasonic', 'wv-', 'network camera']):
        return "IP Camera", "Panasonic"
    if 'panasonic' in server_header:
        return "IP Camera", "Panasonic"
    
    # Canon detection
    if any(x in content for x in ['canon', 'vb-', 'network camera']):
        return "IP Camera", "Canon"
    if 'canon' in server_header:
        return "IP Camera", "Canon"
    
    # FLIR detection
    if any(x in content for x in ['flir', 'thermal', 'fc-']):
        return "IP Camera", "FLIR"
    if 'flir' in server_header:
        return "IP Camera", "FLIR"
    
    # Generic camera detection
    if any(x in content for x in [
        'network camera', 'ip camera', 'webcam', 'cctv', 'surveillance',
        'video', 'stream', 'rtsp', 'onvif', 'ptz', 'dome camera'
    ]):
        return "IP Camera", "Generic"
    
    # DVR/NVR detection
    if any(x in content for x in [
        'dvr', 'nvr', 'digital video recorder', 'network video recorder',
        'surveillance system', 'security system'
    ]):
        return "DVR/NVR", "Generic"
    
    # Router detection
    if any(x in content for x in [
        'router', 'gateway', 'wifi', 'wireless', 'broadband',
        'dsl', 'modem', 'access point'
    ]):
        return "Router", "Generic"
    
    # Check if it responds to common camera URLs
    if _check_camera_endpoints(ip, port):
        return "IP Camera", "Generic"
    
    return None, None


def _check_camera_endpoints(ip: str, port: int, timeout: float = 3.0) -> bool:
    """
    Check for common camera endpoints
    
    Args:
        ip: Target IP
        port: Target port
        timeout: Request timeout
        
    Returns:
        bool: True if camera endpoints are found
    """
    camera_endpoints = [
        '/video.cgi',
        '/video/stream',
        '/axis-cgi/mjpg/video.cgi',
        '/videostream.cgi',
        '/onvif/device_service',
        '/ISAPI/System/deviceInfo',
        '/cgi-bin/hi3510/snap.cgi',
        '/dms?nowprofileid=1',
        '/video.mjpg'
    ]
    
    for endpoint in camera_endpoints:
        try:
            url = f"http://{ip}:{port}{endpoint}"
            response = requests.get(url, timeout=timeout, verify=False)
            
            # Check for camera-specific responses
            if response.status_code in [200, 401, 403]:
                content_type = response.headers.get('content-type', '').lower()
                if any(x in content_type for x in ['video', 'image', 'mjpeg']):
                    return True
                
                # Check for authentication challenges typical of cameras
                if response.status_code == 401:
                    auth_header = response.headers.get('www-authenticate', '').lower()
                    if any(x in auth_header for x in ['digest', 'basic']):
                        return True
        
        except requests.exceptions.RequestException:
            continue
    
    return False


def get_device_details(target: ScanTarget) -> Tuple[Optional[str], Optional[str]]:
    """
    Get detailed device model and firmware if available by checking common endpoints.
    """
    model, firmware = None, None
    
    info_endpoints = [
        '/ISAPI/System/deviceInfo',
        '/onvif/device_service',
        '/cgi-bin/hi3510/param.cgi?cmd=getserverinfo',
        '/api/system/device_info',
        '/system_info.cgi',
        '/axis-cgi/admin/param.cgi?action=list'
    ]
    
    http_ports = [p.port for p in target.open_ports if p.port in [80, 8080, 443, 8443]]

    for port in http_ports:
        protocol = "https" if port in [443, 8443] else "http"
        for endpoint in info_endpoints:
            try:
                url = f"{protocol}://{target.ip}:{port}{endpoint}"
                response = requests.get(url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    content = response.text

                    # Regex patterns for model and firmware
                    model_patterns = [
                        r'<model[^>]*>([^<]+)</model>', r'"model"\s*:\s*"([^"]+)"',
                        r'Model\s*:\s*([^\r\n]+)', r'root\.Brand\.ProdShortName=([^\r\n]+)'
                    ]
                    fw_patterns = [
                        r'<firmwareVersion[^>]*>([^<]+)</firmwareVersion>',
                        r'"firmware"\s*:\s*"([^"]+)"', r'Firmware\s*:\s*([^\r\n]+)',
                        r'root\.Brand\.FirmwareVersion=([^\r\n]+)'
                    ]

                    if not model:
                        for pattern in model_patterns:
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                model = match.group(1).strip().replace('"', '')
                                break

                    if not firmware:
                        for pattern in fw_patterns:
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                firmware = match.group(1).strip().replace('"', '')
                                break
                
                if model and firmware:
                    return model, firmware
            except requests.exceptions.RequestException:
                continue
                
    return model, firmware