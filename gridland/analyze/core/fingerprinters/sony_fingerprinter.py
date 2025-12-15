"""
Sony Camera Fingerprinter for GRIDLAND v3.0

Implements Sony-specific device fingerprinting using Sony's proprietary
CGI endpoints and response patterns.

Key Endpoints:
- /command/inquiry.cgi?inq=system - System information
- /command/inquiry.cgi?inq=camera - Camera details
- /image.cgi - Image stream (reveals model in headers)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SonyDeviceInfo:
    """Sony device information extracted from fingerprinting."""

    brand: str = "sony"
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None
    product_id: str | None = None
    system_version: str | None = None
    confidence: float = 0.0
    raw_response: dict[str, Any] = field(default_factory=dict)


class SonyFingerprinter:
    """
    Sony camera fingerprinter using proprietary CGI endpoints.
    
    Sony cameras expose device information through specific CGI endpoints.
    This fingerprinter queries these endpoints and parses the responses
    to extract model, firmware, and other identifying information.
    
    Attributes:
        timeout: Request timeout in seconds.
        endpoints: List of fingerprinting endpoints to query.
        model_patterns: Regex patterns for model extraction.
    """

    def __init__(self, timeout: int = 10):
        """Initialize the Sony fingerprinter.
        
        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        
        # Sony-specific endpoints for fingerprinting
        self.endpoints = [
            "/command/inquiry.cgi?inq=system",
            "/command/inquiry.cgi?inq=camera",
            "/command/inquiry.cgi?inq=network",
            "/cgi-bin/view/getSysteminfo.cgi",
            "/System/configurationFile",
            "/oneshotimage.jpg",
        ]
        
        # Sony model patterns
        self.model_patterns = [
            re.compile(r"Model[:\s]*([A-Z]{3,4}[-]?[A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"SNC[-]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"IPE[LA][-]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"XNV[-]?([A-Z0-9]+)", re.IGNORECASE),
        ]
        
        # Firmware version patterns
        self.firmware_patterns = [
            re.compile(r"Version[:\s]*([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
            re.compile(r"Firmware[:\s]*([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
            re.compile(r"SoftwareVersion[:\s]*([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
        ]
        
        # Known Sony camera models
        self.known_models = {
            "SNC-CH110", "SNC-CH120", "SNC-CH140", "SNC-CH160",
            "SNC-CH210", "SNC-CH220", "SNC-CH240", "SNC-CH260",
            "SNC-DH110", "SNC-DH120", "SNC-DH140", "SNC-DH160",
            "SNC-EB600", "SNC-EB602R", "SNC-EB630", "SNC-EB632R",
            "SNC-VB600", "SNC-VB630", "SNC-VB632D",
            "SNC-VM600", "SNC-VM630", "SNC-VM631",
            "SNC-WR600", "SNC-WR602", "SNC-WR630",
            "SNC-XM631", "SNC-XM636", "SNC-XM637",
            "IPELA-PCS-XG80", "IPELA-PCS-XG100",
        }

    async def fingerprint(
        self, target_ip: str, target_port: int = 80, use_https: bool = False
    ) -> SonyDeviceInfo:
        """
        Perform comprehensive Sony device fingerprinting.
        
        Args:
            target_ip: Target IP address.
            target_port: Target port number.
            use_https: Whether to use HTTPS.
            
        Returns:
            SonyDeviceInfo with extracted device information.
        """
        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"
        
        info = SonyDeviceInfo()
        confidence_factors = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Query system inquiry endpoint
            system_data = await self._query_system_inquiry(session, base_url)
            if system_data:
                info.raw_response["system"] = system_data
                self._parse_system_response(system_data, info)
                confidence_factors.append(0.4)
            
            # Query camera inquiry endpoint
            camera_data = await self._query_camera_inquiry(session, base_url)
            if camera_data:
                info.raw_response["camera"] = camera_data
                self._parse_camera_response(camera_data, info)
                confidence_factors.append(0.3)
            
            # Check server headers
            header_data = await self._check_server_headers(session, base_url)
            if header_data.get("is_sony"):
                confidence_factors.append(0.2)
                if header_data.get("model"):
                    info.model = info.model or header_data["model"]
            
            # Check for Sony-specific paths
            paths_data = await self._check_sony_paths(session, base_url)
            if paths_data.get("sony_paths_found"):
                confidence_factors.append(0.1)
        
        # Calculate overall confidence
        info.confidence = min(1.0, sum(confidence_factors))
        
        # Validate model against known models
        if info.model:
            normalized = info.model.upper().replace(" ", "-")
            if any(normalized in m for m in self.known_models):
                info.confidence = min(1.0, info.confidence + 0.1)
        
        return info

    async def _query_system_inquiry(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any] | None:
        """
        Query Sony system inquiry endpoint.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Parsed system data or None.
        """
        url = f"{base_url}/command/inquiry.cgi?inq=system"
        
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    return self._parse_inquiry_response(text)
        except Exception as e:
            logger.debug(f"System inquiry failed for {base_url}: {e}")
        
        return None

    async def _query_camera_inquiry(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any] | None:
        """
        Query Sony camera inquiry endpoint.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Parsed camera data or None.
        """
        url = f"{base_url}/command/inquiry.cgi?inq=camera"
        
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    return self._parse_inquiry_response(text)
        except Exception as e:
            logger.debug(f"Camera inquiry failed for {base_url}: {e}")
        
        return None

    async def _check_server_headers(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any]:
        """
        Check HTTP headers for Sony indicators.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Dict with Sony header analysis results.
        """
        result = {"is_sony": False, "model": None}
        
        try:
            async with session.head(base_url) as response:
                server = response.headers.get("Server", "")
                if "sony" in server.lower() or "snc" in server.lower():
                    result["is_sony"] = True
                    # Try to extract model from server header
                    for pattern in self.model_patterns:
                        match = pattern.search(server)
                        if match:
                            result["model"] = match.group(1)
                            break
        except Exception as e:
            logger.debug(f"Header check failed for {base_url}: {e}")
        
        return result

    async def _check_sony_paths(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any]:
        """
        Check for Sony-specific paths.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Dict with path check results.
        """
        sony_paths = [
            "/command/inquiry.cgi",
            "/cgi-bin/view/getSysteminfo.cgi",
            "/image.cgi",
        ]
        
        result = {"sony_paths_found": False, "paths": []}
        
        for path in sony_paths:
            try:
                async with session.head(f"{base_url}{path}") as response:
                    if response.status in (200, 401, 403):
                        result["sony_paths_found"] = True
                        result["paths"].append(path)
            except Exception:
                pass
        
        return result

    def _parse_inquiry_response(self, text: str) -> dict[str, Any]:
        """
        Parse Sony inquiry CGI response.
        
        Sony responses are typically key=value pairs separated by newlines.
        
        Args:
            text: Raw response text.
            
        Returns:
            Parsed key-value dictionary.
        """
        result = {}
        
        for line in text.split("\n"):
            line = line.strip()
            if "=" in line:
                key, _, value = line.partition("=")
                result[key.strip()] = value.strip()
        
        return result

    def _parse_system_response(self, data: dict[str, Any], info: SonyDeviceInfo) -> None:
        """
        Parse system inquiry data into SonyDeviceInfo.
        
        Args:
            data: Parsed system data.
            info: SonyDeviceInfo to populate.
        """
        # Model extraction
        model_keys = ["Model", "ModelName", "ProductID", "model"]
        for key in model_keys:
            if key in data and data[key]:
                info.model = data[key]
                break
        
        # Firmware extraction
        fw_keys = ["Version", "FirmwareVersion", "SoftwareVersion", "version"]
        for key in fw_keys:
            if key in data and data[key]:
                info.firmware_version = data[key]
                break
        
        # Serial number
        serial_keys = ["SerialNumber", "Serial", "serial"]
        for key in serial_keys:
            if key in data and data[key]:
                info.serial_number = data[key]
                break
        
        # MAC address
        mac_keys = ["MacAddress", "MAC", "mac", "EthernetAddress"]
        for key in mac_keys:
            if key in data and data[key]:
                info.mac_address = data[key]
                break

    def _parse_camera_response(self, data: dict[str, Any], info: SonyDeviceInfo) -> None:
        """
        Parse camera inquiry data into SonyDeviceInfo.
        
        Args:
            data: Parsed camera data.
            info: SonyDeviceInfo to populate (fills in any missing fields).
        """
        # Fill in any missing model info
        if not info.model:
            for key in ["CameraModel", "Model", "Type"]:
                if key in data and data[key]:
                    info.model = data[key]
                    break
        
        # Product ID
        if "ProductID" in data:
            info.product_id = data["ProductID"]

    def is_sony_device(self, banner: str) -> bool:
        """
        Check if banner indicates a Sony device.
        
        Args:
            banner: HTTP/RTSP banner string.
            
        Returns:
            True if banner suggests Sony device.
        """
        sony_indicators = [
            "sony", "snc-", "ipela", "network camera",
            "/command/inquiry.cgi", "sony corporation",
        ]
        
        banner_lower = banner.lower()
        return any(indicator in banner_lower for indicator in sony_indicators)

    def extract_model_from_banner(self, banner: str) -> str | None:
        """
        Extract Sony model from banner.
        
        Args:
            banner: HTTP/RTSP banner string.
            
        Returns:
            Model string or None.
        """
        for pattern in self.model_patterns:
            match = pattern.search(banner)
            if match:
                return f"SNC-{match.group(1)}"
        return None

    def extract_firmware_from_banner(self, banner: str) -> str | None:
        """
        Extract firmware version from banner.
        
        Args:
            banner: HTTP/RTSP banner string.
            
        Returns:
            Firmware version or None.
        """
        for pattern in self.firmware_patterns:
            match = pattern.search(banner)
            if match:
                return match.group(1)
        return None


# Convenience function for quick fingerprinting
async def fingerprint_sony(
    target_ip: str, target_port: int = 80, use_https: bool = False
) -> SonyDeviceInfo:
    """Quick Sony device fingerprinting.
    
    Args:
        target_ip: Target IP address.
        target_port: Target port.
        use_https: Whether to use HTTPS.
        
    Returns:
        SonyDeviceInfo with fingerprint results.
    """
    fingerprinter = SonyFingerprinter()
    return await fingerprinter.fingerprint(target_ip, target_port, use_https)
