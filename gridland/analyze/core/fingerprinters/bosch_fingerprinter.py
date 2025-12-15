"""
Bosch Camera Fingerprinter for GRIDLAND v3.0

Implements Bosch-specific device fingerprinting using Bosch's RCP
(Remote Control Protocol) endpoints and XML response patterns.

Key Endpoints:
- /rcp.xml?command=0x0a10 - Device info (model, serial)
- /rcp.xml?command=0x0a00 - System info
- /rcp.xml?command=0x093b - Firmware version
- /bvip/info.cgi - BVIP system info
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class BoschDeviceInfo:
    """Bosch device information extracted from fingerprinting."""

    brand: str = "bosch"
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None
    hardware_version: str | None = None
    product_name: str | None = None
    device_type: str | None = None
    confidence: float = 0.0
    raw_response: dict[str, Any] = field(default_factory=dict)


class BoschFingerprinter:
    """
    Bosch camera fingerprinter using RCP (Remote Control Protocol).
    
    Bosch cameras expose device information through their proprietary
    RCP protocol via XML endpoints. This fingerprinter queries these
    endpoints and parses the XML responses.
    
    Attributes:
        timeout: Request timeout in seconds.
        rcp_commands: Dictionary of RCP command codes to names.
        model_patterns: Regex patterns for model extraction.
    """

    def __init__(self, timeout: int = 10):
        """Initialize the Bosch fingerprinter.
        
        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        
        # RCP command codes
        self.rcp_commands = {
            "device_info": "0x0a10",
            "system_info": "0x0a00",
            "firmware_version": "0x093b",
            "unit_name": "0x0100",
            "mac_address": "0x0901",
        }
        
        # Fingerprinting endpoints
        self.endpoints = [
            "/rcp.xml?command=0x0a10",
            "/rcp.xml?command=0x0a00",
            "/bvip/info.cgi",
            "/system/info.cgi",
            "/cgi-bin/viewer/getparam.cgi",
        ]
        
        # Bosch model patterns
        self.model_patterns = [
            re.compile(r"NBN[-_]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"NIN[-_]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"NII[-_]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"NDE[-_]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"NDN[-_]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"NEZ[-_]?([A-Z0-9]+)", re.IGNORECASE),
            re.compile(r"FLEXIDOME", re.IGNORECASE),
            re.compile(r"DINION", re.IGNORECASE),
            re.compile(r"AUTODOME", re.IGNORECASE),
        ]
        
        # Firmware version patterns
        self.firmware_patterns = [
            re.compile(r"FirmwareVersion[:\s]*([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
            re.compile(r"Version[:\s]*([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
            re.compile(r"SWVersion[:\s]*([0-9]+\.[0-9]+\.?[0-9]*)", re.IGNORECASE),
        ]
        
        # Known Bosch camera models
        self.known_models = {
            # FLEXIDOME series
            "FLEXIDOME IP 4000i", "FLEXIDOME IP 5000i", "FLEXIDOME IP 6000",
            "FLEXIDOME IP outdoor 4000 HD", "FLEXIDOME IP panoramic 7000",
            # DINION series
            "DINION IP bullet 4000", "DINION IP bullet 5000",
            "DINION IP 4000 HD", "DINION IP 5000 HD", "DINION IP 7000 HD",
            "DINION IP starlight 6000 HD", "DINION IP starlight 7000 HD",
            # AUTODOME series
            "AUTODOME IP 4000i", "AUTODOME IP 5000i",
            "AUTODOME IP starlight 5000i",
            # NBN/NIN/NDE models
            "NBN-40012-V3", "NBN-50022-V3", "NBN-73013-BA",
            "NIN-70122-F0", "NIN-73023-A10",
            "NDE-3502-AL", "NDE-3512-AL", "NDN-265-PIO",
        }

    async def fingerprint(
        self, target_ip: str, target_port: int = 80, use_https: bool = False
    ) -> BoschDeviceInfo:
        """
        Perform comprehensive Bosch device fingerprinting.
        
        Args:
            target_ip: Target IP address.
            target_port: Target port number.
            use_https: Whether to use HTTPS.
            
        Returns:
            BoschDeviceInfo with extracted device information.
        """
        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"
        
        info = BoschDeviceInfo()
        confidence_factors = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            # Query device info RCP command
            device_data = await self._query_rcp_device_info(session, base_url)
            if device_data:
                info.raw_response["device_info"] = device_data
                self._parse_rcp_device_info(device_data, info)
                confidence_factors.append(0.5)
            
            # Query BVIP info
            bvip_data = await self._query_bvip_info(session, base_url)
            if bvip_data:
                info.raw_response["bvip_info"] = bvip_data
                self._parse_bvip_info(bvip_data, info)
                confidence_factors.append(0.3)
            
            # Check server headers
            header_data = await self._check_server_headers(session, base_url)
            if header_data.get("is_bosch"):
                confidence_factors.append(0.1)
                if header_data.get("model"):
                    info.model = info.model or header_data["model"]
            
            # Check for Bosch-specific paths
            paths_data = await self._check_bosch_paths(session, base_url)
            if paths_data.get("bosch_paths_found"):
                confidence_factors.append(0.1)
        
        # Calculate overall confidence
        info.confidence = min(1.0, sum(confidence_factors))
        
        return info

    async def _query_rcp_device_info(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any] | None:
        """
        Query Bosch RCP device info endpoint.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Parsed XML data or None.
        """
        url = f"{base_url}/rcp.xml?command=0x0a10"
        
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    return self._parse_rcp_xml(text)
        except Exception as e:
            logger.debug(f"RCP device info failed for {base_url}: {e}")
        
        return None

    async def _query_bvip_info(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any] | None:
        """
        Query Bosch BVIP info endpoint.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Parsed data or None.
        """
        url = f"{base_url}/bvip/info.cgi"
        
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    return self._parse_bvip_response(text)
        except Exception as e:
            logger.debug(f"BVIP info failed for {base_url}: {e}")
        
        return None

    async def _check_server_headers(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any]:
        """
        Check HTTP headers for Bosch indicators.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Dict with Bosch header analysis results.
        """
        result = {"is_bosch": False, "model": None}
        
        try:
            async with session.head(base_url) as response:
                server = response.headers.get("Server", "")
                if "bosch" in server.lower() or "bvip" in server.lower():
                    result["is_bosch"] = True
                    for pattern in self.model_patterns:
                        match = pattern.search(server)
                        if match:
                            result["model"] = match.group(0)
                            break
        except Exception as e:
            logger.debug(f"Header check failed for {base_url}: {e}")
        
        return result

    async def _check_bosch_paths(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> dict[str, Any]:
        """
        Check for Bosch-specific paths.
        
        Args:
            session: aiohttp session.
            base_url: Base URL for requests.
            
        Returns:
            Dict with path check results.
        """
        bosch_paths = [
            "/rcp.xml",
            "/bvip/info.cgi",
            "/cgi-bin/viewer/getparam.cgi",
        ]
        
        result = {"bosch_paths_found": False, "paths": []}
        
        for path in bosch_paths:
            try:
                async with session.head(f"{base_url}{path}") as response:
                    if response.status in (200, 401, 403):
                        result["bosch_paths_found"] = True
                        result["paths"].append(path)
            except Exception:
                pass
        
        return result

    def _parse_rcp_xml(self, text: str) -> dict[str, Any]:
        """
        Parse Bosch RCP XML response.
        
        Args:
            text: Raw XML response text.
            
        Returns:
            Parsed data dictionary.
        """
        result = {}
        
        try:
            root = ET.fromstring(text)
            
            # Extract all child elements
            for child in root.iter():
                if child.text and child.text.strip():
                    result[child.tag] = child.text.strip()
                
                # Also check attributes
                for attr, value in child.attrib.items():
                    result[f"{child.tag}_{attr}"] = value
        except ET.ParseError:
            # Fall back to regex extraction
            result = self._regex_extract_from_xml(text)
        
        return result

    def _regex_extract_from_xml(self, text: str) -> dict[str, Any]:
        """
        Fallback regex extraction from malformed XML.
        
        Args:
            text: Raw text to parse.
            
        Returns:
            Extracted key-value pairs.
        """
        result = {}
        
        # Common tag patterns
        patterns = [
            (r"<model>([^<]+)</model>", "model"),
            (r"<serial>([^<]+)</serial>", "serial"),
            (r"<version>([^<]+)</version>", "version"),
            (r"<firmware>([^<]+)</firmware>", "firmware"),
            (r"<mac>([^<]+)</mac>", "mac"),
            (r"<hardware>([^<]+)</hardware>", "hardware"),
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                result[key] = match.group(1)
        
        return result

    def _parse_bvip_response(self, text: str) -> dict[str, Any]:
        """
        Parse Bosch BVIP info response.
        
        BVIP responses are typically key=value pairs.
        
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
            elif ":" in line:
                key, _, value = line.partition(":")
                result[key.strip()] = value.strip()
        
        return result

    def _parse_rcp_device_info(self, data: dict[str, Any], info: BoschDeviceInfo) -> None:
        """
        Parse RCP device info into BoschDeviceInfo.
        
        Args:
            data: Parsed RCP data.
            info: BoschDeviceInfo to populate.
        """
        # Model extraction
        model_keys = ["model", "Model", "ProductName", "DeviceType", "product"]
        for key in model_keys:
            if key in data and data[key]:
                info.model = data[key]
                break
        
        # Firmware extraction
        fw_keys = ["firmware", "version", "Version", "FirmwareVersion", "SWVersion"]
        for key in fw_keys:
            if key in data and data[key]:
                info.firmware_version = data[key]
                break
        
        # Serial number
        serial_keys = ["serial", "Serial", "SerialNumber", "serialnumber"]
        for key in serial_keys:
            if key in data and data[key]:
                info.serial_number = data[key]
                break
        
        # MAC address
        mac_keys = ["mac", "MAC", "MacAddress", "macaddress"]
        for key in mac_keys:
            if key in data and data[key]:
                info.mac_address = data[key]
                break
        
        # Hardware version
        hw_keys = ["hardware", "Hardware", "HWVersion", "HardwareVersion"]
        for key in hw_keys:
            if key in data and data[key]:
                info.hardware_version = data[key]
                break

    def _parse_bvip_info(self, data: dict[str, Any], info: BoschDeviceInfo) -> None:
        """
        Parse BVIP info into BoschDeviceInfo.
        
        Args:
            data: Parsed BVIP data.
            info: BoschDeviceInfo to populate.
        """
        # Fill in any missing fields
        if not info.model and "ProductName" in data:
            info.model = data["ProductName"]
        
        if not info.product_name and "ProductName" in data:
            info.product_name = data["ProductName"]
        
        if not info.device_type and "DeviceType" in data:
            info.device_type = data["DeviceType"]

    def is_bosch_device(self, banner: str) -> bool:
        """
        Check if banner indicates a Bosch device.
        
        Args:
            banner: HTTP/RTSP banner string.
            
        Returns:
            True if banner suggests Bosch device.
        """
        bosch_indicators = [
            "bosch", "bvip", "rcp.xml", "flexidome", "dinion",
            "autodome", "nbn-", "nin-", "nde-", "ndn-",
        ]
        
        banner_lower = banner.lower()
        return any(indicator in banner_lower for indicator in bosch_indicators)

    def extract_model_from_banner(self, banner: str) -> str | None:
        """
        Extract Bosch model from banner.
        
        Args:
            banner: HTTP/RTSP banner string.
            
        Returns:
            Model string or None.
        """
        for pattern in self.model_patterns:
            match = pattern.search(banner)
            if match:
                return match.group(0)
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
async def fingerprint_bosch(
    target_ip: str, target_port: int = 80, use_https: bool = False
) -> BoschDeviceInfo:
    """Quick Bosch device fingerprinting.
    
    Args:
        target_ip: Target IP address.
        target_port: Target port.
        use_https: Whether to use HTTPS.
        
    Returns:
        BoschDeviceInfo with fingerprint results.
    """
    fingerprinter = BoschFingerprinter()
    return await fingerprinter.fingerprint(target_ip, target_port, use_https)
