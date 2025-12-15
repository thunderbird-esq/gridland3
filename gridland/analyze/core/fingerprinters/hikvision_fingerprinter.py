"""
Hikvision Camera Fingerprinter

Comprehensive device fingerprinting for Hikvision IP cameras including:
- ISAPI endpoint queries
- SDK endpoint queries  
- Model/firmware extraction
- Device capability detection
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class HikvisionFingerprint:
    """Fingerprint data for Hikvision devices."""
    
    brand: str = "hikvision"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""
    hardware_version: str = ""
    encoder_version: str = ""
    boot_version: str = ""
    device_id: str = ""
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class HikvisionFingerprinter:
    """Fingerprinter for Hikvision IP cameras and NVRs."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # ISAPI endpoints for device info
        self.isapi_endpoints = {
            "deviceInfo": "/ISAPI/System/deviceInfo",
            "capabilities": "/ISAPI/System/capabilities",
            "networkInterface": "/ISAPI/System/Network/interfaces",
            "time": "/ISAPI/System/time",
            "streaming": "/ISAPI/Streaming/channels",
            "users": "/ISAPI/Security/users",
        }
        
        # SDK/CGI endpoints for legacy devices
        self.sdk_endpoints = {
            "configFile": "/System/configurationFile",
            "deviceConfig": "/PSIA/System/deviceInfo",
            "sysConfig": "/cgi-bin/configManager.cgi?action=getConfig&name=General",
        }

    async def _init_session(self) -> None:
        """Initialize HTTP session."""
        if not self.session:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers={"User-Agent": "GRIDLAND Scanner/3.0"},
            )

    async def _cleanup_session(self) -> None:
        """Cleanup HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None

    async def fingerprint(
        self,
        ip: str,
        port: int,
        username: str = "",
        password: str = "",
    ) -> HikvisionFingerprint:
        """
        Perform comprehensive Hikvision device fingerprinting.
        
        Args:
            ip: Target IP address
            port: Target port
            username: Optional username for authenticated requests
            password: Optional password for authenticated requests
            
        Returns:
            HikvisionFingerprint with device details
        """
        fingerprint = HikvisionFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try ISAPI device info (primary method)
            device_info = await self._query_isapi_device_info(base_url, auth)
            if device_info:
                fingerprint.model = device_info.get("model", "")
                fingerprint.firmware_version = device_info.get("firmwareVersion", "")
                fingerprint.serial_number = device_info.get("serialNumber", "")
                fingerprint.mac_address = device_info.get("macAddress", "")
                fingerprint.device_type = device_info.get("deviceType", "")
                fingerprint.hardware_version = device_info.get("hardwareVersion", "")
                fingerprint.encoder_version = device_info.get("encoderVersion", "")
                fingerprint.boot_version = device_info.get("bootVersion", "")
                fingerprint.device_id = device_info.get("deviceID", "")
                fingerprint.detection_methods.append("isapi_deviceinfo")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["isapi_deviceinfo"] = device_info
            
            # Try SDK/CGI endpoints (fallback)
            if not fingerprint.model:
                sdk_info = await self._query_sdk_endpoints(base_url, auth)
                if sdk_info:
                    fingerprint.model = sdk_info.get("model", "")
                    fingerprint.firmware_version = sdk_info.get("version", "")
                    fingerprint.serial_number = sdk_info.get("serialNumber", "")
                    fingerprint.detection_methods.append("sdk_endpoints")
                    fingerprint.confidence = max(fingerprint.confidence, 0.80)
                    fingerprint.raw_data["sdk_info"] = sdk_info
            
            # Try capability detection
            capabilities = await self._query_capabilities(base_url, auth)
            if capabilities:
                fingerprint.detection_methods.append("capabilities")
                fingerprint.raw_data["capabilities"] = capabilities
                fingerprint.confidence = max(fingerprint.confidence, 0.75)
            
        except Exception as e:
            logger.debug(f"Hikvision fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_isapi_device_info(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query ISAPI deviceInfo endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.isapi_endpoints['deviceInfo']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_isapi_xml(content)
        except Exception as e:
            logger.debug(f"ISAPI query error: {e}")
        
        return result

    async def _query_sdk_endpoints(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query SDK/CGI endpoints for device info."""
        result = {}
        
        for name, endpoint in self.sdk_endpoints.items():
            try:
                url = f"{base_url}{endpoint}"
                async with self.session.get(url, auth=auth) as response:
                    if response.status == 200:
                        content = await response.text()
                        parsed = self._parse_sdk_response(content)
                        result.update(parsed)
                        break
            except Exception:
                continue
        
        return result

    async def _query_capabilities(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, Any]:
        """Query device capabilities."""
        result = {}
        
        try:
            url = f"{base_url}{self.isapi_endpoints['capabilities']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_capabilities_xml(content)
        except Exception as e:
            logger.debug(f"Capabilities query error: {e}")
        
        return result

    def _parse_isapi_xml(self, content: str) -> dict[str, str]:
        """Parse ISAPI XML response."""
        result = {}
        
        try:
            # Remove namespace for simpler parsing
            content = re.sub(r'xmlns="[^"]+"', '', content)
            root = ElementTree.fromstring(content)
            
            # Map XML elements to result keys
            mappings = {
                "model": ["model", "deviceModel"],
                "firmwareVersion": ["firmwareVersion", "Version"],
                "serialNumber": ["serialNumber", "serialNo", "deviceSerialNo"],
                "macAddress": ["macAddress", "MACAddress"],
                "deviceType": ["deviceType", "type"],
                "hardwareVersion": ["hardwareVersion"],
                "encoderVersion": ["encoderVersion"],
                "bootVersion": ["bootVersion"],
                "deviceID": ["deviceID", "id"],
            }
            
            for key, possible_names in mappings.items():
                for name in possible_names:
                    elem = root.find(f".//{name}")
                    if elem is not None and elem.text:
                        result[key] = elem.text.strip()
                        break
        
        except Exception as e:
            logger.debug(f"ISAPI XML parse error: {e}")
        
        return result

    def _parse_sdk_response(self, content: str) -> dict[str, str]:
        """Parse SDK/CGI response."""
        result = {}
        
        try:
            # Parse key=value format
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip().strip('"')
                    
                    if "model" in key or "type" in key:
                        result["model"] = value
                    elif "version" in key or "firmware" in key:
                        result["version"] = value
                    elif "serial" in key:
                        result["serialNumber"] = value
        
        except Exception as e:
            logger.debug(f"SDK response parse error: {e}")
        
        return result

    def _parse_capabilities_xml(self, content: str) -> dict[str, Any]:
        """Parse capabilities XML response."""
        result = {}
        
        try:
            content = re.sub(r'xmlns="[^"]+"', '', content)
            root = ElementTree.fromstring(content)
            
            # Extract key capabilities
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    result[elem.tag] = elem.text.strip()
        
        except Exception as e:
            logger.debug(f"Capabilities XML parse error: {e}")
        
        return result


# Module-level instance for convenience
hikvision_fingerprinter = HikvisionFingerprinter()
