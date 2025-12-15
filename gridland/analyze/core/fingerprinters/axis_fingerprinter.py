"""
Axis Camera Fingerprinter

Comprehensive device fingerprinting for Axis IP cameras including:
- VAPIX endpoint queries
- ACAP endpoint queries
- Model/firmware extraction
- Device capability detection
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AxisFingerprint:
    """Fingerprint data for Axis devices."""
    
    brand: str = "axis"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""
    hardware_id: str = ""
    product_full_name: str = ""
    product_short_name: str = ""
    vendor: str = "Axis Communications"
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class AxisFingerprinter:
    """Fingerprinter for Axis IP cameras."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # VAPIX API endpoints
        self.vapix_endpoints = {
            "brand": "/axis-cgi/param.cgi?action=list&group=root.Brand",
            "properties": "/axis-cgi/param.cgi?action=list&group=root.Properties",
            "system": "/axis-cgi/param.cgi?action=list&group=root.System",
            "network": "/axis-cgi/param.cgi?action=list&group=root.Network",
            "basicDeviceInfo": "/axis-cgi/basicdeviceinfo.cgi",
        }
        
        # ACAP endpoints
        self.acap_endpoints = {
            "applications": "/axis-cgi/applications/list.cgi",
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
    ) -> AxisFingerprint:
        """
        Perform comprehensive Axis device fingerprinting.
        
        Args:
            ip: Target IP address
            port: Target port
            username: Optional username for authenticated requests
            password: Optional password for authenticated requests
            
        Returns:
            AxisFingerprint with device details
        """
        fingerprint = AxisFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try VAPIX brand parameters (primary method)
            brand_info = await self._query_vapix_brand(base_url, auth)
            if brand_info:
                fingerprint.model = brand_info.get("model", "")
                fingerprint.product_full_name = brand_info.get("prodFullName", "")
                fingerprint.product_short_name = brand_info.get("prodShortName", "")
                fingerprint.detection_methods.append("vapix_brand")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["vapix_brand"] = brand_info
            
            # Try VAPIX properties (supplementary)
            properties = await self._query_vapix_properties(base_url, auth)
            if properties:
                fingerprint.firmware_version = properties.get("firmwareVersion", "")
                fingerprint.serial_number = properties.get("serialNumber", "")
                fingerprint.hardware_id = properties.get("hardwareId", "")
                fingerprint.detection_methods.append("vapix_properties")
                fingerprint.confidence = max(fingerprint.confidence, 0.90)
                fingerprint.raw_data["vapix_properties"] = properties
            
            # Try basic device info (fallback)
            if not fingerprint.model:
                basic_info = await self._query_basic_device_info(base_url, auth)
                if basic_info:
                    fingerprint.model = basic_info.get("model", "")
                    fingerprint.firmware_version = basic_info.get("version", "")
                    fingerprint.serial_number = basic_info.get("serial", "")
                    fingerprint.detection_methods.append("basic_device_info")
                    fingerprint.confidence = max(fingerprint.confidence, 0.80)
                    fingerprint.raw_data["basic_info"] = basic_info
            
        except Exception as e:
            logger.debug(f"Axis fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_vapix_brand(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query VAPIX brand parameters."""
        result = {}
        
        try:
            url = f"{base_url}{self.vapix_endpoints['brand']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_vapix_response(content)
        except Exception as e:
            logger.debug(f"VAPIX brand query error: {e}")
        
        return result

    async def _query_vapix_properties(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query VAPIX properties."""
        result = {}
        
        try:
            url = f"{base_url}{self.vapix_endpoints['properties']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_vapix_response(content)
        except Exception as e:
            logger.debug(f"VAPIX properties query error: {e}")
        
        return result

    async def _query_basic_device_info(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query basic device info endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.vapix_endpoints['basicDeviceInfo']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_basic_info_response(content)
        except Exception as e:
            logger.debug(f"Basic device info query error: {e}")
        
        return result

    def _parse_vapix_response(self, content: str) -> dict[str, str]:
        """Parse VAPIX parameter response."""
        result = {}
        
        try:
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    # Extract the last part of the parameter name
                    key_parts = key.split(".")
                    short_key = key_parts[-1] if key_parts else key
                    result[short_key] = value.strip()
        
        except Exception as e:
            logger.debug(f"VAPIX response parse error: {e}")
        
        return result

    def _parse_basic_info_response(self, content: str) -> dict[str, str]:
        """Parse basic device info response."""
        result = {}
        
        try:
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if "model" in key or "product" in key:
                        result["model"] = value
                    elif "version" in key or "firmware" in key:
                        result["version"] = value
                    elif "serial" in key:
                        result["serial"] = value
        
        except Exception as e:
            logger.debug(f"Basic info parse error: {e}")
        
        return result


# Module-level instance for convenience
axis_fingerprinter = AxisFingerprinter()
