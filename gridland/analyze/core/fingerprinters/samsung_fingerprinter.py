"""
Samsung Camera Fingerprinter

Comprehensive device fingerprinting for Samsung/Hanwha Techwin IP cameras including:
- CGI endpoint queries  
- Model/firmware extraction
- Device capability detection

Note: Samsung Techwin was acquired by Hanwha and rebranded as Hanwha Techwin/Wisenet.
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
class SamsungFingerprint:
    """Fingerprint data for Samsung/Hanwha devices."""
    
    brand: str = "samsung"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""
    hardware_version: str = ""
    vendor: str = "Samsung Techwin / Hanwha"
    wisenet_model: bool = False  # True if Wisenet branding
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class SamsungFingerprinter:
    """Fingerprinter for Samsung/Hanwha Techwin IP cameras."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # Samsung/Hanwha specific endpoints
        self.endpoints = {
            "device_info": "/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view",
            "network_info": "/stw-cgi/network.cgi?msubmenu=interface&action=view",
            "storage_info": "/stw-cgi/recording.cgi?msubmenu=storageinfo&action=view",
            "attributes": "/stw-cgi/attributes.cgi/attributes",
            "video_profile": "/stw-cgi/video.cgi?msubmenu=profile&action=view",
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
    ) -> SamsungFingerprint:
        """Perform comprehensive Samsung device fingerprinting."""
        fingerprint = SamsungFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try device info (primary method)
            device_info = await self._query_device_info(base_url, auth)
            if device_info:
                fingerprint.model = device_info.get("model", "")
                fingerprint.firmware_version = device_info.get("firmwareversion", "")
                fingerprint.serial_number = device_info.get("serialnumber", "")
                fingerprint.mac_address = device_info.get("macaddress", "")
                fingerprint.detection_methods.append("device_info")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["device_info"] = device_info
                
                # Check for Wisenet branding
                if "wisenet" in str(device_info).lower():
                    fingerprint.wisenet_model = True
            
            # Try attributes endpoint
            attributes = await self._query_attributes(base_url, auth)
            if attributes:
                if not fingerprint.model:
                    fingerprint.model = attributes.get("modelname", "")
                fingerprint.detection_methods.append("attributes")
                fingerprint.confidence = max(fingerprint.confidence, 0.90)
                fingerprint.raw_data["attributes"] = attributes
            
        except Exception as e:
            logger.debug(f"Samsung fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_device_info(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query device info endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['device_info']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_samsung_response(content)
        except Exception as e:
            logger.debug(f"Device info query error: {e}")
        
        return result

    async def _query_attributes(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query attributes endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['attributes']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_samsung_response(content)
        except Exception as e:
            logger.debug(f"Attributes query error: {e}")
        
        return result

    def _parse_samsung_response(self, content: str) -> dict[str, str]:
        """Parse Samsung CGI response."""
        result = {}
        
        try:
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    result[key] = value
        except Exception as e:
            logger.debug(f"Samsung response parse error: {e}")
        
        return result


# Module-level instance
samsung_fingerprinter = SamsungFingerprinter()
