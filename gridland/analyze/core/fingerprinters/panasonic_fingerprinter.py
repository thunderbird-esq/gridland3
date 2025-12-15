"""
Panasonic Camera Fingerprinter

Comprehensive device fingerprinting for Panasonic IP cameras including:
- CGI endpoint queries
- Model/firmware extraction
- i-PRO series support
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
class PanasonicFingerprint:
    """Fingerprint data for Panasonic devices."""
    
    brand: str = "panasonic"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""
    hardware_version: str = ""
    vendor: str = "Panasonic"
    ipro_model: bool = False  # True if i-PRO series
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class PanasonicFingerprinter:
    """Fingerprinter for Panasonic IP cameras."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # Panasonic specific endpoints
        self.endpoints = {
            "system_info": "/cgi-bin/get_camerainfo?FILE=1",
            "device_info": "/cgi-bin/getinfo?FILE=1",
            "config": "/cgi-bin/get_query?query=CAMERA_INFO",
            "network": "/cgi-bin/get_query?query=NETWORK",
            "live": "/nphMotionJpeg?Resolution=320x240&Quality=Standard",
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
    ) -> PanasonicFingerprint:
        """Perform comprehensive Panasonic device fingerprinting."""
        fingerprint = PanasonicFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try camera info (primary method)
            camera_info = await self._query_camera_info(base_url, auth)
            if camera_info:
                fingerprint.model = camera_info.get("model_no", "") or camera_info.get("model", "")
                fingerprint.firmware_version = camera_info.get("firmware_version", "")
                fingerprint.serial_number = camera_info.get("serial_no", "")
                fingerprint.mac_address = camera_info.get("mac_address", "")
                fingerprint.detection_methods.append("camera_info")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["camera_info"] = camera_info
                
                # Check for i-PRO branding
                if "i-pro" in str(camera_info).lower() or "ipro" in str(camera_info).lower():
                    fingerprint.ipro_model = True
            
            # Try device info
            device_info = await self._query_device_info(base_url, auth)
            if device_info:
                if not fingerprint.model:
                    fingerprint.model = device_info.get("model", "")
                fingerprint.detection_methods.append("device_info")
                fingerprint.confidence = max(fingerprint.confidence, 0.85)
                fingerprint.raw_data["device_info"] = device_info
            
        except Exception as e:
            logger.debug(f"Panasonic fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_camera_info(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query camera info endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['system_info']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_panasonic_response(content)
        except Exception as e:
            logger.debug(f"Camera info query error: {e}")
        
        return result

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
                    result = self._parse_panasonic_response(content)
        except Exception as e:
            logger.debug(f"Device info query error: {e}")
        
        return result

    def _parse_panasonic_response(self, content: str) -> dict[str, str]:
        """Parse Panasonic CGI response."""
        result = {}
        
        try:
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip().lower().replace("-", "_")
                    value = value.strip()
                    result[key] = value
        except Exception as e:
            logger.debug(f"Panasonic response parse error: {e}")
        
        return result


# Module-level instance
panasonic_fingerprinter = PanasonicFingerprinter()
