"""
Vivotek Camera Fingerprinter

Comprehensive device fingerprinting for Vivotek IP cameras including:
- CGI endpoint queries
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
class VivotekFingerprint:
    """Fingerprint data for Vivotek devices."""
    
    brand: str = "vivotek"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""
    hardware_version: str = ""
    vendor: str = "Vivotek"
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class VivotekFingerprinter:
    """Fingerprinter for Vivotek IP cameras."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # Vivotek specific endpoints
        self.endpoints = {
            "system_info": "/cgi-bin/viewer/getparam.cgi?system",
            "video_info": "/cgi-bin/viewer/getparam.cgi?video",
            "network_info": "/cgi-bin/viewer/getparam.cgi?network",
            "admin_info": "/cgi-bin/admin/getparam.cgi?system",
            "capability": "/cgi-bin/viewer/capability.cgi",
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
    ) -> VivotekFingerprint:
        """Perform comprehensive Vivotek device fingerprinting."""
        fingerprint = VivotekFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try system info (primary method)
            system_info = await self._query_system_info(base_url, auth)
            if system_info:
                fingerprint.model = system_info.get("model", "")
                fingerprint.firmware_version = system_info.get("firmware", "")
                fingerprint.serial_number = system_info.get("serialnumber", "")
                fingerprint.detection_methods.append("system_info")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["system_info"] = system_info
            
            # Try capability endpoint
            capability = await self._query_capability(base_url, auth)
            if capability:
                if not fingerprint.model:
                    fingerprint.model = capability.get("productname", "")
                fingerprint.detection_methods.append("capability")
                fingerprint.confidence = max(fingerprint.confidence, 0.85)
                fingerprint.raw_data["capability"] = capability
            
        except Exception as e:
            logger.debug(f"Vivotek fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_system_info(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query system info endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['system_info']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_vivotek_response(content)
        except Exception as e:
            logger.debug(f"System info query error: {e}")
        
        return result

    async def _query_capability(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query capability endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['capability']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_vivotek_response(content)
        except Exception as e:
            logger.debug(f"Capability query error: {e}")
        
        return result

    def _parse_vivotek_response(self, content: str) -> dict[str, str]:
        """Parse Vivotek CGI response."""
        result = {}
        
        try:
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip().lower().replace("'", "").replace('"', "")
                    value = value.strip().replace("'", "").replace('"', "")
                    result[key] = value
        except Exception as e:
            logger.debug(f"Vivotek response parse error: {e}")
        
        return result


# Module-level instance
vivotek_fingerprinter = VivotekFingerprinter()
