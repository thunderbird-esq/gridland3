"""
Foscam Camera Fingerprinter

Comprehensive device fingerprinting for Foscam IP cameras including:
- CGI proxy endpoint queries
- Model/firmware extraction
- Device capability detection
"""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FoscamFingerprint:
    """Fingerprint data for Foscam devices."""
    
    brand: str = "foscam"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = "IP Camera"
    hardware_version: str = ""
    vendor: str = "Foscam"
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class FoscamFingerprinter:
    """Fingerprinter for Foscam IP cameras."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # Foscam CGIProxy endpoints
        self.endpoints = {
            "dev_info": "/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo",
            "dev_state": "/cgi-bin/CGIProxy.fcgi?cmd=getDevState",
            "product_all": "/cgi-bin/CGIProxy.fcgi?cmd=getProductAllInfo",
            "system_time": "/cgi-bin/CGIProxy.fcgi?cmd=getSystemTime",
            "log_config": "/cgi-bin/CGIProxy.fcgi?cmd=getLogConfig",
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
        username: str = "admin",
        password: str = "",
    ) -> FoscamFingerprint:
        """Perform comprehensive Foscam device fingerprinting."""
        fingerprint = FoscamFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            
            # Build auth params for Foscam (uses URL params, not HTTP auth)
            auth_params = f"&usr={username}&pwd={password}" if username else ""
            
            # Try device info (primary method)
            dev_info = await self._query_dev_info(base_url, auth_params)
            if dev_info:
                fingerprint.model = dev_info.get("productname", "") or dev_info.get("devname", "")
                fingerprint.firmware_version = dev_info.get("firmwarever", "")
                fingerprint.hardware_version = dev_info.get("hardwarever", "")
                fingerprint.serial_number = dev_info.get("serialno", "")
                fingerprint.mac_address = dev_info.get("mac", "")
                fingerprint.detection_methods.append("dev_info")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["dev_info"] = dev_info
            
            # Try product all info
            product_info = await self._query_product_info(base_url, auth_params)
            if product_info:
                if not fingerprint.model:
                    fingerprint.model = product_info.get("productname", "")
                fingerprint.detection_methods.append("product_info")
                fingerprint.confidence = max(fingerprint.confidence, 0.90)
                fingerprint.raw_data["product_info"] = product_info
            
        except Exception as e:
            logger.debug(f"Foscam fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_dev_info(
        self, base_url: str, auth_params: str
    ) -> dict[str, str]:
        """Query device info endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['dev_info']}{auth_params}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_foscam_xml(content)
        except Exception as e:
            logger.debug(f"Dev info query error: {e}")
        
        return result

    async def _query_product_info(
        self, base_url: str, auth_params: str
    ) -> dict[str, str]:
        """Query product info endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['product_all']}{auth_params}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_foscam_xml(content)
        except Exception as e:
            logger.debug(f"Product info query error: {e}")
        
        return result

    def _parse_foscam_xml(self, content: str) -> dict[str, str]:
        """Parse Foscam XML response."""
        result = {}
        
        try:
            # Foscam returns XML responses
            root = ET.fromstring(content)
            for child in root:
                result[child.tag.lower()] = child.text or ""
        except ET.ParseError:
            # Fallback to key=value parsing
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    result[key.strip().lower()] = value.strip()
        except Exception as e:
            logger.debug(f"Foscam XML parse error: {e}")
        
        return result


# Module-level instance
foscam_fingerprinter = FoscamFingerprinter()
