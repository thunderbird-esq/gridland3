"""
CP Plus Camera Fingerprinter

Comprehensive device fingerprinting for CP Plus IP cameras including:
- CGI endpoint queries
- UVR/DVR model detection
- Model/firmware extraction
- Device capability detection

CP Plus is a major brand especially in India/Asia, with specific endpoint patterns
different from Western manufacturers.
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
class CPPlusFingerprint:
    """Fingerprint data for CP Plus devices."""
    
    brand: str = "cp_plus"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""  # DVR, NVR, IPC, etc.
    hardware_id: str = ""
    product_name: str = ""
    channel_count: int = 0
    vendor: str = "CP Plus"
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class CPPlusFingerprinter:
    """Fingerprinter for CP Plus IP cameras and DVR/NVR devices."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # CP Plus specific endpoints
        self.endpoints = {
            # System info endpoints
            "system_info": "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "device_type": "/cgi-bin/magicBox.cgi?action=getDeviceType",
            "software_version": "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
            "hardware_version": "/cgi-bin/magicBox.cgi?action=getHardwareVersion",
            "serial_number": "/cgi-bin/magicBox.cgi?action=getSerialNo",
            "device_class": "/cgi-bin/magicBox.cgi?action=getDeviceClass",
            
            # Config endpoints
            "machine_name": "/cgi-bin/configManager.cgi?action=getConfig&name=General.MachineName",
            "channel_title": "/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle",
            
            # Alternative endpoints
            "web_config": "/config/",
            "api_system": "/api/system",
        }
        
        # Model patterns for UVR devices
        self.model_patterns = {
            r"uvr.?0401": "CP-UVR-0401",
            r"uvr.?0801": "CP-UVR-0801", 
            r"uvr.?1601": "CP-UVR-1601",
            r"cp.?vnr.?3104": "CP-VNR-3104",
            r"cp.?vnr.?3108": "CP-VNR-3108",
            r"cp.?vnr.?3208": "CP-VNR-3208",
            r"cp.?plus": "CP Plus Device",
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
    ) -> CPPlusFingerprint:
        """
        Perform comprehensive CP Plus device fingerprinting.
        
        Args:
            ip: Target IP address
            port: Target port
            username: Optional username for authenticated requests
            password: Optional password for authenticated requests
            
        Returns:
            CPPlusFingerprint with device details
        """
        fingerprint = CPPlusFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try magicBox system info (primary method)
            system_info = await self._query_magicbox_system(base_url, auth)
            if system_info:
                fingerprint.model = system_info.get("model", "")
                fingerprint.device_type = system_info.get("deviceType", "")
                fingerprint.detection_methods.append("magicbox_system")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["system_info"] = system_info
            
            # Try device type endpoint
            device_type = await self._query_device_type(base_url, auth)
            if device_type:
                fingerprint.device_type = device_type.get("type", fingerprint.device_type)
                fingerprint.detection_methods.append("device_type")
                fingerprint.confidence = max(fingerprint.confidence, 0.90)
                fingerprint.raw_data["device_type"] = device_type
            
            # Try software version
            software = await self._query_software_version(base_url, auth)
            if software:
                fingerprint.firmware_version = software.get("version", "")
                fingerprint.detection_methods.append("software_version")
                fingerprint.confidence = max(fingerprint.confidence, 0.85)
                fingerprint.raw_data["software"] = software
            
            # Try serial number
            serial = await self._query_serial_number(base_url, auth)
            if serial:
                fingerprint.serial_number = serial.get("sn", "")
                fingerprint.detection_methods.append("serial_number")
                fingerprint.raw_data["serial"] = serial
            
            # Fallback: Check main page for CP Plus indicators
            if not fingerprint.model:
                page_info = await self._check_main_page(base_url, auth)
                if page_info:
                    fingerprint.model = page_info.get("model", "")
                    fingerprint.product_name = page_info.get("product", "")
                    fingerprint.detection_methods.append("page_analysis")
                    fingerprint.confidence = max(fingerprint.confidence, 0.70)
                    fingerprint.raw_data["page_info"] = page_info
            
        except Exception as e:
            logger.debug(f"CP Plus fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_magicbox_system(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query magicBox system info."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['system_info']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_cpplus_response(content)
        except Exception as e:
            logger.debug(f"magicBox system query error: {e}")
        
        return result

    async def _query_device_type(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query device type endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['device_type']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_cpplus_response(content)
        except Exception as e:
            logger.debug(f"Device type query error: {e}")
        
        return result

    async def _query_software_version(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query software version endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['software_version']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_cpplus_response(content)
        except Exception as e:
            logger.debug(f"Software version query error: {e}")
        
        return result

    async def _query_serial_number(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query serial number endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.endpoints['serial_number']}"
            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    result = self._parse_cpplus_response(content)
        except Exception as e:
            logger.debug(f"Serial number query error: {e}")
        
        return result

    async def _check_main_page(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Check main page for CP Plus indicators."""
        result = {}
        
        try:
            async with self.session.get(base_url, auth=auth) as response:
                if response.status == 200:
                    content = await response.text()
                    content_lower = content.lower()
                    
                    # Check for CP Plus indicators
                    if any(x in content_lower for x in ["cp plus", "cpplus", "cp-plus", "cp_plus"]):
                        result["product"] = "CP Plus"
                        
                        # Try to extract model from patterns
                        for pattern, model_name in self.model_patterns.items():
                            if re.search(pattern, content_lower):
                                result["model"] = model_name
                                break
                        
                        # Check for UVR/DVR indicators
                        if "uvr" in content_lower:
                            result["device_type"] = "UVR"
                        elif "nvr" in content_lower:
                            result["device_type"] = "NVR"
                        elif "dvr" in content_lower:
                            result["device_type"] = "DVR"
                            
        except Exception as e:
            logger.debug(f"Main page check error: {e}")
        
        return result

    def _parse_cpplus_response(self, content: str) -> dict[str, str]:
        """Parse CP Plus CGI response (key=value format)."""
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
            logger.debug(f"CP Plus response parse error: {e}")
        
        return result


# Module-level instance for convenience
cpplus_fingerprinter = CPPlusFingerprinter()
