"""
Dahua Camera Fingerprinter

Comprehensive device fingerprinting for Dahua IP cameras including:
- RPC2 endpoint queries
- JSON-RPC endpoint queries
- Model/firmware extraction
- Device capability detection
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from gridland.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DahuaFingerprint:
    """Fingerprint data for Dahua devices."""
    
    brand: str = "dahua"
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    device_type: str = ""
    hardware_version: str = ""
    system_version: str = ""
    processor: str = ""
    vendor: str = "Dahua Technology"
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


class DahuaFingerprinter:
    """Fingerprinter for Dahua IP cameras and NVRs."""

    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10)
        
        # RPC2 API endpoints
        self.rpc2_endpoints = {
            "magicBox": "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "deviceType": "/cgi-bin/magicBox.cgi?action=getDeviceType",
            "softwareVersion": "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
            "hardwareVersion": "/cgi-bin/magicBox.cgi?action=getHardwareVersion",
            "serialNo": "/cgi-bin/magicBox.cgi?action=getSerialNo",
            "macAddress": "/cgi-bin/magicBox.cgi?action=getMacAddress",
        }
        
        # JSON-RPC API endpoint
        self.jsonrpc_endpoint = "/RPC2"
        
        # Legacy endpoints
        self.legacy_endpoints = {
            "config": "/cgi-bin/configManager.cgi?action=getConfig&name=General",
            "deviceInfo": "/cgi-bin/devInfo.cgi?action=get",
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
    ) -> DahuaFingerprint:
        """
        Perform comprehensive Dahua device fingerprinting.
        
        Args:
            ip: Target IP address
            port: Target port
            username: Optional username for authenticated requests
            password: Optional password for authenticated requests
            
        Returns:
            DahuaFingerprint with device details
        """
        fingerprint = DahuaFingerprint()
        
        await self._init_session()
        
        try:
            base_url = f"http://{ip}:{port}"
            auth = None
            if username and password:
                auth = aiohttp.BasicAuth(username, password)
            
            # Try RPC2 magicBox (primary method)
            system_info = await self._query_magic_box(base_url, auth)
            if system_info:
                fingerprint.model = system_info.get("deviceType", "")
                fingerprint.firmware_version = system_info.get("softwareVersion", "")
                fingerprint.serial_number = system_info.get("serialNo", "")
                fingerprint.hardware_version = system_info.get("hardwareVersion", "")
                fingerprint.processor = system_info.get("processor", "")
                fingerprint.detection_methods.append("rpc2_magicbox")
                fingerprint.confidence = 0.95
                fingerprint.raw_data["magicbox"] = system_info
            
            # Try JSON-RPC (supplementary)
            jsonrpc_info = await self._query_jsonrpc(base_url, auth)
            if jsonrpc_info:
                if not fingerprint.model:
                    fingerprint.model = jsonrpc_info.get("model", "")
                if not fingerprint.firmware_version:
                    fingerprint.firmware_version = jsonrpc_info.get("version", "")
                fingerprint.detection_methods.append("jsonrpc")
                fingerprint.confidence = max(fingerprint.confidence, 0.85)
                fingerprint.raw_data["jsonrpc"] = jsonrpc_info
            
            # Try legacy endpoints (fallback)
            if not fingerprint.model:
                legacy_info = await self._query_legacy_endpoints(base_url, auth)
                if legacy_info:
                    fingerprint.model = legacy_info.get("model", "")
                    fingerprint.firmware_version = legacy_info.get("version", "")
                    fingerprint.detection_methods.append("legacy")
                    fingerprint.confidence = max(fingerprint.confidence, 0.70)
                    fingerprint.raw_data["legacy"] = legacy_info
            
        except Exception as e:
            logger.debug(f"Dahua fingerprinting error: {e}")
            
        finally:
            await self._cleanup_session()
        
        return fingerprint

    async def _query_magic_box(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query RPC2 magicBox endpoints."""
        result = {}
        
        for name, endpoint in self.rpc2_endpoints.items():
            try:
                url = f"{base_url}{endpoint}"
                async with self.session.get(url, auth=auth) as response:
                    if response.status == 200:
                        content = await response.text()
                        parsed = self._parse_rpc2_response(content, name)
                        result.update(parsed)
            except Exception:
                continue
        
        return result

    async def _query_jsonrpc(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query JSON-RPC endpoint."""
        result = {}
        
        try:
            url = f"{base_url}{self.jsonrpc_endpoint}"
            payload = {
                "method": "magicBox.getDeviceType",
                "params": None,
                "id": 1,
                "session": None
            }
            
            headers = {"Content-Type": "application/json"}
            async with self.session.post(url, json=payload, auth=auth, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if "result" in data:
                        result["model"] = data["result"]
                        
        except Exception as e:
            logger.debug(f"JSON-RPC query error: {e}")
        
        return result

    async def _query_legacy_endpoints(
        self, base_url: str, auth: aiohttp.BasicAuth | None
    ) -> dict[str, str]:
        """Query legacy CGI endpoints."""
        result = {}
        
        for name, endpoint in self.legacy_endpoints.items():
            try:
                url = f"{base_url}{endpoint}"
                async with self.session.get(url, auth=auth) as response:
                    if response.status == 200:
                        content = await response.text()
                        parsed = self._parse_legacy_response(content)
                        result.update(parsed)
                        if result:
                            break
            except Exception:
                continue
        
        return result

    def _parse_rpc2_response(self, content: str, endpoint_name: str) -> dict[str, str]:
        """Parse RPC2 response."""
        result = {}
        
        try:
            # RPC2 returns key=value format
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    result[key] = value
        
        except Exception as e:
            logger.debug(f"RPC2 parse error: {e}")
        
        return result

    def _parse_legacy_response(self, content: str) -> dict[str, str]:
        """Parse legacy CGI response."""
        result = {}
        
        try:
            for line in content.split("\n"):
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip().strip('"')
                    
                    if "model" in key or "devicetype" in key:
                        result["model"] = value
                    elif "version" in key:
                        result["version"] = value
                    elif "serial" in key:
                        result["serialNumber"] = value
        
        except Exception as e:
            logger.debug(f"Legacy response parse error: {e}")
        
        return result


# Module-level instance for convenience
dahua_fingerprinter = DahuaFingerprinter()
