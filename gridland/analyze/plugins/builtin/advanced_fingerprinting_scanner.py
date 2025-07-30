"""
Advanced Fingerprinting Scanner with brand-specific intelligence extraction.
Implements CamXploit.py fingerprinting methods (lines 616-765) with enhanced capabilities.
"""

import asyncio
import aiohttp
import xml.etree.ElementTree as ET
import re
import base64
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import json

from ...core.logger import logger
from ...core.models import BasePlugin, DeviceFingerprint
from ...core.database_manager import db_manager # <-- IMPORT THE SINGLETON
import aiohttp
from typing import Optional

@dataclass
class DeviceFingerprint:
    """Comprehensive device fingerprint information"""
    brand: str
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    hardware_version: Optional[str] = None
    serial_number: Optional[str] = None
    device_type: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    authentication_methods: List[str] = field(default_factory=list)
    configuration_access: bool = False
    vulnerability_indicators: List[str] = field(default_factory=list)

class AdvancedFingerprintingScanner(BasePlugin):
    def __init__(self, scheduler, memory_pool):
        super().__init__(scheduler, memory_pool)
        self.plugin_name = "Advanced Fingerprinting Scanner"

        # --- THIS IS THE FIX ---
        # Instead of loading the file here, we get the already-loaded
        # database from the global manager.
        self.fingerprinting_database = db_manager.get_db('fingerprinting_database')

        if not self.fingerprinting_database:
            logger.error(
                "Fingerprinting database not found in DatabaseManager. "
                "The plugin will be disabled."
            )

    async def analyze(self, target: dict) -> Optional[DeviceFingerprint]:
        pass

    async def _perform_brand_fingerprinting(self, target_ip: str, target_port: int,
                                          brand: str) -> Optional[DeviceFingerprint]:
        """Perform brand-specific detailed fingerprinting"""

        if brand == 'hikvision':
            return await self._fingerprint_hikvision(target_ip, target_port)
        elif brand == 'dahua':
            return await self._fingerprint_dahua(target_ip, target_port)
        elif brand == 'axis':
            return await self._fingerprint_axis(target_ip, target_port)
        elif brand == 'cp_plus':
            return await self._fingerprint_cp_plus(target_ip, target_port)

        return None

async def _fingerprint_hikvision(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
    """Hikvision-specific fingerprinting using ISAPI"""
    protocol = "https" if target_port in [443, 8443] else "http"
    base_url = f"{protocol}://{target_ip}:{target_port}"
    fingerprint = DeviceFingerprint(brand="hikvision", capabilities=[], api_endpoints=[])

    try:
        request_timeout = config_manager.get('network', 'timeout', default=10)

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=request_timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            hik_db = self.fingerprinting_database['hikvision']
            for endpoint in hik_db['endpoints']:
                try:
                    url = f"{base_url}{endpoint}"
                    async with session.get(url) as response:
                        if response.status == 200:
                            fingerprint.api_endpoints.append(endpoint)
                            content = await response.text()
                            if "deviceInfo" in endpoint or "configurationFile" in endpoint:
                                await self._parse_hikvision_xml(content, fingerprint)
                            if "configurationFile" in endpoint:
                                fingerprint.configuration_access = True
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Hikvision fingerprinting failed: {e}")

    return fingerprint if fingerprint.api_endpoints else None

    async def _parse_hikvision_xml(self, content: str, fingerprint: DeviceFingerprint):
        """Parse Hikvision ISAPI XML responses"""

        try:
            root = ET.fromstring(content)

            # Extract device information using multiple XPath patterns
            hik_db = self.fingerprinting_database['hikvision']

            for field, paths in hik_db['xml_paths'].items():
                for path in paths:
                    element = root.find(path)
                    if element is not None and element.text:
                        if field == 'model':
                            fingerprint.model = element.text.strip()
                        elif field == 'firmware':
                            fingerprint.firmware_version = element.text.strip()
                        elif field == 'hardware':
                            fingerprint.hardware_version = element.text.strip()
                        elif field == 'serial':
                            fingerprint.serial_number = element.text.strip()
                        break

            # Extract capabilities
            caps = root.findall('.//capability') + root.findall('.//Channel')
            if caps:
                fingerprint.capabilities.extend([cap.get('name', 'unknown') for cap in caps[:5]])

        except ET.ParseError as e:
            logger.debug(f"XML parsing failed: {e}")

    async def _parse_dahua_response(self, content: str, fingerprint: DeviceFingerprint):
        """Parse Dahua magicBox.cgi responses"""

        dahua_db = self.fingerprinting_database['dahua']

        for field, patterns in dahua_db['response_patterns'].items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if field == 'model':
                        fingerprint.model = value
                    elif field == 'firmware':
                        fingerprint.firmware_version = value
                    elif field == 'serial':
                        fingerprint.serial_number = value
                    break

    async def _parse_axis_parameters(self, content: str, fingerprint: DeviceFingerprint):
        """Parse Axis VAPIX parameter responses"""

        axis_db = self.fingerprinting_database['axis']

        for field, param_names in axis_db['parameter_patterns'].items():
            for param_name in param_names:
                pattern = rf"{param_name}=([^\\r\\n]+)"
                match = re.search(pattern, content)
                if match:
                    value = match.group(1).strip()
                    if field == 'model':
                        fingerprint.model = value
                    elif field == 'firmware':
                        fingerprint.firmware_version = value
                    elif field == 'hardware':
                        fingerprint.hardware_version = value
                    elif field == 'serial':
                        fingerprint.serial_number = value
                    break

    async def _parse_cp_plus_content(self, content: str, fingerprint: DeviceFingerprint):
        """Parse CP Plus content for device information"""

        cp_db = self.fingerprinting_database['cp_plus']
        content_lower = content.lower()

        for field, patterns in cp_db['content_patterns'].items():
            for pattern in patterns:
                try:
                    if field == 'device_type':
                        if pattern in content_lower:
                            fingerprint.device_type = pattern.upper()
                            break
                    else:
                        # Regex pattern
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match and len(match.groups()) > 0:
                            value = match.group(1).strip()
                            if field == 'model':
                                fingerprint.model = value
                            elif field == 'firmware':
                                fingerprint.firmware_version = value
                            break
                except re.error as e:
                    logger.debug(f"Regex error for pattern '{pattern}': {e}")
                except Exception as e:
                    logger.debug(f"Firmware pattern extraction error: {e}")

    async def _test_credentials(self, session: aiohttp.ClientSession, base_url: str,
                              brand: str) -> Optional[Tuple[str, str]]:
        """Test default credentials for the brand"""

        brand_db = self.fingerprinting_database.get(brand, {})
        credentials = brand_db.get('default_credentials', [])

        for username, password in credentials:
            try:
                auth = aiohttp.BasicAuth(username, password)
                async with session.get(base_url, auth=auth, timeout=aiohttp.ClientTimeout(total=3)) as response:
                    if response.status == 200:
                        return (username, password)
            except Exception:
                continue

        return None

async def _fingerprint_dahua(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
    """Dahua-specific fingerprinting using magicBox.cgi"""
    protocol = "https" if target_port in [443, 8443] else "http"
    base_url = f"{protocol}://{target_ip}:{target_port}"
    fingerprint = DeviceFingerprint(brand="dahua", capabilities=[], api_endpoints=[])

    try:
        request_timeout = config_manager.get('network', 'timeout', default=10)
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=request_timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            dahua_db = self.fingerprinting_database['dahua']
            for endpoint in dahua_db['endpoints']:
                try:
                    url = f"{base_url}{endpoint}"
                    async with session.get(url) as response:
                        if response.status == 200:
                            fingerprint.api_endpoints.append(endpoint)
                            content = await response.text()
                            if 'magicBox.cgi' in endpoint:
                                await self._parse_dahua_response(content, fingerprint)
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Dahua fingerprinting failed: {e}")

    return fingerprint if fingerprint.api_endpoints else None

async def _fingerprint_axis(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
    """Axis-specific fingerprinting using VAPIX API"""
    protocol = "https" if target_port in [443, 8443] else "http"
    base_url = f"{protocol}://{target_ip}:{target_port}"
    fingerprint = DeviceFingerprint(brand="axis", capabilities=[], api_endpoints=[])

    try:
        request_timeout = config_manager.get('network', 'timeout', default=10)
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=request_timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            axis_db = self.fingerprinting_database['axis']
            for endpoint in axis_db['endpoints']:
                try:
                    url = f"{base_url}{endpoint}"
                    async with session.get(url) as response:
                        if response.status == 200:
                            fingerprint.api_endpoints.append(endpoint)
                            content = await response.text()
                            if 'param.cgi' in endpoint:
                                await self._parse_axis_parameters(content, fingerprint)
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Axis fingerprinting failed: {e}")

    return fingerprint if fingerprint.api_endpoints else None

    async def _fingerprint_cp_plus(self, target_ip: str, target_port: int) -> Optional[DeviceFingerprint]:
        """CP Plus-specific fingerprinting"""

        protocol = "https" if target_port in [443, 8443] else "http"
        base_url = f"{protocol}://{target_ip}:{target_port}"

        fingerprint = DeviceFingerprint(brand="cp_plus", capabilities=[], api_endpoints=[])

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

                cp_db = self.fingerprinting_database['cp_plus']

                for endpoint in cp_db['endpoints']:
                    try:
                        url = f"{base_url}{endpoint}"

                        async with session.get(url) as response:
                            if response.status == 200:
                                fingerprint.api_endpoints.append(endpoint)
                                content = await response.text()

                                # Parse CP Plus content patterns
                                await self._parse_cp_plus_content(content, fingerprint)

                            elif response.status == 401:
                                fingerprint.api_endpoints.append(f"{endpoint} (auth required)")

                    except Exception as e:
                        logger.debug(f"CP Plus endpoint test failed for {endpoint}: {e}")

        except Exception as e:
            logger.debug(f"CP Plus fingerprinting failed: {e}")

        return fingerprint if fingerprint.api_endpoints else None
