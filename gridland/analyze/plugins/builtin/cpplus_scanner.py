"""
CP Plus Camera Scanner Plugin for GRIDLAND v3.0

This plugin detects CP Plus DVR/NVR camera systems through brand identification,
model detection, and device type classification.

100% feature parity with CamXploit.py fingerprint_cp_plus() (lines 1417-1453).
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import urllib3

from gridland.analyze.memory import get_memory_pool
from gridland.analyze.plugins.manager import PluginMetadata, VulnerabilityPlugin
from gridland.core.logger import get_logger

# Disable SSL warnings for camera endpoints
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)


class CPPlusScanner(VulnerabilityPlugin):
    """
    CP Plus DVR/NVR detection plugin.

    Detects CP Plus camera systems through keyword analysis and model extraction.
    Supports UVR, DVR, and NVR series identification.

    Attributes:
        cpplus_data (Dict): CP Plus detection data from cpplus_data.json.
        timeout (int): HTTP request timeout in seconds (default: 5).
    """

    def __init__(self):
        """Initialize the CP Plus Scanner plugin."""
        super().__init__()
        self.cpplus_data = self._load_cpplus_data()
        self.timeout = 5  # From CamXploit.py TIMEOUT constant line 797
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.memory_pool = get_memory_pool()

    def _load_cpplus_data(self) -> dict[str, Any]:
        """
        Load CP Plus detection data from cpplus_data.json.

        Returns:
            Dict containing CP Plus ports, models, keywords, and endpoints.
        """
        try:
            # Get path to cpplus_data.json
            data_dir = Path(__file__).parent.parent.parent.parent / "data"
            cpplus_file = data_dir / "cpplus_data.json"

            with open(cpplus_file, encoding="utf-8") as f:
                data = json.load(f)

            return data

        except Exception as e:
            logger.error(f"Failed to load CP Plus data: {e}")
            # Fallback to minimal detection data from CamXploit.py lines 1335-1336
            return {
                "detection_keywords": {
                    "brand": ["cp plus", "cp-plus", "cpplus", "cp_plus"],
                    "model_indicators": ["uvr", "uvr-0401e1", "uvr0401e1", "0401e1"],
                    "device_types": ["dvr", "nvr"],
                },
                "endpoints": {
                    "detection": [
                        "/",
                        "/index.html",
                        "/login",
                        "/admin",
                        "/cgi-bin",
                        "/api",
                        "/config",
                    ]
                },
            }

    def get_metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.

        Returns:
            PluginMetadata: Plugin information and configuration.
        """
        return PluginMetadata(
            name="CP Plus Scanner",
            version="1.0.0",
            author="GRIDLAND Security Team",
            description="CP Plus DVR/NVR camera system detection and fingerprinting",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=list(range(1, 65536)),
            requires_auth=False,
            performance_impact="LOW",
            priority=70,
        )

    async def scan_vulnerabilities(
        self, target_ip: str, target_port: int, service: str = "", banner: str = ""
    ) -> list[Any]:
        """
        Scan for CP Plus camera systems.

        This method is called by the plugin framework for individual port analysis.
        For multi-port scanning, detection results are aggregated.

        Args:
            target_ip: Target IP address.
            target_port: Target port number.
            service: Detected service type (unused).
            banner: Service banner (unused).

        Returns:
            List of VulnerabilityResult objects for CP Plus detection.
        """
        # Perform CP Plus detection on single port
        detection_result = self._detect_cp_plus_brand(target_ip, target_port)

        if detection_result["brand_detected"]:
            return self._convert_to_vulnerability_results(target_ip, target_port, detection_result)

        return []

    def detect_cp_plus(
        self, ip: str, open_ports: list[int], brand: str | None = None
    ) -> dict[str, Any]:
        """
        Detect CP Plus camera systems across multiple ports.

        100% feature parity with CamXploit.py fingerprint_cp_plus() (lines 1417-1453).

        Args:
            ip: Target IP address.
            open_ports: List of open ports to test.
            brand: Optional pre-detected brand (if "cp_plus", enhances detection).

        Returns:
            Dict containing:
                - 'brand_detected': Boolean indicating if CP Plus was detected
                - 'brand': Brand name ('cp_plus' or 'unknown')
                - 'model': Detected model number (e.g., 'CP-UVR-0401E1-IC2')
                - 'device_type': Device type ('dvr', 'nvr', 'unknown')
                - 'confidence': Confidence score (0.0-1.0)
                - 'evidence': List of detection evidence strings
        """
        # Check if brand already detected as CP Plus
        if brand and brand.lower() in ["cp_plus", "cpplus", "cp-plus", "cp plus"]:
            logger.info(f"CP Plus brand pre-detected for {ip}, performing detailed fingerprinting")

        # Try detection on each port
        best_result = {
            "brand_detected": False,
            "brand": "unknown",
            "model": "unknown",
            "device_type": "unknown",
            "confidence": 0.0,
            "evidence": [],
        }

        for port in open_ports:
            result = self._detect_cp_plus_brand(ip, port)

            # Keep best result (highest confidence)
            if result["confidence"] > best_result["confidence"]:
                best_result = result

            # If we have high confidence detection, stop searching
            if result["confidence"] >= 0.9:
                break

        return best_result

    def _detect_cp_plus_brand(self, ip: str, port: int) -> dict[str, Any]:
        """
        Detect CP Plus brand on a single port.

        CamXploit.py lines 1417-1453.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Dict with detection results including brand, model, device_type, confidence, evidence.
        """
        protocol = self._get_protocol(port)
        endpoints = self.cpplus_data.get("endpoints", {}).get(
            "detection", ["/", "/index.html", "/login"]
        )

        # Detection state
        brand_detected = False
        model_number = "unknown"
        device_type = "unknown"
        evidence = []
        confidence = 0.0

        # Test each endpoint (CamXploit.py lines 1422-1430)
        for endpoint in endpoints:
            url = f"{protocol}://{ip}:{port}{endpoint}"

            try:
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)

                # Only process successful responses (CamXploit.py line 1435)
                if resp.status_code == 200:
                    content = resp.text.lower()

                    # Extract model number (CamXploit.py lines 1440-1441)
                    model_number = self._extract_model_number(content, resp.text)
                    if model_number != "unknown":
                        evidence.append(f"Found model '{model_number}' in {endpoint}")
                        confidence += 0.4

                    # Detect brand (CamXploit.py lines 1442-1443)
                    if self._contains_brand_keywords(content):
                        brand_detected = True
                        evidence.append(f"Found CP Plus brand keywords in {endpoint}")
                        confidence += 0.3

                    # Detect device type (CamXploit.py lines 1444-1445)
                    detected_type = self._detect_device_type(content)
                    if detected_type != "unknown":
                        device_type = detected_type
                        evidence.append(f"Detected device type '{device_type}' in {endpoint}")
                        confidence += 0.2

                    # If we found something, we can stop (CamXploit.py line 1449)
                    if evidence:
                        break

            except Exception as e:
                # Silent failure as in CamXploit.py lines 1450-1451
                logger.debug(f"CP Plus detection failed for {url}: {e}")
                continue

        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)

        return {
            "brand_detected": brand_detected,
            "brand": "cp_plus" if brand_detected else "unknown",
            "model": model_number,
            "device_type": device_type,
            "confidence": confidence,
            "evidence": evidence,
        }

    def _extract_model_number(self, content_lower: str, content_original: str) -> str:
        """
        Extract CP Plus model number from response content.

        CamXploit.py lines 1440-1441.

        Args:
            content_lower: Response content in lowercase.
            content_original: Original response content (preserves case).

        Returns:
            Model number string or 'unknown' if not found.
        """
        # Check for UVR-0401E1 pattern (CamXploit.py line 1440)
        if "uvr-0401e1" in content_lower or "uvr0401e1" in content_lower:
            return "CP-UVR-0401E1-IC2"

        # Try to extract model number with regex pattern
        # Looking for patterns like: CP-UVR-XXXXXX, CP-DVR-XXXXXX, CP-NVR-XXXXXX
        patterns = [
            r"CP-UVR-[0-9]{4}[A-Z0-9-]*",
            r"CP-DVR-[0-9]{4}[A-Z0-9-]*",
            r"CP-NVR-[0-9]{4}[A-Z0-9-]*",
            r"UVR-[0-9]{4}[A-Z0-9-]*",
            r"DVR-[0-9]{4}[A-Z0-9-]*",
            r"NVR-[0-9]{4}[A-Z0-9-]*",
        ]

        for pattern in patterns:
            match = re.search(pattern, content_original, re.IGNORECASE)
            if match:
                model = match.group(0).upper()
                # Ensure CP- prefix
                if not model.startswith("CP-"):
                    model = "CP-" + model
                return model

        return "unknown"

    def _contains_brand_keywords(self, content: str) -> bool:
        """
        Check if content contains CP Plus brand keywords.

        CamXploit.py lines 1335-1336, 1442-1443.

        Args:
            content: Response content in lowercase.

        Returns:
            True if brand keywords found, False otherwise.
        """
        keywords = self.cpplus_data.get("detection_keywords", {}).get(
            "brand", ["cp plus", "cp-plus", "cpplus", "cp_plus"]
        )

        # Check each brand keyword
        for keyword in keywords:
            if keyword.lower() in content:
                return True

        return False

    def _detect_device_type(self, content: str) -> str:
        """
        Detect device type (DVR/NVR) from response content.

        CamXploit.py lines 1444-1445.

        Args:
            content: Response content in lowercase.

        Returns:
            Device type: 'dvr', 'nvr', or 'unknown'.
        """
        device_keywords = self.cpplus_data.get("detection_keywords", {}).get(
            "device_types", ["dvr", "nvr"]
        )

        # Check for DVR first (most common)
        if "dvr" in content:
            return "dvr"

        # Check for NVR
        if "nvr" in content:
            return "nvr"

        # Check other keywords
        for keyword in device_keywords:
            if keyword.lower() in content:
                return keyword.lower()

        return "unknown"

    def _get_protocol(self, port: int) -> str:
        """
        Determine protocol (http/https) based on port number.

        Args:
            port: Port number.

        Returns:
            'https' for SSL ports, 'http' otherwise.
        """
        # From CamXploit.py lines 793, 926-927
        https_ports = [443, 8443, 8444]
        return "https" if port in https_ports else "http"

    def _convert_to_vulnerability_results(
        self, ip: str, port: int, detection_result: dict[str, Any]
    ) -> list[Any]:
        """
        Convert detection results to VulnerabilityResult objects.

        Args:
            ip: Target IP address.
            port: Target port number.
            detection_result: Results from _detect_cp_plus_brand().

        Returns:
            List of VulnerabilityResult objects.
        """
        results = []

        if detection_result["brand_detected"]:
            vuln = self.memory_pool.acquire_vulnerability_result()
            vuln.ip = ip
            vuln.port = port
            vuln.service = "http"
            vuln.vulnerability_id = "CP-PLUS-DETECTION"
            vuln.severity = "INFO"
            vuln.confidence = int(detection_result["confidence"] * 100)
            vuln.description = (
                f"CP Plus {detection_result['device_type'].upper()} detected: "
                f"{detection_result['model']}"
            )
            vuln.exploit_available = False

            # Add details
            details = {
                "brand": detection_result["brand"],
                "model": detection_result["model"],
                "device_type": detection_result["device_type"],
                "evidence": detection_result["evidence"],
                "plugin": "cpplus_scanner",
            }
            vuln.details = json.dumps(details)

            results.append(vuln)

        return results


# Plugin instance for automatic discovery
cpplus_scanner = CPPlusScanner()
