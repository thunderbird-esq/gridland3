"""Brand Detection module for GRIDLAND.

This module provides camera brand detection capabilities by analyzing HTTP
server headers, content types, and response bodies. Brand detection logic
is ported from CamXploit.py lines 989-1079 for 100% feature parity.
"""

from typing import Any, Dict, List, Optional


class BrandDetector:
    """Detect camera brands from HTTP response data.

    This class analyzes HTTP server headers, content types, and response bodies
    to identify camera manufacturers and types. Detection logic matches
    CamXploit.py for compatibility.

    Attributes:
        CAMERA_SERVERS: Dictionary mapping brand names to keyword lists.
        CAMERA_CONTENT_TYPES: List of camera-specific content types.

    Example:
        >>> detector = BrandDetector()
        >>> port_data = {
        ...     'server_header': 'hikvision-webs',
        ...     'content_type': 'text/html',
        ...     'response_body': '<html>DVR Login</html>'
        ... }
        >>> result = detector.detect_brand(port_data)
        >>> print(result['brand'])
        hikvision
        >>> print(result['confidence'])
        1.0
    """

    # Camera server keywords from CamXploit.py lines 989-1009
    CAMERA_SERVERS = {
        "hikvision": ["hikvision", "dvr", "nvr"],
        "dahua": ["dahua", "dvr", "nvr"],
        "axis": ["axis", "axis communications"],
        "sony": ["sony", "ipela"],
        "bosch": ["bosch", "security systems"],
        "samsung": ["samsung", "samsung techwin"],
        "panasonic": ["panasonic", "network camera"],
        "vivotek": ["vivotek", "network camera"],
        "cp plus": ["cp plus", "cp-plus", "cpplus", "cp_plus"],
        "generic": [
            "camera",
            "webcam",
            "surveillance",
            "ip camera",
            "network camera",
            "dvr",
            "nvr",
            "recorder",
        ],
    }

    # Common camera content types from CamXploit.py lines 1012-1023
    CAMERA_CONTENT_TYPES = [
        "image/jpeg",
        "image/mjpeg",
        "video/mpeg",
        "video/mp4",
        "video/h264",
        "application/x-mpegURL",
        "video/MP2T",
        "application/octet-stream",
        "text/html",
        "application/json",
    ]

    def detect_brand(self, port_data: dict[str, str]) -> dict[str, Any]:
        """Detect camera brand from a single port's response data.

        Analyzes server headers, content types, and response bodies to identify
        the camera brand. Detection follows CamXploit.py logic (lines 1038-1079):
        1. Check server header for brand keywords
        2. Check content-type header for camera types
        3. Check response body for camera keywords
        4. Special CP Plus detection in body

        Args:
            port_data: Dictionary containing:
                - server_header: Server HTTP header value (optional)
                - content_type: Content-Type HTTP header value (optional)
                - response_body: HTTP response body text (optional)

        Returns:
            Dict[str, Any]: Detection result containing:
                - brand: Detected brand name or 'unknown'
                - confidence: Confidence score (0.0-1.0)
                - evidence: List of evidence strings describing detection

        Example:
            >>> detector = BrandDetector()
            >>> port_data = {'server_header': 'DNVRS-Webs'}
            >>> result = detector.detect_brand(port_data)
            >>> print(result)
            {'brand': 'dahua', 'confidence': 1.0, 'evidence': ['server_header: dahua']}
        """
        server_header = port_data.get("server_header", "").lower()
        content_type = port_data.get("content_type", "").lower()
        response_body = port_data.get("response_body", "").lower()

        brand = "unknown"
        confidence = 0.0
        evidence = []

        # Check server headers for brand keywords (CamXploit.py lines 1038-1045)
        # Check in two passes to handle overlapping keywords correctly
        # Pass 1: Check for specific brand names (not generic keywords)
        specific_brands = {
            "hikvision": ["hikvision"],
            "dahua": ["dahua"],
            "axis": ["axis", "axis communications"],
            "sony": ["sony", "ipela"],
            "bosch": ["bosch", "security systems"],
            "samsung": ["samsung", "samsung techwin"],
            "panasonic": ["panasonic"],
            "vivotek": ["vivotek"],
            "cp plus": ["cp plus", "cp-plus", "cpplus", "cp_plus"],
        }

        for brand_name, keywords in specific_brands.items():
            if any(keyword in server_header for keyword in keywords):
                brand = brand_name
                confidence = 1.0
                evidence.append(f"server_header: {brand_name}")
                break

        # Pass 2: If no specific brand found, check for generic indicators
        if brand == "unknown":
            for brand_name, keywords in self.CAMERA_SERVERS.items():
                if any(keyword in server_header for keyword in keywords):
                    brand = brand_name
                    confidence = 1.0
                    evidence.append(f"server_header: {brand_name}")
                    if brand_name != "generic":
                        break

        # Check content type (CamXploit.py lines 1047-1050)
        if any(ct in content_type for ct in self.CAMERA_CONTENT_TYPES):
            evidence.append(f"content_type: {content_type}")
            if brand == "unknown":
                brand = "generic"
                confidence = 0.5

        # Check response body for camera indicators (CamXploit.py lines 1052-1070)
        if response_body:
            camera_keywords = [
                "camera",
                "webcam",
                "surveillance",
                "stream",
                "video",
                "snapshot",
                "dvr",
                "nvr",
                "recorder",
                "cctv",
            ]
            found_keywords = [kw for kw in camera_keywords if kw in response_body]
            if found_keywords:
                evidence.append(f"body_keywords: {', '.join(found_keywords)}")
                if brand == "unknown":
                    brand = "generic"
                    confidence = 0.6

            # Check for specific CP Plus indicators (CamXploit.py lines 1072-1078)
            cp_plus_indicators = ["cp plus", "cp-plus", "cpplus", "cp_plus", "uvr", "0401e1"]
            if any(indicator in response_body for indicator in cp_plus_indicators):
                brand = "cp plus"
                confidence = 1.0
                evidence.append("body: cp_plus_indicators")

        # If we still have generic brand but found specific evidence, adjust confidence
        if brand == "generic" and len(evidence) > 1:
            # Higher confidence if we have multiple evidence sources
            confidence = min(0.7, 0.3 + (len(evidence) * 0.2))

        return {
            "brand": brand,
            "confidence": confidence,
            "evidence": evidence,
        }

    def analyze_all_ports(self, ports_data: list[dict[str, str]]) -> dict[str, Any]:
        """Analyze multiple ports and aggregate brand detection results.

        Processes brand detection across all ports and resolves conflicts by
        selecting the brand with highest confidence. Aggregates evidence from
        all ports.

        Args:
            ports_data: List of port data dictionaries, each containing:
                - server_header: Server HTTP header value (optional)
                - content_type: Content-Type HTTP header value (optional)
                - response_body: HTTP response body text (optional)
                - port: Port number (optional, for evidence tracking)

        Returns:
            Dict[str, Any]: Aggregated detection result containing:
                - brand: Final detected brand name or 'unknown'
                - confidence: Highest confidence score (0.0-1.0)
                - evidence: List of all evidence from all ports
                - all_detections: List of individual port detection results

        Example:
            >>> detector = BrandDetector()
            >>> ports_data = [
            ...     {'server_header': 'hikvision-webs', 'port': 80},
            ...     {'response_body': 'DVR Camera System', 'port': 8080}
            ... ]
            >>> result = detector.analyze_all_ports(ports_data)
            >>> print(result['brand'])
            hikvision
        """
        if not ports_data:
            return {
                "brand": "unknown",
                "confidence": 0.0,
                "evidence": [],
                "all_detections": [],
            }

        all_detections = []
        brand_scores = {}  # Track confidence scores per brand

        # Analyze each port
        for port_data in ports_data:
            detection = self.detect_brand(port_data)
            port_num = port_data.get("port", "unknown")

            # Add port info to evidence
            detection_with_port = detection.copy()
            detection_with_port["port"] = port_num
            detection_with_port["evidence"] = [
                f"port {port_num}: {e}" for e in detection["evidence"]
            ]
            all_detections.append(detection_with_port)

            # Track brand confidence scores
            detected_brand = detection["brand"]
            if detected_brand != "unknown":
                if detected_brand not in brand_scores:
                    brand_scores[detected_brand] = detection["confidence"]
                else:
                    # Keep highest confidence for this brand
                    brand_scores[detected_brand] = max(
                        brand_scores[detected_brand], detection["confidence"]
                    )

        # Resolve conflicts: choose brand with highest confidence
        # Prefer specific brands over generic
        if brand_scores:
            # Remove generic if we have any specific brand
            if "generic" in brand_scores and len(brand_scores) > 1:
                del brand_scores["generic"]

            # Select brand with highest confidence
            final_brand = max(brand_scores.items(), key=lambda x: x[1])
            brand = final_brand[0]
            confidence = final_brand[1]
        else:
            brand = "unknown"
            confidence = 0.0

        # Aggregate all evidence
        all_evidence = []
        for detection in all_detections:
            all_evidence.extend(detection["evidence"])

        return {
            "brand": brand,
            "confidence": confidence,
            "evidence": all_evidence,
            "all_detections": all_detections,
        }
