"""
CVE Correlation Scanner with comprehensive vulnerability intelligence.
Correlates device fingerprints with known CVEs and provides detailed assessment.
"""

import asyncio
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import re

from gridland.analyze.memory.pool import get_memory_pool, VulnerabilityResult
from gridland.analyze.plugins.manager import VulnerabilityPlugin, PluginMetadata
from gridland.core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class CVEMatch:
    """CVE match with detailed vulnerability information"""
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_versions: List[str]
    affected_products: List[str]
    exploit_public: bool
    exploit_difficulty: str
    attack_vector: str
    references: List[str]
    detection_confidence: float
    match_reason: str

class CVECorrelationScanner(VulnerabilityPlugin):
    """
    Advanced CVE correlation scanner with comprehensive vulnerability intelligence.

    Correlates detected device information with known CVEs and provides
    detailed vulnerability assessments with exploit information.
    """

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            name="CVE Correlation Scanner",
            version="2.0.0",
            author="GRIDLAND Security Team",
            plugin_type="vulnerability",
            supported_services=["http", "https"],
            supported_ports=[80, 443, 8080, 8443, 8000, 8001],
            description="Comprehensive CVE correlation with detailed vulnerability intelligence"
        )
        self.cve_database = self._load_cve_database()
        self.memory_pool = get_memory_pool()

    def _load_cve_database(self) -> Dict:
        """Load comprehensive CVE database"""
        try:
            db_path = Path(__file__).parent.parent.parent.parent / "data" / "cve_database.json"
            with open(db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load CVE database: {e}, using defaults")
            return self._get_default_cve_database()

    def _get_default_cve_database(self) -> Dict:
        """Fallback CVE database with essential vulnerabilities"""
        return {
            "brands": {
                "hikvision": {
                    "cves": {
                        "CVE-2017-7921": {
                            "severity": "CRITICAL",
                            "cvss_score": 9.8,
                            "description": "Authentication bypass vulnerability",
                            "affected_versions": ["5.4.1", "5.4.0"],
                            "exploit_public": True,
                            "detection_patterns": ["/System/configurationFile"]
                        }
                    }
                }
            }
        }

    async def scan_vulnerabilities(self, target_ip: str, target_port: int,
                                    service: str, banner: str) -> List[VulnerabilityResult]:
        """Correlate device information with CVE database"""

        # This plugin works in conjunction with fingerprinting results
        # In a real implementation, it would receive device fingerprint data
        # For now, we'll demonstrate with banner analysis

        if not banner:
            return []

        detected_brand = self._detect_brand_from_banner(banner)
        if not detected_brand:
            return []

        # Get CVEs for detected brand
        brand_cves = self.cve_database.get("brands", {}).get(detected_brand, {}).get("cves", {})

        if not brand_cves:
            return []

        # Correlate with detected information
        cve_matches = await self._correlate_cves(brand_cves, banner, detected_brand)

        # Generate vulnerability results
        return self._generate_cve_results(cve_matches, target_ip, target_port)

    def _detect_brand_from_banner(self, banner: str) -> Optional[str]:
        """Detect brand from banner for CVE correlation"""

        banner_lower = banner.lower()

        brand_patterns = {
            'hikvision': ['hikvision', 'dvr', 'web server'],
            'dahua': ['dahua', 'dvr'],
            'axis': ['axis', 'axis communications'],
            'cp_plus': ['cp plus', 'cp-plus', 'cpplus', 'guardian']
        }

        for brand, patterns in brand_patterns.items():
            if any(pattern in banner_lower for pattern in patterns):
                return brand

        return None

    async def _correlate_cves(self, brand_cves: Dict, banner: str, brand: str) -> List[CVEMatch]:
        """Correlate detected information with brand CVEs"""

        matches = []

        for cve_id, cve_data in brand_cves.items():
            confidence = await self._calculate_cve_confidence(cve_data, banner, brand)

            if confidence >= 0.5:  # Minimum confidence threshold
                match_reason = self._determine_match_reason(cve_data, banner)

                cve_match = CVEMatch(
                    cve_id=cve_id,
                    severity=cve_data.get("severity", "UNKNOWN"),
                    cvss_score=cve_data.get("cvss_score", 0.0),
                    description=cve_data.get("description", ""),
                    affected_versions=cve_data.get("affected_versions", []),
                    affected_products=cve_data.get("affected_products", []),
                    exploit_public=cve_data.get("exploit_public", False),
                    exploit_difficulty=cve_data.get("exploit_difficulty", "UNKNOWN"),
                    attack_vector=cve_data.get("attack_vector", "UNKNOWN"),
                    references=cve_data.get("references", []),
                    detection_confidence=confidence,
                    match_reason=match_reason
                )

                matches.append(cve_match)

        # Sort by severity and confidence
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        matches.sort(key=lambda m: (severity_order.get(m.severity, 0), m.detection_confidence), reverse=True)

        return matches

    async def _calculate_cve_confidence(self, cve_data: Dict, banner: str, brand: str) -> float:
        """Calculate confidence that CVE applies to this device"""

        confidence = 0.5  # Base confidence for brand match

        # Check detection patterns
        detection_patterns = cve_data.get("detection_patterns", [])
        for pattern in detection_patterns:
            if pattern.lower() in banner.lower():
                confidence += 0.2

        # Check affected products (if available in banner)
        affected_products = cve_data.get("affected_products", [])
        for product in affected_products:
            if product.lower() in banner.lower():
                confidence += 0.15

        # Higher confidence for newer CVEs (approximate)
        cve_year = self._extract_cve_year(cve_data.get("cve_id", ""))
        if cve_year >= 2022:
            confidence += 0.1
        elif cve_year >= 2020:
            confidence += 0.05

        return min(confidence, 0.95)  # Cap at 95%

    def _extract_cve_year(self, cve_id: str) -> int:
        """Extract year from CVE ID"""
        match = re.search(r'CVE-(\d{4})-', cve_id)
        return int(match.group(1)) if match else 2000

    def _determine_match_reason(self, cve_data: Dict, banner: str) -> str:
        """Determine reason for CVE match"""

        reasons = []

        # Brand match
        reasons.append("Brand identification")

        # Pattern matches
        detection_patterns = cve_data.get("detection_patterns", [])
        matched_patterns = [p for p in detection_patterns if p.lower() in banner.lower()]
        if matched_patterns:
            reasons.append(f"Detection patterns: {', '.join(matched_patterns[:2])}")

        # Product matches
        affected_products = cve_data.get("affected_products", [])
        matched_products = [p for p in affected_products if p.lower() in banner.lower()]
        if matched_products:
            reasons.append(f"Product match: {matched_products[0]}")

        return " | ".join(reasons)

    def _generate_cve_results(self, cve_matches: List[CVEMatch],
                            target_ip: str, target_port: int) -> List[VulnerabilityResult]:
        """Generate vulnerability results for CVE matches"""

        results = []

        for match in cve_matches[:10]:  # Limit to top 10 matches
            vuln_result = self.memory_pool.acquire_vulnerability_result()
            vuln_result.vulnerability_id = f"cve-{match.cve_id.lower().replace('-', '_')}"
            vuln_result.severity = match.severity
            vuln_result.confidence = match.detection_confidence
            vuln_result.description = f"{match.cve_id}: {match.description}"
            vuln_result.exploit_available = match.exploit_public

            results.append(vuln_result)

        # Generate summary result if multiple CVEs found
        if len(cve_matches) > 1:
            summary_result = self.memory_pool.acquire_vulnerability_result()
            summary_result.vulnerability_id = "cve-correlation-summary"
            summary_result.severity = "INFO"
            summary_result.confidence = 0.90
            summary_result.description = f"CVE correlation completed: {len(cve_matches)} potential vulnerabilities identified"
            summary_result.exploit_available = any(match.exploit_public for match in cve_matches)

            results.append(summary_result)

        return results
