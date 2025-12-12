"""CVE Lookup module for GRIDLAND.

This module provides CVE (Common Vulnerabilities and Exposures) lookup
capabilities for camera brands. It integrates with the CVE database from
Phase 1 and generates NVD (National Vulnerability Database) URLs for
detailed vulnerability information.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from gridland.core.data_loader import get_cves_by_brand, load_cve_database


class CVELookup:
    """Lookup CVE vulnerabilities for camera brands.

    This class provides methods to retrieve CVE information from the local
    database and generate URLs to the National Vulnerability Database for
    detailed vulnerability information.

    Example:
        >>> lookup = CVELookup()
        >>> cves = lookup.get_cves('hikvision')
        >>> print(len(cves))
        12
        >>> urls = lookup.generate_nvd_urls(cves)
        >>> print(urls[0])
        https://nvd.nist.gov/vuln/detail/CVE-2021-36260
    """

    def __init__(self):
        """Initialize CVE Lookup with the CVE database.

        Loads the CVE database from gridland/data/cve_database.json on
        initialization.
        """
        self._cve_database = load_cve_database()

    def get_cves(
        self,
        brand: str,
        severity: str | None = None,
        exploits_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get CVEs for a specific camera brand.

        Retrieves CVE information from the local database, with optional
        filtering by severity level and exploit availability.

        Args:
            brand: Camera brand name (hikvision, dahua, axis, cp_plus).
            severity: Optional severity filter (critical, high, medium, low).
            exploits_only: If True, return only CVEs with public exploits.

        Returns:
            List[Dict[str, Any]]: List of CVE dictionaries, each containing:
                - cve_id: CVE identifier
                - cvss_score: CVSS v3 score (0.0-10.0)
                - severity: Severity rating
                - description: Vulnerability description
                - affected_versions: List of affected versions
                - exploit_available: Boolean for exploit availability
                - exploit_references: List of reference URLs
                - year: Year of disclosure

        Raises:
            KeyError: If the specified brand does not exist in database.

        Example:
            >>> lookup = CVELookup()
            >>> cves = lookup.get_cves('hikvision', severity='critical')
            >>> print(len(cves))
            2
            >>> exploitable = lookup.get_cves('dahua', exploits_only=True)
            >>> print(len(exploitable))
            2
        """
        # Get CVEs for the brand
        try:
            cves = get_cves_by_brand(brand)
        except KeyError:
            # Return empty list for unknown brands
            return []

        # Apply severity filter if specified
        if severity:
            cves = [cve for cve in cves if cve.get("severity") == severity]

        # Apply exploit filter if specified
        if exploits_only:
            cves = [cve for cve in cves if cve.get("exploit_available", False)]

        return cves

    def generate_nvd_urls(self, cves: list[dict[str, Any]]) -> list[str]:
        """Generate NVD URLs for a list of CVEs.

        Creates properly formatted URLs to the National Vulnerability Database
        for each CVE. URL format matches CamXploit.py line 1309.

        Args:
            cves: List of CVE dictionaries with 'cve_id' keys.

        Returns:
            List[str]: List of NVD URLs in format:
                      https://nvd.nist.gov/vuln/detail/{cve_id}

        Example:
            >>> lookup = CVELookup()
            >>> cves = lookup.get_cves('hikvision')
            >>> urls = lookup.generate_nvd_urls(cves)
            >>> print(urls[0])
            https://nvd.nist.gov/vuln/detail/CVE-2021-36260
        """
        return [f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}" for cve in cves]

    def get_cve_by_id(self, cve_id: str) -> dict[str, Any] | None:
        """Get a specific CVE by its CVE ID.

        Searches the entire database for a CVE with the specified ID.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-36260').

        Returns:
            Optional[Dict[str, Any]]: CVE dictionary if found, None otherwise.

        Example:
            >>> lookup = CVELookup()
            >>> cve = lookup.get_cve_by_id('CVE-2021-36260')
            >>> print(cve['severity'])
            critical
        """
        for brand, cves in self._cve_database["brands"].items():
            for cve in cves:
                if cve["cve_id"] == cve_id:
                    # Add brand information
                    cve_with_brand = cve.copy()
                    cve_with_brand["brand"] = brand
                    return cve_with_brand
        return None

    def get_available_brands(self) -> list[str]:
        """Get list of available brands in the CVE database.

        Returns:
            List[str]: List of brand names.

        Example:
            >>> lookup = CVELookup()
            >>> brands = lookup.get_available_brands()
            >>> print(brands)
            ['hikvision', 'dahua', 'axis', 'cp_plus']
        """
        return list(self._cve_database["brands"].keys())

    def get_cve_statistics(self, brand: str | None = None) -> dict[str, Any]:
        """Get CVE statistics for a brand or entire database.

        Args:
            brand: Optional brand name. If None, returns global statistics.

        Returns:
            Dict[str, Any]: Statistics dictionary containing counts by
                           severity, exploit availability, etc.

        Example:
            >>> lookup = CVELookup()
            >>> stats = lookup.get_cve_statistics('hikvision')
            >>> print(stats['total'])
            12
            >>> print(stats['by_severity']['critical'])
            2
        """
        if brand:
            cves = self.get_cves(brand)
        else:
            # Get all CVEs
            cves = []
            for b in self.get_available_brands():
                cves.extend(self.get_cves(b))

        # Calculate statistics
        total = len(cves)
        by_severity = {
            "critical": len([c for c in cves if c["severity"] == "critical"]),
            "high": len([c for c in cves if c["severity"] == "high"]),
            "medium": len([c for c in cves if c["severity"] == "medium"]),
            "low": len([c for c in cves if c["severity"] == "low"]),
        }
        with_exploits = len([c for c in cves if c.get("exploit_available", False)])

        return {
            "total": total,
            "by_severity": by_severity,
            "with_exploits": with_exploits,
        }
