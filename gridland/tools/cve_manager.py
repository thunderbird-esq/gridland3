"""
CVE Database Management Tool for maintaining comprehensive vulnerability intelligence.
"""

import asyncio
import aiohttp
import json
from pathlib import Path
from typing import Dict, List
import argparse

class CVEManager:
    """Manage CVE database updates and maintenance"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def update_cve_database(self, brands: List[str] = None):
        """Update CVE database with latest vulnerabilities"""

        if not brands:
            brands = ["hikvision", "dahua", "axis", "cp_plus"]

        print(f"Updating CVE database for brands: {', '.join(brands)}")

        updated_db = {"brands": {}}

        for brand in brands:
            print(f"Fetching CVEs for {brand}...")
            brand_cves = await self._fetch_brand_cves(brand)

            if brand_cves:
                updated_db["brands"][brand] = {"cves": brand_cves}
                print(f"Found {len(brand_cves)} CVEs for {brand}")

        # Save updated database
        with open(self.db_path, 'w') as f:
            json.dump(updated_db, f, indent=2)

        print(f"CVE database updated: {self.db_path}")

    async def _fetch_brand_cves(self, brand: str) -> Dict:
        """Fetch CVEs for specific brand from NVD"""

        # This is a simplified example - real implementation would
        # use NVD API with proper brand-specific queries

        brand_keywords = {
            "hikvision": ["hikvision", "hik-connect"],
            "dahua": ["dahua", "dahua technology"],
            "axis": ["axis communications", "axis"],
            "cp_plus": ["cp plus", "aditya infotech"]
        }

        keywords = brand_keywords.get(brand, [brand])
        cves = {}

        try:
            connector = aiohttp.TCPConnector()
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for keyword in keywords:
                    # NVD API query (simplified)
                    params = {
                        "keywordSearch": keyword,
                        "resultsPerPage": 50
                    }

                    async with session.get(self.nvd_base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()

                            # Parse NVD response (simplified)
                            for cve_item in data.get("vulnerabilities", []):
                                cve_data = cve_item.get("cve", {})
                                cve_id = cve_data.get("id", "")

                                if cve_id:
                                    cves[cve_id] = self._parse_nvd_cve(cve_data)

        except Exception as e:
            print(f"Error fetching CVEs for {brand}: {e}")

        return cves

    def _parse_nvd_cve(self, cve_data: Dict) -> Dict:
        """Parse NVD CVE data into our format"""

        # Simplified parsing - real implementation would be more comprehensive
        return {
            "severity": "HIGH",  # Would extract from CVSS
            "cvss_score": 7.5,   # Would extract actual score
            "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
            "affected_versions": [],  # Would extract from configurations
            "affected_products": [],  # Would extract from configurations
            "exploit_public": False,  # Would check exploit databases
            "exploit_difficulty": "MEDIUM",
            "attack_vector": "NETWORK",
            "references": [ref.get("url", "") for ref in cve_data.get("references", [])],
            "detection_patterns": []  # Would be manually curated
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE Database Manager")
    parser.add_argument("--update", action="store_true", help="Update CVE database")
    parser.add_argument("--brands", nargs="+", help="Specific brands to update")
    parser.add_argument("--db-path", default="gridland/data/cve_database.json", help="Database path")

    args = parser.parse_args()

    if args.update:
        manager = CVEManager(Path(args.db_path))
        asyncio.run(manager.update_cve_database(args.brands))
