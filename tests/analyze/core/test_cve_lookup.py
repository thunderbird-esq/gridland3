"""Unit tests for CVE Lookup.

Tests CVE retrieval, filtering, and NVD URL generation.
"""

from gridland.analyze.core.cve_lookup import CVELookup


class TestCVELookup:
    """Tests for CVELookup class."""

    def test_initialization(self):
        """Test CVELookup initialization loads database."""
        lookup = CVELookup()
        assert hasattr(lookup, "_cve_database")
        assert isinstance(lookup._cve_database, dict)
        assert "brands" in lookup._cve_database

    def test_get_cves_hikvision(self):
        """Test retrieving CVEs for Hikvision brand."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision")

        assert isinstance(cves, list)
        assert len(cves) == 12
        assert all("cve_id" in cve for cve in cves)
        assert all("severity" in cve for cve in cves)

    def test_get_cves_dahua(self):
        """Test retrieving CVEs for Dahua brand."""
        lookup = CVELookup()
        cves = lookup.get_cves("dahua")

        assert isinstance(cves, list)
        assert len(cves) == 12

    def test_get_cves_axis(self):
        """Test retrieving CVEs for Axis brand."""
        lookup = CVELookup()
        cves = lookup.get_cves("axis")

        assert isinstance(cves, list)
        assert len(cves) == 12

    def test_get_cves_cp_plus(self):
        """Test retrieving CVEs for CP Plus brand."""
        lookup = CVELookup()
        cves = lookup.get_cves("cp_plus")

        assert isinstance(cves, list)
        assert len(cves) == 3

    def test_get_cves_unknown_brand(self):
        """Test retrieving CVEs for unknown brand returns empty list."""
        lookup = CVELookup()
        cves = lookup.get_cves("unknown_brand")

        assert isinstance(cves, list)
        assert len(cves) == 0

    def test_get_cves_severity_filter_critical(self):
        """Test filtering CVEs by critical severity."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision", severity="critical")

        assert isinstance(cves, list)
        assert all(cve["severity"] == "critical" for cve in cves)
        assert len(cves) == 2  # Hikvision has 2 critical CVEs

    def test_get_cves_severity_filter_high(self):
        """Test filtering CVEs by high severity."""
        lookup = CVELookup()
        cves = lookup.get_cves("dahua", severity="high")

        assert isinstance(cves, list)
        assert all(cve["severity"] == "high" for cve in cves)

    def test_get_cves_severity_filter_medium(self):
        """Test filtering CVEs by medium severity."""
        lookup = CVELookup()
        cves = lookup.get_cves("axis", severity="medium")

        assert isinstance(cves, list)
        assert all(cve["severity"] == "medium" for cve in cves)

    def test_get_cves_exploits_only(self):
        """Test filtering CVEs with public exploits."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision", exploits_only=True)

        assert isinstance(cves, list)
        assert all(cve.get("exploit_available", False) for cve in cves)
        assert len(cves) == 2  # Hikvision has 2 CVEs with exploits

    def test_get_cves_combined_filters(self):
        """Test combining severity and exploit filters."""
        lookup = CVELookup()
        cves = lookup.get_cves("dahua", severity="critical", exploits_only=True)

        assert isinstance(cves, list)
        assert all(cve["severity"] == "critical" for cve in cves)
        assert all(cve.get("exploit_available", False) for cve in cves)

    def test_generate_nvd_urls_single_cve(self):
        """Test NVD URL generation for single CVE."""
        lookup = CVELookup()
        cves = [{"cve_id": "CVE-2021-36260"}]
        urls = lookup.generate_nvd_urls(cves)

        assert isinstance(urls, list)
        assert len(urls) == 1
        assert urls[0] == "https://nvd.nist.gov/vuln/detail/CVE-2021-36260"

    def test_generate_nvd_urls_multiple_cves(self):
        """Test NVD URL generation for multiple CVEs."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision")
        urls = lookup.generate_nvd_urls(cves)

        assert isinstance(urls, list)
        assert len(urls) == len(cves)
        assert all(url.startswith("https://nvd.nist.gov/vuln/detail/CVE-") for url in urls)

    def test_generate_nvd_urls_format(self):
        """Test NVD URL format matches CamXploit.py."""
        lookup = CVELookup()
        cves = [
            {"cve_id": "CVE-2021-36260"},
            {"cve_id": "CVE-2017-7921"},
        ]
        urls = lookup.generate_nvd_urls(cves)

        assert urls[0] == "https://nvd.nist.gov/vuln/detail/CVE-2021-36260"
        assert urls[1] == "https://nvd.nist.gov/vuln/detail/CVE-2017-7921"

    def test_generate_nvd_urls_empty_list(self):
        """Test NVD URL generation with empty CVE list."""
        lookup = CVELookup()
        urls = lookup.generate_nvd_urls([])

        assert isinstance(urls, list)
        assert len(urls) == 0

    def test_get_cve_by_id_found(self):
        """Test retrieving specific CVE by ID."""
        lookup = CVELookup()
        cve = lookup.get_cve_by_id("CVE-2021-36260")

        assert cve is not None
        assert cve["cve_id"] == "CVE-2021-36260"
        assert "brand" in cve
        assert cve["brand"] == "hikvision"

    def test_get_cve_by_id_not_found(self):
        """Test retrieving non-existent CVE by ID."""
        lookup = CVELookup()
        cve = lookup.get_cve_by_id("CVE-9999-99999")

        assert cve is None

    def test_get_available_brands(self):
        """Test getting list of available brands."""
        lookup = CVELookup()
        brands = lookup.get_available_brands()

        assert isinstance(brands, list)
        assert len(brands) == 4
        assert "hikvision" in brands
        assert "dahua" in brands
        assert "axis" in brands
        assert "cp_plus" in brands

    def test_get_cve_statistics_hikvision(self):
        """Test getting CVE statistics for Hikvision."""
        lookup = CVELookup()
        stats = lookup.get_cve_statistics("hikvision")

        assert isinstance(stats, dict)
        assert "total" in stats
        assert stats["total"] == 12
        assert "by_severity" in stats
        assert "with_exploits" in stats
        assert stats["with_exploits"] == 2

    def test_get_cve_statistics_global(self):
        """Test getting global CVE statistics."""
        lookup = CVELookup()
        stats = lookup.get_cve_statistics()

        assert isinstance(stats, dict)
        assert stats["total"] == 39  # Total CVEs across all brands
        assert stats["by_severity"]["critical"] == 5
        assert stats["by_severity"]["high"] == 22
        assert stats["by_severity"]["medium"] == 12
        assert stats["with_exploits"] == 5

    def test_get_cve_statistics_by_severity(self):
        """Test CVE statistics severity breakdown."""
        lookup = CVELookup()
        stats = lookup.get_cve_statistics("dahua")

        assert "by_severity" in stats
        assert "critical" in stats["by_severity"]
        assert "high" in stats["by_severity"]
        assert "medium" in stats["by_severity"]
        assert "low" in stats["by_severity"]

    def test_cve_structure_complete(self):
        """Test that CVE structure contains all required fields."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision")

        assert len(cves) > 0
        cve = cves[0]
        assert "cve_id" in cve
        assert "cvss_score" in cve
        assert "severity" in cve
        assert "description" in cve
        assert "affected_versions" in cve
        assert "exploit_available" in cve
        assert "year" in cve

    def test_cve_cvss_scores_valid(self):
        """Test that CVSS scores are in valid range."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision")

        for cve in cves:
            assert 0.0 <= cve["cvss_score"] <= 10.0

    def test_cve_severity_levels_valid(self):
        """Test that severity levels are valid."""
        lookup = CVELookup()
        valid_severities = ["critical", "high", "medium", "low"]

        for brand in lookup.get_available_brands():
            cves = lookup.get_cves(brand)
            for cve in cves:
                assert cve["severity"] in valid_severities

    def test_get_cves_preserves_all_fields(self):
        """Test that get_cves preserves all CVE fields."""
        lookup = CVELookup()
        cves = lookup.get_cves("axis")

        assert len(cves) > 0
        cve = cves[0]
        # Check that filtering doesn't remove fields
        assert isinstance(cve["affected_versions"], list)
        assert isinstance(cve["description"], str)
        assert isinstance(cve["exploit_available"], bool)

    def test_nvd_url_integration(self):
        """Test complete workflow of getting CVEs and generating URLs."""
        lookup = CVELookup()

        # Get critical CVEs for Hikvision
        cves = lookup.get_cves("hikvision", severity="critical")
        urls = lookup.generate_nvd_urls(cves)

        assert len(urls) == len(cves)
        for url in urls:
            assert url.startswith("https://nvd.nist.gov/vuln/detail/")
            assert "CVE-" in url

    def test_exploit_available_field_type(self):
        """Test that exploit_available field is boolean."""
        lookup = CVELookup()
        cves = lookup.get_cves("hikvision")

        for cve in cves:
            assert isinstance(cve["exploit_available"], bool)

    def test_cve_id_format(self):
        """Test that CVE IDs follow correct format."""
        lookup = CVELookup()
        cves = lookup.get_cves("dahua")

        for cve in cves:
            cve_id = cve["cve_id"]
            assert cve_id.startswith("CVE-")
            assert len(cve_id.split("-")) == 3

    def test_get_cve_by_id_includes_all_fields(self):
        """Test that get_cve_by_id returns complete CVE data."""
        lookup = CVELookup()
        cve = lookup.get_cve_by_id("CVE-2021-36260")

        assert cve is not None
        assert "cve_id" in cve
        assert "cvss_score" in cve
        assert "severity" in cve
        assert "description" in cve
        assert "brand" in cve

    def test_multiple_severity_filters(self):
        """Test applying different severity filters."""
        lookup = CVELookup()

        critical = lookup.get_cves("hikvision", severity="critical")
        high = lookup.get_cves("hikvision", severity="high")
        medium = lookup.get_cves("hikvision", severity="medium")

        # Verify no overlap
        critical_ids = {cve["cve_id"] for cve in critical}
        high_ids = {cve["cve_id"] for cve in high}
        medium_ids = {cve["cve_id"] for cve in medium}

        assert not (critical_ids & high_ids)  # No intersection
        assert not (critical_ids & medium_ids)
        assert not (high_ids & medium_ids)
