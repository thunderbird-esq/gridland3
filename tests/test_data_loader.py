"""
Unit tests for the data_loader module.

Tests all data loading functions for camera ports, login paths, and CVE database.
Validates data integrity, structure, and counts.
"""

import json
from pathlib import Path

import pytest

from gridland.core.data_loader import (  # Port functions; Login path functions; CVE functions
    get_all_cves,
    get_all_login_paths,
    get_all_ports,
    get_cve_brands,
    get_cve_statistics,
    get_cves_by_brand,
    get_cves_by_severity,
    get_cves_with_exploits,
    get_login_path_brands,
    get_login_paths_by_auth_type,
    get_login_paths_by_brand,
    get_metadata,
    get_port_categories,
    get_ports_by_category,
    load_camera_ports,
    load_cve_database,
    load_login_paths,
)

# ============================================================================
# Camera Ports Tests
# ============================================================================


class TestCameraPorts:
    """Tests for camera port loading and querying functions."""

    def test_load_camera_ports_structure(self):
        """Test that camera_ports.json loads with correct structure."""
        ports_data = load_camera_ports()

        assert "metadata" in ports_data
        assert "categories" in ports_data
        assert isinstance(ports_data["metadata"], dict)
        assert isinstance(ports_data["categories"], dict)

    def test_load_camera_ports_metadata(self):
        """Test metadata contains required fields."""
        metadata = get_metadata()

        assert "version" in metadata
        assert "source" in metadata
        assert "total_ports" in metadata
        assert "description" in metadata
        assert metadata["source"] == "CamXploit.py"

    def test_port_count_matches_camxploit(self):
        """Test that we have exactly 685 unique ports from CamXploit.py."""
        all_ports = get_all_ports()

        # CamXploit.py has 688 total ports but 685 unique (3 duplicates)
        assert len(all_ports) == 685

        # Verify all are unique
        assert len(all_ports) == len(set(all_ports))

        # Verify sorted
        assert all_ports == sorted(all_ports)

    def test_port_categories_exist(self):
        """Test that all expected port categories exist."""
        categories = get_port_categories()

        expected_categories = ["web", "rtsp", "rtmp", "mms", "onvif", "custom"]
        assert set(categories) == set(expected_categories)

    def test_get_ports_by_category_web(self):
        """Test retrieving web ports."""
        web_ports = get_ports_by_category("web")

        assert isinstance(web_ports, list)
        assert len(web_ports) > 0
        assert 80 in web_ports
        assert 443 in web_ports
        assert 8080 in web_ports

    def test_get_ports_by_category_rtsp(self):
        """Test retrieving RTSP ports."""
        rtsp_ports = get_ports_by_category("rtsp")

        assert isinstance(rtsp_ports, list)
        assert len(rtsp_ports) == 11
        assert 554 in rtsp_ports
        assert 8554 in rtsp_ports

    def test_get_ports_by_category_onvif(self):
        """Test retrieving ONVIF ports."""
        onvif_ports = get_ports_by_category("onvif")

        assert isinstance(onvif_ports, list)
        assert len(onvif_ports) == 9
        assert 3702 in onvif_ports
        assert all(3702 <= port <= 3710 for port in onvif_ports)

    def test_get_ports_by_category_invalid(self):
        """Test that invalid category raises KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_ports_by_category("invalid_category")

        assert "invalid_category" in str(exc_info.value)
        assert "Available categories" in str(exc_info.value)

    def test_all_ports_sum_matches_categories(self):
        """Test that sum of all category ports matches total unique ports."""
        all_ports = get_all_ports()
        categories = get_port_categories()

        category_ports = set()
        for category in categories:
            ports = get_ports_by_category(category)
            category_ports.update(ports)

        assert len(category_ports) == len(all_ports)
        assert set(all_ports) == category_ports

    def test_port_ranges_valid(self):
        """Test that all ports are in valid range 1-65535."""
        all_ports = get_all_ports()

        assert all(1 <= port <= 65535 for port in all_ports)

    def test_standard_camera_ports_present(self):
        """Test that standard camera ports are present."""
        all_ports = get_all_ports()

        # Standard ports that must be present
        required_ports = [80, 443, 554, 8080, 8443, 37777]
        for port in required_ports:
            assert port in all_ports, f"Required port {port} not found"


# ============================================================================
# Login Paths Tests
# ============================================================================


class TestLoginPaths:
    """Tests for login path loading and querying functions."""

    def test_load_login_paths_structure(self):
        """Test that login_paths.json loads with correct structure."""
        login_data = load_login_paths()

        assert "version" in login_data
        assert "categories" in login_data
        assert "total_paths" in login_data
        assert "auth_types" in login_data

    def test_login_paths_count(self):
        """Test that we have exactly 72 login paths."""
        login_data = load_login_paths()
        all_paths = get_all_login_paths()

        assert login_data["total_paths"] == 72
        assert len(all_paths) == 72

    def test_login_path_brands_exist(self):
        """Test that all expected brands exist."""
        brands = get_login_path_brands()

        expected_brands = [
            "generic",
            "hikvision",
            "dahua",
            "axis",
            "sony",
            "bosch",
            "panasonic",
            "cp_plus",
        ]
        assert set(brands) == set(expected_brands)

    def test_get_login_paths_by_brand_hikvision(self):
        """Test retrieving Hikvision login paths."""
        hikvision_paths = get_login_paths_by_brand("hikvision")

        assert isinstance(hikvision_paths, list)
        assert len(hikvision_paths) == 15

        # Check structure of paths
        for path in hikvision_paths:
            assert "path" in path
            assert "auth_type" in path
            assert "description" in path

    def test_get_login_paths_by_brand_generic(self):
        """Test retrieving generic login paths."""
        generic_paths = get_login_paths_by_brand("generic")

        assert isinstance(generic_paths, list)
        assert len(generic_paths) == 21

        # Check for common paths
        paths_list = [p["path"] for p in generic_paths]
        assert "/" in paths_list
        assert "/admin" in paths_list
        assert "/login" in paths_list

    def test_get_login_paths_by_brand_invalid(self):
        """Test that invalid brand raises KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_login_paths_by_brand("invalid_brand")

        assert "invalid_brand" in str(exc_info.value)

    def test_get_login_paths_by_auth_type_basic(self):
        """Test retrieving basic auth paths."""
        basic_paths = get_login_paths_by_auth_type("basic")

        assert isinstance(basic_paths, list)
        assert len(basic_paths) > 0
        assert all(p["auth_type"] == "basic" for p in basic_paths)

    def test_get_login_paths_by_auth_type_digest(self):
        """Test retrieving digest auth paths."""
        digest_paths = get_login_paths_by_auth_type("digest")

        assert isinstance(digest_paths, list)
        assert len(digest_paths) == 33
        assert all(p["auth_type"] == "digest" for p in digest_paths)

    def test_get_login_paths_by_auth_type_form(self):
        """Test retrieving form auth paths."""
        form_paths = get_login_paths_by_auth_type("form")

        assert isinstance(form_paths, list)
        assert len(form_paths) == 8
        assert all(p["auth_type"] == "form" for p in form_paths)

    def test_all_paths_have_brand_info(self):
        """Test that get_all_login_paths adds brand information."""
        all_paths = get_all_login_paths()

        for path in all_paths:
            assert "brand" in path
            assert "path" in path
            assert "auth_type" in path
            assert "description" in path

    def test_auth_type_totals_match(self):
        """Test that auth type counts add up to total."""
        basic = len(get_login_paths_by_auth_type("basic"))
        digest = len(get_login_paths_by_auth_type("digest"))
        form = len(get_login_paths_by_auth_type("form"))

        assert basic + digest + form == 72


# ============================================================================
# CVE Database Tests
# ============================================================================


class TestCVEDatabase:
    """Tests for CVE database loading and querying functions."""

    def test_load_cve_database_structure(self):
        """Test that cve_database.json loads with correct structure."""
        cve_data = load_cve_database()

        assert "metadata" in cve_data
        assert "brands" in cve_data
        assert "statistics" in cve_data
        assert "severity_levels" in cve_data

    def test_cve_count(self):
        """Test that we have exactly 39 CVEs."""
        cve_data = load_cve_database()
        all_cves = get_all_cves()
        stats = get_cve_statistics()

        assert cve_data["metadata"]["total_cves"] == 39
        assert len(all_cves) == 39
        assert stats["total_cves"] == 39

    def test_cve_brands_exist(self):
        """Test that all expected brands exist in CVE database."""
        brands = get_cve_brands()

        expected_brands = ["hikvision", "dahua", "axis", "cp_plus"]
        assert set(brands) == set(expected_brands)

    def test_get_cves_by_brand_hikvision(self):
        """Test retrieving Hikvision CVEs."""
        hikvision_cves = get_cves_by_brand("hikvision")

        assert len(hikvision_cves) == 12

        # Check structure
        for cve in hikvision_cves:
            assert "cve_id" in cve
            assert "cvss_score" in cve
            assert "severity" in cve
            assert "description" in cve
            assert "affected_versions" in cve
            assert "exploit_available" in cve
            assert "exploit_references" in cve
            assert "year" in cve

    def test_get_cves_by_brand_dahua(self):
        """Test retrieving Dahua CVEs."""
        dahua_cves = get_cves_by_brand("dahua")

        assert len(dahua_cves) == 12

    def test_get_cves_by_brand_axis(self):
        """Test retrieving Axis CVEs."""
        axis_cves = get_cves_by_brand("axis")

        assert len(axis_cves) == 12

    def test_get_cves_by_brand_cp_plus(self):
        """Test retrieving CP Plus CVEs."""
        cp_plus_cves = get_cves_by_brand("cp_plus")

        assert len(cp_plus_cves) == 3

    def test_get_cves_by_brand_invalid(self):
        """Test that invalid brand raises KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_cves_by_brand("invalid_brand")

        assert "invalid_brand" in str(exc_info.value)

    def test_get_cves_by_severity_critical(self):
        """Test retrieving critical severity CVEs."""
        critical_cves = get_cves_by_severity("critical")

        assert len(critical_cves) == 5
        assert all(cve["severity"] == "critical" for cve in critical_cves)
        assert all(cve["cvss_score"] >= 9.0 for cve in critical_cves)

    def test_get_cves_by_severity_high(self):
        """Test retrieving high severity CVEs."""
        high_cves = get_cves_by_severity("high")

        assert len(high_cves) == 22
        assert all(cve["severity"] == "high" for cve in high_cves)
        assert all(7.0 <= cve["cvss_score"] < 9.0 for cve in high_cves)

    def test_get_cves_by_severity_medium(self):
        """Test retrieving medium severity CVEs."""
        medium_cves = get_cves_by_severity("medium")

        assert len(medium_cves) == 12
        assert all(cve["severity"] == "medium" for cve in medium_cves)
        assert all(4.0 <= cve["cvss_score"] < 7.0 for cve in medium_cves)

    def test_get_cves_with_exploits(self):
        """Test retrieving CVEs with public exploits."""
        exploit_cves = get_cves_with_exploits()

        assert len(exploit_cves) == 5
        assert all(cve["exploit_available"] is True for cve in exploit_cves)

        # Verify known CVEs with exploits
        exploit_ids = [cve["cve_id"] for cve in exploit_cves]
        assert "CVE-2021-36260" in exploit_ids  # Hikvision
        assert "CVE-2017-7921" in exploit_ids  # Hikvision
        assert "CVE-2021-33044" in exploit_ids  # Dahua
        assert "CVE-2022-30563" in exploit_ids  # Dahua
        assert "CVE-2018-10660" in exploit_ids  # Axis

    def test_all_cves_have_brand_info(self):
        """Test that get_all_cves adds brand information."""
        all_cves = get_all_cves()

        for cve in all_cves:
            assert "brand" in cve
            assert cve["brand"] in ["hikvision", "dahua", "axis", "cp_plus"]

    def test_cvss_scores_valid(self):
        """Test that all CVSS scores are in valid range."""
        all_cves = get_all_cves()

        for cve in all_cves:
            assert 0.0 <= cve["cvss_score"] <= 10.0

    def test_statistics_accuracy(self):
        """Test that statistics match actual data."""
        stats = get_cve_statistics()

        assert stats["total_cves"] == 39
        assert stats["by_brand"]["hikvision"] == 12
        assert stats["by_brand"]["dahua"] == 12
        assert stats["by_brand"]["axis"] == 12
        assert stats["by_brand"]["cp_plus"] == 3
        assert stats["by_severity"]["critical"] == 5
        assert stats["by_severity"]["high"] == 22
        assert stats["by_severity"]["medium"] == 12
        assert stats["with_exploits"] == 5

    def test_cve_id_format(self):
        """Test that CVE IDs follow correct format."""
        all_cves = get_all_cves()

        import re

        cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")

        for cve in all_cves:
            cve_id = cve["cve_id"]
            # Allow placeholder IDs for CP Plus
            if "XXXXX" not in cve_id:
                assert cve_pattern.match(cve_id), f"Invalid CVE ID format: {cve_id}"


# ============================================================================
# Integration Tests
# ============================================================================


class TestDataIntegration:
    """Integration tests across all data files."""

    def test_all_data_files_load_successfully(self):
        """Test that all data files can be loaded without errors."""
        # Should not raise any exceptions
        ports_data = load_camera_ports()
        login_data = load_login_paths()
        cve_data = load_cve_database()

        assert ports_data is not None
        assert login_data is not None
        assert cve_data is not None

    def test_data_file_json_validity(self):
        """Test that all data files are valid JSON."""
        from gridland.core.data_loader import get_data_dir

        data_dir = get_data_dir()

        data_files = [
            data_dir / "camera_ports.json",
            data_dir / "login_paths.json",
            data_dir / "cve_database.json",
        ]

        for file_path in data_files:
            assert file_path.exists(), f"Data file not found: {file_path}"

            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
                assert data is not None

    def test_brand_consistency_across_files(self):
        """Test that common brands are consistent across login paths and CVEs."""
        login_brands = set(get_login_path_brands())
        cve_brands = set(get_cve_brands())

        # These brands should appear in both
        common_brands = {"hikvision", "dahua", "axis"}

        assert common_brands.issubset(login_brands)
        assert common_brands.issubset(cve_brands)
