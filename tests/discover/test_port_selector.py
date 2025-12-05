"""Tests for the PortSelector class."""

import pytest

from gridland.discover.port_selector import PortSelector


class TestPortSelectorGetCameraPorts:
    """Test PortSelector.get_camera_ports() method."""

    def test_get_all_camera_ports(self):
        """Test retrieving all camera ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="all")

        # Should return 685 unique ports
        assert len(ports) == 685
        assert isinstance(ports, list)
        assert all(isinstance(p, int) for p in ports)

        # All ports should be in valid range
        assert all(1 <= p <= 65535 for p in ports)

        # Should be sorted
        assert ports == sorted(ports)

        # Should be unique
        assert len(ports) == len(set(ports))

    def test_get_web_ports(self):
        """Test retrieving web category ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="web")

        # Should have 35 web ports
        assert len(ports) == 35
        assert isinstance(ports, list)

        # Common web ports should be included
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports

        # All should be valid port numbers
        assert all(1 <= p <= 65535 for p in ports)

    def test_get_rtsp_ports(self):
        """Test retrieving RTSP category ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="rtsp")

        # Should have 11 RTSP ports
        assert len(ports) == 11
        assert isinstance(ports, list)

        # Standard RTSP port should be included
        assert 554 in ports

        # Should include common RTSP variant ports
        assert 1554 in ports
        assert 8554 in ports

        # All should be valid port numbers
        assert all(1 <= p <= 65535 for p in ports)

    def test_get_rtmp_ports(self):
        """Test retrieving RTMP category ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="rtmp")

        assert isinstance(ports, list)
        assert len(ports) > 0

        # Standard RTMP port should be included
        assert 1935 in ports

        # All should be valid port numbers
        assert all(1 <= p <= 65535 for p in ports)

    def test_get_mms_ports(self):
        """Test retrieving MMS category ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="mms")

        assert isinstance(ports, list)
        assert len(ports) > 0

        # Standard MMS port should be included
        assert 1755 in ports

        # All should be valid port numbers
        assert all(1 <= p <= 65535 for p in ports)

    def test_get_onvif_ports(self):
        """Test retrieving ONVIF category ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="onvif")

        assert isinstance(ports, list)
        assert len(ports) > 0

        # Standard ONVIF discovery port (WS-Discovery)
        assert 3702 in ports

        # All should be valid port numbers
        assert all(1 <= p <= 65535 for p in ports)

    def test_get_custom_ports(self):
        """Test retrieving custom category ports."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="custom")

        assert isinstance(ports, list)
        # Custom category should have some ports
        assert len(ports) > 0

        # All should be valid port numbers
        assert all(1 <= p <= 65535 for p in ports)

    def test_default_category_is_all(self):
        """Test that default category is 'all'."""
        selector = PortSelector()

        # Call without category argument
        ports_default = selector.get_camera_ports()
        ports_all = selector.get_camera_ports(category="all")

        # Should be identical
        assert ports_default == ports_all
        assert len(ports_default) == 685

    def test_invalid_category_raises_error(self):
        """Test that invalid category raises ValueError."""
        selector = PortSelector()

        with pytest.raises(ValueError, match="Invalid category"):
            selector.get_camera_ports(category="invalid_category")

        with pytest.raises(ValueError, match="Invalid category"):
            selector.get_camera_ports(category="webrtc")

        with pytest.raises(ValueError, match="Invalid category"):
            selector.get_camera_ports(category="")

    def test_case_sensitive_category(self):
        """Test that category names are case-sensitive."""
        selector = PortSelector()

        # These should raise errors (wrong case)
        with pytest.raises(ValueError, match="Invalid category"):
            selector.get_camera_ports(category="Web")

        with pytest.raises(ValueError, match="Invalid category"):
            selector.get_camera_ports(category="RTSP")

        with pytest.raises(ValueError, match="Invalid category"):
            selector.get_camera_ports(category="ALL")


class TestPortSelectorPortValidation:
    """Test port validation in PortSelector."""

    def test_all_ports_in_valid_range(self):
        """Test that all returned ports are in valid range (1-65535)."""
        selector = PortSelector()

        # Test all categories
        for category in ["all", "web", "rtsp", "rtmp", "mms", "onvif", "custom"]:
            ports = selector.get_camera_ports(category=category)

            # All ports should be in valid range
            assert all(1 <= p <= 65535 for p in ports), (
                f"Category {category} has invalid ports"
            )

            # All ports should be integers
            assert all(isinstance(p, int) for p in ports), (
                f"Category {category} has non-integer ports"
            )

    def test_no_duplicate_ports_in_all(self):
        """Test that 'all' category has no duplicates."""
        selector = PortSelector()
        ports = selector.get_camera_ports(category="all")

        # Should have no duplicates
        assert len(ports) == len(set(ports))


class TestPortSelectorStaticMethod:
    """Test that PortSelector methods can be called statically."""

    def test_static_method_call(self):
        """Test calling get_camera_ports as a static method."""
        # Should work without instantiating the class
        ports = PortSelector.get_camera_ports(category="all")

        assert len(ports) == 685
        assert isinstance(ports, list)

    def test_static_method_with_category(self):
        """Test static method call with different categories."""
        rtsp_ports = PortSelector.get_camera_ports(category="rtsp")
        web_ports = PortSelector.get_camera_ports(category="web")

        assert 554 in rtsp_ports
        assert 80 in web_ports
        assert rtsp_ports != web_ports


class TestPortSelectorIntegration:
    """Integration tests for PortSelector."""

    def test_all_categories_are_subset_of_all(self):
        """Test that each category is a subset of 'all'."""
        selector = PortSelector()
        all_ports = set(selector.get_camera_ports(category="all"))

        for category in ["web", "rtsp", "rtmp", "mms", "onvif", "custom"]:
            category_ports = set(selector.get_camera_ports(category=category))

            # Each category should be a subset of 'all'
            assert category_ports.issubset(all_ports), (
                f"Category {category} has ports not in 'all'"
            )

    def test_categories_combined_equal_or_exceed_all(self):
        """Test that combining categories covers at least 'all' ports."""
        selector = PortSelector()
        all_ports = set(selector.get_camera_ports(category="all"))

        # Combine all category ports
        combined = set()
        for category in ["web", "rtsp", "rtmp", "mms", "onvif", "custom"]:
            combined.update(selector.get_camera_ports(category=category))

        # Combined should include all ports (may have duplicates across categories)
        assert all_ports.issubset(combined), (
            "Not all ports are covered by categories"
        )

    def test_common_camera_ports_present(self):
        """Test that common camera ports are present."""
        selector = PortSelector()
        all_ports = selector.get_camera_ports(category="all")

        # Common camera ports that should definitely be included
        common_ports = [
            80,  # HTTP
            443,  # HTTPS
            554,  # RTSP
            1935,  # RTMP
            8000,  # Common alt HTTP
            8080,  # Common alt HTTP
            8443,  # Common alt HTTPS
        ]

        for port in common_ports:
            assert port in all_ports, f"Common camera port {port} not found"

    def test_consistent_results(self):
        """Test that multiple calls return consistent results."""
        selector = PortSelector()

        # Call multiple times
        ports1 = selector.get_camera_ports(category="all")
        ports2 = selector.get_camera_ports(category="all")
        ports3 = selector.get_camera_ports(category="all")

        # Should be identical
        assert ports1 == ports2 == ports3

    def test_different_instances_same_results(self):
        """Test that different instances return same results."""
        selector1 = PortSelector()
        selector2 = PortSelector()

        ports1 = selector1.get_camera_ports(category="rtsp")
        ports2 = selector2.get_camera_ports(category="rtsp")

        assert ports1 == ports2
