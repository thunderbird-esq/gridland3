"""Unit tests for IP Validator.

Tests IP address validation, private IP detection, and warning messages.
"""

from gridland.core.validators import IPValidator


class TestIPValidator:
    """Tests for IPValidator class."""

    def test_validate_ip_valid_public_ipv4(self):
        """Test validation of valid public IPv4 address."""
        is_valid, warning = IPValidator.validate_ip("8.8.8.8")

        assert is_valid is True
        assert warning is None

    def test_validate_ip_valid_private_ipv4_192(self):
        """Test validation of private IPv4 address (192.168.x.x)."""
        is_valid, warning = IPValidator.validate_ip("192.168.1.1")

        assert is_valid is True
        assert warning is not None
        assert "Warning: Private IP address detected" in warning
        assert "This tool is meant for public IPs" in warning

    def test_validate_ip_valid_private_ipv4_10(self):
        """Test validation of private IPv4 address (10.x.x.x)."""
        is_valid, warning = IPValidator.validate_ip("10.0.0.1")

        assert is_valid is True
        assert warning is not None
        assert "Warning: Private IP address detected" in warning

    def test_validate_ip_valid_private_ipv4_172(self):
        """Test validation of private IPv4 address (172.16-31.x.x)."""
        is_valid, warning = IPValidator.validate_ip("172.16.0.1")

        assert is_valid is True
        assert warning is not None
        assert "Warning: Private IP address detected" in warning

    def test_validate_ip_valid_public_ipv4_google_dns(self):
        """Test validation of Google DNS (8.8.8.8)."""
        is_valid, warning = IPValidator.validate_ip("8.8.8.8")

        assert is_valid is True
        assert warning is None

    def test_validate_ip_valid_public_ipv4_cloudflare_dns(self):
        """Test validation of Cloudflare DNS (1.1.1.1)."""
        is_valid, warning = IPValidator.validate_ip("1.1.1.1")

        assert is_valid is True
        assert warning is None

    def test_validate_ip_valid_public_ipv6(self):
        """Test validation of valid public IPv6 address."""
        is_valid, warning = IPValidator.validate_ip("2001:4860:4860::8888")

        assert is_valid is True
        assert warning is None

    def test_validate_ip_valid_private_ipv6(self):
        """Test validation of private IPv6 address."""
        is_valid, warning = IPValidator.validate_ip("fd00::1")

        assert is_valid is True
        assert warning is not None
        assert "Warning: Private IP address detected" in warning

    def test_validate_ip_invalid_format(self):
        """Test validation of invalid IP format."""
        is_valid, warning = IPValidator.validate_ip("invalid")

        assert is_valid is False
        assert warning is None

    def test_validate_ip_invalid_octets(self):
        """Test validation of invalid IPv4 octets."""
        is_valid, warning = IPValidator.validate_ip("256.256.256.256")

        assert is_valid is False
        assert warning is None

    def test_validate_ip_invalid_incomplete(self):
        """Test validation of incomplete IP address."""
        is_valid, warning = IPValidator.validate_ip("192.168.1")

        assert is_valid is False
        assert warning is None

    def test_validate_ip_empty_string(self):
        """Test validation of empty string."""
        is_valid, warning = IPValidator.validate_ip("")

        assert is_valid is False
        assert warning is None

    def test_validate_ip_localhost(self):
        """Test validation of localhost (127.0.0.1)."""
        is_valid, warning = IPValidator.validate_ip("127.0.0.1")

        assert is_valid is True
        # Localhost is considered private
        assert warning is not None

    def test_validate_ip_warning_message_exact(self):
        """Test exact warning message matches CamXploit.py."""
        is_valid, warning = IPValidator.validate_ip("192.168.1.1")

        assert warning == (
            "Warning: Private IP address detected. " "This tool is meant for public IPs."
        )

    def test_is_ipv4_valid(self):
        """Test is_ipv4 with valid IPv4 address."""
        assert IPValidator.is_ipv4("192.168.1.1") is True

    def test_is_ipv4_invalid(self):
        """Test is_ipv4 with IPv6 address."""
        assert IPValidator.is_ipv4("2001:db8::1") is False

    def test_is_ipv4_invalid_format(self):
        """Test is_ipv4 with invalid format."""
        assert IPValidator.is_ipv4("invalid") is False

    def test_is_ipv6_valid(self):
        """Test is_ipv6 with valid IPv6 address."""
        assert IPValidator.is_ipv6("2001:db8::1") is True

    def test_is_ipv6_invalid(self):
        """Test is_ipv6 with IPv4 address."""
        assert IPValidator.is_ipv6("192.168.1.1") is False

    def test_is_ipv6_invalid_format(self):
        """Test is_ipv6 with invalid format."""
        assert IPValidator.is_ipv6("invalid") is False

    def test_is_public_ip_true(self):
        """Test is_public_ip with public IP."""
        assert IPValidator.is_public_ip("8.8.8.8") is True

    def test_is_public_ip_false(self):
        """Test is_public_ip with private IP."""
        assert IPValidator.is_public_ip("192.168.1.1") is False

    def test_is_public_ip_invalid(self):
        """Test is_public_ip with invalid IP."""
        assert IPValidator.is_public_ip("invalid") is False

    def test_is_private_ip_true(self):
        """Test is_private_ip with private IP."""
        assert IPValidator.is_private_ip("192.168.1.1") is True

    def test_is_private_ip_false(self):
        """Test is_private_ip with public IP."""
        assert IPValidator.is_private_ip("8.8.8.8") is False

    def test_is_private_ip_invalid(self):
        """Test is_private_ip with invalid IP."""
        assert IPValidator.is_private_ip("invalid") is False

    def test_get_ip_type_public_ipv4(self):
        """Test get_ip_type for public IPv4."""
        ip_type = IPValidator.get_ip_type("8.8.8.8")
        assert ip_type == "public_ipv4"

    def test_get_ip_type_private_ipv4(self):
        """Test get_ip_type for private IPv4."""
        ip_type = IPValidator.get_ip_type("192.168.1.1")
        assert ip_type == "private_ipv4"

    def test_get_ip_type_public_ipv6(self):
        """Test get_ip_type for public IPv6."""
        ip_type = IPValidator.get_ip_type("2001:4860:4860::8888")
        assert ip_type == "public_ipv6"

    def test_get_ip_type_private_ipv6(self):
        """Test get_ip_type for private IPv6."""
        ip_type = IPValidator.get_ip_type("fd00::1")
        assert ip_type == "private_ipv6"

    def test_get_ip_type_invalid(self):
        """Test get_ip_type for invalid IP."""
        ip_type = IPValidator.get_ip_type("invalid")
        assert ip_type is None

    def test_validate_ip_return_type(self):
        """Test that validate_ip returns correct tuple type."""
        result = IPValidator.validate_ip("8.8.8.8")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert result[1] is None or isinstance(result[1], str)

    def test_multiple_private_ranges(self):
        """Test validation across different private IP ranges."""
        private_ips = [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.254",
        ]

        for ip in private_ips:
            is_valid, warning = IPValidator.validate_ip(ip)
            assert is_valid is True
            assert warning is not None
            assert "Private IP" in warning

    def test_multiple_public_ips(self):
        """Test validation of multiple public IPs."""
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
            "9.9.9.9",
        ]

        for ip in public_ips:
            is_valid, warning = IPValidator.validate_ip(ip)
            assert is_valid is True
            assert warning is None

    def test_edge_case_ips(self):
        """Test edge case IP addresses."""
        # Test broadcast address
        is_valid, warning = IPValidator.validate_ip("255.255.255.255")
        assert is_valid is True

        # Test zero address
        is_valid, warning = IPValidator.validate_ip("0.0.0.0")  # nosec
        assert is_valid is True

    def test_ipv6_loopback(self):
        """Test IPv6 loopback address."""
        is_valid, warning = IPValidator.validate_ip("::1")
        assert is_valid is True
        # Loopback is considered private
        assert warning is not None

    def test_ipv6_link_local(self):
        """Test IPv6 link-local address."""
        is_valid, warning = IPValidator.validate_ip("fe80::1")
        assert is_valid is True
        assert warning is not None

    def test_static_method_no_instance(self):
        """Test that static methods work without instantiation."""
        # Should be able to call without creating instance
        is_valid, warning = IPValidator.validate_ip("8.8.8.8")
        assert is_valid is True

        assert IPValidator.is_ipv4("192.168.1.1") is True
        assert IPValidator.is_public_ip("8.8.8.8") is True

    def test_consistency_between_methods(self):
        """Test consistency between different validation methods."""
        test_ip = "192.168.1.1"

        is_valid, warning = IPValidator.validate_ip(test_ip)
        assert is_valid is True
        assert warning is not None

        assert IPValidator.is_private_ip(test_ip) is True
        assert IPValidator.is_public_ip(test_ip) is False
        assert IPValidator.is_ipv4(test_ip) is True
        assert IPValidator.get_ip_type(test_ip) == "private_ipv4"

    def test_all_invalid_formats(self):
        """Test various invalid IP formats."""
        invalid_ips = [
            "999.999.999.999",
            "192.168.1",
            "192.168.1.1.1",
            "abc.def.ghi.jkl",
            "192.168.-1.1",
            "192.168.1.1/24",
            "http://192.168.1.1",
        ]

        for ip in invalid_ips:
            is_valid, warning = IPValidator.validate_ip(ip)
            assert is_valid is False
            assert warning is None
