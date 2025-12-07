"""Validators module for GRIDLAND.

This module provides validation utilities for IP addresses and other
inputs. Validation logic is ported from CamXploit.py for 100% feature parity.
"""

import ipaddress


class IPValidator:
    """Validate IP addresses and detect private IP ranges.

    This class provides static methods for IP address validation using
    Python's ipaddress module. It detects private IP addresses and
    provides appropriate warnings, matching CamXploit.py behavior
    (lines 913-923).

    Example:
        >>> is_valid, warning = IPValidator.validate_ip("8.8.8.8")
        >>> print(is_valid)
        True
        >>> print(warning)
        None

        >>> is_valid, warning = IPValidator.validate_ip("192.168.1.1")
        >>> print(is_valid)
        True
        >>> print(warning)
        Warning: Private IP address detected. This tool is meant for public IPs.
    """

    @staticmethod
    def validate_ip(ip_str: str) -> tuple[bool, str | None]:
        """Validate an IP address and check if it's private.

        Validates IP address format using Python's ipaddress module and
        checks if the IP is in a private range (RFC 1918). Returns validation
        status and an optional warning message for private IPs.

        Matches CamXploit.py validate_ip() function (lines 913-923).

        Args:
            ip_str: IP address string to validate (IPv4 or IPv6).

        Returns:
            Tuple[bool, Optional[str]]: A tuple containing:
                - is_valid: True if IP format is valid, False otherwise
                - warning: Warning string for private IPs, None otherwise

        Example:
            >>> is_valid, warning = IPValidator.validate_ip("203.0.113.1")
            >>> print(is_valid)
            True
            >>> print(warning)
            None

            >>> is_valid, warning = IPValidator.validate_ip("10.0.0.1")
            >>> print(is_valid)
            True
            >>> print(warning)
            Warning: Private IP address detected. This tool is meant for public IPs.

            >>> is_valid, warning = IPValidator.validate_ip("invalid")
            >>> print(is_valid)
            False
            >>> print(warning)
            None
        """
        try:
            ip = ipaddress.ip_address(ip_str)

            # Check if IP is private
            if ip.is_private:
                warning = (
                    "Warning: Private IP address detected. " "This tool is meant for public IPs."
                )
                return (True, warning)

            # Valid public IP
            return (True, None)

        except ValueError:
            # Invalid IP format
            return (False, None)

    @staticmethod
    def is_ipv4(ip_str: str) -> bool:
        """Check if an IP address is IPv4.

        Args:
            ip_str: IP address string to check.

        Returns:
            bool: True if valid IPv4, False otherwise.

        Example:
            >>> IPValidator.is_ipv4("192.168.1.1")
            True
            >>> IPValidator.is_ipv4("2001:db8::1")
            False
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.version == 4
        except ValueError:
            return False

    @staticmethod
    def is_ipv6(ip_str: str) -> bool:
        """Check if an IP address is IPv6.

        Args:
            ip_str: IP address string to check.

        Returns:
            bool: True if valid IPv6, False otherwise.

        Example:
            >>> IPValidator.is_ipv6("2001:db8::1")
            True
            >>> IPValidator.is_ipv6("192.168.1.1")
            False
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.version == 6
        except ValueError:
            return False

    @staticmethod
    def is_public_ip(ip_str: str) -> bool:
        """Check if an IP address is public (not private).

        Args:
            ip_str: IP address string to check.

        Returns:
            bool: True if valid public IP, False otherwise.

        Example:
            >>> IPValidator.is_public_ip("8.8.8.8")
            True
            >>> IPValidator.is_public_ip("192.168.1.1")
            False
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_private
        except ValueError:
            return False

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if an IP address is private.

        Args:
            ip_str: IP address string to check.

        Returns:
            bool: True if valid private IP, False otherwise.

        Example:
            >>> IPValidator.is_private_ip("192.168.1.1")
            True
            >>> IPValidator.is_private_ip("8.8.8.8")
            False
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    @staticmethod
    def get_ip_type(ip_str: str) -> str | None:
        """Get the type of IP address (public_ipv4, private_ipv4, etc).

        Args:
            ip_str: IP address string to check.

        Returns:
            Optional[str]: IP type string or None if invalid:
                - 'public_ipv4': Public IPv4 address
                - 'private_ipv4': Private IPv4 address
                - 'public_ipv6': Public IPv6 address
                - 'private_ipv6': Private IPv6 address
                - None: Invalid IP address

        Example:
            >>> IPValidator.get_ip_type("8.8.8.8")
            'public_ipv4'
            >>> IPValidator.get_ip_type("192.168.1.1")
            'private_ipv4'
            >>> IPValidator.get_ip_type("2001:db8::1")
            'private_ipv6'
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            privacy = "private" if ip.is_private else "public"
            version = f"ipv{ip.version}"
            return f"{privacy}_{version}"
        except ValueError:
            return None
