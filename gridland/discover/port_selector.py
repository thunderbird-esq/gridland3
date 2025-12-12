"""Port selector for camera reconnaissance in GRIDLAND.

This module provides the PortSelector class for retrieving camera-specific
ports from the data files. It supports filtering by protocol category and
validates port ranges.
"""

from typing import List

from gridland.core.data_loader import (
    get_all_ports,
    get_port_categories,
    get_ports_by_category,
)


class PortSelector:
    """Select and filter camera ports for reconnaissance scanning.

    This class provides methods to retrieve camera ports from the
    gridland/data/camera_ports.json file with category filtering support.
    It uses the data loader functions from Phase 1 of the migration.

    Example:
        >>> selector = PortSelector()
        >>> rtsp_ports = selector.get_camera_ports(category='rtsp')
        >>> print(len(rtsp_ports))
        11
        >>> all_ports = selector.get_camera_ports(category='all')
        >>> print(len(all_ports))
        685
    """

    @staticmethod
    def get_camera_ports(category: str = "all") -> List[int]:
        """Get camera ports filtered by category.

        Retrieves camera ports from the data file, optionally filtered by
        protocol category. Supports the following categories:
        - 'web': HTTP/HTTPS web interface ports (80, 443, 8080, etc.)
        - 'rtsp': RTSP streaming protocol ports (554, 1554, etc.)
        - 'rtmp': RTMP streaming protocol ports (1935, etc.)
        - 'mms': MMS streaming protocol ports (1755, etc.)
        - 'onvif': ONVIF protocol ports (80, 8080, etc.)
        - 'custom': Custom manufacturer-specific ports
        - 'all': All camera ports across all categories (default)

        Args:
            category: Port category to filter by. Valid values are:
                      'web', 'rtsp', 'rtmp', 'mms', 'onvif', 'custom', 'all'.
                      Default: 'all'.

        Returns:
            List[int]: List of port numbers (1-65535) for the specified
                       category. For 'all', returns the complete deduplicated
                       list of 685 unique ports. For specific categories,
                       returns the ports in that category.

        Raises:
            ValueError: If category is invalid or not recognized.
            FileNotFoundError: If camera_ports.json does not exist.
            json.JSONDecodeError: If camera_ports.json is malformed.

        Example:
            >>> selector = PortSelector()
            >>> # Get all camera ports
            >>> all_ports = selector.get_camera_ports('all')
            >>> print(len(all_ports))
            685
            >>> # Get RTSP-specific ports
            >>> rtsp_ports = selector.get_camera_ports('rtsp')
            >>> print(rtsp_ports)
            [554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 8554, 9554, 10554]
            >>> # Get web interface ports
            >>> web_ports = selector.get_camera_ports('web')
            >>> print(len(web_ports))
            35
        """
        # Validate category
        valid_categories = get_port_categories() + ["all"]

        if category not in valid_categories:
            raise ValueError(
                f"Invalid category: {category!r}. "
                f"Valid categories: {', '.join(valid_categories)}"
            )

        # Get ports based on category
        if category == "all":
            ports = get_all_ports()
        else:
            ports = get_ports_by_category(category)

        # Validate port ranges (should already be valid from data file)
        for port in ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"Invalid port number in data: {port}")

        return ports
