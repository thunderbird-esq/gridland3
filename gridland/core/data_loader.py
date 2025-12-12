"""Data loader module for GRIDLAND.

This module provides functions to load static data files used by GRIDLAND,
including camera ports, default credentials, stream paths, and login paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def get_data_dir() -> Path:
    """Get the path to the data directory.

    Returns:
        Path: Absolute path to the gridland/data directory.
    """
    # Get the directory of this file (gridland/core)
    current_dir = Path(__file__).parent
    # Go up one level and into data directory
    data_dir = current_dir.parent / "data"
    return data_dir


def load_camera_ports() -> dict[str, Any]:
    """Load camera ports from camera_ports.json.

    This function loads the comprehensive list of camera ports categorized by
    protocol type (web, rtsp, rtmp, mms, onvif, custom). The port data is used
    for network scanning and camera discovery operations.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - metadata: Information about the port data (version, source, total_ports)
            - categories: Dictionary of port categories, each containing:
                - description: Description of the category
                - ports: List of port numbers for that category

    Raises:
        FileNotFoundError: If camera_ports.json does not exist.
        json.JSONDecodeError: If camera_ports.json is not valid JSON.
        KeyError: If required keys are missing from the JSON structure.

    Example:
        >>> ports_data = load_camera_ports()
        >>> print(ports_data['metadata']['total_ports'])
        685
        >>> web_ports = ports_data['categories']['web']['ports']
        >>> print(len(web_ports))
        35
        >>> print(web_ports[:3])
        [80, 443, 8000]
    """
    data_dir = get_data_dir()
    ports_file = data_dir / "camera_ports.json"

    if not ports_file.exists():
        raise FileNotFoundError(f"Camera ports file not found: {ports_file}")

    with open(ports_file, encoding="utf-8") as f:
        ports_data = json.load(f)

    # Validate the structure
    if "metadata" not in ports_data:
        raise KeyError("Missing 'metadata' key in camera_ports.json")
    if "categories" not in ports_data:
        raise KeyError("Missing 'categories' key in camera_ports.json")

    return ports_data


def get_all_ports() -> list[int]:
    """Get a flat list of all unique camera ports.

    Returns:
        List[int]: Sorted list of all unique port numbers across all categories.

    Raises:
        FileNotFoundError: If camera_ports.json does not exist.
        json.JSONDecodeError: If camera_ports.json is not valid JSON.

    Example:
        >>> all_ports = get_all_ports()
        >>> print(len(all_ports))
        685
        >>> print(all_ports[:5])
        [80, 443, 554, 1554, 1755]
    """
    ports_data = load_camera_ports()
    all_ports = set()

    for category_data in ports_data["categories"].values():
        all_ports.update(category_data["ports"])

    return sorted(list(all_ports))


def get_ports_by_category(category: str) -> list[int]:
    """Get ports for a specific category.

    Args:
        category: The category name (web, rtsp, rtmp, mms, onvif, custom).

    Returns:
        List[int]: List of port numbers for the specified category.

    Raises:
        FileNotFoundError: If camera_ports.json does not exist.
        json.JSONDecodeError: If camera_ports.json is not valid JSON.
        KeyError: If the specified category does not exist.

    Example:
        >>> rtsp_ports = get_ports_by_category('rtsp')
        >>> print(len(rtsp_ports))
        11
        >>> print(rtsp_ports)
        [554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 8554, 9554, 10554]
    """
    ports_data = load_camera_ports()

    if category not in ports_data["categories"]:
        available = ", ".join(ports_data["categories"].keys())
        raise KeyError(f"Category {category!r} not found. Available categories: {available}")

    return ports_data["categories"][category]["ports"]


def get_port_categories() -> list[str]:
    """Get a list of all available port categories.

    Returns:
        List[str]: List of category names.

    Raises:
        FileNotFoundError: If camera_ports.json does not exist.
        json.JSONDecodeError: If camera_ports.json is not valid JSON.

    Example:
        >>> categories = get_port_categories()
        >>> print(categories)
        ['web', 'rtsp', 'rtmp', 'mms', 'onvif', 'custom']
    """
    ports_data = load_camera_ports()
    return list(ports_data["categories"].keys())


def get_metadata() -> dict[str, Any]:
    """Get metadata about the camera ports data.

    Returns:
        Dict[str, Any]: Metadata dictionary containing version, source,
                        total_ports, and description.

    Raises:
        FileNotFoundError: If camera_ports.json does not exist.
        json.JSONDecodeError: If camera_ports.json is not valid JSON.

    Example:
        >>> metadata = get_metadata()
        >>> print(metadata['version'])
        1.0
        >>> print(metadata['total_ports'])
        685
    """
    ports_data = load_camera_ports()
    return ports_data["metadata"]


def load_login_paths() -> dict[str, Any]:
    """Load login paths from login_paths.json.

    This function loads the comprehensive list of login and authentication paths
    categorized by camera brand (generic, hikvision, dahua, axis, sony, bosch,
    panasonic, cp_plus). The path data is used for authentication testing and
    login page discovery operations.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - version: Version of the login paths data
            - last_updated: Last update date
            - source: Source of the data
            - description: Description of the data
            - total_paths: Total number of login paths
            - categories: Dictionary of brand categories, each containing a list of:
                - path: The URL path
                - auth_type: Authentication type (basic, digest, form)
                - description: Description of the path
            - auth_types: Dictionary mapping auth type codes to descriptions

    Raises:
        FileNotFoundError: If login_paths.json does not exist.
        json.JSONDecodeError: If login_paths.json is not valid JSON.
        KeyError: If required keys are missing from the JSON structure.

    Example:
        >>> login_data = load_login_paths()
        >>> print(login_data['total_paths'])
        72
        >>> generic_paths = login_data['categories']['generic']
        >>> print(len(generic_paths))
        21
        >>> print(generic_paths[0]['path'])
        /
        >>> print(generic_paths[0]['auth_type'])
        basic
    """
    data_dir = get_data_dir()
    login_file = data_dir / "login_paths.json"

    if not login_file.exists():
        raise FileNotFoundError(f"Login paths file not found: {login_file}")

    with open(login_file, encoding="utf-8") as f:
        login_data = json.load(f)

    # Validate the structure
    if "categories" not in login_data:
        raise KeyError("Missing 'categories' key in login_paths.json")
    if "total_paths" not in login_data:
        raise KeyError("Missing 'total_paths' key in login_paths.json")

    return login_data


def get_all_login_paths() -> list[dict[str, str]]:
    """Get a flat list of all login paths across all categories.

    Returns:
        List[Dict[str, str]]: List of all login path dictionaries, each containing:
            - path: The URL path
            - auth_type: Authentication type
            - description: Description of the path
            - brand: Brand category (added to each path)

    Raises:
        FileNotFoundError: If login_paths.json does not exist.
        json.JSONDecodeError: If login_paths.json is not valid JSON.

    Example:
        >>> all_paths = get_all_login_paths()
        >>> print(len(all_paths))
        72
        >>> print(all_paths[0])
        {'path': '/', 'auth_type': 'basic', 'description': 'Root path', 'brand': 'generic'}
    """
    login_data = load_login_paths()
    all_paths = []

    for brand, paths in login_data["categories"].items():
        for path_info in paths:
            # Create a copy and add brand information
            path_with_brand = path_info.copy()
            path_with_brand["brand"] = brand
            all_paths.append(path_with_brand)

    return all_paths


def get_login_paths_by_brand(brand: str) -> list[dict[str, str]]:
    """Get login paths for a specific brand.

    Args:
        brand: The brand name (generic, hikvision, dahua, axis, sony, bosch,
               panasonic, cp_plus).

    Returns:
        List[Dict[str, str]]: List of login path dictionaries for the brand.

    Raises:
        FileNotFoundError: If login_paths.json does not exist.
        json.JSONDecodeError: If login_paths.json is not valid JSON.
        KeyError: If the specified brand does not exist.

    Example:
        >>> hikvision_paths = get_login_paths_by_brand('hikvision')
        >>> print(len(hikvision_paths))
        15
        >>> print(hikvision_paths[0]['path'])
        /ISAPI/System/deviceInfo
    """
    login_data = load_login_paths()

    if brand not in login_data["categories"]:
        available = ", ".join(login_data["categories"].keys())
        raise KeyError(f"Brand {brand!r} not found. Available brands: {available}")

    return login_data["categories"][brand]


def get_login_paths_by_auth_type(auth_type: str) -> list[dict[str, str]]:
    """Get all login paths that use a specific authentication type.

    Args:
        auth_type: The authentication type (basic, digest, form).

    Returns:
        List[Dict[str, str]]: List of login path dictionaries matching the auth type,
                              each with brand information added.

    Raises:
        FileNotFoundError: If login_paths.json does not exist.
        json.JSONDecodeError: If login_paths.json is not valid JSON.

    Example:
        >>> digest_paths = get_login_paths_by_auth_type('digest')
        >>> print(len(digest_paths))
        39
        >>> form_paths = get_login_paths_by_auth_type('form')
        >>> print(len(form_paths))
        8
    """
    all_paths = get_all_login_paths()
    return [p for p in all_paths if p["auth_type"] == auth_type]


def get_login_path_brands() -> list[str]:
    """Get a list of all available brand categories for login paths.

    Returns:
        List[str]: List of brand category names.

    Raises:
        FileNotFoundError: If login_paths.json does not exist.
        json.JSONDecodeError: If login_paths.json is not valid JSON.

    Example:
        >>> brands = get_login_path_brands()
        >>> print(brands)
        ['generic', 'hikvision', 'dahua', 'axis', 'sony', 'bosch', 'panasonic', 'cp_plus']
    """
    login_data = load_login_paths()
    return list(login_data["categories"].keys())


def load_cve_database() -> dict[str, Any]:
    """Load CVE database from cve_database.json.

    This function loads the comprehensive CVE database containing security
    vulnerabilities for various camera brands, including CVSS scores, severity
    ratings, descriptions, exploit availability, and references.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - metadata: Information about the CVE data (version, source, total_cves)
            - brands: Dictionary of brand-specific CVE lists, each CVE containing:
                - cve_id: CVE identifier
                - cvss_score: CVSS v3 score (0.0-10.0)
                - severity: Severity rating (critical, high, medium, low)
                - description: Vulnerability description
                - affected_versions: List of affected product versions
                - exploit_available: Boolean indicating public exploit availability
                - exploit_references: List of reference URLs
                - year: Year of disclosure
            - severity_levels: Mapping of severity levels to CVSS ranges
            - statistics: Aggregate statistics about the CVE data

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.
        KeyError: If required keys are missing from the JSON structure.

    Example:
        >>> cve_data = load_cve_database()
        >>> print(cve_data['metadata']['total_cves'])
        39
        >>> hikvision_cves = cve_data['brands']['hikvision']
        >>> print(len(hikvision_cves))
        12
        >>> critical_cve = hikvision_cves[0]
        >>> print(f"{critical_cve['cve_id']}: {critical_cve['severity']}")
        CVE-2021-36260: critical
    """
    data_dir = get_data_dir()
    cve_file = data_dir / "cve_database.json"

    if not cve_file.exists():
        raise FileNotFoundError(f"CVE database file not found: {cve_file}")

    with open(cve_file, encoding="utf-8") as f:
        cve_data = json.load(f)

    # Validate the structure
    if "metadata" not in cve_data:
        raise KeyError("Missing 'metadata' key in cve_database.json")
    if "brands" not in cve_data:
        raise KeyError("Missing 'brands' key in cve_database.json")

    return cve_data


def get_all_cves() -> list[dict[str, Any]]:
    """Get a flat list of all CVEs across all brands.

    Returns:
        List[Dict[str, Any]]: List of all CVE dictionaries with brand information added.

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.

    Example:
        >>> all_cves = get_all_cves()
        >>> print(len(all_cves))
        39
        >>> critical_cves = [cve for cve in all_cves if cve['severity'] == 'critical']
        >>> print(len(critical_cves))
        5
    """
    cve_data = load_cve_database()
    all_cves = []

    for brand, cves in cve_data["brands"].items():
        for cve in cves:
            # Create a copy and add brand information
            cve_with_brand = cve.copy()
            cve_with_brand["brand"] = brand
            all_cves.append(cve_with_brand)

    return all_cves


def get_cves_by_brand(brand: str) -> list[dict[str, Any]]:
    """Get CVEs for a specific camera brand.

    Args:
        brand: The brand name (hikvision, dahua, axis, cp_plus).

    Returns:
        List[Dict[str, Any]]: List of CVE dictionaries for the specified brand.

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.
        KeyError: If the specified brand does not exist.

    Example:
        >>> hikvision_cves = get_cves_by_brand('hikvision')
        >>> print(len(hikvision_cves))
        12
        >>> print(hikvision_cves[0]['cve_id'])
        CVE-2021-36260
    """
    cve_data = load_cve_database()

    if brand not in cve_data["brands"]:
        available = ", ".join(cve_data["brands"].keys())
        raise KeyError(f"Brand {brand!r} not found. Available brands: {available}")

    return cve_data["brands"][brand]


def get_cves_by_severity(severity: str) -> list[dict[str, Any]]:
    """Get all CVEs matching a specific severity level.

    Args:
        severity: The severity level (critical, high, medium, low).

    Returns:
        List[Dict[str, Any]]: List of CVE dictionaries matching the severity,
                              each with brand information added.

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.

    Example:
        >>> critical_cves = get_cves_by_severity('critical')
        >>> print(len(critical_cves))
        5
        >>> for cve in critical_cves:
        ...     print(f"{cve['cve_id']}: {cve['cvss_score']}")
        CVE-2021-36260: 9.8
        CVE-2017-7921: 9.8
        CVE-2021-33044: 9.8
        CVE-2022-30563: 9.8
        CVE-2018-10660: 9.8
    """
    all_cves = get_all_cves()
    return [cve for cve in all_cves if cve["severity"] == severity]


def get_cves_with_exploits() -> list[dict[str, Any]]:
    """Get all CVEs that have publicly available exploits.

    Returns:
        List[Dict[str, Any]]: List of CVE dictionaries where exploit_available is True,
                              each with brand information added.

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.

    Example:
        >>> exploit_cves = get_cves_with_exploits()
        >>> print(len(exploit_cves))
        5
        >>> for cve in exploit_cves:
        ...     print(f"{cve['cve_id']}: {cve['brand']}")
        CVE-2021-36260: hikvision
        CVE-2017-7921: hikvision
        CVE-2021-33044: dahua
        CVE-2022-30563: dahua
        CVE-2018-10660: axis
    """
    all_cves = get_all_cves()
    return [cve for cve in all_cves if cve.get("exploit_available", False)]


def get_cve_brands() -> list[str]:
    """Get a list of all available brands in the CVE database.

    Returns:
        List[str]: List of brand names.

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.

    Example:
        >>> brands = get_cve_brands()
        >>> print(brands)
        ['hikvision', 'dahua', 'axis', 'cp_plus']
    """
    cve_data = load_cve_database()
    return list(cve_data["brands"].keys())


def get_cve_statistics() -> dict[str, Any]:
    """Get statistics about the CVE database.

    Returns:
        Dict[str, Any]: Statistics dictionary containing counts by brand,
                        severity, exploit availability, and years.

    Raises:
        FileNotFoundError: If cve_database.json does not exist.
        json.JSONDecodeError: If cve_database.json is not valid JSON.

    Example:
        >>> stats = get_cve_statistics()
        >>> print(stats['total_cves'])
        39
        >>> print(stats['by_severity']['critical'])
        5
        >>> print(stats['with_exploits'])
        5
    """
    cve_data = load_cve_database()
    return cve_data.get("statistics", {})


def load_stream_paths() -> dict[str, Any]:
    """Load stream paths from stream_paths.json.

    This function loads the comprehensive list of stream discovery paths
    categorized by protocol (rtsp, rtmp, http, websocket, webrtc). The path data
    is used for live stream enumeration and discovery operations.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - version: Version of the stream paths data
            - last_updated: Last update date
            - source: Source of the data
            - protocols: Dictionary of protocol-specific stream paths
            - content_types: Expected content-type headers for stream validation
            - detection_patterns: Patterns for successful stream detection
            - port_protocols: Mapping of ports to their typical protocols
            - optimization: High-success paths and brand indicators

    Raises:
        FileNotFoundError: If stream_paths.json does not exist.
        json.JSONDecodeError: If stream_paths.json is not valid JSON.
        KeyError: If required keys are missing from the JSON structure.

    Example:
        >>> stream_data = load_stream_paths()
        >>> print(stream_data['version'])
        2.1
        >>> rtsp_paths = stream_data['protocols']['rtsp']['generic']
        >>> print(len(rtsp_paths))
        29
        >>> print(rtsp_paths[0])
        /live.sdp
    """
    data_dir = get_data_dir()
    stream_file = data_dir / "stream_paths.json"

    if not stream_file.exists():
        raise FileNotFoundError(f"Stream paths file not found: {stream_file}")

    with open(stream_file, encoding="utf-8") as f:
        stream_data = json.load(f)

    # Validate the structure
    if "protocols" not in stream_data:
        raise KeyError("Missing 'protocols' key in stream_paths.json")
    if "version" not in stream_data:
        raise KeyError("Missing 'version' key in stream_paths.json")

    return stream_data
