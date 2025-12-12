# Core Modules API

The core modules provide fundamental data loading, validation, and utility functions.

## gridland.core.data_loader

Data loading functions for camera reconnaissance databases.

### Port Functions

#### load_camera_ports()

Load the full camera ports database.

```python
from gridland.core.data_loader import load_camera_ports

ports_data = load_camera_ports()
# Returns: dict with 'metadata' and 'data' keys
```

**Returns:**
- `dict`: Full database structure with metadata

#### get_all_ports()

Get a flat list of all unique camera ports.

```python
from gridland.core.data_loader import get_all_ports

all_ports = get_all_ports()
# Returns: [80, 443, 554, 8080, ...]
```

**Returns:**
- `list[int]`: List of 685 unique port numbers

#### get_ports_by_category(category)

Query ports by protocol category.

```python
from gridland.core.data_loader import get_ports_by_category

rtsp_ports = get_ports_by_category('rtsp')
# Returns: [554, 1554, 8554, ...]

web_ports = get_ports_by_category('web')
# Returns: [80, 443, 8080, 8443, ...]
```

**Parameters:**
- `category` (str): Port category (`'web'`, `'rtsp'`, `'rtmp'`, `'mms'`, `'onvif'`, `'custom'`)

**Returns:**
- `list[int]`: List of ports in the specified category

**Raises:**
- `ValueError`: If category is invalid

#### get_port_categories()

List all available port categories.

```python
from gridland.core.data_loader import get_port_categories

categories = get_port_categories()
# Returns: ['web', 'rtsp', 'rtmp', 'mms', 'onvif', 'custom']
```

**Returns:**
- `list[str]`: List of category names

### Login Path Functions

#### load_login_paths()

Load the full login paths database.

```python
from gridland.core.data_loader import load_login_paths

paths_data = load_login_paths()
# Returns: dict with 'metadata' and 'data' keys
```

**Returns:**
- `dict`: Full database structure with metadata

#### get_all_login_paths()

Get all authentication paths with brand information.

```python
from gridland.core.data_loader import get_all_login_paths

all_paths = get_all_login_paths()
# Returns: list of dicts with 'path', 'brand', 'auth_type' keys
```

**Returns:**
- `list[dict]`: List of 72 login path objects

#### get_login_paths_by_brand(brand)

Query authentication paths by camera brand.

```python
from gridland.core.data_loader import get_login_paths_by_brand

hik_paths = get_login_paths_by_brand('hikvision')
# Returns: list of paths specific to Hikvision
```

**Parameters:**
- `brand` (str): Camera brand name

**Returns:**
- `list[dict]`: List of login path objects for the brand

**Raises:**
- `ValueError`: If brand is not in database

#### get_login_paths_by_auth_type(auth_type)

Filter authentication paths by auth mechanism.

```python
from gridland.core.data_loader import get_login_paths_by_auth_type

digest_paths = get_login_paths_by_auth_type('digest')
basic_paths = get_login_paths_by_auth_type('basic')
form_paths = get_login_paths_by_auth_type('form')
```

**Parameters:**
- `auth_type` (str): Authentication type (`'basic'`, `'digest'`, `'form'`)

**Returns:**
- `list[dict]`: List of paths using the specified auth type

**Raises:**
- `ValueError`: If auth_type is invalid

#### get_login_path_brands()

List all brands in the login paths database.

```python
from gridland.core.data_loader import get_login_path_brands

brands = get_login_path_brands()
# Returns: ['generic', 'hikvision', 'dahua', 'axis', ...]
```

**Returns:**
- `list[str]`: List of brand names

### CVE Functions

#### load_cve_database()

Load the full CVE database.

```python
from gridland.core.data_loader import load_cve_database

cve_data = load_cve_database()
# Returns: dict with 'metadata' and 'data' keys
```

**Returns:**
- `dict`: Full CVE database structure

#### get_all_cves()

Get all CVEs with brand information.

```python
from gridland.core.data_loader import get_all_cves

all_cves = get_all_cves()
# Returns: list of 39 CVE objects
```

**Returns:**
- `list[dict]`: List of all CVE objects

#### get_cves_by_brand(brand)

Query CVEs by camera manufacturer.

```python
from gridland.core.data_loader import get_cves_by_brand

hik_cves = get_cves_by_brand('hikvision')  # 12 CVEs
dahua_cves = get_cves_by_brand('dahua')    # 12 CVEs
```

**Parameters:**
- `brand` (str): Brand name

**Returns:**
- `list[dict]`: List of CVEs for the brand

**Raises:**
- `ValueError`: If brand not in database

#### get_cves_by_severity(severity)

Filter CVEs by severity level.

```python
from gridland.core.data_loader import get_cves_by_severity

critical = get_cves_by_severity('critical')  # 5 CVEs
high = get_cves_by_severity('high')          # 22 CVEs
medium = get_cves_by_severity('medium')      # 12 CVEs
```

**Parameters:**
- `severity` (str): Severity level (`'critical'`, `'high'`, `'medium'`, `'low'`)

**Returns:**
- `list[dict]`: List of CVEs with the specified severity

**Raises:**
- `ValueError`: If severity is invalid

#### get_cves_with_exploits()

Get CVEs that have public exploits.

```python
from gridland.core.data_loader import get_cves_with_exploits

exploitable = get_cves_with_exploits()  # 5 CVEs with exploits
```

**Returns:**
- `list[dict]`: List of CVEs with `exploit_available: true`

#### get_cve_brands()

List all brands in the CVE database.

```python
from gridland.core.data_loader import get_cve_brands

brands = get_cve_brands()
# Returns: ['hikvision', 'dahua', 'axis', 'cp_plus']
```

**Returns:**
- `list[str]`: List of brand names

#### get_cve_statistics(brand=None)

Get aggregate CVE statistics.

```python
from gridland.core.data_loader import get_cve_statistics

# Global statistics
stats = get_cve_statistics()
# Returns: {
#   'total_cves': 39,
#   'by_severity': {'critical': 5, 'high': 22, 'medium': 12},
#   'with_exploits': 5,
#   'by_brand': {'hikvision': 12, 'dahua': 12, ...}
# }

# Brand-specific statistics
hik_stats = get_cve_statistics(brand='hikvision')
# Returns: {
#   'brand': 'hikvision',
#   'total_cves': 12,
#   'by_severity': {'critical': 3, 'high': 6, 'medium': 3},
#   'with_exploits': 2
# }
```

**Parameters:**
- `brand` (str, optional): Brand name for specific statistics

**Returns:**
- `dict`: Statistics dictionary

**Raises:**
- `ValueError`: If brand specified but not in database

## gridland.core.validators

IP address validation and classification.

### IPValidator

Static validator for IP addresses.

#### validate_ip(ip_str)

Validate IP address and detect private addresses.

```python
from gridland.core import IPValidator

# Public IP
is_valid, warning = IPValidator.validate_ip('8.8.8.8')
# Returns: (True, None)

# Private IP
is_valid, warning = IPValidator.validate_ip('192.168.1.1')
# Returns: (True, 'Warning: Private IP address detected...')

# Invalid IP
is_valid, warning = IPValidator.validate_ip('999.999.999.999')
# Returns: (False, None)
```

**Parameters:**
- `ip_str` (str): IP address string

**Returns:**
- `tuple[bool, str | None]`: (is_valid, warning_message)

#### is_ipv4(ip_str)

Check if string is valid IPv4.

```python
IPValidator.is_ipv4('192.168.1.1')  # True
IPValidator.is_ipv4('2001:db8::1')  # False
```

**Parameters:**
- `ip_str` (str): IP address string

**Returns:**
- `bool`: True if valid IPv4

#### is_ipv6(ip_str)

Check if string is valid IPv6.

```python
IPValidator.is_ipv6('2001:db8::1')  # True
IPValidator.is_ipv6('192.168.1.1')  # False
```

**Parameters:**
- `ip_str` (str): IP address string

**Returns:**
- `bool`: True if valid IPv6

#### is_public_ip(ip_str)

Check if IP is public (not private or reserved).

```python
IPValidator.is_public_ip('8.8.8.8')      # True
IPValidator.is_public_ip('192.168.1.1')  # False
IPValidator.is_public_ip('10.0.0.1')     # False
```

**Parameters:**
- `ip_str` (str): IP address string

**Returns:**
- `bool`: True if public IP

#### is_private_ip(ip_str)

Check if IP is in private range (RFC 1918).

```python
IPValidator.is_private_ip('192.168.1.1')  # True
IPValidator.is_private_ip('10.0.0.1')     # True
IPValidator.is_private_ip('8.8.8.8')      # False
```

**Parameters:**
- `ip_str` (str): IP address string

**Returns:**
- `bool`: True if private IP

#### get_ip_type(ip_str)

Get detailed IP type information.

```python
ip_type = IPValidator.get_ip_type('8.8.8.8')
# Returns: 'public_ipv4'

ip_type = IPValidator.get_ip_type('192.168.1.1')
# Returns: 'private_ipv4'

ip_type = IPValidator.get_ip_type('2001:db8::1')
# Returns: 'public_ipv6'
```

**Parameters:**
- `ip_str` (str): IP address string

**Returns:**
- `str`: IP type (`'public_ipv4'`, `'private_ipv4'`, `'public_ipv6'`, `'private_ipv6'`, `'invalid'`)

## Complete Example

```python
from gridland.core.data_loader import (
    get_all_ports,
    get_ports_by_category,
    get_login_paths_by_brand,
    get_cves_by_severity,
    get_cve_statistics
)
from gridland.core import IPValidator

# Load camera ports
all_ports = get_all_ports()
print(f"Total camera ports: {len(all_ports)}")

rtsp_ports = get_ports_by_category('rtsp')
print(f"RTSP ports: {rtsp_ports}")

# Get login paths
hik_paths = get_login_paths_by_brand('hikvision')
print(f"Hikvision login paths: {len(hik_paths)}")

# Query CVEs
critical_cves = get_cves_by_severity('critical')
print(f"Critical CVEs: {len(critical_cves)}")

# Get statistics
stats = get_cve_statistics()
print(f"Total CVEs: {stats['total_cves']}")
print(f"CVEs with exploits: {stats['with_exploits']}")

# Validate IPs
targets = ['8.8.8.8', '192.168.1.1', '999.999.999.999']
for target in targets:
    is_valid, warning = IPValidator.validate_ip(target)
    if is_valid:
        ip_type = IPValidator.get_ip_type(target)
        print(f"{target}: Valid ({ip_type})")
        if warning:
            print(f"  Warning: {warning}")
    else:
        print(f"{target}: Invalid")
```

## See Also

- [Analyze Modules API](analyze.md) - Brand detection, CVE lookup, OSINT
- [Discover Modules API](discover.md) - Port scanning and discovery
- [Plugins API](plugins.md) - Vulnerability scanning plugins
