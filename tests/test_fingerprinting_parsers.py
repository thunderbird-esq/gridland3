import pytest
from unittest.mock import MagicMock
from gridland.analyze.plugins.builtin.advanced_fingerprinting_scanner import AdvancedFingerprintingScanner
from gridland.analyze.plugins.builtin.advanced_fingerprinting_scanner import DeviceFingerprint

# This is a sample XML response from a Hikvision camera's ISAPI endpoint
HIKVISION_DEVICE_INFO_XML = """
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
  <deviceName>HIKVISION-CAMERA</deviceName>
  <deviceID>abcdef-123456-fedcba</deviceID>
  <deviceType>IPCamera</deviceType>
  <model>DS-2CD2143G0-I</model>
  <firmwareVersion>V5.5.82</firmwareVersion>
  <firmwareReleasedDate>build 190120</firmwareReleasedDate>
</DeviceInfo>
"""

@pytest.fixture
def scanner_instance():
    """Creates a mock instance of the scanner for testing."""
    # We use MagicMock to avoid initializing the real scheduler and memory pool
    scanner = AdvancedFingerprintingScanner(MagicMock(), MagicMock())
    return scanner

def test_parse_hikvision_xml(scanner_instance):
    """
    Tests if the _parse_hikvision_xml method correctly extracts the
    model and firmware from a sample XML string.
    """
    # Arrange: Create an empty fingerprint object to be filled
    fingerprint = DeviceFingerprint(brand="hikvision")

    # Act: Call the method we want to test
    scanner_instance._parse_hikvision_xml(HIKVISION_DEVICE_INFO_XML, fingerprint)

    # Assert: Check if the fields were populated correctly
    assert fingerprint.model == "DS-2CD2143G0-I"
    assert fingerprint.firmware_version == "V5.5.82"
    assert "IPCamera" in fingerprint.device_type
