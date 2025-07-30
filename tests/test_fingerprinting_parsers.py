# In tests/test_fingerprinting_parsers.py

import pytest
from unittest.mock import MagicMock
from gridland.analyze.plugins.builtin.advanced_fingerprinting_scanner import AdvancedFingerprintingScanner
from gridland.core.models import DeviceFingerprint
import xml.etree.ElementTree as ET

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
    scheduler = MagicMock()
    memory_pool = MagicMock()
    scanner = AdvancedFingerprintingScanner(scheduler, memory_pool)
    scanner.fingerprinting_database = {'hikvision': {}, 'dahua': {}}
    return scanner

# This is now a standard, synchronous test.
def test_parse_hikvision_xml(scanner_instance):
    """
    Tests if the _parse_hikvision_xml method correctly extracts the
    model and firmware from a sample XML string.
    """
    fingerprint = DeviceFingerprint(brand="hikvision")

    # Act: We call the synchronous method directly. No 'await' is needed.
    scanner_instance._parse_hikvision_xml(HIKVISION_DEVICE_INFO_XML, fingerprint)

    # Assert: Check that the method correctly populated the object.
    assert fingerprint.model == "DS-2CD2143G0-I"
    assert fingerprint.firmware_version == "V5.5.82"
    assert fingerprint.device_type == "IPCamera"
