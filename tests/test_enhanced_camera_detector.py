# In tests/test_enhanced_camera_detector.py

import pytest
from unittest.mock import MagicMock
from gridland.analyze.plugins.builtin.enhanced_camera_detector import EnhancedCameraDetector, CameraIndicator

@pytest.fixture
def detector():
    """Provides a fresh detector instance for each test."""
    # --- THIS IS THE FIX ---
    # The class __init__ requires scheduler and memory_pool. We provide mocks.
    scheduler, memory_pool = MagicMock(), MagicMock()
    detector_instance = EnhancedCameraDetector(scheduler, memory_pool)
    # --- END OF FIX ---

    detector_instance.fingerprinting_database = {
        'server_header_patterns': {
            'hikvision': ['hikvision', 'dvr'],
            'dahua': ['dahua'],
            'generic': ['webcam', 'ip camera']
        },
        'content_keywords': {
            'device_type': ['ip camera', 'network camera'],
            'functionality': ['live video', 'stream']
        }
    }
    return detector_instance

def test_analyze_server_header_hikvision(detector):
    header = "server: hikvision-dvr"
    indicators = detector._analyze_server_header(header)
    assert len(indicators) > 0
    assert indicators[0].brand == "hikvision"

def test_analyze_server_header_dahua(detector):
    header = "server: dahua http server"
    indicators = detector._analyze_server_header(header)
    assert len(indicators) > 0
    assert indicators[0].brand == "dahua"

def test_analyze_server_header_generic(detector):
    header = "server: my webcam"
    indicators = detector._analyze_server_header(header)
    assert len(indicators) > 0
    assert all(ind.brand == "generic" for ind in indicators)

def test_analyze_content_keywords_device_types(detector):
    """Test content keyword analysis for device type detection"""
    content = "This is an IP Camera interface"
    indicators = detector._analyze_content_keywords(content, "device_type")
    assert len(indicators) > 0
    assert any(ind.value == "ip camera" for ind in indicators)
    assert all(ind.indicator_type == "CONTENT_KEYWORD" for ind in indicators)

def test_analyze_content_keywords_functionality(detector):
    """Test content keyword analysis for functionality detection"""
    content = "Welcome to live video streaming service"
    indicators = detector._analyze_content_keywords(content, "functionality")
    assert len(indicators) > 0
    assert any(ind.value == "live video" for ind in indicators)
    assert all(ind.indicator_type == "CONTENT_KEYWORD" for ind in indicators)
