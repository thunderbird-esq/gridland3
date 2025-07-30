import pytest
from gridland.analyze.plugins.builtin.enhanced_camera_detector import EnhancedCameraDetector, CameraIndicator

@pytest.fixture
def detector():
    return EnhancedCameraDetector()

def test_analyze_server_header_hikvision(detector):
    header = "server: hikvision-dvr"
    indicators = detector._analyze_server_header(header)
    assert len(indicators) > 0
    assert indicators[0].brand == "hikvision"
    assert indicators[0].confidence == 0.85

def test_analyze_server_header_dahua(detector):
    header = "server: dahua http server"
    indicators = detector._analyze_server_header(header)
    assert len(indicators) > 0
    assert indicators[0].brand == "dahua"
    assert indicators[0].confidence == 0.85

def test_analyze_server_header_generic(detector):
    header = "server: my webcam"
    indicators = detector._analyze_server_header(header)
    assert len(indicators) > 0
    assert indicators[0].brand is None
    assert indicators[0].confidence == 0.60

def test_analyze_content_keywords_device_types(detector):
    content = "<html><head><title>My Camera</title></head><body>This is a page for my new ip camera.</body></html>"
    indicators = detector._analyze_content_keywords(content)
    assert len(indicators) > 0
    assert indicators[0].indicator_type == "content_keyword"
    assert "device_types" in indicators[0].value
    assert indicators[0].confidence > 0.7

def test_analyze_content_keywords_functionality(detector):
    content = "<html><head><title>Live Stream</title></head><body>Click here for the live video stream.</body></html>"
    indicators = detector._analyze_content_keywords(content)
    assert len(indicators) > 0
    assert indicators[0].indicator_type == "content_keyword"
    assert "functionality" in indicators[0].value
    assert indicators[0].confidence > 0.5
