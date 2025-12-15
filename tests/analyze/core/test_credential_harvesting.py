"""
Comprehensive test suite for credential_harvesting.py module.

Tests cover:
- CredentialPair, AuthenticationVector, CredentialHarvest dataclasses
- IntelligentCredentialGenerator credential list generation
- AuthenticationMethodDetector authentication detection
- CredentialTestingEngine testing pipeline
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gridland.analyze.core.credential_harvesting import (
    CredentialPair,
    AuthenticationVector,
    CredentialHarvest,
    IntelligentCredentialGenerator,
    AuthenticationMethodDetector,
    CredentialTestingEngine,
)


class TestCredentialPairDataclass:
    """Test CredentialPair dataclass."""

    def test_basic_creation(self):
        """Test basic credential pair creation."""
        cred = CredentialPair(
            username="admin",
            password="12345",
            service="http",
            port=80,
            confidence=0.9,
            discovery_method="brute_force",
            authentication_type="basic",
            verification_status="valid"
        )
        assert cred.username == "admin"
        assert cred.password == "12345"
        assert cred.verification_status == "valid"

    def test_metadata_default(self):
        """Test metadata default value."""
        cred = CredentialPair(
            username="root",
            password="root",
            service="ssh",
            port=22,
            confidence=0.8,
            discovery_method="default_credentials",
            authentication_type="form",
            verification_status="unverified"
        )
        assert cred.metadata == {}

    def test_all_auth_types(self):
        """Test different authentication types."""
        auth_types = ["basic", "digest", "form", "api_key", "token"]
        for auth_type in auth_types:
            cred = CredentialPair(
                username="test",
                password="test",
                service="http",
                port=80,
                confidence=0.5,
                discovery_method="test",
                authentication_type=auth_type,
                verification_status="unverified"
            )
            assert cred.authentication_type == auth_type


class TestAuthenticationVectorDataclass:
    """Test AuthenticationVector dataclass."""

    def test_basic_creation(self):
        """Test basic authentication vector creation."""
        vector = AuthenticationVector(
            target_ip="192.168.1.1",
            target_port=80,
            service_type="http",
            authentication_method="http_basic",
            endpoint_url="http://192.168.1.1/login",
            required_fields=["username", "password"],
            success_indicators=["200", "dashboard"],
            failure_indicators=["401", "403"],
            rate_limit_indicators=["429"],
            bypass_techniques=["url_manipulation"]
        )
        assert vector.target_ip == "192.168.1.1"
        assert vector.authentication_method == "http_basic"

    def test_rtsp_vector(self):
        """Test RTSP authentication vector."""
        vector = AuthenticationVector(
            target_ip="192.168.1.100",
            target_port=554,
            service_type="rtsp",
            authentication_method="rtsp_digest",
            endpoint_url="rtsp://192.168.1.100/stream",
            required_fields=["username", "password"],
            success_indicators=["200 OK"],
            failure_indicators=["401 Unauthorized"],
            rate_limit_indicators=[],
            bypass_techniques=["null_authentication"]
        )
        assert vector.service_type == "rtsp"
        assert vector.target_port == 554


class TestCredentialHarvestDataclass:
    """Test CredentialHarvest dataclass."""

    def test_basic_creation(self):
        """Test basic harvest result creation."""
        valid_cred = CredentialPair(
            username="admin",
            password="admin",
            service="http",
            port=80,
            confidence=1.0,
            discovery_method="default",
            authentication_type="basic",
            verification_status="valid"
        )
        harvest = CredentialHarvest(
            target_ip="192.168.1.1",
            valid_credentials=[valid_cred],
            potential_credentials=[],
            authentication_vectors=[],
            configuration_data={},
            session_tokens=[],
            vulnerability_indicators=[],
            harvest_metadata={"duration": 45.5}
        )
        assert harvest.target_ip == "192.168.1.1"
        assert len(harvest.valid_credentials) == 1

    def test_empty_harvest(self):
        """Test empty harvest result."""
        harvest = CredentialHarvest(
            target_ip="10.0.0.1",
            valid_credentials=[],
            potential_credentials=[],
            authentication_vectors=[],
            configuration_data={},
            session_tokens=[],
            vulnerability_indicators=[],
            harvest_metadata={}
        )
        assert len(harvest.valid_credentials) == 0


class TestIntelligentCredentialGenerator:
    """Test IntelligentCredentialGenerator class."""

    def test_initialization(self):
        """Test generator initialization."""
        generator = IntelligentCredentialGenerator()
        assert generator is not None
        assert hasattr(generator, 'brand_credentials')
        assert hasattr(generator, 'generic_credentials')

    def test_brand_credentials_exist(self):
        """Test brand-specific credentials exist."""
        generator = IntelligentCredentialGenerator()
        assert "hikvision" in generator.brand_credentials
        assert "dahua" in generator.brand_credentials
        assert "axis" in generator.brand_credentials
        assert "bosch" in generator.brand_credentials

    def test_hikvision_credentials(self):
        """Test Hikvision default credentials."""
        generator = IntelligentCredentialGenerator()
        hik_creds = generator.brand_credentials["hikvision"]
        assert ("admin", "12345") in hik_creds
        assert ("admin", "admin") in hik_creds

    def test_generic_credentials_exist(self):
        """Test generic credentials list."""
        generator = IntelligentCredentialGenerator()
        assert len(generator.generic_credentials) > 0
        assert ("admin", "admin") in generator.generic_credentials

    def test_generate_credential_list_no_brand(self):
        """Test credential list generation without brand."""
        generator = IntelligentCredentialGenerator()
        creds = generator.generate_credential_list()
        assert isinstance(creds, list)
        assert len(creds) > 0
        # Should contain generic credentials
        assert ("admin", "admin") in creds

    def test_generate_credential_list_with_brand(self):
        """Test credential list generation with brand."""
        generator = IntelligentCredentialGenerator()
        creds = generator.generate_credential_list(brand="hikvision")
        assert isinstance(creds, list)
        # Brand-specific creds should be at the front
        assert ("admin", "12345") in creds

    def test_generate_credential_list_with_model(self):
        """Test credential list generation with model."""
        generator = IntelligentCredentialGenerator()
        creds = generator.generate_credential_list(model="DS-2CD2142")
        assert isinstance(creds, list)

    def test_generate_credential_list_with_hostname(self):
        """Test credential list generation with hostname."""
        generator = IntelligentCredentialGenerator()
        creds = generator.generate_credential_list(hostname="camera.company.local")
        assert isinstance(creds, list)

    def test_generate_credential_list_unique(self):
        """Test credential list has no duplicates."""
        generator = IntelligentCredentialGenerator()
        creds = generator.generate_credential_list(brand="hikvision")
        assert len(creds) == len(set(creds))

    def test_extract_credentials_from_text(self):
        """Test credential extraction from text."""
        generator = IntelligentCredentialGenerator()
        text = "username=admin password=secret123"
        creds = generator._extract_credentials_from_text(text)
        assert isinstance(creds, list)

    def test_generate_intelligence_based_credentials(self):
        """Test intelligence-based credential generation."""
        generator = IntelligentCredentialGenerator()
        intelligence = {
            "firmware_version": "V5.5.0",
            "serial_number": "ABC123456",
            "mac_address": "AA:BB:CC:DD:EE:FF"
        }
        creds = generator._generate_intelligence_based_credentials(intelligence)
        assert isinstance(creds, list)


class TestAuthenticationMethodDetector:
    """Test AuthenticationMethodDetector class."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = AuthenticationMethodDetector()
        assert detector is not None
        assert hasattr(detector, 'authentication_signatures')

    def test_authentication_signatures_exist(self):
        """Test authentication signatures are populated."""
        detector = AuthenticationMethodDetector()
        assert "http_basic" in detector.authentication_signatures
        assert "http_digest" in detector.authentication_signatures
        assert "form_based" in detector.authentication_signatures
        assert "api_key" in detector.authentication_signatures
        assert "bearer_token" in detector.authentication_signatures

    def test_analyze_authentication_response_basic(self):
        """Test authentication response analysis for Basic auth."""
        detector = AuthenticationMethodDetector()
        methods = detector._analyze_authentication_response(
            status_code=401,
            headers={"www-authenticate": "Basic realm=\"camera\""},
            content=""
        )
        assert "http_basic" in methods

    def test_analyze_authentication_response_digest(self):
        """Test authentication response analysis for Digest auth."""
        detector = AuthenticationMethodDetector()
        methods = detector._analyze_authentication_response(
            status_code=401,
            headers={"www-authenticate": "Digest realm=\"camera\""},
            content=""
        )
        assert "http_digest" in methods

    def test_analyze_authentication_response_form(self):
        """Test authentication response analysis for form auth."""
        detector = AuthenticationMethodDetector()
        methods = detector._analyze_authentication_response(
            status_code=200,
            headers={},
            content='<form method="post"><input name="username"><input name="password"></form>'
        )
        assert "form_based" in methods

    def test_get_required_fields(self):
        """Test getting required fields for auth methods."""
        detector = AuthenticationMethodDetector()
        fields = detector._get_required_fields("http_basic", "")
        assert "username" in fields
        assert "password" in fields

    def test_get_success_indicators(self):
        """Test getting success indicators."""
        detector = AuthenticationMethodDetector()
        indicators = detector._get_success_indicators("http_basic")
        assert isinstance(indicators, list)
        assert "200" in indicators

    def test_get_failure_indicators(self):
        """Test getting failure indicators."""
        detector = AuthenticationMethodDetector()
        indicators = detector._get_failure_indicators("http_basic")
        assert isinstance(indicators, list)
        assert "401" in indicators

    def test_get_rate_limit_indicators(self):
        """Test getting rate limit indicators."""
        detector = AuthenticationMethodDetector()
        indicators = detector._get_rate_limit_indicators()
        assert isinstance(indicators, list)
        assert "429" in indicators

    def test_get_bypass_techniques(self):
        """Test getting bypass techniques."""
        detector = AuthenticationMethodDetector()
        techniques = detector._get_bypass_techniques("http_basic")
        assert isinstance(techniques, list)

    def test_extract_form_fields(self):
        """Test form field extraction."""
        detector = AuthenticationMethodDetector()
        content = '<input name="user"><input name="pass"><input name="submit">'
        fields = detector._extract_form_fields(content)
        assert isinstance(fields, list)


class TestCredentialTestingEngine:
    """Test CredentialTestingEngine class."""

    def test_initialization(self):
        """Test engine initialization."""
        engine = CredentialTestingEngine()
        assert engine is not None
        assert hasattr(engine, 'credential_generator')
        assert hasattr(engine, 'auth_detector')
        assert hasattr(engine, 'testing_stats')

    def test_has_credential_generator(self):
        """Test engine has credential generator."""
        engine = CredentialTestingEngine()
        assert isinstance(engine.credential_generator, IntelligentCredentialGenerator)

    def test_has_auth_detector(self):
        """Test engine has auth detector."""
        engine = CredentialTestingEngine()
        assert isinstance(engine.auth_detector, AuthenticationMethodDetector)

    def test_testing_stats_initialized(self):
        """Test testing statistics are initialized."""
        engine = CredentialTestingEngine()
        assert engine.testing_stats["attempts_made"] == 0
        assert engine.testing_stats["rate_limits_hit"] == 0
        assert engine.testing_stats["valid_credentials_found"] == 0

    def test_order_credentials_by_likelihood(self):
        """Test credential ordering by likelihood."""
        engine = CredentialTestingEngine()
        credentials = [
            ("user", "pass"),
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "12345"),
        ]
        ordered = engine._order_credentials_by_likelihood(credentials, "http")
        assert isinstance(ordered, list)
        # admin:admin and admin:12345 should be prioritized for cameras
        assert ordered[0] in [("admin", "admin"), ("admin", "12345")]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
