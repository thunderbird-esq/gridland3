"""
Test Suite for OSINT Integration Scanner Plugin.

Tests the OSINTIntegrationScanner plugin including:
- Plugin initialization
- Metadata
- URL generation
- Dork generation
- Geolocation integration
- API key handling
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gridland.analyze.plugins.builtin.osint_integration_scanner import (
    OSINTIntegrationScanner,
)


# =============================================================================
# Plugin Initialization Tests
# =============================================================================


class TestOSINTScannerInit:
    """Tests for OSINT scanner initialization."""

    def test_initialization(self):
        """Test basic initialization."""
        scanner = OSINTIntegrationScanner()
        assert scanner.url_generator is not None
        assert scanner.geo_lookup is not None
        assert scanner.memory_pool is not None

    def test_api_keys_loaded(self):
        """Test API keys are loaded."""
        scanner = OSINTIntegrationScanner()
        assert isinstance(scanner.api_keys, dict)
        assert "shodan" in scanner.api_keys
        assert "censys_id" in scanner.api_keys

    def test_extended_dorks_initialized(self):
        """Test extended dorks list is initialized."""
        scanner = OSINTIntegrationScanner()
        assert len(scanner.extended_dorks) > 0
        assert any("webcam" in dork for dork in scanner.extended_dorks)


# =============================================================================
# Metadata Tests
# =============================================================================


class TestOSINTScannerMetadata:
    """Tests for plugin metadata."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    def test_metadata_name(self, scanner):
        """Test metadata name."""
        metadata = scanner.get_metadata()
        assert metadata.name == "OSINT Integration Scanner"

    def test_metadata_version(self, scanner):
        """Test metadata version."""
        metadata = scanner.get_metadata()
        assert metadata.version == "1.0.0"

    def test_metadata_type(self, scanner):
        """Test metadata plugin type."""
        metadata = scanner.get_metadata()
        assert metadata.plugin_type == "reconnaissance"

    def test_metadata_services(self, scanner):
        """Test supported services."""
        metadata = scanner.get_metadata()
        assert "http" in metadata.supported_services
        assert "https" in metadata.supported_services
        assert "rtsp" in metadata.supported_services

    def test_metadata_performance(self, scanner):
        """Test performance impact."""
        metadata = scanner.get_metadata()
        assert metadata.performance_impact == "LOW"


# =============================================================================
# URL Generation Tests
# =============================================================================


class TestURLGeneration:
    """Tests for URL generation."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    def test_generate_all_urls(self, scanner):
        """Test URL generation for all platforms."""
        urls = scanner._generate_all_urls("192.168.1.1")
        assert "shodan" in urls
        assert "censys" in urls
        assert "binaryedge" in urls
        assert "virustotal" in urls

    def test_url_contains_ip(self, scanner):
        """Test URLs contain target IP."""
        urls = scanner._generate_all_urls("10.0.0.1")
        for platform, url in urls.items():
            assert "10.0.0.1" in url, f"{platform} URL missing IP"

    def test_shodan_url_format(self, scanner):
        """Test Shodan URL format."""
        urls = scanner._generate_all_urls("192.168.1.1")
        assert "shodan.io" in urls["shodan"]

    def test_virustotal_url_format(self, scanner):
        """Test VirusTotal URL format."""
        urls = scanner._generate_all_urls("192.168.1.1")
        assert "virustotal.com" in urls["virustotal"]

    def test_greynoise_url_format(self, scanner):
        """Test GreyNoise URL format."""
        urls = scanner._generate_all_urls("192.168.1.1")
        assert "greynoise.io" in urls["greynoise"]


# =============================================================================
# Dork Generation Tests
# =============================================================================


class TestDorkGeneration:
    """Tests for Google Dork generation."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    def test_generate_all_dorks(self, scanner):
        """Test dork generation returns list."""
        dorks = scanner._generate_all_dorks("192.168.1.1")
        assert isinstance(dorks, list)

    def test_generate_extended_dorks(self, scanner):
        """Test extended dork generation."""
        dorks = scanner._generate_extended_dorks("192.168.1.1")
        assert len(dorks) > 0

    def test_extended_dorks_have_google(self, scanner):
        """Test extended dorks include Google variants."""
        dorks = scanner._generate_extended_dorks("192.168.1.1")
        google_dorks = [d for d in dorks if d.get("engine") == "google"]
        assert len(google_dorks) > 0

    def test_extended_dorks_have_bing(self, scanner):
        """Test extended dorks include Bing variants."""
        dorks = scanner._generate_extended_dorks("192.168.1.1")
        bing_dorks = [d for d in dorks if d.get("engine") == "bing"]
        assert len(bing_dorks) > 0

    def test_dorks_have_url(self, scanner):
        """Test dorks include search URL."""
        dorks = scanner._generate_extended_dorks("192.168.1.1")
        for dork in dorks:
            assert "url" in dork
            assert dork["url"].startswith("http")

    def test_dorks_have_query(self, scanner):
        """Test dorks include query string."""
        dorks = scanner._generate_extended_dorks("192.168.1.1")
        for dork in dorks:
            assert "query" in dork
            assert "192.168.1.1" in dork["query"]


# =============================================================================
# API Key Tests
# =============================================================================


class TestAPIKeyHandling:
    """Tests for API key handling."""

    def test_get_available_apis_empty(self):
        """Test available APIs when no keys configured."""
        with patch.dict("os.environ", {}, clear=True):
            scanner = OSINTIntegrationScanner()
            apis = scanner.get_available_apis()
            assert isinstance(apis, list)

    def test_has_api_key_false(self):
        """Test has_api_key returns False when not set."""
        with patch.dict("os.environ", {}, clear=True):
            scanner = OSINTIntegrationScanner()
            assert scanner.has_api_key("shodan") is False

    def test_has_api_key_true(self):
        """Test has_api_key returns True when set."""
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test_key"}):
            scanner = OSINTIntegrationScanner()
            assert scanner.has_api_key("shodan") is True

    def test_get_available_apis_with_key(self):
        """Test available APIs includes configured keys."""
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test_key"}):
            scanner = OSINTIntegrationScanner()
            apis = scanner.get_available_apis()
            assert "shodan" in apis


# =============================================================================
# Scan Vulnerabilities Tests
# =============================================================================


class TestScanVulnerabilities:
    """Tests for scan_vulnerabilities method."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_scan_returns_results(self, scanner):
        """Test scan returns vulnerability results."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock_geo:
            mock_geo.return_value = {"country": "US", "city": "Test"}
            with patch.object(scanner.geo_lookup, "generate_map_urls") as mock_map:
                mock_map.return_value = {"google": "http://maps.google.com"}
                
                results = await scanner.scan_vulnerabilities("192.168.1.1", 80)
                
                assert len(results) >= 1
                assert results[0].vulnerability_id == "OSINT-INTELLIGENCE"

    @pytest.mark.asyncio
    async def test_scan_includes_ip(self, scanner):
        """Test scan result includes target IP."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock:
            mock.return_value = {}
            with patch.object(scanner.geo_lookup, "generate_map_urls") as mock_map:
                mock_map.return_value = {}
                
                results = await scanner.scan_vulnerabilities("10.0.0.1", 8080)
                
                assert results[0].ip == "10.0.0.1"
                assert results[0].port == 8080

    @pytest.mark.asyncio
    async def test_scan_severity_info(self, scanner):
        """Test scan result has INFO severity."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock:
            mock.return_value = {}
            with patch.object(scanner.geo_lookup, "generate_map_urls") as mock_map:
                mock_map.return_value = {}
                
                results = await scanner.scan_vulnerabilities("192.168.1.1", 80)
                
                assert results[0].severity == "INFO"

    @pytest.mark.asyncio
    async def test_scan_handles_geo_error(self, scanner):
        """Test scan handles geolocation errors gracefully."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock:
            mock.side_effect = Exception("GeoIP lookup failed")
            
            # Should not raise, just log error in geo data
            results = await scanner.scan_vulnerabilities("192.168.1.1", 80)
            
            assert len(results) >= 1


# =============================================================================
# OSINT Report Tests
# =============================================================================


class TestOSINTReport:
    """Tests for OSINT report generation."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_report_structure(self, scanner):
        """Test OSINT report has expected structure."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock:
            mock.return_value = {"country": "US"}
            with patch.object(scanner.geo_lookup, "generate_map_urls") as mock_map:
                mock_map.return_value = {}
                
                report = await scanner._generate_osint_report("192.168.1.1")
                
                assert "target_ip" in report
                assert "search_urls" in report
                assert "google_dorks" in report
                assert "extended_dorks" in report
                assert "geolocation" in report
                assert "apis_available" in report

    @pytest.mark.asyncio
    async def test_report_target_ip(self, scanner):
        """Test report includes correct target IP."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock:
            mock.return_value = {}
            with patch.object(scanner.geo_lookup, "generate_map_urls") as mock_map:
                mock_map.return_value = {}
                
                report = await scanner._generate_osint_report("10.20.30.40")
                
                assert report["target_ip"] == "10.20.30.40"

    @pytest.mark.asyncio
    async def test_report_geo_error_recorded(self, scanner):
        """Test geolocation errors are recorded in report."""
        with patch.object(scanner.geo_lookup, "get_ip_info", new_callable=AsyncMock) as mock:
            mock.side_effect = Exception("API error")
            
            report = await scanner._generate_osint_report("192.168.1.1")
            
            assert "error" in report["geolocation"]


# =============================================================================
# API Query Method Tests
# =============================================================================


class TestShodanAPIQuery:
    """Tests for Shodan API query method."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_shodan_no_api_key(self, scanner):
        """Test Shodan query without API key."""
        with patch.dict("os.environ", {}, clear=True):
            scanner.api_keys = scanner._load_api_keys()
            result = await scanner.query_shodan_api("192.168.1.1")
            assert result["available"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_shodan_success(self, scanner):
        """Test successful Shodan query."""
        from aioresponses import aioresponses
        
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test_key"}):
            scanner.api_keys = scanner._load_api_keys()
            
            with aioresponses() as m:
                m.get(
                    "https://api.shodan.io/shodan/host/192.168.1.1?key=test_key",
                    payload={
                        "ip_str": "192.168.1.1",
                        "org": "Test Org",
                        "ports": [80, 443],
                        "hostnames": ["test.com"],
                        "data": [{"port": 80, "product": "nginx"}]
                    }
                )
                
                result = await scanner.query_shodan_api("192.168.1.1")
                
                assert result["available"] is True
                assert result["ip"] == "192.168.1.1"
                assert result["organization"] == "Test Org"

    @pytest.mark.asyncio
    async def test_shodan_not_found(self, scanner):
        """Test Shodan query with IP not found."""
        from aioresponses import aioresponses
        
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test_key"}):
            scanner.api_keys = scanner._load_api_keys()
            
            with aioresponses() as m:
                m.get(
                    "https://api.shodan.io/shodan/host/192.168.1.1?key=test_key",
                    status=404
                )
                
                result = await scanner.query_shodan_api("192.168.1.1")
                
                assert result["available"] is True
                assert result.get("no_data") is True


class TestCensysAPIQuery:
    """Tests for Censys API query method."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_censys_no_credentials(self, scanner):
        """Test Censys query without credentials."""
        with patch.dict("os.environ", {}, clear=True):
            scanner.api_keys = scanner._load_api_keys()
            result = await scanner.query_censys_api("192.168.1.1")
            assert result["available"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_censys_success(self, scanner):
        """Test successful Censys query."""
        from aioresponses import aioresponses
        
        with patch.dict("os.environ", {
            "CENSYS_API_ID": "test_id",
            "CENSYS_API_SECRET": "test_secret"
        }):
            scanner.api_keys = scanner._load_api_keys()
            
            with aioresponses() as m:
                m.get(
                    "https://search.censys.io/api/v2/hosts/192.168.1.1",
                    payload={
                        "result": {
                            "ip": "192.168.1.1",
                            "services": [{"port": 80, "service_name": "HTTP"}],
                            "location": {"country": "US"},
                        }
                    }
                )
                
                result = await scanner.query_censys_api("192.168.1.1")
                
                assert result["available"] is True
                assert result["ip"] == "192.168.1.1"


class TestZoomEyeAPIQuery:
    """Tests for ZoomEye API query method."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_zoomeye_no_api_key(self, scanner):
        """Test ZoomEye query without API key."""
        with patch.dict("os.environ", {}, clear=True):
            scanner.api_keys = scanner._load_api_keys()
            result = await scanner.query_zoomeye_api("192.168.1.1")
            assert result["available"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_zoomeye_success(self, scanner):
        """Test successful ZoomEye query."""
        from aioresponses import aioresponses
        
        with patch.dict("os.environ", {"ZOOMEYE_API_KEY": "test_key"}):
            scanner.api_keys = scanner._load_api_keys()
            
            with aioresponses() as m:
                m.get(
                    "https://api.zoomeye.org/host/search?query=ip:192.168.1.1",
                    payload={
                        "total": 1,
                        "matches": [{"ip": "192.168.1.1", "portinfo": {"port": 80}}]
                    }
                )
                
                result = await scanner.query_zoomeye_api("192.168.1.1")
                
                assert result["available"] is True
                assert result["total"] == 1


class TestPassiveDNSQuery:
    """Tests for passive DNS query method."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_passive_dns_success(self, scanner):
        """Test successful passive DNS query."""
        from aioresponses import aioresponses
        
        with aioresponses() as m:
            m.get(
                "https://dns.google/resolve?name=8.8.8.8&type=PTR",
                payload={
                    "Answer": [{"data": "test.example.com."}]
                }
            )
            
            result = await scanner.query_passive_dns("8.8.8.8")
            
            assert result["available"] is True
            assert "test.example.com" in result["hostnames"]

    @pytest.mark.asyncio
    async def test_passive_dns_no_results(self, scanner):
        """Test passive DNS with no results."""
        from aioresponses import aioresponses
        
        with aioresponses() as m:
            m.get(
                "https://dns.google/resolve?name=192.168.1.1&type=PTR",
                payload={}
            )
            
            result = await scanner.query_passive_dns("192.168.1.1")
            
            assert result["available"] is True
            assert result["hostnames"] == []


class TestQueryAllAPIs:
    """Tests for query_all_apis method."""

    @pytest.fixture
    def scanner(self):
        return OSINTIntegrationScanner()

    @pytest.mark.asyncio
    async def test_query_all_apis_with_no_keys(self, scanner):
        """Test query_all_apis with no API keys configured."""
        from aioresponses import aioresponses
        
        with patch.dict("os.environ", {}, clear=True):
            scanner.api_keys = scanner._load_api_keys()
            
            with aioresponses() as m:
                # Mock passive DNS (always runs)
                m.get(
                    "https://dns.google/resolve?name=192.168.1.1&type=PTR",
                    payload={}
                )
                
                result = await scanner.query_all_apis("192.168.1.1")
                
                # Should still have passive_dns since it's free
                assert "passive_dns" in result

    @pytest.mark.asyncio
    async def test_query_all_apis_handles_exceptions(self, scanner):
        """Test query_all_apis handles exceptions gracefully."""
        from aioresponses import aioresponses
        
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test_key"}):
            scanner.api_keys = scanner._load_api_keys()
            
            with aioresponses() as m:
                # Mock Shodan to fail
                m.get(
                    "https://api.shodan.io/shodan/host/192.168.1.1?key=test_key",
                    exception=Exception("Network error")
                )
                # Mock passive DNS to succeed
                m.get(
                    "https://dns.google/resolve?name=192.168.1.1&type=PTR",
                    payload={}
                )
                
                result = await scanner.query_all_apis("192.168.1.1")
                
                # Should have shodan with error
                assert "shodan" in result
                assert "error" in result["shodan"]


