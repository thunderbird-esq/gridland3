import pytest
import asyncio
from aiohttp import web

from gridland.analyze.plugins.builtin.shodan_enrichment import ShodanEnrichment
from gridland.core.config import get_config

@pytest.fixture
def scanner():
    """Provides a fresh scanner instance for each test."""
    return ShodanEnrichment()

@pytest.fixture
def mock_shodan_api(aiohttp_server):
    async def handler(request):
        return web.json_response({
            "org": "Test Org",
            "os": "Linux",
            "isp": "Test ISP",
            "hostnames": ["test.com"],
            "vulns": ["CVE-2021-1234"]
        })

    app = web.Application()
    app.router.add_get('/shodan/host/{ip}', handler)
    return aiohttp_server(app)

@pytest.mark.asyncio
async def test_shodan_enrichment(scanner, mock_shodan_api):
    """Test that the scanner correctly enriches the target with Shodan data."""
    config = get_config()
    config.shodan_api_key = "test_key" # Mock API key

    server = await mock_shodan_api
    target_ip = server.host

    # Override the API URL to point to the mock server
    scanner.config.shodan_api_url = f"http://{server.host}:{server.port}/shodan/host/{{ip}}?key={{key}}"

    results = await scanner.scan_vulnerabilities(target_ip, 80, "http", "")

    assert len(results) == 1
    assert results[0].vulnerability_id == "SHODAN-ENRICHMENT"
    assert "Org: Test Org" in results[0].description
    assert "OS: Linux" in results[0].description
    assert "ISP: Test ISP" in results[0].description
    assert "Hostnames: test.com" in results[0].description
    assert "Vulnerabilities: CVE-2021-1234" in results[0].description
