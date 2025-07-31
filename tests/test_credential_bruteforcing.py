import pytest
import asyncio
from aiohttp import web

from gridland.analyze.plugins.builtin.credential_bruteforcing import CredentialBruteforcingScanner

@pytest.fixture
def scanner():
    """Provides a fresh scanner instance for each test."""
    return CredentialBruteforcingScanner()

async def handler_200(request):
    return web.Response(text="OK")

async def handler_401(request):
    return web.Response(text="Unauthorized", status=401)

@pytest.mark.asyncio
async def test_successful_login(scanner, aiohttp_server):
    """Test that the scanner finds the correct credentials."""
    async def handler_200_auth(request):
        if request.headers.get('Authorization') == 'Basic YWRtaW46YWRtaW4=': # admin:admin
            return web.Response(text="<html><body>Welcome admin, please logout when done.</body></html>")
        return web.Response(text="Unauthorized", status=401)

    app = web.Application()
    app.router.add_get('/', handler_200_auth)
    server = await aiohttp_server(app)

    scanner.default_credentials = [("admin", "admin")]
    target_ip = server.host
    target_port = server.port

    results = await scanner.scan_vulnerabilities(target_ip, target_port, "http", "")

    assert len(results) == 1
    assert results[0].vulnerability_id == "DEFAULT-CREDENTIALS"
    assert results[0].description == "Default credentials found via HTTP Basic Auth: admin:admin"

@pytest.mark.asyncio
async def test_failed_login(scanner, aiohttp_server):
    """Test that the scanner finds no credentials when login fails."""
    async def handler_401_auth(request):
        return web.Response(text="Unauthorized", status=401)

    app = web.Application()
    app.router.add_get('/', handler_401_auth)
    server = await aiohttp_server(app)

    scanner.default_credentials = [("admin", "wrong_password")]
    target_ip = server.host
    target_port = server.port

    results = await scanner.scan_vulnerabilities(target_ip, target_port, "http", "")

    assert len(results) == 0

@pytest.mark.asyncio
async def test_successful_form_login(scanner, aiohttp_server):
    """Test that the scanner finds correct credentials via form-based auth."""
    async def handler_form_auth(request):
        if request.method == 'POST':
            data = await request.post()
            if data.get('username') == 'admin' and data.get('password') == 'admin':
                return web.Response(text="<html><body>Welcome admin, please logout when done.</body></html>")
            else:
                return web.Response(text="<html><body>Invalid username or password</body></html>")
        return web.Response(text="Please log in", status=401)

    app = web.Application()
    app.router.add_post('/login', handler_form_auth)
    server = await aiohttp_server(app)

    # The scanner should find these credentials
    scanner.default_credentials = [("user", "wrong"), ("admin", "admin")]
    target_ip = server.host
    target_port = server.port

    results = await scanner.scan_vulnerabilities(target_ip, target_port, "http", "")

    assert len(results) == 1
    assert results[0].vulnerability_id == "DEFAULT-CREDENTIALS"
    assert results[0].description == "Default credentials found via Form-Based Auth: admin:admin"
