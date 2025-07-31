import pytest
import asyncio
import os
from unittest.mock import AsyncMock, patch, MagicMock
from aiohttp import web

from gridland.analyze.plugins.builtin.generic_camera_scanner import GenericCameraScanner
from gridland.core.config import GridlandConfig

@pytest.fixture
def scanner():
    """Provides a fresh scanner instance for each test."""
    return GenericCameraScanner()

@pytest.mark.asyncio
@patch('pyppeteer.launch')
async def test_screenshot_on_login_page_discovery(mock_launch, scanner, aiohttp_server):
    """
    Test that a screenshot is taken when a login page is discovered.
    """
    # --- Arrange ---

    # 1. Mock the browser launch and screenshot functionality
    mock_browser = AsyncMock()
    mock_page = AsyncMock()
    mock_browser.newPage.return_value = mock_page
    mock_launch.return_value.__aenter__.return_value = mock_browser # For async with

    # 2. Mock the configuration to control the output directory
    # In a real scenario, get_config would load this from yaml
    mock_config_instance = GridlandConfig()
    mock_config_instance.output = {'screenshots': 'test_screenshots'}

    # 3. Setup a mock web server to return a page with login indicators
    async def login_page_handler(request):
        return web.Response(text="<html><body><form>Username: <input name='username'/></form></body></html>", content_type='text/html')

    app = web.Application()
    # Add a root handler that looks like a camera to pass the initial check
    async def root_handler(request):
        return web.Response(text="<title>IP Camera Interface</title>", content_type='text/html')
    app.router.add_get('/', root_handler)
    app.router.add_get('/login.html', login_page_handler)
    server = await aiohttp_server(app)

    target_ip = server.host
    target_port = server.port

    # --- Act ---
    with patch('gridland.analyze.plugins.builtin.generic_camera_scanner.get_config', return_value=mock_config_instance):
        results = await scanner.scan_vulnerabilities(target_ip, target_port, "http", "banner")

    # --- Assert ---

    # 1. Check that a vulnerability result for the login page was created
    assert len(results) > 0
    login_page_result = next((r for r in results if r.vulnerability_id == "LOGIN-PAGE-DISCOVERED"), None)
    assert login_page_result is not None
    assert login_page_result.severity == "INFO"
    assert "login.html" in login_page_result.description

    # 2. Check that the browser was launched
    mock_launch.assert_called_once()

    # 3. Check that the browser navigated to the correct page
    print(f"DEBUG: mock_page.method_calls: {mock_page.method_calls}")
    mock_page.goto.assert_called_once_with(f'http://{target_ip}:{target_port}/login.html', {'waitUntil': 'networkidle0'})

    # 4. Check that a screenshot was attempted
    mock_page.screenshot.assert_called_once()

    # 5. Check that the screenshot path in the metadata is correct
    screenshot_call_args = mock_page.screenshot.call_args
    # The 'path' is in the first positional argument, which is a dictionary
    saved_path = screenshot_call_args[0][0]['path']

    assert saved_path.startswith('test_screenshots/')
    assert saved_path.endswith('.png')
    assert f"{target_ip.replace('.', '_')}_{target_port}" in saved_path

    assert login_page_result.metadata is not None
    assert login_page_result.metadata.get('screenshot_path') == saved_path

    # Cleanup created directory if it exists
    if os.path.exists('test_screenshots'):
        # In a real test, the mock wouldn't create the dir, but good practice
        # to clean up if the test setup did.
        import shutil
        shutil.rmtree('test_screenshots')
