import pytest
import asyncio
import os
from unittest.mock import AsyncMock, patch

from gridland.analyze.plugins.builtin.generic_camera_scanner import GenericCameraScanner

@pytest.fixture
def scanner():
    """Provides a fresh scanner instance for each test."""
    return GenericCameraScanner()

@pytest.mark.asyncio
@patch('pyppeteer.launch')
async def test_get_screenshot_success(mock_launch, scanner):
    """
    Test that the get_screenshot method successfully captures a screenshot.
    """
    # --- Arrange ---
    test_url = "http://example.com"
    output_dir = "test_output"
    target_ip = "1.2.3.4"
    target_port = 80

    # Mock the browser and page objects
    mock_browser = AsyncMock()
    mock_page = AsyncMock()
    mock_browser.newPage.return_value = mock_page
    mock_launch.return_value = mock_browser

    # --- Act ---
    result_path = await scanner.get_screenshot(test_url, output_dir, target_ip, target_port)

    # --- Assert ---
    # 1. Check that the browser was launched and closed
    mock_launch.assert_called_once()
    mock_browser.close.assert_called_once()

    # 2. Check that the browser navigated to the correct page
    mock_page.goto.assert_called_once_with(test_url, {'waitUntil': 'networkidle0', 'timeout': 10000})

    # 3. Check that a screenshot was taken with the correct path
    mock_page.screenshot.assert_called_once()
    screenshot_args = mock_page.screenshot.call_args
    saved_path = screenshot_args[0][0]['path'] # path is in the dict in the first positional arg

    assert saved_path.startswith(output_dir)
    assert f"{target_ip.replace('.', '_')}_{target_port}" in saved_path
    assert saved_path.endswith('.png')

    # 4. Check that the method returned the correct path
    assert result_path == saved_path

    # Cleanup created directory if it exists
    if os.path.exists(output_dir):
        import shutil
        shutil.rmtree(output_dir)

@pytest.mark.asyncio
@patch('pyppeteer.launch', new_callable=AsyncMock)
async def test_get_screenshot_failure(mock_launch, scanner):
    """
    Test that get_screenshot handles errors gracefully and returns None.
    """
    # --- Arrange ---
    test_url = "http://example-fails.com"
    output_dir = "test_output_fail"
    target_ip = "5.6.7.8"
    target_port = 8080

    # Configure the mock to raise a specific pyppeteer error
    from pyppeteer.errors import TimeoutError
    mock_launch.side_effect = TimeoutError("Browser launch failed")

    # --- Act ---
    result_path = await scanner.get_screenshot(test_url, output_dir, target_ip, target_port)

    # --- Assert ---
    # 1. Check that the method returned None
    assert result_path is None

    # 2. Check that the browser launch was attempted
    mock_launch.assert_called_once()
