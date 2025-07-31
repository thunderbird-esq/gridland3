import pytest
from gridland.analyze.plugins.builtin.metasploit_plugin import MetasploitPlugin
from gridland.core.models import VulnerabilityResult

@pytest.fixture
def plugin():
    """Provides a fresh plugin instance for each test."""
    return MetasploitPlugin()

def test_generate_rc_script_for_known_cve(plugin):
    """
    Tests that the plugin generates a correct .rc file for a known CVE.
    """
    # --- Arrange ---
    vuln = VulnerabilityResult(
        ip="192.168.1.100",
        port=80,
        vulnerability_id="CVE-2017-7921",
        severity="CRITICAL",
        description="Hikvision Auth Bypass",
        confidence=0.9,
        details={}
    )

    # --- Act ---
    rc_content = plugin.generate_rc_script(vuln)

    # --- Assert ---
    assert rc_content is not None
    assert "use exploit/multi/http/hikvision_auth_bypass" in rc_content
    assert "set RHOSTS 192.168.1.100" in rc_content
    assert "set RPORT 80" in rc_content
    assert "run" in rc_content

def test_generate_rc_script_for_unknown_cve(plugin):
    """
    Tests that the plugin returns None for a CVE it doesn't know about.
    """
    # --- Arrange ---
    vuln = VulnerabilityResult(
        ip="10.0.0.5",
        port=443,
        vulnerability_id="CVE-2099-9999", # An unknown CVE
        severity="HIGH",
        description="A fake vulnerability",
        confidence=0.9,
        details={}
    )

    # --- Act ---
    rc_content = plugin.generate_rc_script(vuln)

    # --- Assert ---
    assert rc_content is None
