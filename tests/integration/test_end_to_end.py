import subprocess
import json

def test_end_to_end():
    """
    This is an end-to-end integration test that runs the discover and analyze
    commands against a known vulnerable target.
    """
    # Discover the target
    discover_process = subprocess.run(
        [
            "python3",
            "gridland.py",
            "discover",
            "--engine",
            "masscan",
            "--range",
            "45.33.32.156", # metasploitable
            "--ports",
            "80",
            "--output-format",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    assert discover_process.returncode == 0
    discover_results = json.loads(discover_process.stdout)
    assert len(discover_results) > 0

    # Analyze the target
    analyze_process = subprocess.run(
        [
            "python3",
            "gridland.py",
            "analyze",
            "--targets",
            "45.33.32.156:80",
            "--output-format",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    assert analyze_process.returncode == 0
    analyze_results = json.loads(analyze_process.stdout)
    assert len(analyze_results) > 0
    assert len(analyze_results[0]["vulnerabilities"]) > 0
