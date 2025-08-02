import subprocess
import json
import sys

def main():
    """
    This is an end-to-end integration test that runs the discover and analyze
    commands against a known vulnerable target.
    """
    # Discover the target
    discover_process = subprocess.run(
        [
            "python3",
            "main.py",
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

    if discover_process.returncode != 0:
        print("Discovery process failed!")
        print(discover_process.stderr)
        sys.exit(1)

    try:
        discover_results = json.loads(discover_process.stdout)
    except json.JSONDecodeError:
        print("Failed to decode discovery results as JSON!")
        print(discover_process.stdout)
        sys.exit(1)

    if not discover_results:
        print("Discovery did not find any results!")
        sys.exit(1)

    print("Discovery successful!")

    # Analyze the target
    analyze_process = subprocess.run(
        [
            "python3",
            "main.py",
            "analyze",
            "--targets",
            "45.33.32.156:80",
            "--output-format",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    if analyze_process.returncode != 0:
        print("Analysis process failed!")
        print(analyze_process.stderr)
        sys.exit(1)

    try:
        analyze_results = json.loads(analyze_process.stdout)
    except json.JSONDecodeError:
        print("Failed to decode analysis results as JSON!")
        print(analyze_process.stdout)
        sys.exit(1)

    if not analyze_results:
        print("Analysis did not produce any results!")
        sys.exit(1)
        
    if not analyze_results[0]["vulnerabilities"]:
        print("Analysis did not find any vulnerabilities!")
        sys.exit(1)

    print("Analysis successful!")
    print("All tests passed!")

if __name__ == "__main__":
    main()
