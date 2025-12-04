#!/usr/bin/env python3
"""
Temporary script to extract and categorize ports from CamXploit.py
"""

import json
import re

# Read the CamXploit.py file
with open("/home/user/gridland3/CamXploit.py") as f:
    content = f.read()

# Extract the COMMON_PORTS list using regex
match = re.search(r"COMMON_PORTS = \[(.*?)\]", content, re.DOTALL)
if not match:
    print("Could not find COMMON_PORTS list")
    exit(1)

ports_text = match.group(1)

# Extract all port numbers
ports = []
for line in ports_text.split("\n"):
    # Remove comments
    line = line.split("#")[0].strip()
    if line and line.endswith(","):
        line = line[:-1].strip()
    if line and line.isdigit():
        ports.append(int(line))

print(f"Total ports extracted: {len(ports)}")
print(f"Unique ports: {len(set(ports))}")

# Now categorize based on the comments and port ranges
categorized = {"web": [], "rtsp": [], "rtmp": [], "mms": [], "onvif": [], "custom": []}

descriptions = {
    "web": "Standard HTTP/HTTPS ports used for web interfaces (80, 443, 8080, etc.)",
    "rtsp": "Real Time Streaming Protocol ports for video streams (554, 8554, etc.)",
    "rtmp": "Real-Time Messaging Protocol ports for streaming (1935-1939)",
    "mms": "Microsoft Media Server protocol ports (1755-1760)",
    "onvif": "Open Network Video Interface Forum protocol ports (3702-3710)",
    "custom": "Proprietary camera manufacturer ports and custom ranges (37777-37800, 5000+)",
}

for port in set(ports):  # Use set to remove duplicates
    # Check specific protocol ports first (more specific to less specific)
    if port in range(1935, 1940):  # 1935-1939 RTMP
        categorized["rtmp"].append(port)
    elif port in range(1755, 1761):  # 1755-1760 MMS
        categorized["mms"].append(port)
    elif port in range(3702, 3711):  # 3702-3710 ONVIF
        categorized["onvif"].append(port)
    elif port in [
        554,
        8554,
        10554,
        1554,
        2554,
        3554,
        4554,
        5554,
        6554,
        7554,
        9554,
    ]:  # RTSP specific ports
        categorized["rtsp"].append(port)
    elif port in [80, 443]:  # Standard HTTP/HTTPS
        categorized["web"].append(port)
    elif port in range(8000, 8200):  # 8000-8199 web ports
        categorized["web"].append(port)
    elif port in range(37777, 37801):  # 37777-37800 Dahua/custom camera ports
        categorized["custom"].append(port)
    elif port in range(5000, 5011):  # 5000-5010
        categorized["custom"].append(port)
    elif port in range(6000, 6011):  # 6000-6010
        categorized["custom"].append(port)
    elif port in range(7000, 7011):  # 7000-7010
        categorized["custom"].append(port)
    elif port in range(8888, 8900):  # 8888-8899
        categorized["custom"].append(port)
    elif port in range(9000, 9011):  # 9000-9010
        categorized["custom"].append(port)
    elif port in range(9990, 10000):  # 9990-9999
        categorized["custom"].append(port)
    else:  # All other high ports (10000+)
        categorized["custom"].append(port)

# Sort each category
for category in categorized:
    categorized[category].sort()

# Count total unique ports
total_unique = sum(len(categorized[cat]) for cat in categorized)
print(f"\nCategorized unique ports: {total_unique}")
print("\nBreakdown by category:")
for cat in categorized:
    print(f"  {cat}: {len(categorized[cat])} ports")

# Create the final JSON structure
output = {
    "metadata": {
        "version": "1.0",
        "source": "CamXploit.py",
        "total_ports": total_unique,
        "description": "Comprehensive list of camera ports used for network scanning and discovery",
    },
    "categories": {},
}

for cat in categorized:
    output["categories"][cat] = {"description": descriptions[cat], "ports": categorized[cat]}

# Save to JSON file
output_path = "/home/user/gridland3/gridland/data/camera_ports.json"
with open(output_path, "w") as f:
    json.dump(output, f, indent=2)

print(f"\nJSON file created at: {output_path}")
print(f"Total unique ports in JSON: {output['metadata']['total_ports']}")
