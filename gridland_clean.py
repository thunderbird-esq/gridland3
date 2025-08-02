#!/usr/bin/env python3
"""
GRIDLAND - Real Security Scanner
Clean implementation based on proven CamXploit.py functionality
"""

import socket
import threading
import requests
import ipaddress
import time
import json
import warnings
import click
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.auth import HTTPBasicAuth

# Suppress SSL warnings for embedded devices
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

@dataclass
class ScanTarget:
    ip: str
    open_ports: List[int] = None
    device_type: Optional[str] = None
    brand: Optional[str] = None
    credentials: Dict[str, str] = None
    streams: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.credentials is None:
            self.credentials = {}
        if self.streams is None:
            self.streams = []

# This file will now primarily be for the CLI implementation and orchestrating
# the calls to the new modular library functions.

import ipaddress
import time
import json
import warnings
import click
from typing import List, Dict, Optional, Tuple

# New modular imports
from lib.core import ScanTarget
from lib.network import scan_ports
from lib.identify import identify_device

# Suppress SSL warnings for embedded devices
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except:
    pass

# TODO: The credential testing and stream discovery logic still needs to be
# deconstructed and moved into plugins. For now, we will keep the old
# methods here and have the CLI call them directly.

# Comprehensive camera port list from CamXploit.py
CAMERA_PORTS = [
    80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
    1935, 1936, 1937, 1938, 1939,
    37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
    37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800,
    3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
    5000, 5001, 5002, 5003, 5004, 5005, 6000, 6001, 6002, 6003, 6004, 6005,
    7000, 7001, 7002, 7003, 7004, 7005, 9000, 9001, 9002, 9003, 9004, 9005,
    8888, 8889, 8890, 8891, 8892, 8893, 9999, 9998, 9997, 9996, 9995, 9994
]

from lib.plugin_manager import PluginManager

def run_single_target_scan(ip: str, aggressive: bool, threads: int) -> Optional[ScanTarget]:
    """Orchestrates a scan against a single target IP."""
    print(f"\n[🎯] Scanning {ip}")
    target = ScanTarget(ip=ip)

    # Step 1: Port scan
    print(f"[🔍] Scanning {ip} for open ports...")
    target.open_ports = scan_ports(ip, CAMERA_PORTS, max_threads=threads)
    if not target.open_ports:
        print("[❌] No open ports found")
        return None

    # Step 2: Device identification
    print(f"[📷] Identifying device at {ip}...")
    target.device_type, target.brand = identify_device(ip, target.open_ports)

    if aggressive:
        # Step 3: Run scanner plugins
        print(f"[🔌] Running scanner plugins on {ip}...")
        manager = PluginManager()
        findings = manager.run_all_plugins(target)

        # For now, we'll just print the findings.
        # In the future, these will be added to the ScanTarget object.
        for finding in findings:
            print(f"   [+] {finding.category}: {finding.description}")

        # TODO: The stream discovery logic will also be moved to a plugin.
        # target.streams = discover_streams(ip, [p.port for p in target.open_ports])

    print(f"[✅] Scan complete for {ip}")
    return target

# CLI Implementation
@click.group()
def gridland():
    """GRIDLAND - Real Network Security Scanner"""
    pass

@gridland.command()
@click.argument('target')
@click.option('--aggressive', '-a', is_flag=True, help='Enable credential testing and stream discovery')
@click.option('--threads', '-t', default=100, help='Number of threads')
@click.option('--output', '-o', help='Output JSON file')
def scan(target, aggressive, threads, output):
    """Scan single IP or network range"""
    results = []
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            print(f"\n[🌐] Scanning network: {target}")
            for ip_obj in network.hosts():
                ip = str(ip_obj)
                result = run_single_target_scan(ip, aggressive, threads)
                if result:
                    results.append(result)
            print(f"\n[📊] Found {len(results)} devices with open ports")
        else:
            result = run_single_target_scan(target, aggressive, threads)
            if result:
                results.append(result)
        
        # Display results
        for result in results:
            print(f"\n🎯 {result.ip}")
            print(f"   📡 Open Ports: {', '.join(map(str, [p.port for p in result.open_ports]))}")
            if result.device_type:
                print(f"   📷 Device: {result.device_type} ({result.brand})")
            if result.credentials:
                print(f"   🔑 CREDENTIALS FOUND:")
                for k, v in result.credentials.items():
                    print(f"      🔥 {v}")
            if result.streams:
                print(f"   🎥 STREAMS FOUND:")
                for stream in result.streams:
                    print(f"      📺 {stream}")
        
        # Save to file if requested
        if output and results:
            # Note: The data saved is not as rich as the original ScanTarget object yet
            data = [r.__dict__ for r in results]
            with open(output, 'w') as f:
                json.dump(data, f, indent=2, default=lambda o: o.__dict__)
            print(f"\n[📄] Results saved to {output}")
    
    except KeyboardInterrupt:
        print("\n[⏹️] Scan stopped by user")

@gridland.command()
@click.argument('target')
def quick(target):
    """Quick aggressive scan"""
    result = run_single_target_scan(target, aggressive=True, threads=100)
    
    if result:
        print(f"\n🎯 {result.ip} - {len(result.open_ports)} open ports")
        if result.credentials:
            print(f"🔥 CREDENTIALS: {list(result.credentials.values())}")
        if result.streams:
            print(f"📺 STREAMS: {len(result.streams)} found")
    else:
        print(f"❌ No open ports on {target}")

if __name__ == '__main__':
    gridland()