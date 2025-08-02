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
import logging
import os
from datetime import datetime
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

# New modular imports
from lib.core import ScanTarget
from lib.network import scan_ports
from lib.identify import identify_device

# Configure comprehensive logging
def setup_logging(target_name: str = None) -> logging.Logger:
    """Setup detailed logging for scan operations"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if target_name:
        # Replace dots and slashes for safe filename
        safe_target = target_name.replace(".", "_").replace("/", "_")
        log_filename = f"gridland_scan_{safe_target}_{timestamp}.log"
    else:
        log_filename = f"gridland_scan_{timestamp}.log"
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    log_path = os.path.join('logs', log_filename)
    
    # Configure logger
    logger = logging.getLogger('gridland')
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler for detailed logs
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler for user feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Detailed formatter for file
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # Simple formatter for console
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"=== GRIDLAND SCAN SESSION STARTED ===")
    logger.info(f"Target: {target_name}")
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Log file: {log_path}")
    logger.info(f"=" * 50)
    
    return logger


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

def run_single_target_scan(ip: str, aggressive: bool, threads: int, logger: logging.Logger = None) -> Optional[ScanTarget]:
    """Orchestrates a scan against a single target IP."""
    if not logger:
        logger = logging.getLogger('gridland')
    
    logger.info(f"\n[🎯] Scanning {ip}")
    logger.debug(f"Parameters: aggressive={aggressive}, threads={threads}")
    target = ScanTarget(ip=ip)

    # Step 1: Port scan
    logger.info(f"[🔍] Scanning {ip} for open ports...")
    logger.debug(f"Scanning {len(CAMERA_PORTS)} camera-specific ports")
    
    try:
        target.open_ports = scan_ports(ip, CAMERA_PORTS, max_threads=threads)
        logger.debug(f"Port scan completed. Found {len(target.open_ports)} open ports")
        
        if not target.open_ports:
            logger.info("[❌] No open ports found")
            logger.debug("Scan terminated - no open ports detected")
            return None

        logger.info(f"[✅] Found {len(target.open_ports)} open ports: {[p.port for p in target.open_ports]}")

    except Exception as e:
        logger.error(f"Port scan failed: {str(e)}")
        logger.debug(f"Port scan exception details", exc_info=True)
        return None

    # Step 2: Device identification
    logger.info(f"[📷] Identifying device at {ip}...")
    
    try:
        target.device_type, target.brand = identify_device(ip, target.open_ports)
        logger.debug(f"Device identification result: type={target.device_type}, brand={target.brand}")
        
        if target.device_type:
            logger.info(f"[✅] Device identified: {target.device_type} ({target.brand})")
        else:
            logger.info(f"[⚠️] Could not identify specific device type")
            
    except Exception as e:
        logger.error(f"Device identification failed: {str(e)}")
        logger.debug(f"Device identification exception details", exc_info=True)

    if aggressive:
        # Step 3: Run scanner plugins
        logger.info(f"[🔌] Running aggressive scanner plugins on {ip}...")
        logger.debug(f"Aggressive mode enabled - running all available plugins")
        
        try:
            manager = PluginManager()
            logger.debug(f"Plugin manager initialized")
            
            findings = manager.run_all_plugins(target)
            logger.debug(f"Plugin execution completed. Found {len(findings)} findings")

            # Process findings and add to target
            for finding in findings:
                logger.info(f"   [+] {finding.category}: {finding.description}")
                logger.debug(f"Finding details: {finding.__dict__}")
                
                if finding.category == "credential":
                    # Extract credentials from finding
                    if finding.data and "username" in finding.data and "password" in finding.data:
                        creds_key = f"{finding.data['username']}:{finding.data['password']}"
                        target.credentials[creds_key] = finding.url or f"{ip}:{finding.port}"
                        logger.debug(f"Added credential: {creds_key}")
                
                elif finding.category == "stream":
                    # Add discovered streams
                    if finding.url:
                        target.streams.append(finding.url)
                        logger.debug(f"Added stream: {finding.url}")
                
                else:
                    # Add other findings as vulnerabilities
                    target.vulnerabilities.append(finding.description)
                    logger.debug(f"Added vulnerability: {finding.description}")
                    
        except Exception as e:
            logger.error(f"Plugin execution failed: {str(e)}")
            logger.debug(f"Plugin execution exception details", exc_info=True)

    logger.info(f"[✅] Scan complete for {ip}")
    logger.debug(f"Final scan results: {len(target.open_ports)} ports, {len(target.credentials)} credentials, {len(target.streams)} streams, {len(target.vulnerabilities)} vulnerabilities")
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
    logger = setup_logging(target)
    results = []
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            logger.info(f"\n[🌐] Scanning network: {target}")
            logger.debug(f"Network contains {network.num_addresses} addresses")
            for ip_obj in network.hosts():
                ip = str(ip_obj)
                result = run_single_target_scan(ip, aggressive, threads, logger)
                if result:
                    results.append(result)
            logger.info(f"\n[📊] Found {len(results)} devices with open ports")
        else:
            result = run_single_target_scan(target, aggressive, threads, logger)
            if result:
                results.append(result)
        
        # Display results
        for result in results:
            logger.info(f"\n🎯 {result.ip}")
            logger.info(f"   📡 Open Ports: {', '.join(map(str, [p.port for p in result.open_ports]))}")
            if result.device_type:
                logger.info(f"   📷 Device: {result.device_type} ({result.brand})")
            if result.credentials:
                logger.info(f"   🔑 CREDENTIALS FOUND:")
                for k, v in result.credentials.items():
                    logger.info(f"      🔥 {v}")
            if result.streams:
                logger.info(f"   🎥 STREAMS FOUND:")
                for stream in result.streams:
                    logger.info(f"      📺 {stream}")
        
        # Save to file if requested
        if output and results:
            # Note: The data saved is not as rich as the original ScanTarget object yet
            data = [r.__dict__ for r in results]
            with open(output, 'w') as f:
                json.dump(data, f, indent=2, default=lambda o: o.__dict__)
            logger.info(f"\n[📄] Results saved to {output}")
            logger.debug(f"Saved {len(results)} results to {output}")
    
    except KeyboardInterrupt:
        logger.info("\n[⏹️] Scan stopped by user")
        logger.debug("Scan interrupted by user with KeyboardInterrupt")

@gridland.command()
@click.argument('target')
def quick(target):
    """Quick aggressive scan"""
    logger = setup_logging(target)
    result = run_single_target_scan(target, True, 100, logger)
    
    if result:
        logger.info(f"\n🎯 {result.ip} - {len(result.open_ports)} open ports")
        if result.device_type:
            logger.info(f"📷 Device: {result.device_type} ({result.brand})")
        if result.credentials:
            logger.info(f"🔥 CREDENTIALS: {list(result.credentials.values())}")
        if result.streams:
            logger.info(f"📺 STREAMS: {len(result.streams)} found")
    else:
        logger.info(f"❌ No open ports on {target}")

if __name__ == '__main__':
    gridland()