"""
Real CLI implementation that actually works
Based on functional CamXploit.py code, not fake frameworks
"""

import click
import json
import time
from pathlib import Path
from typing import List

from ..core.comprehensive_scanner import (
    ComprehensiveScanner, ScanConfiguration, quick_scan, network_discovery
)

@click.group()
def gridland():
    """GRIDLAND: Real Network Security Assessment Tool"""
    pass

@gridland.command()
@click.argument('target')
@click.option('--aggressive', '-a', is_flag=True, help='Enable aggressive scanning (credentials + streams)')
@click.option('--threads', '-t', default=100, help='Number of scanning threads')
@click.option('--timeout', default=1.5, help='Port scan timeout in seconds')
@click.option('--output', '-o', help='Output file for results (JSON)')
@click.option('--no-creds', is_flag=True, help='Skip credential testing')
@click.option('--no-streams', is_flag=True, help='Skip stream discovery')
def scan(target, aggressive, threads, timeout, output, no_creds, no_streams):
    """Scan single target or network range"""
    
    config = ScanConfiguration(
        max_threads=threads,
        port_timeout=timeout,
        credential_testing=aggressive and not no_creds,
        stream_discovery=aggressive and not no_streams,
        aggressive_scanning=aggressive
    )
    
    scanner = ComprehensiveScanner(config)
    
    try:
        # Determine if target is single IP or range
        if '/' in target:
            print(f"[🌐] Scanning network range: {target}")
            results = scanner.scan_network_range(target)
        else:
            print(f"[🎯] Scanning single target: {target}")
            result = scanner.scan_single_target(target)
            results = [result] if result.open_ports else []
        
        # Display results
        display_scan_results(results)
        
        # Generate report if requested
        if output:
            report = scanner.generate_report(results, output)
            print(f"\n[📄] Detailed report saved to {output}")
        
        # Display statistics
        stats = scanner.get_scan_statistics(results)
        display_statistics(stats)
        
    except KeyboardInterrupt:
        print("\n[⏹️] Scan interrupted by user")
        scanner.stop_scan()

@gridland.command()
@click.argument('file_path')
@click.option('--aggressive', '-a', is_flag=True, help='Enable aggressive scanning')
@click.option('--threads', '-t', default=50, help='Number of scanning threads')
@click.option('--output', '-o', help='Output file for results (JSON)')
def scan_file(file_path, aggressive, threads, output):
    """Scan targets from file (one IP per line)"""
    
    config = ScanConfiguration(
        max_threads=threads,
        credential_testing=aggressive,
        stream_discovery=aggressive,
        aggressive_scanning=aggressive
    )
    
    scanner = ComprehensiveScanner(config)
    
    try:
        results = scanner.scan_from_file(file_path)
        
        display_scan_results(results)
        
        if output:
            report = scanner.generate_report(results, output)
            print(f"\n[📄] Report saved to {output}")
        
        stats = scanner.get_scan_statistics(results)
        display_statistics(stats)
        
    except KeyboardInterrupt:
        print("\n[⏹️] Scan interrupted by user")
        scanner.stop_scan()

@gridland.command()
@click.argument('target')
@click.option('--output', '-o', help='Output file for results')
def quick(target, output):
    """Quick aggressive scan of single target"""
    print(f"[⚡] Quick scan: {target}")
    
    result = quick_scan(target, aggressive=True)
    
    if result.open_ports:
        display_target_details(result)
        
        if output:
            with open(output, 'w') as f:
                json.dump({
                    'target': result.ip,
                    'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'open_ports': result.open_ports,
                    'device_type': result.device_type,
                    'brand': result.brand,
                    'credentials': result.credentials,
                    'streams': result.streams
                }, f, indent=2)
            print(f"[📄] Results saved to {output}")
    else:
        print(f"[❌] No open ports found on {target}")

@gridland.command()
@click.argument('network_range')
@click.option('--output', '-o', help='Output directory for results')
@click.option('--threads', '-t', default=200, help='Number of scanning threads')
def discover(network_range, output, threads):
    """Discover all devices in network range"""
    print(f"[🔍] Network discovery: {network_range}")
    
    results = network_discovery(network_range, full_analysis=True)
    
    if results:
        print(f"\n[✅] Found {len(results)} devices:")
        for result in results:
            print(f"  🎯 {result.ip} - {result.device_type or 'Unknown'} - {len(result.open_ports)} ports")
        
        if output:
            Path(output).mkdir(exist_ok=True)
            
            # Save individual target files
            for result in results:
                filename = f"{output}/{result.ip.replace('.', '_')}.json"
                with open(filename, 'w') as f:
                    json.dump({
                        'ip': result.ip,
                        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'open_ports': result.open_ports,
                        'device_type': result.device_type,
                        'brand': result.brand,
                        'credentials': result.credentials,
                        'streams': result.streams
                    }, f, indent=2)
            
            # Save summary report
            summary_file = f"{output}/network_summary.json"
            with open(summary_file, 'w') as f:
                json.dump({
                    'network_range': network_range,
                    'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'total_devices': len(results),
                    'devices': [result.ip for result in results]
                }, f, indent=2)
            
            print(f"[📁] Results saved to {output}/")
    else:
        print(f"[❌] No devices found in {network_range}")

def display_scan_results(results: List):
    """Display scan results in readable format"""
    if not results:
        print("[❌] No targets with open ports found")
        return
    
    print(f"\n[📊] SCAN RESULTS ({len(results)} targets)")
    print("=" * 60)
    
    for result in results:
        display_target_details(result)
        print("-" * 40)

def display_target_details(target):
    """Display detailed information for single target"""
    print(f"\n🎯 TARGET: {target.ip}")
    print(f"   📡 Open Ports: {', '.join(map(str, target.open_ports))}")
    
    if target.device_type:
        print(f"   📷 Device Type: {target.device_type}")
    
    if target.brand:
        print(f"   🏷️  Brand: {target.brand}")
    
    if target.credentials:
        print(f"   🔑 COMPROMISED CREDENTIALS:")
        for cred_key, cred_value in target.credentials.items():
            print(f"      🔥 {cred_key}: {cred_value}")
    
    if target.streams:
        print(f"   🎥 EXPOSED STREAMS:")
        for stream in target.streams:
            print(f"      📺 {stream}")

def display_statistics(stats):
    """Display scan statistics"""
    print(f"\n[📈] SCAN STATISTICS")
    print("=" * 30)
    print(f"📊 Total Targets: {stats['total_targets']}")
    print(f"🔌 Total Open Ports: {stats['total_open_ports']}")
    print(f"📷 Devices Detected: {stats['devices_detected']}")
    print(f"🔑 Credentials Found: {stats['credentials_found']}")
    print(f"🎥 Streams Found: {stats['streams_found']}")
    print(f"⚠️  High Risk Targets: {stats['high_risk_targets']}")
    
    if stats['brands_detected']:
        print(f"🏷️  Brands Found: {', '.join(stats['brands_detected'])}")

if __name__ == '__main__':
    gridland()