"""
Comprehensive Security Scanner - Real Implementation
Combines all CamXploit.py functionality into enterprise-grade scanning engine.
"""

import asyncio
import ipaddress
import json
import time
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path

from .scanner import (
    RealPortScanner, DeviceDetector, CredentialTester, StreamDiscovery, ScanTarget
)

@dataclass
class ScanConfiguration:
    """Configuration for comprehensive scanning"""
    max_threads: int = 100
    port_timeout: float = 1.5
    http_timeout: int = 5
    credential_testing: bool = True
    stream_discovery: bool = True
    aggressive_scanning: bool = True
    scan_all_ports: bool = False  # If True, scan 1-65535, else use camera ports
    
class ScanReport:
    """Professional scan report generator"""
    
    def __init__(self, targets: List[ScanTarget], scan_config: ScanConfiguration):
        self.targets = targets
        self.config = scan_config
        self.start_time = time.time()
        
    def generate_summary(self) -> Dict:
        """Generate executive summary"""
        total_targets = len(self.targets)
        devices_found = len([t for t in self.targets if t.device_type])
        credentials_compromised = len([t for t in self.targets if t.credentials])
        streams_exposed = sum(len(t.streams) for t in self.targets)
        
        summary = {
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_targets_scanned': total_targets,
            'devices_identified': devices_found,
            'compromised_credentials': credentials_compromised,
            'exposed_streams': streams_exposed,
            'high_risk_devices': credentials_compromised,
            'scan_duration': f"{time.time() - self.start_time:.2f} seconds"
        }
        
        return summary
    
    def generate_detailed_report(self) -> List[Dict]:
        """Generate detailed findings"""
        detailed_findings = []
        
        for target in self.targets:
            if not target.open_ports:  # Skip targets with no open ports
                continue
                
            finding = {
                'ip_address': target.ip,
                'open_ports': target.open_ports,
                'device_type': target.device_type or 'Unknown',
                'brand': target.brand or 'Unknown',
                'risk_level': self._calculate_risk_level(target),
                'compromised_credentials': target.credentials or {},
                'exposed_streams': target.streams or [],
                'recommended_actions': self._get_recommendations(target)
            }
            
            detailed_findings.append(finding)
        
        return detailed_findings
    
    def _calculate_risk_level(self, target: ScanTarget) -> str:
        """Calculate risk level for target"""
        risk_score = 0
        
        # Open ports contribute to risk
        risk_score += len(target.open_ports) * 0.1
        
        # Compromised credentials are high risk
        if target.credentials:
            risk_score += 5.0
        
        # Exposed streams are medium risk
        if target.streams:
            risk_score += 2.0
        
        # Known device types are higher risk
        if target.device_type == 'camera':
            risk_score += 1.0
        
        if risk_score >= 5.0:
            return "HIGH"
        elif risk_score >= 2.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_recommendations(self, target: ScanTarget) -> List[str]:
        """Get security recommendations for target"""
        recommendations = []
        
        if target.credentials:
            recommendations.append("URGENT: Change default credentials immediately")
            recommendations.append("Implement strong password policy")
        
        if target.streams:
            recommendations.append("Secure video streams with authentication")
            recommendations.append("Consider network segmentation for media devices")
        
        if len(target.open_ports) > 10:
            recommendations.append("Review and close unnecessary open ports")
        
        if target.device_type == 'camera':
            recommendations.append("Update firmware to latest version")
            recommendations.append("Enable encryption for video streams")
        
        if not recommendations:
            recommendations.append("Monitor device for configuration changes")
        
        return recommendations
    
    def export_json(self, filename: str):
        """Export report to JSON"""
        report_data = {
            'summary': self.generate_summary(),
            'detailed_findings': self.generate_detailed_report(),
            'scan_configuration': asdict(self.config)
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[📄] Report exported to {filename}")

class ComprehensiveScanner:
    """
    Main scanning engine that orchestrates all scanning components.
    Based entirely on proven CamXploit.py functionality.
    """
    
    def __init__(self, config: ScanConfiguration = None):
        self.config = config or ScanConfiguration()
        
        # Initialize scanning components with real implementations
        self.port_scanner = RealPortScanner(
            max_threads=self.config.max_threads,
            timeout=self.config.port_timeout
        )
        self.device_detector = DeviceDetector(timeout=self.config.http_timeout)
        self.credential_tester = CredentialTester(timeout=self.config.http_timeout)
        self.stream_discovery = StreamDiscovery(timeout=self.config.http_timeout)
        
        # Scanning state
        self._scanning = False
        self._current_targets: List[ScanTarget] = []
    
    def scan_single_target(self, ip: str) -> ScanTarget:
        """Scan single IP address"""
        print(f"\n[🎯] Starting comprehensive scan of {ip}")
        
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[❌] Invalid IP address: {ip}")
            return ScanTarget(ip=ip, ports=[])
        
        # Step 1: Port scanning
        ports = None if self.config.scan_all_ports else None  # Use default camera ports
        target = self.port_scanner.scan_target(ip, ports)
        
        if not target.open_ports:
            print(f"[❌] No open ports found on {ip}")
            return target
        
        # Step 2: Device detection
        target = self.device_detector.detect_device(target)
        
        # Step 3: Credential testing (if enabled)
        if self.config.credential_testing:
            target = self.credential_tester.test_credentials(target)
        
        # Step 4: Stream discovery (if enabled)
        if self.config.stream_discovery:
            target = self.stream_discovery.discover_streams(target)
        
        print(f"[✅] Scan complete for {ip}")
        return target
    
    def scan_network_range(self, ip_range: str) -> List[ScanTarget]:
        """Scan entire network range"""
        print(f"\n[🌐] Starting network range scan: {ip_range}")
        
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_hosts = network.num_addresses - 2  # Exclude network and broadcast
            print(f"[📊] Scanning {total_hosts} hosts in {ip_range}")
        except ValueError:
            print(f"[❌] Invalid network range: {ip_range}")
            return []
        
        self._scanning = True
        self._current_targets = []
        
        # First pass: Quick port scan to identify live hosts
        live_hosts = []
        
        for ip in network.hosts():
            if not self._scanning:
                break
                
            target = self.port_scanner.scan_target(str(ip))
            if target.open_ports:
                live_hosts.append(target)
                self._current_targets.append(target)
                print(f"[🎯] Found live host: {ip} ({len(target.open_ports)} open ports)")
        
        print(f"\n[📊] Found {len(live_hosts)} live hosts, performing detailed analysis...")
        
        # Second pass: Detailed analysis of live hosts
        for target in live_hosts:
            if not self._scanning:
                break
                
            print(f"\n[🔍] Analyzing {target.ip}...")
            
            # Device detection
            target = self.device_detector.detect_device(target)
            
            # Credential testing
            if self.config.credential_testing:
                target = self.credential_tester.test_credentials(target)
            
            # Stream discovery
            if self.config.stream_discovery:
                target = self.stream_discovery.discover_streams(target)
        
        print(f"\n[✅] Network scan complete: {len(live_hosts)} devices analyzed")
        return live_hosts
    
    def scan_from_file(self, filename: str) -> List[ScanTarget]:
        """Scan targets from file (one IP per line)"""
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[❌] File not found: {filename}")
            return []
        
        print(f"[📁] Loaded {len(ips)} targets from {filename}")
        
        targets = []
        for ip in ips:
            if not self._scanning:
                break
            target = self.scan_single_target(ip)
            if target.open_ports:  # Only keep targets with open ports
                targets.append(target)
        
        return targets
    
    def stop_scan(self):
        """Stop ongoing scan"""
        print("\n[⏹️] Stopping scan...")
        self._scanning = False
        self.port_scanner.stop()
    
    def generate_report(self, targets: List[ScanTarget], output_file: str = None) -> ScanReport:
        """Generate comprehensive scan report"""
        report = ScanReport(targets, self.config)
        
        if output_file:
            report.export_json(output_file)
        
        return report
    
    def get_scan_statistics(self, targets: List[ScanTarget]) -> Dict:
        """Get scan statistics"""
        stats = {
            'total_targets': len(targets),
            'total_open_ports': sum(len(t.open_ports) for t in targets),
            'devices_detected': len([t for t in targets if t.device_type]),
            'credentials_found': len([t for t in targets if t.credentials]),
            'streams_found': sum(len(t.streams) for t in targets),
            'brands_detected': list(set(t.brand for t in targets if t.brand)),
            'high_risk_targets': len([t for t in targets if t.credentials])
        }
        
        return stats

# Convenience functions for common scanning patterns
def quick_scan(ip: str, aggressive: bool = True) -> ScanTarget:
    """Quick scan of single target"""
    config = ScanConfiguration(
        aggressive_scanning=aggressive,
        credential_testing=aggressive,
        stream_discovery=True
    )
    scanner = ComprehensiveScanner(config)
    return scanner.scan_single_target(ip)

def network_discovery(ip_range: str, full_analysis: bool = True) -> List[ScanTarget]:
    """Discover and analyze all devices in network range"""
    config = ScanConfiguration(
        credential_testing=full_analysis,
        stream_discovery=full_analysis,
        aggressive_scanning=full_analysis
    )
    scanner = ComprehensiveScanner(config)
    return scanner.scan_network_range(ip_range)

def stealth_scan(ip: str) -> ScanTarget:
    """Stealthier scan with reduced threading and timeouts"""
    config = ScanConfiguration(
        max_threads=20,
        port_timeout=3.0,
        http_timeout=10,
        credential_testing=False,  # Skip credential testing for stealth
        aggressive_scanning=False
    )
    scanner = ComprehensiveScanner(config)
    return scanner.scan_single_target(ip)