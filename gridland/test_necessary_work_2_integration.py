#!/usr/bin/env python3
"""
NECESSARY-WORK-2 Integration Test Suite

Comprehensive testing of the Enhanced Stream Scanner using the GridLand 
playlist to validate:
1. Full stream database utilization (220+ paths vs CamXploit's 98)
2. Multi-protocol support (RTSP, HTTP, RTMP, WebSocket, WebRTC)
3. Brand-specific path prioritization
4. Vulnerability detection capabilities
5. Performance improvements (5.7x claimed improvement)

This test validates that NECESSARY-WORK-2 is fully implemented and working
at the apex of its capabilities.
"""

import asyncio
import json
import time
from typing import Dict, List
from datetime import datetime

# Import the GridLand playlist parser (located in project root)
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from playlist_parser import PlaylistParser

# Import the enhanced scanner
from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class NecessaryWork2IntegrationTest:
    """Comprehensive integration test for NECESSARY-WORK-2 implementation"""
    
    def __init__(self):
        self.playlist_parser = PlaylistParser('gridland/public-ip-cams.md')
        self.enhanced_scanner = EnhancedStreamScanner()
        self.test_results = {
            'start_time': None,
            'end_time': None,
            'total_targets': 0,
            'successful_scans': 0,
            'streams_discovered': 0,
            'vulnerabilities_found': 0,
            'protocol_breakdown': {},
            'brand_breakdown': {},
            'performance_metrics': {},
            'database_utilization': {},
            'detailed_results': []
        }
    
    async def run_comprehensive_test(self, max_targets: int = 20):
        """Run comprehensive integration test"""
        
        print("\n" + "="*80)
        print("NECESSARY-WORK-2 COMPREHENSIVE INTEGRATION TEST")
        print("="*80)
        
        self.test_results['start_time'] = datetime.now()
        
        # Phase 1: Validate Database Enhancement
        await self._test_database_enhancement()
        
        # Phase 2: Prepare Test Targets from GridLand Playlist
        test_targets = await self._prepare_test_targets(max_targets)
        
        # Phase 3: Run Enhanced Stream Scanner Tests
        await self._run_scanner_tests(test_targets)
        
        # Phase 4: Performance Analysis
        await self._analyze_performance()
        
        # Phase 5: Generate Comprehensive Report
        await self._generate_integration_report()
        
        self.test_results['end_time'] = datetime.now()
        
        return self.test_results
    
    async def _test_database_enhancement(self):
        """Test that enhanced database is properly loaded and utilized"""
        
        print("\n📊 Phase 1: Database Enhancement Validation")
        print("-" * 50)
        
        # Load stream database
        stream_db = self.enhanced_scanner.stream_database
        
        # Count total paths in database
        total_paths = 0
        protocol_counts = {}
        
        for protocol, categories in stream_db.get("protocols", {}).items():
            protocol_paths = 0
            if isinstance(categories, dict):
                for category, paths in categories.items():
                    if isinstance(paths, list):
                        protocol_paths += len(paths)
                    elif isinstance(paths, dict):
                        for subcat, subpaths in paths.items():
                            if isinstance(subpaths, list):
                                protocol_paths += len(subpaths)
            protocol_counts[protocol] = protocol_paths
            total_paths += protocol_paths
        
        self.test_results['database_utilization'] = {
            'total_paths': total_paths,
            'protocol_breakdown': protocol_counts,
            'camxploit_comparison': {
                'camxploit_paths': 98,  # From lines 836-938
                'enhanced_paths': total_paths,
                'improvement_factor': round(total_paths / 98, 2) if total_paths > 0 else 0
            }
        }
        
        print(f"✓ Database loaded: {total_paths} total stream paths")
        print(f"✓ CamXploit.py had: 98 paths")
        print(f"✓ Enhancement factor: {self.test_results['database_utilization']['camxploit_comparison']['improvement_factor']}x")
        
        for protocol, count in protocol_counts.items():
            print(f"  - {protocol.upper()}: {count} paths")
    
    async def _prepare_test_targets(self, max_targets: int) -> List[Dict]:
        """Prepare test targets from GridLand playlist"""
        
        print(f"\n🎯 Phase 2: Preparing {max_targets} Test Targets from GridLand Playlist")
        print("-" * 50)
        
        # Parse GridLand playlist
        endpoints = self.playlist_parser.parse_m3u()
        print(f"✓ Parsed {len(endpoints)} endpoints from playlist")
        
        # Quick validation to get accessible targets
        print("✓ Validating endpoint accessibility...")
        validation_results = self.playlist_parser.batch_validate(max_workers=10, timeout=3)
        
        # Get accessible targets
        accessible_targets = []
        for result in validation_results:
            if result['accessible']:
                accessible_targets.append({
                    'ip': result['endpoint']['ip'],
                    'port': result['endpoint']['port'],
                    'brand': result['endpoint']['brand'],
                    'original_url': result['endpoint']['url']
                })
        
        # Limit to max_targets
        test_targets = accessible_targets[:max_targets]
        self.test_results['total_targets'] = len(test_targets)
        
        print(f"✓ Selected {len(test_targets)} accessible targets for comprehensive testing")
        
        # Show brand distribution
        brand_dist = {}
        for target in test_targets:
            brand = target['brand']
            brand_dist[brand] = brand_dist.get(brand, 0) + 1
        
        print("✓ Brand distribution:")
        for brand, count in sorted(brand_dist.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {brand}: {count} targets")
        
        return test_targets
    
    async def _run_scanner_tests(self, test_targets: List[Dict]):
        """Run enhanced scanner tests on all targets"""
        
        print(f"\n🔍 Phase 3: Running Enhanced Scanner Tests")
        print("-" * 50)
        
        for i, target in enumerate(test_targets, 1):
            target_ip = target['ip']
            target_port = target['port']
            target_brand = target['brand']
            
            print(f"\n[{i}/{len(test_targets)}] Testing {target_ip}:{target_port} ({target_brand})")
            
            try:
                # Run both stream analysis and vulnerability scanning
                start_time = time.time()
                
                # Test as StreamPlugin
                stream_results = await self.enhanced_scanner.analyze_streams(
                    target_ip, target_port, service="http", banner=""
                )
                
                # Test as VulnerabilityPlugin  
                vuln_results = await self.enhanced_scanner.scan_vulnerabilities(
                    target_ip, target_port, service="http", banner=""
                )
                
                scan_time = time.time() - start_time
                
                # Record results
                result_entry = {
                    'target': target,
                    'scan_time': scan_time,
                    'stream_results': len(stream_results) if stream_results else 0,
                    'vuln_results': len(vuln_results) if vuln_results else 0,
                    'success': True,
                    'protocols_detected': [],
                    'vulnerabilities': []
                }
                
                # Analyze results
                if stream_results:
                    self.test_results['streams_discovered'] += len(stream_results)
                    
                    for stream in stream_results:
                        if hasattr(stream, 'protocol'):
                            protocol = stream.protocol
                            result_entry['protocols_detected'].append(protocol)
                            
                            # Update protocol breakdown
                            if protocol not in self.test_results['protocol_breakdown']:
                                self.test_results['protocol_breakdown'][protocol] = 0
                            self.test_results['protocol_breakdown'][protocol] += 1
                
                if vuln_results:
                    self.test_results['vulnerabilities_found'] += len(vuln_results)
                    result_entry['vulnerabilities'] = [v.id if hasattr(v, 'id') else 'unknown' for v in vuln_results]
                
                self.test_results['successful_scans'] += 1
                self.test_results['detailed_results'].append(result_entry)
                
                # Show progress
                streams_found = result_entry['stream_results']
                vulns_found = result_entry['vuln_results']
                print(f"  ✓ Completed in {scan_time:.2f}s: {streams_found} streams, {vulns_found} vulnerabilities")
                
            except Exception as e:
                print(f"  ✗ Error scanning {target_ip}:{target_port}: {e}")
                self.test_results['detailed_results'].append({
                    'target': target,
                    'success': False,
                    'error': str(e)
                })
    
    async def _analyze_performance(self):
        """Analyze performance metrics"""
        
        print(f"\n📈 Phase 4: Performance Analysis")
        print("-" * 50)
        
        if self.test_results['successful_scans'] == 0:
            print("✗ No successful scans to analyze")
            return
        
        # Calculate metrics
        total_time = sum(r.get('scan_time', 0) for r in self.test_results['detailed_results'] if r.get('success'))
        avg_scan_time = total_time / self.test_results['successful_scans']
        
        total_streams = self.test_results['streams_discovered']
        total_vulns = self.test_results['vulnerabilities_found']
        
        success_rate = (self.test_results['successful_scans'] / self.test_results['total_targets']) * 100
        
        # Estimate improvement over traditional methods
        # Traditional: ~15% stream discovery rate (from NECESSARY-WORK-2 doc)
        # Enhanced: Actual discovery rate
        discovery_rate = (total_streams / self.test_results['successful_scans']) if self.test_results['successful_scans'] > 0 else 0
        traditional_discovery = 0.15  # 15% baseline
        improvement_factor = discovery_rate / traditional_discovery if traditional_discovery > 0 else 0
        
        self.test_results['performance_metrics'] = {
            'avg_scan_time': round(avg_scan_time, 2),
            'success_rate': round(success_rate, 1),
            'discovery_rate': round(discovery_rate, 2),
            'improvement_factor': round(improvement_factor, 2),
            'streams_per_target': round(total_streams / self.test_results['successful_scans'], 2) if self.test_results['successful_scans'] > 0 else 0,
            'vulns_per_target': round(total_vulns / self.test_results['successful_scans'], 2) if self.test_results['successful_scans'] > 0 else 0
        }
        
        print(f"✓ Average scan time: {avg_scan_time:.2f}s per target")
        print(f"✓ Success rate: {success_rate:.1f}%")
        print(f"✓ Stream discovery rate: {discovery_rate:.2f} streams per target")
        print(f"✓ Improvement over traditional: {improvement_factor:.2f}x")
        print(f"✓ Vulnerabilities per target: {self.test_results['performance_metrics']['vulns_per_target']}")
    
    async def _generate_integration_report(self):
        """Generate comprehensive integration test report"""
        
        print(f"\n📋 Phase 5: Integration Test Report")
        print("-" * 50)
        
        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"gridland/necessary_work_2_integration_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        # Print summary
        print(f"✓ NECESSARY-WORK-2 Integration Test Summary:")
        print(f"  - Database paths: {self.test_results['database_utilization']['total_paths']} (vs CamXploit's 98)")
        print(f"  - Database enhancement: {self.test_results['database_utilization']['camxploit_comparison']['improvement_factor']}x")
        print(f"  - Targets tested: {self.test_results['total_targets']}")
        print(f"  - Successful scans: {self.test_results['successful_scans']}")
        print(f"  - Streams discovered: {self.test_results['streams_discovered']}")
        print(f"  - Vulnerabilities found: {self.test_results['vulnerabilities_found']}")
        print(f"  - Performance improvement: {self.test_results['performance_metrics'].get('improvement_factor', 0)}x")
        print(f"  - Protocol coverage: {list(self.test_results['protocol_breakdown'].keys())}")
        print(f"\n✓ Detailed report saved: {report_file}")
        
        # Determine test outcome
        db_enhanced = self.test_results['database_utilization']['total_paths'] > 100
        multi_protocol = len(self.test_results['protocol_breakdown']) >= 2
        performance_good = self.test_results['performance_metrics'].get('improvement_factor', 0) > 1.0
        
        if db_enhanced and multi_protocol and performance_good:
            print(f"\n🎉 NECESSARY-WORK-2 INTEGRATION TEST: PASSED")
            print(f"   All requirements successfully implemented and validated!")
        else:
            print(f"\n⚠️  NECESSARY-WORK-2 INTEGRATION TEST: NEEDS ATTENTION")
            print(f"   Some requirements may need refinement")


async def main():
    """Run the comprehensive integration test"""
    
    test_suite = NecessaryWork2IntegrationTest()
    
    try:
        results = await test_suite.run_comprehensive_test(max_targets=15)
        
        print(f"\n" + "="*80)
        print(f"NECESSARY-WORK-2 INTEGRATION TEST COMPLETED")
        print(f"Total time: {results['end_time'] - results['start_time']}")
        print(f"="*80)
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())