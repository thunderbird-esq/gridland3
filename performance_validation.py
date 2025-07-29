#!/usr/bin/env python3
"""
Performance Validation Script for NECESSARY-WORK-2

Side-by-side comparison between OLD rtsp_scanner vs NEW enhanced_scanner
to validate the claimed 5.7x performance improvement.

This script measures:
- Streams found per target
- Scan time per target  
- Discovery accuracy
- Resource utilization

Usage:
    python3 performance_validation.py
"""

import asyncio
import json
import time
import resource
import psutil
import os
from typing import Dict, List, Any
from datetime import datetime
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from playlist_parser import PlaylistParser

# Import both scanners for comparison
from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
from gridland.analyze.plugins.builtin.rtsp_stream_scanner import RTSPStreamScanner
from gridland.core.logger import get_logger

logger = get_logger(__name__)


class PerformanceValidator:
    """Side-by-side performance comparison validator"""
    
    def __init__(self):
        self.playlist_parser = PlaylistParser('gridland/public-ip-cams.md')
        self.old_scanner = RTSPStreamScanner()
        self.new_scanner = EnhancedStreamScanner()
        
        self.results = {
            'test_info': {
                'timestamp': datetime.now().isoformat(),
                'purpose': 'Validate NECESSARY-WORK-2 5.7x performance improvement claims',
                'baseline': 'OLD rtsp_scanner vs NEW enhanced_scanner'
            },
            'test_targets': [],
            'old_scanner_results': {
                'total_time': 0,
                'streams_found': 0,
                'successful_scans': 0,
                'errors': 0,
                'avg_time_per_target': 0,
                'streams_per_target': 0,
                'discovery_rate': 0,
                'detailed_results': []
            },
            'new_scanner_results': {
                'total_time': 0,
                'streams_found': 0,
                'successful_scans': 0,
                'errors': 0,
                'avg_time_per_target': 0,
                'streams_per_target': 0,
                'discovery_rate': 0,
                'detailed_results': []
            },
            'performance_comparison': {},
            'resource_usage': {
                'old_scanner': {},
                'new_scanner': {}
            }
        }
    
    async def run_validation(self, max_targets: int = 10):
        """Run comprehensive performance validation"""
        
        print("=" * 80)
        print("NECESSARY-WORK-2 PERFORMANCE VALIDATION")
        print("Side-by-side comparison: OLD vs NEW scanner")
        print("=" * 80)
        
        # Prepare test targets
        test_targets = await self._prepare_test_targets(max_targets)
        
        # Test old scanner
        print(f"\n📊 Phase 1: Testing OLD rtsp_scanner")
        print("-" * 50)
        await self._test_old_scanner(test_targets)
        
        # Test new scanner  
        print(f"\n🚀 Phase 2: Testing NEW enhanced_scanner")
        print("-" * 50)
        await self._test_new_scanner(test_targets)
        
        # Compare results
        print(f"\n📈 Phase 3: Performance Analysis")
        print("-" * 50)
        await self._analyze_performance()
        
        # Generate report
        await self._generate_validation_report()
        
        return self.results
    
    async def _prepare_test_targets(self, max_targets: int) -> List[Dict]:
        """Prepare identical test targets for both scanners"""
        
        print(f"🎯 Preparing {max_targets} test targets from GridLand playlist")
        
        # Parse playlist
        endpoints = self.playlist_parser.parse_m3u()
        print(f"✓ Parsed {len(endpoints)} endpoints from playlist")
        
        # Quick validation to get accessible targets
        validation_results = self.playlist_parser.batch_validate(max_workers=5, timeout=2)
        
        # Get accessible targets
        accessible_targets = []
        for result in validation_results:
            if result['accessible']:
                accessible_targets.append({
                    'ip': result['endpoint']['ip'],
                    'port': result['endpoint']['port'],
                    'brand': result['endpoint']['brand'],
                    'url': result['endpoint']['url']
                })
        
        # Limit to max_targets
        test_targets = accessible_targets[:max_targets]
        self.results['test_targets'] = test_targets
        
        print(f"✓ Selected {len(test_targets)} accessible targets for comparison")
        
        return test_targets
    
    async def _test_old_scanner(self, test_targets: List[Dict]):
        """Test the old RTSP scanner"""
        
        start_memory = self._get_memory_usage()
        start_time = time.time()
        
        for i, target in enumerate(test_targets, 1):
            target_ip = target['ip']
            target_port = target['port']
            
            print(f"[{i}/{len(test_targets)}] OLD Scanner: {target_ip}:{target_port}")
            
            try:
                scan_start = time.time()
                
                # Run old scanner (RTSP only)
                results = await self.old_scanner.analyze_streams(
                    target_ip, target_port, service="rtsp", banner=""
                )
                
                scan_time = time.time() - scan_start
                
                # Record results
                streams_found = len(results) if results else 0
                self.results['old_scanner_results']['streams_found'] += streams_found
                self.results['old_scanner_results']['successful_scans'] += 1
                
                result_entry = {
                    'target': target,
                    'scan_time': scan_time,
                    'streams_found': streams_found,
                    'success': True
                }
                
                self.results['old_scanner_results']['detailed_results'].append(result_entry)
                print(f"  ✓ {scan_time:.2f}s: {streams_found} streams")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
                self.results['old_scanner_results']['errors'] += 1
                self.results['old_scanner_results']['detailed_results'].append({
                    'target': target,
                    'success': False,
                    'error': str(e)
                })
        
        end_time = time.time()
        end_memory = self._get_memory_usage()
        
        # Calculate metrics
        total_time = end_time - start_time
        successful_scans = self.results['old_scanner_results']['successful_scans']
        streams_found = self.results['old_scanner_results']['streams_found']
        
        self.results['old_scanner_results']['total_time'] = total_time
        self.results['old_scanner_results']['avg_time_per_target'] = total_time / len(test_targets)
        self.results['old_scanner_results']['streams_per_target'] = streams_found / successful_scans if successful_scans > 0 else 0
        self.results['old_scanner_results']['discovery_rate'] = (streams_found / successful_scans) if successful_scans > 0 else 0
        
        self.results['resource_usage']['old_scanner'] = {
            'memory_start_mb': start_memory,
            'memory_end_mb': end_memory,
            'memory_delta_mb': end_memory - start_memory
        }
        
        print(f"✓ OLD Scanner completed:")
        print(f"  - Total time: {total_time:.2f}s")
        print(f"  - Streams found: {streams_found}")
        print(f"  - Success rate: {successful_scans}/{len(test_targets)}")
        print(f"  - Discovery rate: {self.results['old_scanner_results']['discovery_rate']:.2f} streams/target")
    
    async def _test_new_scanner(self, test_targets: List[Dict]):
        """Test the new enhanced scanner"""
        
        start_memory = self._get_memory_usage()
        start_time = time.time()
        
        for i, target in enumerate(test_targets, 1):
            target_ip = target['ip']
            target_port = target['port']
            
            print(f"[{i}/{len(test_targets)}] NEW Scanner: {target_ip}:{target_port}")
            
            try:
                scan_start = time.time()
                
                # Run new scanner (multi-protocol)
                results = await self.new_scanner.analyze_streams(
                    target_ip, target_port, service="http", banner=""
                )
                
                scan_time = time.time() - scan_start
                
                # Record results
                streams_found = len(results) if results else 0
                self.results['new_scanner_results']['streams_found'] += streams_found
                self.results['new_scanner_results']['successful_scans'] += 1
                
                result_entry = {
                    'target': target,
                    'scan_time': scan_time,
                    'streams_found': streams_found,
                    'success': True
                }
                
                self.results['new_scanner_results']['detailed_results'].append(result_entry)
                print(f"  ✓ {scan_time:.2f}s: {streams_found} streams")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
                self.results['new_scanner_results']['errors'] += 1
                self.results['new_scanner_results']['detailed_results'].append({
                    'target': target,
                    'success': False,
                    'error': str(e)
                })
        
        end_time = time.time()
        end_memory = self._get_memory_usage()
        
        # Calculate metrics
        total_time = end_time - start_time
        successful_scans = self.results['new_scanner_results']['successful_scans']
        streams_found = self.results['new_scanner_results']['streams_found']
        
        self.results['new_scanner_results']['total_time'] = total_time
        self.results['new_scanner_results']['avg_time_per_target'] = total_time / len(test_targets)
        self.results['new_scanner_results']['streams_per_target'] = streams_found / successful_scans if successful_scans > 0 else 0
        self.results['new_scanner_results']['discovery_rate'] = (streams_found / successful_scans) if successful_scans > 0 else 0
        
        self.results['resource_usage']['new_scanner'] = {
            'memory_start_mb': start_memory,
            'memory_end_mb': end_memory,
            'memory_delta_mb': end_memory - start_memory
        }
        
        print(f"✓ NEW Scanner completed:")
        print(f"  - Total time: {total_time:.2f}s")
        print(f"  - Streams found: {streams_found}")
        print(f"  - Success rate: {successful_scans}/{len(test_targets)}")
        print(f"  - Discovery rate: {self.results['new_scanner_results']['discovery_rate']:.2f} streams/target")
    
    async def _analyze_performance(self):
        """Analyze and compare performance metrics"""
        
        old_results = self.results['old_scanner_results']
        new_results = self.results['new_scanner_results']
        
        # Calculate improvement factors
        time_improvement = old_results['avg_time_per_target'] / new_results['avg_time_per_target'] if new_results['avg_time_per_target'] > 0 else 0
        discovery_improvement = new_results['discovery_rate'] / old_results['discovery_rate'] if old_results['discovery_rate'] > 0 else float('inf')
        streams_improvement = new_results['streams_per_target'] / old_results['streams_per_target'] if old_results['streams_per_target'] > 0 else float('inf')
        
        # Overall performance factor (combination of metrics)
        overall_improvement = (discovery_improvement + streams_improvement) / 2 if discovery_improvement != float('inf') and streams_improvement != float('inf') else 0
        
        self.results['performance_comparison'] = {
            'time_improvement_factor': round(time_improvement, 2),
            'discovery_improvement_factor': round(discovery_improvement, 2),
            'streams_improvement_factor': round(streams_improvement, 2),
            'overall_improvement_factor': round(overall_improvement, 2),
            'claimed_improvement': 5.7,
            'improvement_validated': overall_improvement >= 5.7,
            'detailed_metrics': {
                'old_avg_time': round(old_results['avg_time_per_target'], 2),
                'new_avg_time': round(new_results['avg_time_per_target'], 2),
                'old_discovery_rate': round(old_results['discovery_rate'], 2),
                'new_discovery_rate': round(new_results['discovery_rate'], 2),
                'old_streams_per_target': round(old_results['streams_per_target'], 2),
                'new_streams_per_target': round(new_results['streams_per_target'], 2)
            }
        }
        
        print(f"📊 Performance Analysis Results:")
        print(f"  - Time improvement: {time_improvement:.2f}x")
        print(f"  - Discovery improvement: {discovery_improvement:.2f}x")
        print(f"  - Streams improvement: {streams_improvement:.2f}x")
        print(f"  - Overall improvement: {overall_improvement:.2f}x")
        print(f"  - Claimed improvement: 5.7x")
        print(f"  - Validation: {'✅ PASSED' if overall_improvement >= 5.7 else '❌ FAILED'}")
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    async def _generate_validation_report(self):
        """Generate comprehensive validation report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"performance_validation_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n📋 PERFORMANCE VALIDATION REPORT")
        print(f"-" * 50)
        print(f"✓ Report saved: {report_file}")
        
        comparison = self.results['performance_comparison']
        
        print(f"\n🎯 FINAL VERDICT:")
        print(f"  - Overall improvement: {comparison['overall_improvement_factor']}x")
        print(f"  - Claimed improvement: {comparison['claimed_improvement']}x")
        
        if comparison['improvement_validated']:
            print(f"  - Status: ✅ PERFORMANCE CLAIMS VALIDATED")
            print(f"  - The enhanced scanner delivers the claimed improvement!")
        else:
            print(f"  - Status: ❌ PERFORMANCE CLAIMS NOT VALIDATED")
            print(f"  - The enhanced scanner does not meet claimed performance.")
        
        print(f"\n📊 Key Metrics:")
        metrics = comparison['detailed_metrics']
        print(f"  - OLD Scanner: {metrics['old_discovery_rate']} streams/target, {metrics['old_avg_time']}s/target")
        print(f"  - NEW Scanner: {metrics['new_discovery_rate']} streams/target, {metrics['new_avg_time']}s/target")


async def main():
    """Run performance validation"""
    
    validator = PerformanceValidator()
    
    try:
        print("Starting NECESSARY-WORK-2 performance validation...")
        results = await validator.run_validation(max_targets=8)
        
        print(f"\n" + "=" * 80)
        print(f"PERFORMANCE VALIDATION COMPLETED")
        
        comparison = results['performance_comparison']
        if comparison['improvement_validated']:
            print(f"🎉 SUCCESS: Performance claims VALIDATED ({comparison['overall_improvement_factor']}x improvement)")
        else:
            print(f"⚠️  FAILURE: Performance claims NOT validated ({comparison['overall_improvement_factor']}x vs claimed 5.7x)")
        
        print(f"=" * 80)
        
    except Exception as e:
        print(f"\n❌ Performance validation failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())