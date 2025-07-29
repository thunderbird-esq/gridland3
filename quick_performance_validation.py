#!/usr/bin/env python3
"""
Quick Performance Validation - Focused Test

Tests the 5.7x improvement claim with minimal overhead
using synthetic targets to isolate scanner performance.
"""

import asyncio
import json
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
from gridland.analyze.plugins.builtin.rtsp_stream_scanner import RTSPStreamScanner


class QuickValidator:
    """Quick focused performance validation"""
    
    def __init__(self):
        self.old_scanner = RTSPStreamScanner()
        self.new_scanner = EnhancedStreamScanner()
    
    async def run_quick_validation(self):
        """Run focused validation with known targets"""
        
        print("QUICK PERFORMANCE VALIDATION")
        print("=" * 50)
        
        # Use test targets that should respond quickly
        test_targets = [
            {'ip': '127.0.0.1', 'port': 80, 'name': 'localhost-http'},
            {'ip': '8.8.8.8', 'port': 53, 'name': 'google-dns'},
            {'ip': '1.1.1.1', 'port': 80, 'name': 'cloudflare-http'}
        ]
        
        results = {
            'old_scanner': {'total_time': 0, 'streams': 0},
            'new_scanner': {'total_time': 0, 'streams': 0}
        }
        
        # Test OLD scanner
        print(f"\n📊 Testing OLD rtsp_scanner...")
        start_time = time.time()
        
        for target in test_targets:
            try:
                scan_start = time.time()
                streams = await asyncio.wait_for(
                    self.old_scanner.analyze_streams(
                        target['ip'], target['port'], service="rtsp", banner=""
                    ), timeout=5.0
                )
                scan_time = time.time() - scan_start
                
                stream_count = len(streams) if streams else 0
                results['old_scanner']['streams'] += stream_count
                
                print(f"  {target['name']}: {scan_time:.2f}s, {stream_count} streams")
                
            except asyncio.TimeoutError:
                print(f"  {target['name']}: timeout")
            except Exception as e:
                print(f"  {target['name']}: error - {e}")
        
        results['old_scanner']['total_time'] = time.time() - start_time
        
        # Test NEW scanner
        print(f"\n🚀 Testing NEW enhanced_scanner...")
        start_time = time.time()
        
        for target in test_targets:
            try:
                scan_start = time.time()
                streams = await asyncio.wait_for(
                    self.new_scanner.analyze_streams(
                        target['ip'], target['port'], service="http", banner=""
                    ), timeout=5.0
                )
                scan_time = time.time() - scan_start
                
                stream_count = len(streams) if streams else 0
                results['new_scanner']['streams'] += stream_count
                
                print(f"  {target['name']}: {scan_time:.2f}s, {stream_count} streams")
                
            except asyncio.TimeoutError:
                print(f"  {target['name']}: timeout")
            except Exception as e:
                print(f"  {target['name']}: error - {e}")
        
        results['new_scanner']['total_time'] = time.time() - start_time
        
        # Compare results
        print(f"\n📈 Results:")
        print(f"  OLD: {results['old_scanner']['total_time']:.2f}s, {results['old_scanner']['streams']} streams")
        print(f"  NEW: {results['new_scanner']['total_time']:.2f}s, {results['new_scanner']['streams']} streams")
        
        # Calculate improvement
        if results['old_scanner']['total_time'] > 0 and results['new_scanner']['total_time'] > 0:
            time_improvement = results['old_scanner']['total_time'] / results['new_scanner']['total_time']
            print(f"  Time improvement: {time_improvement:.2f}x")
            
            if results['old_scanner']['streams'] > 0:
                stream_improvement = results['new_scanner']['streams'] / results['old_scanner']['streams']
                print(f"  Stream improvement: {stream_improvement:.2f}x")
            
        # Test database enhancement claim
        await self._test_database_enhancement()
        
        return results
    
    async def _test_database_enhancement(self):
        """Test database enhancement claims"""
        
        print(f"\n📊 Database Enhancement Test:")
        
        # Check enhanced scanner database
        try:
            stream_db = self.new_scanner.stream_database
            total_paths = 0
            
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
                total_paths += protocol_paths
            
            print(f"  Enhanced database: {total_paths} total paths")
            print(f"  CamXploit baseline: 98 paths")
            print(f"  Enhancement factor: {total_paths / 98:.2f}x")
            
            if total_paths > 200:
                print(f"  ✅ Database enhancement VALIDATED")
            else:
                print(f"  ❌ Database enhancement INSUFFICIENT")
                
        except Exception as e:
            print(f"  ❌ Database test failed: {e}")


async def main():
    validator = QuickValidator()
    
    try:
        await validator.run_quick_validation()
        print(f"\n✅ Quick validation completed")
        
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())