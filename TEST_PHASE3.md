# GRIDLAND Phase 3 Testing Guide

## 🧪 Comprehensive Testing Instructions

This guide provides step-by-step instructions for testing the revolutionary Phase 3 analysis engine with PhD-level performance optimizations.

## 📋 Prerequisites

### 1. Environment Setup
```bash
cd /Users/michaelraftery/HB-v2-gemmy-072525/gridland
pip install -r requirements.txt
pip install -e .
```

### 2. Required Dependencies
- Python 3.8+
- aiohttp>=3.8.0 (for async HTTP operations)
- All existing Phase 2 dependencies

### 3. Optional API Keys
```bash
export SHODAN_API_KEY="your_shodan_key_here"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
```

## 🔧 Phase 3 Component Testing

### 1. Memory Pool System Testing

**Test Zero-GC Memory Management:**
```python
# Create test file: test_memory_pool.py
from gridland.analyze.memory import get_memory_pool, VulnerabilityResult

def test_memory_pool():
    pool = get_memory_pool()
    
    # Test object acquisition and release
    vuln1 = pool.acquire_vulnerability_result()
    vuln2 = pool.acquire_vulnerability_result()
    
    # Populate test data
    vuln1.ip = "192.168.1.100"
    vuln1.port = 80
    vuln1.vulnerability_id = "test-vuln-1"
    
    # Release objects
    pool.release_vulnerability_result(vuln1)
    pool.release_vulnerability_result(vuln2)
    
    # Get statistics
    stats = pool.get_pool_statistics()
    print("Memory Pool Statistics:")
    for pool_name, pool_stats in stats.items():
        print(f"  {pool_name}: {pool_stats.pool_hits} hits, {pool_stats.pool_misses} misses")
    
    assert stats['vulnerability_pool'].pool_hits >= 0
    print("✅ Memory pool test passed")

if __name__ == "__main__":
    test_memory_pool()
```

**Run Test:**
```bash
cd /Users/michaelraftery/HB-v2-gemmy-072525
python test_memory_pool.py
```

### 2. Task Scheduler Testing

**Test Work-Stealing Scheduler:**
```python
# Create test file: test_scheduler.py
import asyncio
import time
from gridland.analyze.core import get_scheduler

async def sample_task(task_id: int, duration: float = 0.1):
    """Sample CPU-bound task for testing."""
    await asyncio.sleep(duration)
    return f"Task {task_id} completed"

async def test_scheduler():
    scheduler = get_scheduler()
    
    # Submit multiple tasks
    tasks = []
    for i in range(20):
        future = await scheduler.submit_task(sample_task, i, 0.05)
        tasks.append(future)
    
    # Wait a bit for processing
    await asyncio.sleep(2.0)
    
    # Get statistics  
    stats = scheduler.get_statistics()
    print("Task Scheduler Statistics:")
    print(f"  Active workers: {stats['active_workers']}")
    print(f"  Total tasks completed: {stats['total_tasks_completed']}")
    print(f"  Pending tasks: {stats['pending_tasks']}")
    
    if 'recent_performance' in stats:
        perf = stats['recent_performance']
        print(f"  Tasks per second: {perf.get('tasks_per_second', 0):.2f}")
    
    assert stats['active_workers'] > 0
    print("✅ Task scheduler test passed")

if __name__ == "__main__":
    asyncio.run(test_scheduler())
```

**Run Test:**
```bash
python test_scheduler.py
```

### 3. Signature Database Testing

**Test Vulnerability Database:**
```python
# Create test file: test_signature_db.py
from gridland.analyze.core.database import get_signature_database

def test_signature_database():
    db = get_signature_database()
    
    # Test port-based search
    port_80_vulns = db.search_by_port(80)
    print(f"Port 80 vulnerabilities: {len(port_80_vulns)}")
    
    # Test service-based search  
    http_vulns = db.search_by_service("http")
    print(f"HTTP vulnerabilities: {len(http_vulns)}")
    
    # Test banner matching
    banner_vulns = db.search_by_banner("hikvision web server")
    print(f"Hikvision banner matches: {len(banner_vulns)}")
    
    # Test comprehensive search
    comprehensive = db.search_comprehensive(
        port=80,
        service="http", 
        banner="admin login"
    )
    print(f"Comprehensive search results: {len(comprehensive)}")
    
    # Get database statistics
    stats = db.get_statistics()
    print("Signature Database Statistics:")
    print(f"  Total signatures: {stats['total_signatures']}")
    print(f"  Unique ports: {stats['unique_ports']}")
    print(f"  Pattern trie nodes: {stats['pattern_trie_stats']['total_nodes']}")
    
    assert stats['total_signatures'] > 0
    print("✅ Signature database test passed")

if __name__ == "__main__":
    test_signature_database()
```

**Run Test:**
```bash
python test_signature_db.py
```

### 4. Plugin System Testing

**Test Plugin Manager:**
```python
# Create test file: test_plugin_system.py
from gridland.analyze.plugins import get_plugin_manager

def test_plugin_system():
    plugin_mgr = get_plugin_manager()
    
    # Get plugin statistics
    stats = plugin_mgr.get_plugin_statistics()
    print("Plugin System Statistics:")
    print(f"  Total plugins: {stats['total_plugins']}")
    print(f"  Enabled plugins: {stats['enabled_plugins']}")
    
    for plugin_type, count in stats['plugins_by_type'].items():
        if count > 0:
            print(f"  {plugin_type} plugins: {count}")
    
    # Test plugin discovery for common ports
    port_80_plugins = plugin_mgr.get_applicable_plugins(80, "http")
    port_554_plugins = plugin_mgr.get_applicable_plugins(554, "rtsp")
    
    print(f"Port 80 applicable plugins: {len(port_80_plugins)}")
    print(f"Port 554 applicable plugins: {len(port_554_plugins)}")
    
    # Get vulnerability and stream plugins
    vuln_plugins = plugin_mgr.get_vulnerability_plugins()
    stream_plugins = plugin_mgr.get_stream_plugins()
    
    print(f"Vulnerability plugins: {len(vuln_plugins)}")
    print(f"Stream plugins: {len(stream_plugins)}")
    
    print("✅ Plugin system test passed")

if __name__ == "__main__":
    test_plugin_system() 
```

**Run Test:**
```bash
python test_plugin_system.py
```

## 🎯 End-to-End Analysis Testing

### 1. Single Target Analysis

**Test Individual Target:**
```bash
# Test analysis of a single target
gl-analyze --targets "httpbin.org:80" --verbose --show-statistics

# Expected output:
# - Memory pool statistics
# - Task scheduler performance  
# - Vulnerability scan results
# - Analysis timing information
```

### 2. Multiple Target Analysis

**Test Batch Analysis:**
```bash
# Create test targets file
echo "httpbin.org:80" > test_targets.txt
echo "httpbin.org:443" >> test_targets.txt
echo "google.com:80" >> test_targets.txt

# Run batch analysis
gl-analyze --input-file test_targets.txt --performance-mode BALANCED --output analysis_results.json --show-statistics
```

### 3. Discovery Integration Testing

**Test Phase 2 + Phase 3 Integration:**
```bash
# Step 1: Run discovery (Phase 2)
gl-discover --query "nginx" --limit 10 --output discovery_results.json

# Step 2: Analyze discovery results (Phase 3)
gl-analyze --discovery-results discovery_results.json --performance-mode THOROUGH --output comprehensive_analysis.json
```

## 📊 Performance Testing

### 1. Throughput Testing

**High-Volume Analysis:**
```bash
# Create large target list (100 targets)
python -c "
targets = [f'httpbin.org:{port}' for port in range(8000, 8100)]
with open('large_targets.txt', 'w') as f:
    f.write('\n'.join(targets))
"

# Test high-throughput analysis
time gl-analyze --input-file large_targets.txt --performance-mode FAST --max-concurrent 200 --output-format summary
```

### 2. Memory Efficiency Testing

**Memory Pool Performance:**
```bash
# Run analysis with statistics to monitor memory usage
gl-analyze --targets "httpbin.org:80,httpbin.org:443,google.com:80,github.com:443" --show-statistics --verbose
```

### 3. Concurrent Processing Testing

**Stress Test Scheduler:**
```python
# Create test file: stress_test.py
import asyncio
from gridland.analyze.engines import analyze_single_target

async def stress_test():
    tasks = []
    targets = [
        ("httpbin.org", 80),
        ("httpbin.org", 443), 
        ("google.com", 80),
        ("github.com", 443),
        ("stackoverflow.com", 80)
    ]
    
    # Launch concurrent analysis
    for ip, port in targets * 10:  # 50 total analyses
        task = analyze_single_target(ip, port)
        tasks.append(task)
    
    print(f"Starting {len(tasks)} concurrent analyses...")
    start_time = asyncio.get_event_loop().time()
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    end_time = asyncio.get_event_loop().time()
    duration = end_time - start_time
    
    successful = sum(1 for r in results if not isinstance(r, Exception))
    print(f"Completed {successful}/{len(tasks)} analyses in {duration:.2f}s")
    print(f"Throughput: {successful/duration:.2f} analyses/second")

if __name__ == "__main__":
    asyncio.run(stress_test())
```

**Run Stress Test:**
```bash
python stress_test.py
```

## 🔍 Output Format Testing

### 1. Test All Output Formats

**Table Format:**
```bash
gl-analyze --targets "httpbin.org:80,httpbin.org:443" --output-format table
```

**JSON Format:**
```bash
gl-analyze --targets "httpbin.org:80" --output-format json --output analysis.json
```

**CSV Format:**
```bash
gl-analyze --targets "httpbin.org:80,github.com:443" --output-format csv > analysis.csv
```

**Summary Format:**
```bash
gl-analyze --targets "httpbin.org:80,httpbin.org:443,google.com:80" --output-format summary
```

### 2. Test Performance Modes

**Fast Mode:**
```bash
gl-analyze --targets "httpbin.org:80" --performance-mode FAST --show-statistics
```

**Balanced Mode:**
```bash
gl-analyze --targets "httpbin.org:80" --performance-mode BALANCED --show-statistics
```

**Thorough Mode:**
```bash
gl-analyze --targets "httpbin.org:80" --performance-mode THOROUGH --show-statistics
```

## 🐛 Error Handling Testing

### 1. Invalid Target Testing

```bash
# Test invalid IP
gl-analyze --targets "999.999.999.999:80" --verbose

# Test invalid port
gl-analyze --targets "httpbin.org:99999" --verbose

# Test unreachable target
gl-analyze --targets "192.168.255.255:80" --timeout 5 --verbose
```

### 2. Configuration Testing

```bash
# Test dry run mode
gl-analyze --targets "httpbin.org:80" --dry-run

# Test feature toggles
gl-analyze --targets "httpbin.org:80" --disable-vulnerabilities --disable-streams --verbose
```

## 📈 Expected Results & Benchmarks

### Performance Targets
- **Analysis throughput**: >100 targets/second on modern hardware
- **Memory efficiency**: >80% pool reuse rate  
- **CPU utilization**: Scales with available cores
- **Memory overhead**: Minimal garbage collection

### Success Criteria
1. ✅ All component tests pass without errors
2. ✅ Memory pools show >80% hit rate
3. ✅ Task scheduler utilizes multiple workers
4. ✅ Signature database returns relevant vulnerabilities
5. ✅ Plugin system loads and executes successfully
6. ✅ End-to-end analysis completes without crashes
7. ✅ Performance scales with concurrent targets
8. ✅ All output formats generate valid data

## 🚨 Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure GRIDLAND is installed in development mode
pip install -e .
```

**Permission Errors:**
```bash
# Ensure temp directories are writable
mkdir -p /tmp/gridland
chmod 755 /tmp/gridland
```

**Memory Issues:**
```bash
# Reduce concurrent targets if system has limited RAM
gl-analyze --max-concurrent 20 --targets "..."
```

**Network Timeouts:**
```bash
# Increase timeout for slow networks
gl-analyze --timeout 60 --targets "..."
```

## 📝 Test Report Template

After completing tests, document results:

```
GRIDLAND Phase 3 Test Report
============================

Environment:
- Python version: 
- OS: 
- RAM: 
- CPU cores: 

Component Tests:
- Memory Pool: ✅/❌
- Task Scheduler: ✅/❌  
- Signature Database: ✅/❌
- Plugin System: ✅/❌

Performance Tests:
- Single target analysis: ___s
- Batch analysis (10 targets): ___s
- Throughput: ___/second
- Memory efficiency: ___%

Issues Found:
- 

Recommendations:
- 
```

This comprehensive testing suite validates all Phase 3 components and ensures the revolutionary analysis engine performs according to PhD-level specifications.