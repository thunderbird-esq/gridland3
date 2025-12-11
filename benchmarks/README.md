# GRIDLAND v3.0 Performance Benchmark Suite

Comprehensive performance testing suite for measuring GRIDLAND v3.0 module performance.

## Overview

The benchmark suite measures performance across all major GRIDLAND modules:

- **PortScanner**: Multi-threaded port scanning throughput
- **BrandDetector**: Camera brand detection speed
- **CVELookup**: Vulnerability database query performance
- **DataLoader**: Data file loading efficiency
- **OSINTURLGenerator**: URL generation throughput
- **StreamDetector**: Stream URL pattern matching speed
- **IPValidator**: IP address validation throughput

## Quick Start

```bash
# Run with default settings (5 iterations)
PYTHONPATH=/home/user/gridland3:$PYTHONPATH python benchmarks/benchmark_suite.py

# Run with custom iterations
PYTHONPATH=/home/user/gridland3:$PYTHONPATH python benchmarks/benchmark_suite.py --iterations 10

# Save results to custom location
PYTHONPATH=/home/user/gridland3:$PYTHONPATH python benchmarks/benchmark_suite.py --save-results my_results.json
```

## Usage

```
python benchmark_suite.py [OPTIONS]

Options:
  --iterations N        Number of iterations per benchmark (default: 5)
  --save-results FILE   Output file for JSON results (default: benchmarks/results.json)
  -h, --help           Show help message
```

## Benchmark Descriptions

### 1. PortScannerBenchmark
**Measures**: Port scanning throughput (ports/second)

Tests the `PythonPortScanner` multi-threaded scanning capability by scanning 100 ports against localhost. While connections fail quickly, this measures thread pool overhead and socket handling efficiency.

### 2. BrandDetectorBenchmark
**Measures**: Brand detections per second

Tests the `BrandDetector` module by analyzing 1000 mock HTTP responses with various server headers, content-types, and response bodies. Measures multi-source brand identification speed.

### 3. CVELookupBenchmark
**Measures**: CVE lookups per second

Tests the `CVELookup` module by querying CVEs for all brands and generating NVD URLs. Measures database filtering and URL generation performance.

### 4. DataLoaderBenchmark
**Measures**: Cold load time (milliseconds)

Tests data file loading by measuring the time to load all three data files:
- camera_ports.json
- login_paths.json
- cve_database.json

Reports cold load time (first load without caching).

### 5. OSINTURLGeneratorBenchmark
**Measures**: URL sets per second

Tests the `OSINTURLGenerator` by generating search URLs and Google Dorks for 1000 test IPs. Measures URL formatting and encoding efficiency.

### 6. StreamDetectorBenchmark
**Measures**: Pattern matches per second

Tests the `StreamDetector` URL pattern matching (no network calls) by analyzing 1000 URLs for resolution, codec, and stream category detection.

### 7. IPValidatorBenchmark
**Measures**: Validations per second

Tests the `IPValidator` by validating 10,000 IP addresses (mix of public and private IPv4/IPv6). Measures IP parsing and classification speed.

## Output Format

### Console Output

```
================================================================================
GRIDLAND v3.0 Performance Benchmark Suite
================================================================================
Iterations per benchmark: 5
================================================================================

Running PortScanner... ✓ 2011.15 ports/sec
Running BrandDetector... ✓ 12345.67 detections/sec
...

================================================================================
Benchmark Results Summary
================================================================================
Benchmark                 Mean            Min             Max             Std Dev
--------------------------------------------------------------------------------
PortScanner                  2011.15 ports/sec    1742.85 ports/sec    2283.96 ports/sec     270.58 ports/sec
...
================================================================================

================================================================================
Memory Profile
================================================================================
camera_ports               0.18 KB
login_paths                0.27 KB
cve_database               0.18 KB
================================================================================

Results saved to: benchmarks/results.json

✓ Benchmark suite complete!
```

### JSON Output (results.json)

```json
{
  "timestamp": "2025-12-11 05:56:28",
  "iterations": 5,
  "benchmarks": [
    {
      "name": "PortScanner",
      "unit": "ports/sec",
      "min": 1742.85,
      "max": 2283.96,
      "mean": 2011.15,
      "median": 2006.63,
      "stddev": 270.58,
      "iterations": [1742.85, 2283.96, 2006.63, ...]
    },
    ...
  ],
  "memory_profile": {
    "camera_ports": {"size_bytes": 184, "memory_delta_mb": null},
    ...
  }
}
```

## Memory Profiling

The suite includes a `MemoryProfiler` class that:

- Measures object sizes in bytes using `sys.getsizeof()`
- Optionally measures memory deltas with `psutil` (if installed)
- Profiles all loaded data structures

Install `psutil` for enhanced memory profiling:

```bash
pip install psutil
```

## Dependencies

**Required:**
- Python 3.7+
- GRIDLAND v3.0 modules

**Optional:**
- `psutil`: Enhanced memory profiling

## Architecture

### BenchmarkResult Class
Stores and calculates statistics for benchmark results:
- Min, max, mean, median, standard deviation
- JSON serialization
- Formatted string output

### BaseBenchmark Class
Base class for all benchmarks with:
- `setup()`: Pre-benchmark initialization
- `run()`: Execute benchmark and return metric
- `teardown()`: Post-benchmark cleanup
- `get_unit()`: Return metric unit string

### BenchmarkRunner Class
Orchestrates benchmark execution:
- Registers and runs benchmarks
- Collects results across iterations
- Prints formatted tables
- Saves JSON results

### MemoryProfiler Class
Profiles memory usage:
- Current process memory (requires psutil)
- Object size measurements
- Data structure profiling

## Extending the Suite

To add a new benchmark:

1. Create a class inheriting from `BaseBenchmark`:

```python
class MyBenchmark(BaseBenchmark):
    def __init__(self):
        super().__init__("MyBenchmark")
        try:
            from gridland.mymodule import MyClass
            self.my_class = MyClass
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        # Initialize test data
        pass

    def run(self) -> float:
        # Run benchmark and return metric
        start = time.perf_counter()
        # ... benchmark code ...
        elapsed = time.perf_counter() - start
        return operations / elapsed

    def get_unit(self) -> str:
        return "ops/sec"
```

2. Register in `main()`:

```python
runner.register_benchmark(MyBenchmark())
```

## Interpreting Results

### PortScanner
- **Good**: >2000 ports/sec
- **Excellent**: >5000 ports/sec

### BrandDetector
- **Good**: >10000 detections/sec
- **Excellent**: >50000 detections/sec

### CVELookup
- **Good**: >1000 lookups/sec
- **Excellent**: >5000 lookups/sec

### DataLoader
- **Good**: <5 ms cold load
- **Excellent**: <2 ms cold load

### OSINTURLGenerator
- **Good**: >50000 URL_sets/sec
- **Excellent**: >100000 URL_sets/sec

### StreamDetector
- **Good**: >100 pattern_matches/sec
- **Excellent**: >500 pattern_matches/sec

### IPValidator
- **Good**: >50000 validations/sec
- **Excellent**: >100000 validations/sec

## Performance Baseline (Reference)

Typical results on modern hardware (2023):

| Benchmark | Mean Performance |
|-----------|-----------------|
| PortScanner | ~2000 ports/sec |
| BrandDetector | ~15000 detections/sec |
| CVELookup | ~4000 lookups/sec |
| DataLoader | ~1.3 ms |
| OSINTURLGenerator | ~155000 URL_sets/sec |
| StreamDetector | ~136 pattern_matches/sec |
| IPValidator | ~185000 validations/sec |

## Troubleshooting

### Import Errors
If benchmarks are skipped due to import errors:
```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=/home/user/gridland3:$PYTHONPATH

# Or install the package
pip install -e .
```

### Low Performance
- Close other applications
- Run multiple iterations (--iterations 10)
- Check system load with `top` or `htop`

### Memory Profiling Issues
- Install psutil: `pip install psutil`
- Memory deltas may be null if psutil is not available

## Contributing

When adding new GRIDLAND modules, please:
1. Add corresponding benchmark class
2. Update this README with interpretation guidelines
3. Run full benchmark suite to establish baseline
4. Document any dependencies

## License

MIT License - See LICENSE file for details

## Related Documentation

- **MIGRATION_TASKS.md**: Task breakdown (TASKS 332-342)
- **CHANGELOG.md**: Version history
- **DEVLOG.md**: Implementation notes
