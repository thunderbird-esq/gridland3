# GRIDLAND v3.0 Benchmark Suite - Quick Start Guide

## 🚀 Quick Commands

### Run Benchmarks

```bash
# Easy way (recommended)
./benchmarks/run_benchmarks.sh

# With custom iterations
./benchmarks/run_benchmarks.sh --iterations 10

# Manual way (requires PYTHONPATH)
PYTHONPATH=/home/user/gridland3:$PYTHONPATH python benchmarks/benchmark_suite.py
```

### Compare Results

```bash
# Run baseline
./benchmarks/run_benchmarks.sh --save-results benchmarks/baseline.json

# Make some code changes...

# Run current
./benchmarks/run_benchmarks.sh --save-results benchmarks/current.json

# Compare
python benchmarks/compare_results.py benchmarks/baseline.json benchmarks/current.json
```

## 📊 Understanding the Output

### Performance Indicators

When running benchmarks, you'll see output like:

```
Running PortScanner... ✓ 2011.15 ports/sec
```

This means the PortScanner can process approximately 2,011 ports per second.

### Comparison Indicators

When comparing results:

- **🚀 FASTER**: Performance improved by ≥5%
- **🐌 SLOWER**: Performance degraded by ≥5%
- **✓ STABLE**: Performance change is <5%

### Example Output

```
================================================================================
Benchmark Results Summary
================================================================================
Benchmark                 Mean            Min             Max             Std Dev
--------------------------------------------------------------------------------
PortScanner                  2011.15 ports/sec    1742.85 ports/sec    2283.96 ports/sec     270.58 ports/sec
BrandDetector              198649.96 detections/sec  197757.27 detections/sec  199542.65 detections/sec    1262.45 detections/sec
CVELookup                    4402.64 lookups/sec    4234.35 lookups/sec    4570.92 lookups/sec     237.99 lookups/sec
```

- **Mean**: Average performance across all iterations
- **Min**: Worst performance observed
- **Max**: Best performance observed
- **Std Dev**: Standard deviation (lower is more consistent)

## 🎯 Performance Goals

### Good vs Excellent Performance

| Benchmark | Good | Excellent |
|-----------|------|-----------|
| PortScanner | >2,000 ports/sec | >5,000 ports/sec |
| BrandDetector | >10,000 detections/sec | >50,000 detections/sec |
| CVELookup | >1,000 lookups/sec | >5,000 lookups/sec |
| DataLoader | <5 ms | <2 ms |
| OSINTURLGenerator | >50,000 URL_sets/sec | >100,000 URL_sets/sec |
| StreamDetector | >100 pattern_matches/sec | >500 pattern_matches/sec |
| IPValidator | >50,000 validations/sec | >100,000 validations/sec |

## 📁 Output Files

### results.json

Default location: `benchmarks/results.json`

Contains:
- Timestamp of benchmark run
- Number of iterations
- Detailed results for each benchmark
- Memory profiling data

### Custom Output Location

```bash
./benchmarks/run_benchmarks.sh --save-results my_custom_results.json
```

## 🔧 Troubleshooting

### "No module named 'gridland'"

**Solution**: Use the helper script `run_benchmarks.sh` which handles PYTHONPATH automatically.

Or manually set PYTHONPATH:
```bash
export PYTHONPATH=/home/user/gridland3:$PYTHONPATH
```

### Benchmarks Skipped

Some benchmarks may be skipped if dependencies are missing:

```
⊘ Skipping BrandDetector: Import error: No module named 'aiohttp'
```

**Solution**: This is normal if optional dependencies aren't installed. The suite will run all available benchmarks.

### Inconsistent Results

Performance can vary due to:
- System load (other processes running)
- CPU frequency scaling
- Disk caching
- Network conditions (for benchmarks with network calls)

**Solution**:
1. Close unnecessary applications
2. Run with more iterations: `--iterations 10`
3. Take the median value as more reliable than mean
4. Run multiple times and compare

## 📈 Workflow for Performance Testing

### 1. Establish Baseline

Before making changes:
```bash
./benchmarks/run_benchmarks.sh --iterations 10 --save-results benchmarks/before.json
```

### 2. Make Code Changes

Edit GRIDLAND modules, optimize algorithms, etc.

### 3. Run New Benchmarks

```bash
./benchmarks/run_benchmarks.sh --iterations 10 --save-results benchmarks/after.json
```

### 4. Compare Results

```bash
python benchmarks/compare_results.py benchmarks/before.json benchmarks/after.json
```

### 5. Analyze

Look for:
- **Regressions**: Any benchmarks showing 🐌 SLOWER
- **Improvements**: Any benchmarks showing 🚀 FASTER
- **Stability**: Standard deviation should be low (<10% of mean)

## 🔍 Advanced Usage

### Change Significance Threshold

Default threshold is 5%. To change:

```bash
python benchmarks/compare_results.py --threshold 10 baseline.json current.json
```

This will only flag changes >10% as significant.

### Running Specific Benchmarks

Currently, all benchmarks run automatically. To run specific ones, you can modify `benchmark_suite.py`:

```python
# In main():
runner.register_benchmark(PortScannerBenchmark())  # Only run this one
# runner.register_benchmark(BrandDetectorBenchmark())  # Comment out others
```

## 📝 Best Practices

1. **Run Multiple Iterations**: Use `--iterations 10` or higher for reliable results
2. **Consistent Environment**: Run benchmarks on the same machine with similar load
3. **Warm Up**: The first run may be slower due to cold caches (this is why we do multiple iterations)
4. **Document Changes**: Save results with descriptive names:
   ```bash
   ./benchmarks/run_benchmarks.sh --save-results results/v3.0.0-baseline.json
   ./benchmarks/run_benchmarks.sh --save-results results/v3.0.1-optimized-scanner.json
   ```
5. **Track Over Time**: Keep historical results to track performance trends

## 🐛 Debugging Slow Performance

If a benchmark shows poor performance:

1. **Check System Resources**:
   ```bash
   top  # or htop
   ```

2. **Profile the Specific Module**:
   ```bash
   python -m cProfile -s cumtime your_module.py
   ```

3. **Check for Network Issues** (if applicable):
   ```bash
   ping -c 5 target_ip
   ```

4. **Verify Data Files**:
   ```bash
   ls -lh gridland/data/
   ```

## 📚 Related Documentation

- **README.md**: Full benchmark suite documentation
- **MIGRATION_TASKS.md**: Tasks 332-342 (benchmark implementation)
- **benchmark_suite.py**: Source code with detailed docstrings

## 💡 Tips

- Run benchmarks during **development** to catch regressions early
- Run benchmarks **before releases** to ensure performance standards
- Use **comparison tool** to track improvements over time
- Save **historical results** for long-term performance tracking
- Consider **automated benchmarking** in CI/CD pipeline

## ✅ Checklist for Performance Validation

Before releasing a new version:

- [ ] Run full benchmark suite with ≥10 iterations
- [ ] Compare against previous version
- [ ] Verify no regressions (>10% slower)
- [ ] Document any significant changes in CHANGELOG.md
- [ ] Save results with version tag
- [ ] Update performance baselines if improved

---

**Questions?** See full documentation in `benchmarks/README.md`
