#!/usr/bin/env python3
"""
GRIDLAND v3.0 Performance Benchmark Suite

Measures performance across all GRIDLAND modules:
- Port scanning throughput
- Brand detection speed
- CVE lookup performance
- Data loader efficiency
- OSINT URL generation
- Stream detection
- IP validation

Usage:
    python benchmark_suite.py
    python benchmark_suite.py --iterations 10
    python benchmark_suite.py --save-results benchmarks/custom_results.json

Author: GRIDLAND Development Team
Version: 1.0.0
"""

import sys
import time
import json
import statistics
import argparse
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path


# Memory profiling
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class BenchmarkResult:
    """Stores benchmark execution results with statistics."""

    def __init__(self, name: str, iterations: List[float], unit: str = "ops/sec"):
        self.name = name
        self.iterations = iterations
        self.unit = unit

        # Calculate statistics
        self.min = min(iterations) if iterations else 0.0
        self.max = max(iterations) if iterations else 0.0
        self.mean = statistics.mean(iterations) if iterations else 0.0
        self.stddev = statistics.stdev(iterations) if len(iterations) > 1 else 0.0
        self.median = statistics.median(iterations) if iterations else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'name': self.name,
            'unit': self.unit,
            'min': self.min,
            'max': self.max,
            'mean': self.mean,
            'median': self.median,
            'stddev': self.stddev,
            'iterations': self.iterations
        }

    def __str__(self) -> str:
        """Format result for display."""
        return (f"{self.name}: {self.mean:.2f} {self.unit} "
                f"(min: {self.min:.2f}, max: {self.max:.2f}, stddev: {self.stddev:.2f})")


class MemoryProfiler:
    """Profiles memory usage of GRIDLAND modules."""

    def __init__(self):
        self.has_psutil = HAS_PSUTIL
        if self.has_psutil:
            self.process = psutil.Process()

    def get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        if self.has_psutil:
            return self.process.memory_info().rss / 1024 / 1024
        return 0.0

    def measure_object_size(self, obj: Any) -> int:
        """Measure size of Python object in bytes."""
        return sys.getsizeof(obj)

    def profile_data_structures(self) -> Dict[str, Any]:
        """Profile memory usage of loaded data structures."""
        results = {}

        try:
            from gridland.core.data_loader import (
                load_camera_ports, load_login_paths, load_cve_database
            )

            # Measure camera ports
            start_mem = self.get_current_memory_mb()
            ports = load_camera_ports()
            end_mem = self.get_current_memory_mb()
            results['camera_ports'] = {
                'size_bytes': self.measure_object_size(ports),
                'memory_delta_mb': end_mem - start_mem if self.has_psutil else None
            }

            # Measure login paths
            start_mem = self.get_current_memory_mb()
            login_paths = load_login_paths()
            end_mem = self.get_current_memory_mb()
            results['login_paths'] = {
                'size_bytes': self.measure_object_size(login_paths),
                'memory_delta_mb': end_mem - start_mem if self.has_psutil else None
            }

            # Measure CVE database
            start_mem = self.get_current_memory_mb()
            cve_db = load_cve_database()
            end_mem = self.get_current_memory_mb()
            results['cve_database'] = {
                'size_bytes': self.measure_object_size(cve_db),
                'memory_delta_mb': end_mem - start_mem if self.has_psutil else None
            }

        except ImportError as e:
            results['error'] = str(e)

        return results


class BaseBenchmark:
    """Base class for all benchmarks."""

    def __init__(self, name: str):
        self.name = name
        self.available = True
        self.skip_reason = None

    def setup(self):
        """Setup before benchmark runs."""
        pass

    def teardown(self):
        """Cleanup after benchmark runs."""
        pass

    def run(self) -> float:
        """Run benchmark and return metric value."""
        raise NotImplementedError("Subclasses must implement run()")

    def get_unit(self) -> str:
        """Return unit for benchmark metric."""
        return "ops/sec"


class PortScannerBenchmark(BaseBenchmark):
    """Benchmark PythonPortScanner performance."""

    def __init__(self):
        super().__init__("PortScanner")
        try:
            from gridland.discover import PythonPortScanner
            self.scanner_class = PythonPortScanner
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        """Initialize scanner."""
        if self.available:
            self.scanner = self.scanner_class(max_threads=100, timeout=0.1)

    def run(self) -> float:
        """Benchmark scanning 100 ports against localhost."""
        if not self.available:
            return 0.0

        # Use localhost - ports will fail fast but tests thread pool overhead
        ports = list(range(1, 101))  # Scan ports 1-100

        start = time.perf_counter()
        _ = self.scanner.scan_ports("127.0.0.1", ports)
        elapsed = time.perf_counter() - start

        # Return ports per second
        return len(ports) / elapsed if elapsed > 0 else 0.0

    def get_unit(self) -> str:
        return "ports/sec"


class BrandDetectorBenchmark(BaseBenchmark):
    """Benchmark BrandDetector performance."""

    def __init__(self):
        super().__init__("BrandDetector")
        try:
            from gridland.analyze.core import BrandDetector
            self.detector_class = BrandDetector
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        """Initialize detector and create test data."""
        if self.available:
            self.detector = self.detector_class()

            # Create 1000 mock port_data dictionaries
            self.test_data = []
            headers = [
                {'server_header': 'hikvision-dvr', 'content_type': 'text/html', 'response_body': 'camera'},
                {'server_header': 'dahua', 'content_type': 'image/jpeg', 'response_body': 'surveillance'},
                {'server_header': 'axis', 'content_type': 'video/mpeg', 'response_body': 'live'},
                {'server_header': 'camera', 'content_type': 'text/html', 'response_body': 'generic'},
                {'server_header': 'sony', 'content_type': 'application/json', 'response_body': 'api'},
            ]

            for i in range(1000):
                self.test_data.append(headers[i % len(headers)])

    def run(self) -> float:
        """Benchmark brand detection on 1000 samples."""
        if not self.available:
            return 0.0

        start = time.perf_counter()
        for data in self.test_data:
            _ = self.detector.detect_brand(data)
        elapsed = time.perf_counter() - start

        # Return detections per second
        return len(self.test_data) / elapsed if elapsed > 0 else 0.0

    def get_unit(self) -> str:
        return "detections/sec"


class CVELookupBenchmark(BaseBenchmark):
    """Benchmark CVELookup performance."""

    def __init__(self):
        super().__init__("CVELookup")
        try:
            from gridland.analyze.core import CVELookup
            self.lookup_class = CVELookup
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        """Initialize CVE lookup."""
        if self.available:
            self.lookup = self.lookup_class()
            self.brands = self.lookup.get_available_brands()

    def run(self) -> float:
        """Benchmark CVE lookups and URL generation."""
        if not self.available:
            return 0.0

        operations = 0
        start = time.perf_counter()

        # Benchmark get_cves for all brands
        for brand in self.brands:
            cves = self.lookup.get_cves(brand)
            operations += 1

            # Benchmark generate_nvd_urls
            if cves:
                _ = self.lookup.generate_nvd_urls(cves)
                operations += 1

        elapsed = time.perf_counter() - start

        # Return operations per second
        return operations / elapsed if elapsed > 0 else 0.0

    def get_unit(self) -> str:
        return "lookups/sec"


class DataLoaderBenchmark(BaseBenchmark):
    """Benchmark data loader performance."""

    def __init__(self):
        super().__init__("DataLoader")
        try:
            from gridland.core import data_loader
            self.data_loader = data_loader
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def run(self) -> float:
        """Benchmark loading all data files."""
        if not self.available:
            return 0.0

        # Measure cold load time (first load)
        start = time.perf_counter()
        _ = self.data_loader.load_camera_ports()
        _ = self.data_loader.load_login_paths()
        _ = self.data_loader.load_cve_database()
        elapsed = time.perf_counter() - start

        # Return milliseconds for cold load
        return elapsed * 1000

    def get_unit(self) -> str:
        return "ms (cold load)"


class OSINTURLGeneratorBenchmark(BaseBenchmark):
    """Benchmark OSINTURLGenerator performance."""

    def __init__(self):
        super().__init__("OSINTURLGenerator")
        try:
            from gridland.analyze.core.osint import OSINTURLGenerator
            self.generator = OSINTURLGenerator
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        """Create test IPs."""
        if self.available:
            # Generate 1000 test IPs
            self.test_ips = [f"192.168.{i // 256}.{i % 256}" for i in range(1000)]

    def run(self) -> float:
        """Benchmark URL generation for 1000 IPs."""
        if not self.available:
            return 0.0

        operations = 0
        start = time.perf_counter()

        for ip in self.test_ips:
            _ = self.generator.generate_search_urls(ip)
            operations += 1
            _ = self.generator.generate_google_dorks(ip)
            operations += 1

        elapsed = time.perf_counter() - start

        # Return URLs per second
        return operations / elapsed if elapsed > 0 else 0.0

    def get_unit(self) -> str:
        return "URL_sets/sec"


class StreamDetectorBenchmark(BaseBenchmark):
    """Benchmark StreamDetector performance (URL pattern matching only)."""

    def __init__(self):
        super().__init__("StreamDetector")
        try:
            from gridland.analyze.core.stream import StreamDetector
            self.detector_class = StreamDetector
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        """Initialize detector and create test URLs."""
        if self.available:
            self.detector = self.detector_class()

            # Create 1000 test URLs with various patterns
            self.test_urls = []
            patterns = [
                "rtsp://192.168.1.{}/live.sdp",
                "http://192.168.1.{}/video/live_1080p.h264",
                "http://192.168.1.{}/mjpg/video.mjpg",
                "rtmp://192.168.1.{}/live/stream",
                "http://192.168.1.{}/snapshot.jpg",
            ]

            for i in range(1000):
                pattern = patterns[i % len(patterns)]
                self.test_urls.append(pattern.format(i % 256))

    def run(self) -> float:
        """Benchmark URL pattern matching (no network calls)."""
        if not self.available:
            return 0.0

        start = time.perf_counter()
        for url in self.test_urls:
            # Only benchmark get_stream_details which does pattern matching
            _ = self.detector.get_stream_details(url)
        elapsed = time.perf_counter() - start

        # Return detections per second
        return len(self.test_urls) / elapsed if elapsed > 0 else 0.0

    def get_unit(self) -> str:
        return "pattern_matches/sec"


class IPValidatorBenchmark(BaseBenchmark):
    """Benchmark IPValidator performance."""

    def __init__(self):
        super().__init__("IPValidator")
        try:
            from gridland.core import IPValidator
            self.validator = IPValidator
        except ImportError as e:
            self.available = False
            self.skip_reason = f"Import error: {e}"

    def setup(self):
        """Create test IPs."""
        if self.available:
            # Generate 10000 test IPs (mix of public and private)
            self.test_ips = []
            for i in range(10000):
                octet = i % 256
                if i % 3 == 0:
                    # Private IP
                    self.test_ips.append(f"192.168.{octet}.{octet}")
                elif i % 3 == 1:
                    # Public IP
                    self.test_ips.append(f"8.8.{octet}.{octet}")
                else:
                    # Another public IP range
                    self.test_ips.append(f"1.1.{octet}.{octet}")

    def run(self) -> float:
        """Benchmark IP validation for 10000 IPs."""
        if not self.available:
            return 0.0

        start = time.perf_counter()
        for ip in self.test_ips:
            _ = self.validator.validate_ip(ip)
        elapsed = time.perf_counter() - start

        # Return validations per second
        return len(self.test_ips) / elapsed if elapsed > 0 else 0.0

    def get_unit(self) -> str:
        return "validations/sec"


class BenchmarkRunner:
    """Runs benchmarks and collects results."""

    def __init__(self, iterations: int = 5):
        self.iterations = iterations
        self.results: List[BenchmarkResult] = []
        self.memory_profile: Optional[Dict[str, Any]] = None

    def register_benchmark(self, benchmark: BaseBenchmark) -> None:
        """Register a benchmark to run."""
        if not hasattr(self, 'benchmarks'):
            self.benchmarks: List[BaseBenchmark] = []
        self.benchmarks.append(benchmark)

    def run_all(self) -> None:
        """Run all registered benchmarks."""
        print(f"\n{'='*80}")
        print(f"GRIDLAND v3.0 Performance Benchmark Suite")
        print(f"{'='*80}")
        print(f"Iterations per benchmark: {self.iterations}")
        print(f"{'='*80}\n")

        for benchmark in self.benchmarks:
            if not benchmark.available:
                print(f"⊘ Skipping {benchmark.name}: {benchmark.skip_reason}")
                continue

            print(f"Running {benchmark.name}...", end=' ', flush=True)

            # Setup
            benchmark.setup()

            # Run iterations
            iteration_results = []
            for i in range(self.iterations):
                try:
                    result = benchmark.run()
                    iteration_results.append(result)
                except Exception as e:
                    print(f"\n  Error in iteration {i+1}: {e}")

            # Teardown
            benchmark.teardown()

            # Store results
            if iteration_results:
                bench_result = BenchmarkResult(
                    benchmark.name,
                    iteration_results,
                    benchmark.get_unit()
                )
                self.results.append(bench_result)
                print(f"✓ {bench_result.mean:.2f} {bench_result.unit}")
            else:
                print("✗ No results")

        # Run memory profiler
        print(f"\nProfiling memory usage...", end=' ', flush=True)
        profiler = MemoryProfiler()
        self.memory_profile = profiler.profile_data_structures()
        print("✓")

    def print_results(self) -> None:
        """Print formatted results table."""
        if not self.results:
            print("\nNo benchmark results to display.")
            return

        print(f"\n{'='*80}")
        print(f"Benchmark Results Summary")
        print(f"{'='*80}")

        # Print table header
        header = f"{'Benchmark':<25} {'Mean':<15} {'Min':<15} {'Max':<15} {'Std Dev':<15}"
        print(header)
        print("-" * 80)

        # Print each result
        for result in self.results:
            row = (f"{result.name:<25} "
                   f"{result.mean:>10.2f} {result.unit:<4} "
                   f"{result.min:>10.2f} {result.unit:<4} "
                   f"{result.max:>10.2f} {result.unit:<4} "
                   f"{result.stddev:>10.2f} {result.unit:<4}")
            print(row)

        print("=" * 80)

        # Print memory profile
        if self.memory_profile:
            print(f"\n{'='*80}")
            print(f"Memory Profile")
            print(f"{'='*80}")

            for name, data in self.memory_profile.items():
                if name == 'error':
                    print(f"Error: {data}")
                    continue

                size_kb = data['size_bytes'] / 1024
                print(f"{name:<20} {size_kb:>10.2f} KB", end='')

                if data['memory_delta_mb'] is not None:
                    print(f"  (delta: {data['memory_delta_mb']:>6.2f} MB)")
                else:
                    print()

            print("=" * 80)

    def save_results(self, output_file: str) -> None:
        """Save results to JSON file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'iterations': self.iterations,
            'benchmarks': [r.to_dict() for r in self.results],
            'memory_profile': self.memory_profile
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\nResults saved to: {output_path}")


def main():
    """Main entry point for benchmark suite."""
    parser = argparse.ArgumentParser(
        description='GRIDLAND v3.0 Performance Benchmark Suite'
    )
    parser.add_argument(
        '--iterations',
        type=int,
        default=5,
        help='Number of iterations per benchmark (default: 5)'
    )
    parser.add_argument(
        '--save-results',
        type=str,
        default='benchmarks/results.json',
        help='Output file for results (default: benchmarks/results.json)'
    )

    args = parser.parse_args()

    # Create runner
    runner = BenchmarkRunner(iterations=args.iterations)

    # Register all benchmarks
    runner.register_benchmark(PortScannerBenchmark())
    runner.register_benchmark(BrandDetectorBenchmark())
    runner.register_benchmark(CVELookupBenchmark())
    runner.register_benchmark(DataLoaderBenchmark())
    runner.register_benchmark(OSINTURLGeneratorBenchmark())
    runner.register_benchmark(StreamDetectorBenchmark())
    runner.register_benchmark(IPValidatorBenchmark())

    # Run benchmarks
    runner.run_all()

    # Print results
    runner.print_results()

    # Save results
    runner.save_results(args.save_results)

    print("\n✓ Benchmark suite complete!")


if __name__ == '__main__':
    main()
