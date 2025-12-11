#!/usr/bin/env python3
"""
GRIDLAND v3.0 Benchmark Results Comparison Tool

Compares two benchmark result files to identify performance changes.

Usage:
    python compare_results.py baseline.json current.json
    python compare_results.py --threshold 10 baseline.json current.json

Author: GRIDLAND Development Team
Version: 1.0.0
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Any


class ResultComparator:
    """Compares two benchmark result files."""

    def __init__(self, threshold_percent: float = 5.0):
        """
        Initialize comparator.

        Args:
            threshold_percent: Percentage change threshold for highlighting (default: 5.0)
        """
        self.threshold_percent = threshold_percent

    def load_results(self, filepath: str) -> Dict[str, Any]:
        """Load benchmark results from JSON file."""
        with open(filepath, 'r') as f:
            return json.load(f)

    def calculate_change(self, baseline: float, current: float) -> Tuple[float, float]:
        """
        Calculate absolute and percentage change.

        Args:
            baseline: Baseline value
            current: Current value

        Returns:
            Tuple of (absolute_change, percent_change)
        """
        absolute_change = current - baseline
        if baseline != 0:
            percent_change = (absolute_change / baseline) * 100
        else:
            percent_change = 0.0

        return absolute_change, percent_change

    def compare_benchmarks(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Compare all benchmarks between baseline and current results.

        Args:
            baseline: Baseline results dictionary
            current: Current results dictionary

        Returns:
            List of comparison dictionaries
        """
        comparisons = []

        # Create lookup for baseline benchmarks
        baseline_benchmarks = {b['name']: b for b in baseline['benchmarks']}
        current_benchmarks = {b['name']: b for b in current['benchmarks']}

        # Compare common benchmarks
        for name in set(baseline_benchmarks.keys()) & set(current_benchmarks.keys()):
            baseline_bench = baseline_benchmarks[name]
            current_bench = current_benchmarks[name]

            abs_change, pct_change = self.calculate_change(
                baseline_bench['mean'],
                current_bench['mean']
            )

            comparisons.append({
                'name': name,
                'unit': baseline_bench['unit'],
                'baseline_mean': baseline_bench['mean'],
                'current_mean': current_bench['mean'],
                'absolute_change': abs_change,
                'percent_change': pct_change,
                'significant': abs(pct_change) >= self.threshold_percent
            })

        # Identify missing benchmarks
        missing_in_current = set(baseline_benchmarks.keys()) - set(current_benchmarks.keys())
        new_in_current = set(current_benchmarks.keys()) - set(baseline_benchmarks.keys())

        return comparisons, missing_in_current, new_in_current

    def print_comparison(self, comparisons: List[Dict[str, Any]],
                        missing: set, new: set,
                        baseline_file: str, current_file: str) -> None:
        """Print formatted comparison results."""
        print(f"\n{'='*100}")
        print(f"Benchmark Comparison: {baseline_file} → {current_file}")
        print(f"{'='*100}")
        print(f"Threshold for significant change: ±{self.threshold_percent}%")
        print(f"{'='*100}\n")

        if not comparisons:
            print("No common benchmarks found for comparison.\n")
            return

        # Print header
        header = (f"{'Benchmark':<25} {'Baseline':<20} {'Current':<20} "
                 f"{'Change':<15} {'% Change':<12} {'Status':<10}")
        print(header)
        print("-" * 100)

        # Sort by absolute percent change (descending)
        comparisons.sort(key=lambda x: abs(x['percent_change']), reverse=True)

        # Print each comparison
        for comp in comparisons:
            baseline_str = f"{comp['baseline_mean']:.2f} {comp['unit']}"
            current_str = f"{comp['current_mean']:.2f} {comp['unit']}"

            # Format change with sign
            change_sign = '+' if comp['absolute_change'] >= 0 else ''
            change_str = f"{change_sign}{comp['absolute_change']:.2f}"

            pct_sign = '+' if comp['percent_change'] >= 0 else ''
            pct_str = f"{pct_sign}{comp['percent_change']:.2f}%"

            # Status indicator
            if comp['significant']:
                if comp['percent_change'] > 0:
                    status = "🚀 FASTER"
                else:
                    status = "🐌 SLOWER"
            else:
                status = "✓ STABLE"

            row = (f"{comp['name']:<25} {baseline_str:<20} {current_str:<20} "
                  f"{change_str:<15} {pct_str:<12} {status:<10}")
            print(row)

        print("=" * 100)

        # Print summary statistics
        significant_changes = [c for c in comparisons if c['significant']]
        if significant_changes:
            print(f"\nSignificant Changes: {len(significant_changes)}/{len(comparisons)}")
            faster = [c for c in significant_changes if c['percent_change'] > 0]
            slower = [c for c in significant_changes if c['percent_change'] < 0]

            if faster:
                print(f"  🚀 Faster: {len(faster)} benchmarks")
                for c in faster:
                    print(f"     - {c['name']}: +{c['percent_change']:.2f}%")

            if slower:
                print(f"  🐌 Slower: {len(slower)} benchmarks")
                for c in slower:
                    print(f"     - {c['name']}: {c['percent_change']:.2f}%")

        # Print missing/new benchmarks
        if missing:
            print(f"\n⚠️  Missing in current: {', '.join(missing)}")

        if new:
            print(f"\n✨ New in current: {', '.join(new)}")

        print()

    def compare_memory_usage(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> None:
        """Compare memory usage between baseline and current."""
        if 'memory_profile' not in baseline or 'memory_profile' not in current:
            return

        print(f"{'='*100}")
        print(f"Memory Usage Comparison")
        print(f"{'='*100}\n")

        baseline_memory = baseline['memory_profile']
        current_memory = current['memory_profile']

        header = f"{'Data Structure':<25} {'Baseline (KB)':<20} {'Current (KB)':<20} {'Change (KB)':<15} {'% Change':<12}"
        print(header)
        print("-" * 100)

        for name in set(baseline_memory.keys()) & set(current_memory.keys()):
            if name == 'error':
                continue

            baseline_kb = baseline_memory[name]['size_bytes'] / 1024
            current_kb = current_memory[name]['size_bytes'] / 1024

            abs_change, pct_change = self.calculate_change(baseline_kb, current_kb)

            change_sign = '+' if abs_change >= 0 else ''
            pct_sign = '+' if pct_change >= 0 else ''

            row = (f"{name:<25} {baseline_kb:>15.2f} KB {current_kb:>15.2f} KB "
                  f"{change_sign}{abs_change:>10.2f} KB {pct_sign}{pct_change:>8.2f}%")
            print(row)

        print("=" * 100)
        print()


def main():
    """Main entry point for comparison tool."""
    parser = argparse.ArgumentParser(
        description='Compare GRIDLAND v3.0 benchmark results'
    )
    parser.add_argument(
        'baseline',
        type=str,
        help='Baseline results JSON file'
    )
    parser.add_argument(
        'current',
        type=str,
        help='Current results JSON file'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        default=5.0,
        help='Percentage change threshold for highlighting (default: 5.0)'
    )

    args = parser.parse_args()

    # Validate files exist
    baseline_path = Path(args.baseline)
    current_path = Path(args.current)

    if not baseline_path.exists():
        print(f"Error: Baseline file not found: {args.baseline}")
        sys.exit(1)

    if not current_path.exists():
        print(f"Error: Current file not found: {args.current}")
        sys.exit(1)

    # Load and compare results
    comparator = ResultComparator(threshold_percent=args.threshold)

    try:
        baseline = comparator.load_results(args.baseline)
        current = comparator.load_results(args.current)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}")
        sys.exit(1)

    # Compare benchmarks
    comparisons, missing, new = comparator.compare_benchmarks(baseline, current)
    comparator.print_comparison(
        comparisons, missing, new,
        baseline_path.name, current_path.name
    )

    # Compare memory usage
    comparator.compare_memory_usage(baseline, current)

    # Print metadata
    print(f"{'='*100}")
    print(f"Metadata")
    print(f"{'='*100}")
    print(f"Baseline timestamp: {baseline.get('timestamp', 'N/A')}")
    print(f"Current timestamp:  {current.get('timestamp', 'N/A')}")
    print(f"Baseline iterations: {baseline.get('iterations', 'N/A')}")
    print(f"Current iterations:  {current.get('iterations', 'N/A')}")
    print(f"{'='*100}\n")


if __name__ == '__main__':
    main()
