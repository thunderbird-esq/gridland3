#!/bin/bash
#
# GRIDLAND v3.0 Benchmark Runner Helper Script
#
# Usage:
#   ./run_benchmarks.sh [--iterations N] [--save-results FILE]
#
# Examples:
#   ./run_benchmarks.sh
#   ./run_benchmarks.sh --iterations 10
#   ./run_benchmarks.sh --iterations 10 --save-results my_results.json
#

# Get the script directory (benchmarks/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Get the project root (one level up)
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Set PYTHONPATH to include project root
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Run benchmark suite with all arguments passed through
python "$SCRIPT_DIR/benchmark_suite.py" "$@"
