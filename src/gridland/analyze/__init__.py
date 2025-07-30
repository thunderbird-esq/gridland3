"""
GRIDLAND Analysis Module - Phase 3 Implementation

Revolutionary analysis engine with zero-waste resource architecture featuring:
- Memory pools for garbage collection elimination
- Work-stealing task scheduler for optimal CPU utilization
- Memory-mapped vulnerability database for zero-copy access
- Plugin-based extensibility architecture
- Hybrid AsyncIO + Threading concurrent processing

This represents the pinnacle of Python performance optimization for
security scanning operations.
"""

from .memory import (
    AnalysisMemoryPool,
    VulnerabilityResult,
    StreamResult,
    AnalysisResult,
    get_memory_pool,
    initialize_memory_pool
)

from .core import (
    AdaptiveTaskScheduler,
    TaskMetrics,
    WorkerStats,
    get_scheduler,
    initialize_scheduler
)

from .core.database import (
    SignatureDatabase,
    VulnerabilitySignature,
    get_signature_database,
    initialize_signature_database
)

from .plugins import (
    PluginManager,
    AnalysisPlugin,
    VulnerabilityPlugin,
    StreamPlugin,
    PluginMetadata,
    get_plugin_manager,
    initialize_plugin_manager
)

from .engines import (
    AnalysisEngine,
    AnalysisTarget,
    AnalysisConfiguration,
    analyze_discovery_results,
    analyze_single_target,
    create_analysis_config
)

__all__ = [
    # Memory management
    'AnalysisMemoryPool',
    'VulnerabilityResult',
    'StreamResult', 
    'AnalysisResult',
    'get_memory_pool',
    'initialize_memory_pool',
    
    # Task scheduling
    'AdaptiveTaskScheduler',
    'TaskMetrics',
    'WorkerStats',
    'get_scheduler',
    'initialize_scheduler',
    
    # Signature database
    'SignatureDatabase',
    'VulnerabilitySignature',
    'get_signature_database',
    'initialize_signature_database',
    
    # Plugin system
    'PluginManager',
    'AnalysisPlugin',
    'VulnerabilityPlugin',
    'StreamPlugin',
    'PluginMetadata',
    'get_plugin_manager',
    'initialize_plugin_manager',
    
    # Analysis engine
    'AnalysisEngine',
    'AnalysisTarget',
    'AnalysisConfiguration',
    'analyze_discovery_results',
    'analyze_single_target',
    'create_analysis_config'
]

# Module version
__version__ = "3.0.0"

# Performance targets from ROADMAP.md
PERFORMANCE_TARGETS = {
    'analysis_throughput': '1000+ targets/second',
    'memory_efficiency': '90% pool reuse rate',
    'cpu_utilization': '95% across all cores',
    'memory_overhead': '<5% garbage collection time'
}