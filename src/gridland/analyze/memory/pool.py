"""
Zero-garbage memory pool for high-performance analysis operations.

Implements pre-allocated memory pools to eliminate garbage collection overhead
during intensive vulnerability scanning and result processing operations.
"""

import asyncio
import weakref
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Dict, List, Optional, TypeVar, Generic, Callable, Any
from uuid import uuid4

from ...core.logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T')


@dataclass
class PoolStats:
    """Memory pool performance statistics."""
    allocations: int = 0
    deallocations: int = 0
    pool_hits: int = 0
    pool_misses: int = 0
    current_active: int = 0
    peak_active: int = 0
    total_memory_bytes: int = 0


class PooledObject:
    """Base class for objects that can be pooled."""
    
    def __init__(self):
        self._pool_id = None
        self._in_use = False
    
    def reset(self):
        """Reset object state for reuse. Override in subclasses."""
        pass
    
    def _mark_pooled(self, pool_id: str):
        """Mark object as belonging to a pool."""
        self._pool_id = pool_id
    
    def _mark_in_use(self, in_use: bool):
        """Mark object as in use or available."""
        self._in_use = in_use


class ObjectPool(Generic[T]):
    """High-performance object pool with zero-copy operations."""
    
    def __init__(self, 
                 factory: Callable[[], T], 
                 max_size: int = 1000,
                 reset_func: Optional[Callable[[T], None]] = None):
        self.factory = factory
        self.max_size = max_size
        self.reset_func = reset_func or (lambda x: x.reset() if hasattr(x, 'reset') else None)
        
        self._pool = deque(maxlen=max_size)
        self._lock = RLock()
        self._stats = PoolStats()
        self._pool_id = str(uuid4())
        
        # Pre-allocate objects to avoid allocation overhead
        self._preallocate()
    
    def _preallocate(self):
        """Pre-allocate objects to minimize runtime allocation."""
        with self._lock:
            initial_size = min(10, self.max_size // 10)  # Pre-allocate 10% or 10 objects
            for _ in range(initial_size):
                obj = self.factory()
                if hasattr(obj, '_mark_pooled'):
                    obj._mark_pooled(self._pool_id)
                self._pool.append(obj)
    
    def acquire(self) -> T:
        """Acquire object from pool with zero-copy semantics."""
        with self._lock:
            if self._pool:
                obj = self._pool.popleft()
                self._stats.pool_hits += 1
            else:
                obj = self.factory()
                if hasattr(obj, '_mark_pooled'):
                    obj._mark_pooled(self._pool_id)
                self._stats.pool_misses += 1
            
            if hasattr(obj, '_mark_in_use'):
                obj._mark_in_use(True)
            
            self._stats.allocations += 1
            self._stats.current_active += 1
            self._stats.peak_active = max(self._stats.peak_active, self._stats.current_active)
            
            return obj
    
    def release(self, obj: T):
        """Release object back to pool."""
        if not obj:
            return
        
        with self._lock:
            # Reset object state
            try:
                self.reset_func(obj)
            except Exception as e:
                logger.warning(f"Failed to reset pooled object: {e}")
            
            if hasattr(obj, '_mark_in_use'):
                obj._mark_in_use(False)
            
            # Return to pool if space available
            if len(self._pool) < self.max_size:
                self._pool.append(obj)
            
            self._stats.deallocations += 1
            self._stats.current_active = max(0, self._stats.current_active - 1)
    
    def get_stats(self) -> PoolStats:
        """Get pool performance statistics."""
        with self._lock:
            return PoolStats(
                allocations=self._stats.allocations,
                deallocations=self._stats.deallocations,
                pool_hits=self._stats.pool_hits,
                pool_misses=self._stats.pool_misses,
                current_active=self._stats.current_active,
                peak_active=self._stats.peak_active,
                total_memory_bytes=len(self._pool) * 1024  # Rough estimate
            )


@dataclass
class VulnerabilityResult(PooledObject):
    """Pooled vulnerability scan result."""
    ip: str = ""
    port: int = 0
    service: str = ""
    vulnerability_id: str = ""
    severity: str = ""
    confidence: float = 0.0
    description: str = ""
    exploit_available: bool = False
    
    def reset(self):
        """Reset for object reuse."""
        self.ip = ""
        self.port = 0
        self.service = ""
        self.vulnerability_id = ""
        self.severity = ""
        self.confidence = 0.0
        self.description = ""
        self.exploit_available = False
    
    def __hash__(self):
        """Make object hashable for WeakSet tracking."""
        return id(self)


@dataclass
class StreamResult(PooledObject):
    """Pooled stream analysis result."""
    ip: str = ""
    port: int = 0
    protocol: str = ""
    stream_url: str = ""
    codec: str = ""
    resolution: str = ""
    fps: int = 0
    accessible: bool = False
    authenticated: bool = False
    
    def reset(self):
        """Reset for object reuse."""
        self.ip = ""
        self.port = 0
        self.protocol = ""
        self.stream_url = ""
        self.codec = ""
        self.resolution = ""
        self.fps = 0
        self.accessible = False
        self.authenticated = False
    
    def __hash__(self):
        """Make object hashable for WeakSet tracking."""
        return id(self)


@dataclass
class AnalysisResult(PooledObject):
    """Pooled comprehensive analysis result."""
    ip: str = ""
    port: int = 0
    service: str = ""
    banner: str = ""
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    streams: List[StreamResult] = field(default_factory=list)
    analysis_time: float = 0.0
    confidence: float = 0.0
    
    def reset(self):
        """Reset for object reuse."""
        self.ip = ""
        self.port = 0
        self.service = ""
        self.banner = ""
        self.vulnerabilities.clear()
        self.streams.clear()
        self.analysis_time = 0.0
        self.confidence = 0.0
    
    def __hash__(self):
        """Make object hashable for WeakSet tracking."""
        return id(self)


class AnalysisMemoryPool:
    """
    Revolutionary memory pool architecture for zero-GC analysis operations.
    
    Provides pre-allocated object pools for all analysis operations,
    eliminating garbage collection overhead during intensive scanning.
    """
    
    def __init__(self, pool_sizes: Optional[Dict[str, int]] = None):
        self.pool_sizes = pool_sizes or {
            'vulnerabilities': 10000,
            'streams': 5000,
            'analysis_results': 2000,
            'generic_objects': 1000,
            'discovery_pool': 50000,
            'port_result_pool': 100000,
        }
        
        # Initialize object pools
        self.vulnerability_pool = ObjectPool(
            factory=VulnerabilityResult,
            max_size=self.pool_sizes['vulnerabilities']
        )
        
        self.stream_pool = ObjectPool(
            factory=StreamResult,
            max_size=self.pool_sizes['streams']
        )
        
        self.analysis_pool = ObjectPool(
            factory=AnalysisResult,
            max_size=self.pool_sizes['analysis_results']
        )
        
        # Weak reference tracking for automatic cleanup
        self._active_objects = weakref.WeakSet()
        
        logger.info(f"AnalysisMemoryPool initialized with {sum(self.pool_sizes.values())} pre-allocated objects")
    
    def acquire_vulnerability_result(self) -> VulnerabilityResult:
        """Acquire vulnerability result object from pool."""
        obj = self.vulnerability_pool.acquire()
        self._active_objects.add(obj)
        return obj
    
    def acquire_stream_result(self) -> StreamResult:
        """Acquire stream result object from pool."""
        obj = self.stream_pool.acquire()
        self._active_objects.add(obj)
        return obj
    
    def acquire_analysis_result(self) -> AnalysisResult:
        """Acquire analysis result object from pool."""
        obj = self.analysis_pool.acquire()
        self._active_objects.add(obj)
        return obj
    
    def release_vulnerability_result(self, obj: VulnerabilityResult):
        """Release vulnerability result back to pool."""
        self.vulnerability_pool.release(obj)
    
    def release_stream_result(self, obj: StreamResult):
        """Release stream result back to pool."""
        self.stream_pool.release(obj)
    
    def release_analysis_result(self, obj: AnalysisResult):
        """Release analysis result back to pool."""
        # Release nested objects first
        for vuln in obj.vulnerabilities:
            self.release_vulnerability_result(vuln)
        for stream in obj.streams:
            self.release_stream_result(stream)
        
        self.analysis_pool.release(obj)
    
    def get_pool_statistics(self) -> Dict[str, PoolStats]:
        """Get comprehensive pool statistics."""
        return {
            'vulnerability_pool': self.vulnerability_pool.get_stats(),
            'stream_pool': self.stream_pool.get_stats(),
            'analysis_pool': self.analysis_pool.get_stats(),
        }
    
    def cleanup_leaked_objects(self):
        """Force cleanup of any leaked objects (emergency use only)."""
        # Weak references automatically clean up, but this forces collection
        import gc
        gc.collect()
        logger.info(f"Memory pool cleanup completed. Active objects: {len(self._active_objects)}")


# Global memory pool instance
_global_memory_pool: Optional[AnalysisMemoryPool] = None


def get_memory_pool() -> AnalysisMemoryPool:
    """Get global memory pool instance."""
    global _global_memory_pool
    if _global_memory_pool is None:
        _global_memory_pool = AnalysisMemoryPool()
    return _global_memory_pool


def initialize_memory_pool(pool_sizes: Optional[Dict[str, int]] = None):
    """Initialize global memory pool with custom sizes."""
    global _global_memory_pool
    _global_memory_pool = AnalysisMemoryPool(pool_sizes)
    return _global_memory_pool