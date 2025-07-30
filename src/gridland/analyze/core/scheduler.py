"""
Adaptive work-stealing task scheduler for optimal CPU utilization.

Implements a sophisticated task distribution system that dynamically
balances workload across worker threads using work-stealing queues.
"""

import asyncio
import threading
import time
import statistics
from collections import deque
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from threading import Lock, RLock, Event
from typing import List, Dict, Optional, Callable, Any, Tuple, Union
from queue import Queue, Empty
from uuid import uuid4

from ...core.logger import get_logger
from ..memory import get_memory_pool, AnalysisResult

logger = get_logger(__name__)


@dataclass 
class TaskMetrics:
    """Performance metrics for task execution."""
    task_id: str
    worker_id: int
    start_time: float
    end_time: float
    execution_time: float
    cpu_usage: float = 0.0
    memory_usage: int = 0
    success: bool = True
    error: Optional[str] = None


@dataclass
class WorkerStats:
    """Statistics for individual worker performance."""
    worker_id: int
    tasks_completed: int = 0
    tasks_stolen: int = 0  # Tasks stolen FROM this worker
    tasks_acquired: int = 0  # Tasks stolen BY this worker
    total_execution_time: float = 0.0
    average_task_time: float = 0.0
    cpu_utilization: float = 0.0
    idle_time: float = 0.0


class WorkStealingQueue:
    """Double-ended queue optimized for work-stealing operations."""
    
    def __init__(self, max_size: int = 10000):
        self._deque = deque(maxlen=max_size)
        self._lock = RLock()
        self._size = 0
    
    def push_bottom(self, task):
        """Push task to bottom (local worker adds tasks here)."""
        with self._lock:
            self._deque.append(task)
            self._size += 1
    
    def pop_bottom(self):
        """Pop task from bottom (local worker takes tasks here)."""
        with self._lock:
            if self._size == 0:
                return None
            task = self._deque.pop()
            self._size -= 1
            return task
    
    def pop_top(self):
        """Pop task from top (stealing workers take tasks here)."""
        with self._lock:
            if self._size == 0:
                return None
            task = self._deque.popleft()
            self._size -= 1
            return task
    
    def size(self) -> int:
        """Get current queue size."""
        return self._size
    
    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return self._size == 0


class AdaptiveTaskScheduler:
    """
    Revolutionary work-stealing scheduler with dynamic load balancing.
    
    Automatically adjusts worker count and task distribution based on
    system load and task characteristics for optimal performance.
    """
    
    def __init__(self, 
                 max_workers: Optional[int] = None,
                 steal_ratio: float = 0.5,
                 adaptation_interval: float = 5.0):
        """
        Initialize adaptive scheduler.
        
        Args:
            max_workers: Maximum worker threads (default: CPU count * 2)
            steal_ratio: Threshold for work stealing (0.0-1.0) 
            adaptation_interval: Seconds between load balancing adjustments
        """
        import os
        self.max_workers = max_workers or (os.cpu_count() * 2)
        self.steal_ratio = steal_ratio
        self.adaptation_interval = adaptation_interval
        
        # Worker management
        self._workers: List[threading.Thread] = []
        self._worker_queues: List[WorkStealingQueue] = []
        self._worker_stats: List[WorkerStats] = []
        self._active_workers = 0
        
        # Task tracking
        self._task_metrics: List[TaskMetrics] = []
        self._global_task_queue = Queue()
        self._shutdown_event = Event()
        
        # Performance monitoring
        self._load_monitor_thread: Optional[threading.Thread] = None
        self._stats_lock = RLock()
        
        # Memory pool integration
        self._memory_pool = get_memory_pool()
        
        logger.info(f"AdaptiveTaskScheduler initialized with max_workers={self.max_workers}")
    
    def start(self):
        """Start the scheduler and worker threads."""
        if self._workers:
            logger.warning("Scheduler already started")
            return
        
        # Initialize worker queues and stats
        for i in range(self.max_workers):
            self._worker_queues.append(WorkStealingQueue())
            self._worker_stats.append(WorkerStats(worker_id=i))
        
        # Start initial workers (25% of max to begin with)
        initial_workers = max(1, self.max_workers // 4)
        for i in range(initial_workers):
            self._start_worker(i)
        
        # Start load monitor
        self._load_monitor_thread = threading.Thread(
            target=self._load_monitor_loop,
            daemon=True
        )
        self._load_monitor_thread.start()
        
        logger.info(f"Scheduler started with {initial_workers} initial workers")
    
    def _start_worker(self, worker_id: int):
        """Start a specific worker thread."""
        if worker_id >= len(self._workers):
            self._workers.extend([None] * (worker_id - len(self._workers) + 1))
        
        if self._workers[worker_id] is not None:
            return  # Worker already running
        
        worker_thread = threading.Thread(
            target=self._worker_loop,
            args=(worker_id,),
            daemon=True
        )
        worker_thread.start()
        self._workers[worker_id] = worker_thread
        self._active_workers += 1
        
        logger.debug(f"Started worker {worker_id}")
    
    def _worker_loop(self, worker_id: int):
        """Main loop for worker threads."""
        local_queue = self._worker_queues[worker_id]
        stats = self._worker_stats[worker_id]
        
        while not self._shutdown_event.is_set():
            task = None
            start_time = time.time()
            
            # 1. Try local queue first
            task = local_queue.pop_bottom()
            
            # 2. Try work stealing if local queue empty
            if task is None:
                task = self._steal_task(worker_id)
            
            # 3. Try global queue if stealing failed
            if task is None:
                try:
                    task = self._global_task_queue.get(timeout=0.1)
                except Empty:
                    continue
            
            if task is None:
                # Track idle time
                idle_start = time.time()
                time.sleep(0.01)  # Brief sleep to avoid busy waiting
                stats.idle_time += time.time() - idle_start
                continue
            
            # Execute task
            try:
                result = self._execute_task(task, worker_id, start_time)
                self._record_task_metrics(result)
                stats.tasks_completed += 1
                
            except Exception as e:
                logger.error(f"Worker {worker_id} task execution failed: {e}")
                self._record_failed_task(task, worker_id, start_time, str(e))
    
    def _steal_task(self, thief_worker_id: int) -> Optional[Any]:
        """Attempt to steal a task from another worker's queue."""
        # Start with random worker to avoid contention
        import random
        workers_to_try = list(range(self.max_workers))
        workers_to_try.remove(thief_worker_id)
        random.shuffle(workers_to_try)
        
        for victim_worker_id in workers_to_try:
            victim_queue = self._worker_queues[victim_worker_id]
            
            # Only steal if victim has sufficient work
            if victim_queue.size() > 1:  # Leave at least one task for victim
                task = victim_queue.pop_top()
                if task is not None:
                    # Update statistics
                    self._worker_stats[thief_worker_id].tasks_acquired += 1
                    self._worker_stats[victim_worker_id].tasks_stolen += 1
                    return task
        
        return None
    
    def _execute_task(self, task: Tuple[Callable, tuple, dict], 
                     worker_id: int, start_time: float) -> TaskMetrics:
        """Execute a task and return metrics."""
        func, args, kwargs = task
        task_id = str(uuid4())
        
        execution_start = time.time()
        try:
            result = func(*args, **kwargs)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
            raise
        finally:
            execution_time = time.time() - execution_start
            
            return TaskMetrics(
                task_id=task_id,
                worker_id=worker_id,
                start_time=start_time,
                end_time=time.time(),
                execution_time=execution_time,
                success=success,
                error=error
            )
    
    def _record_task_metrics(self, metrics: TaskMetrics):
        """Record task execution metrics."""
        with self._stats_lock:
            self._task_metrics.append(metrics)
            
            # Update worker stats
            worker_stats = self._worker_stats[metrics.worker_id]
            worker_stats.total_execution_time += metrics.execution_time
            
            if worker_stats.tasks_completed > 0:
                worker_stats.average_task_time = (
                    worker_stats.total_execution_time / worker_stats.tasks_completed
                )
    
    def _record_failed_task(self, task: Any, worker_id: int, 
                           start_time: float, error: str):
        """Record failed task metrics."""
        metrics = TaskMetrics(
            task_id=str(uuid4()),
            worker_id=worker_id,
            start_time=start_time,
            end_time=time.time(),
            execution_time=time.time() - start_time,
            success=False,
            error=error
        )
        self._record_task_metrics(metrics)
    
    def _load_monitor_loop(self):
        """Monitor system load and adapt worker count."""
        while not self._shutdown_event.is_set():
            try:
                self._adapt_worker_count()
                time.sleep(self.adaptation_interval)
            except Exception as e:
                logger.error(f"Load monitor error: {e}")
                time.sleep(1.0)
    
    def _adapt_worker_count(self):
        """Dynamically adjust worker count based on load."""
        with self._stats_lock:
            # Calculate queue utilization
            total_queue_size = sum(q.size() for q in self._worker_queues)
            global_queue_size = self._global_task_queue.qsize()
            total_pending = total_queue_size + global_queue_size
            
            # Calculate average task completion rate
            recent_metrics = self._task_metrics[-100:]  # Last 100 tasks
            if recent_metrics:
                avg_task_time = statistics.mean(m.execution_time for m in recent_metrics)
                completion_rate = len(recent_metrics) / (time.time() - recent_metrics[0].start_time)
            else:
                avg_task_time = 1.0
                completion_rate = 0.0
            
            # Decide on worker adjustment
            if total_pending > self._active_workers * 2 and self._active_workers < self.max_workers:
                # Scale up - too many pending tasks
                new_worker_id = self._active_workers
                self._start_worker(new_worker_id)
                logger.info(f"Scaled up to {self._active_workers} workers (pending: {total_pending})")
                
            elif total_pending < self._active_workers // 2 and self._active_workers > 1:
                # Scale down - workers are idle
                # Note: We don't actually stop workers, just let them idle
                # This prevents thread creation/destruction overhead
                logger.debug(f"Workers underutilized (pending: {total_pending}, active: {self._active_workers})")
    
    async def submit_task(self, func: Callable, *args, **kwargs) -> Future:
        """Submit task for execution."""
        task = (func, args, kwargs)
        
        # Try to find least loaded worker queue
        min_size = float('inf')
        best_queue_idx = 0
        
        for i, queue in enumerate(self._worker_queues):
            if queue.size() < min_size:
                min_size = queue.size()
                best_queue_idx = i
        
        # Submit to best queue if not too loaded, otherwise global queue
        if min_size < 10:  # Arbitrary threshold
            self._worker_queues[best_queue_idx].push_bottom(task)
        else:
            self._global_task_queue.put(task)
        
        # Return a future-like object for result tracking
        future = Future()
        # Note: For full implementation, we'd need to track futures
        # and complete them when tasks finish
        return future
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scheduler statistics."""
        with self._stats_lock:
            recent_metrics = self._task_metrics[-1000:]  # Last 1000 tasks
            
            stats = {
                'active_workers': self._active_workers,
                'max_workers': self.max_workers,
                'total_tasks_completed': len(self._task_metrics),
                'pending_tasks': sum(q.size() for q in self._worker_queues) + self._global_task_queue.qsize(),
                'worker_stats': [
                    {
                        'worker_id': ws.worker_id,
                        'tasks_completed': ws.tasks_completed,
                        'tasks_stolen': ws.tasks_stolen,
                        'tasks_acquired': ws.tasks_acquired,
                        'average_task_time': ws.average_task_time,
                        'idle_time': ws.idle_time
                    }
                    for ws in self._worker_stats[:self._active_workers]
                ]
            }
            
            if recent_metrics:
                successful_tasks = [m for m in recent_metrics if m.success]
                if successful_tasks:
                    stats['recent_performance'] = {
                        'average_execution_time': statistics.mean(m.execution_time for m in successful_tasks),
                        'median_execution_time': statistics.median(m.execution_time for m in successful_tasks),
                        'success_rate': len(successful_tasks) / len(recent_metrics),
                        'tasks_per_second': len(recent_metrics) / (time.time() - recent_metrics[0].start_time)
                    }
            
            return stats
    
    def shutdown(self):
        """Shutdown scheduler and all workers."""
        logger.info("Shutting down AdaptiveTaskScheduler")
        self._shutdown_event.set()
        
        # Wait for workers to finish
        for worker in self._workers:
            if worker and worker.is_alive():
                worker.join(timeout=1.0)
        
        # Wait for load monitor
        if self._load_monitor_thread and self._load_monitor_thread.is_alive():
            self._load_monitor_thread.join(timeout=1.0)
        
        logger.info("AdaptiveTaskScheduler shutdown complete")


# Global scheduler instance
_global_scheduler: Optional[AdaptiveTaskScheduler] = None


def get_scheduler() -> AdaptiveTaskScheduler:
    """Get global scheduler instance."""
    global _global_scheduler
    if _global_scheduler is None:
        _global_scheduler = AdaptiveTaskScheduler()
        _global_scheduler.start()
    return _global_scheduler


def initialize_scheduler(max_workers: Optional[int] = None, 
                        steal_ratio: float = 0.5,
                        adaptation_interval: float = 5.0) -> AdaptiveTaskScheduler:
    """Initialize global scheduler with custom parameters."""
    global _global_scheduler
    if _global_scheduler is not None:
        _global_scheduler.shutdown()
    
    _global_scheduler = AdaptiveTaskScheduler(
        max_workers=max_workers,
        steal_ratio=steal_ratio,
        adaptation_interval=adaptation_interval
    )
    _global_scheduler.start()
    return _global_scheduler


class PortScanTaskScheduler(AdaptiveTaskScheduler):
    """Specialized scheduler for high-volume port scanning."""

    def distribute_port_scan_tasks(self, ip_range: str, ports: List[int]) -> List[Future]:
        """Distribute port scanning across workers efficiently."""

        # Group ports into optimal batch sizes
        batch_size = max(10, len(ports) // self.max_workers)
        port_batches = [ports[i:i+batch_size] for i in range(0, len(ports), batch_size)]

        tasks = []
        for batch in port_batches:
            # This assumes a function `scan_ports_batch` exists
            # that can be called as a task.
            # We would need to define this function elsewhere.
            # For now, we'll use a placeholder.
            from ..discover.masscan_engine import MasscanEngine
            engine = MasscanEngine()

            # The task should be a callable.
            # We'll represent it as a tuple of (function, args)
            task_callable = engine.scan_range
            task_args = (ip_range, batch)

            # The scheduler's submit_task should handle this.
            # We are returning a list of futures.
            future = self.submit_task(task_callable, *task_args)
            tasks.append(future)

        return tasks

# Placeholder for a potential PortScanTask dataclass
@dataclass
class PortScanTask:
    ip_range: str
    ports: List[int]