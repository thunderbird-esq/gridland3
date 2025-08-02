"""
Job management for Gridland web interface
"""
import uuid
from typing import Dict, Optional
from .core import Job


# In-memory job storage (could be replaced with database later)
_jobs: Dict[str, Job] = {}


def create_job(target: str) -> Job:
    """
    Create a new scan job
    
    Args:
        target: Target IP or network range
        
    Returns:
        Job: New job instance
    """
    job_id = str(uuid.uuid4())
    job = Job(id=job_id, target=target)
    _jobs[job_id] = job
    return job


def get_job(job_id: str) -> Optional[Job]:
    """
    Retrieve a job by ID
    
    Args:
        job_id: Job identifier
        
    Returns:
        Optional[Job]: Job instance if found
    """
    return _jobs.get(job_id)


def update_job_status(job_id: str, status: str) -> bool:
    """
    Update job status
    
    Args:
        job_id: Job identifier
        status: New status (pending, running, completed, failed)
        
    Returns:
        bool: True if job was found and updated
    """
    job = _jobs.get(job_id)
    if job:
        job.status = status
        return True
    return False


def add_job_log(job_id: str, message: str) -> bool:
    """
    Add a log message to a job
    
    Args:
        job_id: Job identifier
        message: Log message
        
    Returns:
        bool: True if job was found and log added
    """
    job = _jobs.get(job_id)
    if job:
        job.add_log(message)
        return True
    return False


def set_job_results(job_id: str, results: list) -> bool:
    """
    Set scan results for a job
    
    Args:
        job_id: Job identifier
        results: List of ScanTarget objects
        
    Returns:
        bool: True if job was found and results set
    """
    job = _jobs.get(job_id)
    if job:
        job.results = results
        return True
    return False


def list_jobs() -> Dict[str, Job]:
    """
    Get all jobs
    
    Returns:
        Dict[str, Job]: All jobs indexed by ID
    """
    return _jobs.copy()


def cleanup_old_jobs(max_jobs: int = 100) -> int:
    """
    Remove old jobs if we have too many
    
    Args:
        max_jobs: Maximum number of jobs to keep
        
    Returns:
        int: Number of jobs removed
    """
    if len(_jobs) <= max_jobs:
        return 0
    
    # Keep only the most recent jobs
    sorted_jobs = sorted(_jobs.items(), key=lambda x: x[1].id)
    jobs_to_remove = sorted_jobs[:-max_jobs]
    
    for job_id, _ in jobs_to_remove:
        del _jobs[job_id]
    
    return len(jobs_to_remove)