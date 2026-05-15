import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
import threading
import queue
from datetime import datetime
from enum import Enum


# ── Job Status ────────────────────────────────────────────────
class JobStatus(Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETE   = "complete"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


# ── Scan Job ──────────────────────────────────────────────────
class ScanJob:
    """
    Represents a single scan job in the queue.
    """

    def __init__(
        self,
        job_id,
        target_name,
        system_prompt=None,
        categories  =None,
        priority    =5
    ):
        self.job_id       = job_id
        self.target_name  = target_name
        self.system_prompt= system_prompt or \
            "You are a helpful assistant."
        self.categories   = categories
        self.priority     = priority  # 1=highest, 10=lowest
        self.status       = JobStatus.PENDING
        self.created_at   = datetime.now().isoformat()
        self.started_at   = None
        self.completed_at = None
        self.result       = None
        self.error        = None
        self.progress     = 0

    def to_dict(self):
        return {
            "job_id"      : self.job_id,
            "target_name" : self.target_name,
            "priority"    : self.priority,
            "status"      : self.status.value,
            "created_at"  : self.created_at,
            "started_at"  : self.started_at,
            "completed_at": self.completed_at,
            "progress"    : self.progress,
            "error"       : self.error,
            "has_result"  : self.result is not None
        }

    def __lt__(self, other):
        """For priority queue comparison."""
        return self.priority < other.priority


# ── Scan Queue ────────────────────────────────────────────────
class ScanQueue:
    """
    Priority queue for scan jobs.
    Lower priority number = processed first.
    """

    def __init__(self):
        self._queue = queue.PriorityQueue()
        self._jobs  = {}  # job_id -> ScanJob
        self._lock  = threading.Lock()

    def add(self, job):
        """Adds a job to the queue."""
        with self._lock:
            self._jobs[job.job_id] = job
            self._queue.put((job.priority, job.created_at, job))

    def get(self, timeout=1):
        """Gets the next job from the queue."""
        try:
            priority, created_at, job = self._queue.get(timeout=timeout)
            return job
        except queue.Empty:
            return None

    def get_job(self, job_id):
        """Gets job by ID."""
        return self._jobs.get(job_id)

    def get_all_jobs(self):
        """Returns all jobs."""
        with self._lock:
            return list(self._jobs.values())

    def cancel(self, job_id):
        """Cancels a pending job."""
        job = self._jobs.get(job_id)
        if job and job.status == JobStatus.PENDING:
            job.status = JobStatus.CANCELLED
            return True
        return False

    def stats(self):
        """Returns queue statistics."""
        jobs = list(self._jobs.values())
        return {
            "total"    : len(jobs),
            "pending"  : sum(1 for j in jobs if j.status == JobStatus.PENDING),
            "running"  : sum(1 for j in jobs if j.status == JobStatus.RUNNING),
            "complete" : sum(1 for j in jobs if j.status == JobStatus.COMPLETE),
            "failed"   : sum(1 for j in jobs if j.status == JobStatus.FAILED),
            "cancelled": sum(1 for j in jobs if j.status == JobStatus.CANCELLED),
        }


# ── Queue Worker ──────────────────────────────────────────────
class QueueWorker(threading.Thread):
    """
    Background worker that processes scan jobs from the queue.
    Runs in a separate thread.
    """

    def __init__(self, scan_queue, worker_id=1):
        super().__init__(daemon=True)
        self.scan_queue = scan_queue
        self.worker_id  = worker_id
        self.running    = True
        self.current_job= None

    def run(self):
        """Main worker loop."""
        print(f"  Worker {self.worker_id} started")

        while self.running:
            job = self.scan_queue.get(timeout=1)

            if not job:
                continue

            if job.status == JobStatus.CANCELLED:
                continue

            self.current_job = job
            self._process_job(job)
            self.current_job = None

    def _process_job(self, job):
        """Processes a single scan job."""
        print(f"\n  Worker {self.worker_id} processing : {job.target_name}")

        job.status     = JobStatus.RUNNING
        job.started_at = datetime.now().isoformat()
        job.progress   = 0

        try:
            from target  import Target
            from scanner import run_full_scan

            target = Target(
                target_type  ="simulation",
                system_prompt=job.system_prompt
            )

            output_name = f"queue_{job.job_id}"

            result = run_full_scan(
                target     =target,
                target_name=job.target_name,
                output_name=output_name,
                categories =job.categories
            )

            job.status       = JobStatus.COMPLETE
            job.result       = result
            job.progress     = 100
            job.completed_at = datetime.now().isoformat()

            print(f"\n  Worker {self.worker_id} completed : {job.target_name}")
            print(f"  Score : {result['summary']['security_score']}%")

        except Exception as e:
            job.status    = JobStatus.FAILED
            job.error     = str(e)
            job.completed_at = datetime.now().isoformat()
            print(f"\n  Worker {self.worker_id} failed : {e}")

    def stop(self):
        """Stops the worker."""
        self.running = False


# ── Queue Manager ─────────────────────────────────────────────
class QueueManager:
    """
    Manages the scan queue and workers.
    Entry point for the queue system.
    """

    def __init__(self, num_workers=2):
        self.queue      = ScanQueue()
        self.workers    = []
        self.num_workers= num_workers
        self._job_counter = 0
        self._lock      = threading.Lock()

    def start(self):
        """Starts all workers."""
        print(f"\n  Starting {self.num_workers} queue worker(s)...")
        for i in range(self.num_workers):
            worker = QueueWorker(self.queue, worker_id=i+1)
            worker.start()
            self.workers.append(worker)
        print(f"  Queue manager ready !")

    def stop(self):
        """Stops all workers."""
        for worker in self.workers:
            worker.stop()
        print("  Queue manager stopped")

    def submit(
        self,
        target_name,
        system_prompt=None,
        categories  =None,
        priority    =5
    ):
        """
        Submits a new scan job to the queue.
        Returns the job_id.
        """
        with self._lock:
            self._job_counter += 1
            job_id = f"job_{self._job_counter:04d}"

        job = ScanJob(
            job_id      =job_id,
            target_name =target_name,
            system_prompt=system_prompt,
            categories  =categories,
            priority    =priority
        )

        self.queue.add(job)

        print(f"  Job submitted : {job_id} — {target_name}")
        print(f"  Priority      : {priority}")
        print(f"  Queue stats   : {self.queue.stats()}")

        return job_id

    def get_status(self, job_id):
        """Gets status of a specific job."""
        job = self.queue.get_job(job_id)
        if not job:
            return None
        return job.to_dict()

    def get_result(self, job_id):
        """Gets result of a completed job."""
        job = self.queue.get_job(job_id)
        if not job or job.status != JobStatus.COMPLETE:
            return None
        return job.result

    def cancel_job(self, job_id):
        """Cancels a pending job."""
        return self.queue.cancel(job_id)

    def wait_for_job(self, job_id, timeout=600):
        """
        Waits for a job to complete.
        Returns result or None on timeout.
        """
        start = time.time()
        while time.time() - start < timeout:
            job = self.queue.get_job(job_id)
            if not job:
                return None
            if job.status in (JobStatus.COMPLETE, JobStatus.FAILED):
                return job.result
            time.sleep(2)
        return None

    def print_status(self):
        """Prints current queue status."""
        stats = self.queue.stats()
        jobs  = self.queue.get_all_jobs()

        print(f"\n  {'='*50}")
        print(f"  QUEUE STATUS")
        print(f"  {'='*50}")
        print(f"  Workers   : {self.num_workers}")
        print(f"  Pending   : {stats['pending']}")
        print(f"  Running   : {stats['running']}")
        print(f"  Complete  : {stats['complete']}")
        print(f"  Failed    : {stats['failed']}")
        print()

        for job in jobs[-10:]:
            status_icons = {
                "pending"  : "⏳",
                "running"  : "🔄",
                "complete" : "✅",
                "failed"   : "❌",
                "cancelled": "🚫"
            }
            icon = status_icons.get(job.status.value, "?")
            print(
                f"  {icon} [{job.job_id}] "
                f"{job.target_name:<20} "
                f"{job.status.value}"
            )
        print(f"  {'='*50}\n")


# ── Global Queue Manager ──────────────────────────────────────
_global_manager = None


def get_queue_manager(num_workers=2):
    """Returns the global queue manager (singleton)."""
    global _global_manager
    if _global_manager is None:
        _global_manager = QueueManager(num_workers)
        _global_manager.start()
    return _global_manager


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Queue System Demo"
    )
    parser.add_argument("--workers",  type=int, default=2)
    parser.add_argument("--jobs",     type=int, default=3)
    parser.add_argument("--demo",     action="store_true")

    args = parser.parse_args()

    if args.demo:
        print("LLM Scanner — Queue System Demo")
        print("=" * 40)

        manager = QueueManager(num_workers=args.workers)
        manager.start()

        # Submit multiple jobs
        job_ids = []
        for i in range(args.jobs):
            job_id = manager.submit(
                target_name  =f"Test App {i+1}",
                system_prompt="You are a banking assistant.",
                priority     =i + 1
            )
            job_ids.append(job_id)
            time.sleep(0.5)

        manager.print_status()

        print("Waiting for jobs to complete...")
        for job_id in job_ids:
            result = manager.wait_for_job(job_id, timeout=300)
            if result:
                print(
                    f"  {job_id} complete — "
                    f"Score: {result['summary']['security_score']}%"
                )

        manager.print_status()
        manager.stop()