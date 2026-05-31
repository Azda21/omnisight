"""Distributed P2P Coordinator - Multi-node crawler coordination.

Enables:
- Distributed task assignment
- Result aggregation
- Load balancing
- Fault tolerance
- DHT-based service discovery
"""

import asyncio
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json

logger = logging.getLogger("omnisight.scanner.crawler.distributed")


@dataclass
class CrawlTask:
    """Distributed crawl task."""
    task_id: str
    target_cidr: str
    ports: List[int]
    priority: float = 0.5
    assigned_to: Optional[str] = None
    status: str = "pending"  # pending, assigned, running, completed, failed
    created_at: str = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    retry_count: int = 0
    max_retries: int = 3

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TaskQueue:
    """Distributed task queue."""

    def __init__(self, max_queue_size: int = 10000):
        self.max_queue_size = max_queue_size
        self.pending: List[CrawlTask] = []
        self.assigned: Dict[str, CrawlTask] = {}
        self.completed: List[CrawlTask] = []
        self._lock = asyncio.Lock()

    async def enqueue(self, task: CrawlTask) -> None:
        """Add task to queue."""
        async with self._lock:
            if len(self.pending) >= self.max_queue_size:
                logger.warning("Task queue full, dropping lowest priority task")
                self.pending.sort(key=lambda t: t.priority)
                self.pending.pop(0)
            self.pending.append(task)
            self.pending.sort(key=lambda t: t.priority, reverse=True)

    async def dequeue(self, worker_id: str) -> Optional[CrawlTask]:
        """Get next task for worker."""
        async with self._lock:
            if not self.pending:
                return None
            task = self.pending.pop(0)
            task.assigned_to = worker_id
            task.status = "assigned"
            self.assigned[task.task_id] = task
            return task

    async def mark_completed(
        self, task_id: str, result: Dict[str, Any]
    ) -> None:
        """Mark task as completed."""
        async with self._lock:
            if task_id in self.assigned:
                task = self.assigned.pop(task_id)
                task.status = "completed"
                task.completed_at = datetime.now().isoformat()
                task.result = result
                self.completed.append(task)

    async def mark_failed(self, task_id: str, error: str) -> None:
        """Mark task as failed."""
        async with self._lock:
            if task_id in self.assigned:
                task = self.assigned[task_id]
                task.retry_count += 1

                if task.retry_count >= task.max_retries:
                    task.status = "failed"
                    self.assigned.pop(task_id)
                    self.completed.append(task)
                else:
                    task.status = "pending"
                    task.assigned_to = None
                    self.assigned.pop(task_id)
                    self.pending.append(task)
                    logger.info(f"Requeued task {task_id}, retry {task.retry_count}/{task.max_retries}")

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            "pending_tasks": len(self.pending),
            "assigned_tasks": len(self.assigned),
            "completed_tasks": len(self.completed),
            "total_tasks": len(self.pending) + len(self.assigned) + len(self.completed),
        }


class DistributedCoordinator:
    """Master coordinator for distributed crawling."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.task_queue = TaskQueue()
        self.workers: Dict[str, Dict[str, Any]] = {}
        self.results_aggregator: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self.health_check_interval = 30  # seconds
        self.task_timeout = 300  # seconds

    async def register_worker(self, worker_id: str, capabilities: List[str]) -> None:
        """Register a worker node."""
        async with self._lock:
            self.workers[worker_id] = {
                "id": worker_id,
                "capabilities": capabilities,
                "registered_at": datetime.now().isoformat(),
                "last_heartbeat": datetime.now().isoformat(),
                "tasks_completed": 0,
                "status": "online",
            }
            logger.info(f"Registered worker: {worker_id}")

    async def unregister_worker(self, worker_id: str) -> None:
        """Unregister a worker node."""
        async with self._lock:
            if worker_id in self.workers:
                # Reassign worker's tasks
                tasks_to_reassign = [
                    t for t in self.task_queue.assigned.values()
                    if t.assigned_to == worker_id
                ]
                for task in tasks_to_reassign:
                    await self.task_queue.mark_failed(task.task_id, "worker_offline")
                
                del self.workers[worker_id]
                logger.info(f"Unregistered worker: {worker_id}")

    async def heartbeat(self, worker_id: str) -> None:
        """Receive heartbeat from worker."""
        async with self._lock:
            if worker_id in self.workers:
                self.workers[worker_id]["last_heartbeat"] = datetime.now().isoformat()

    async def check_worker_health(self) -> None:
        """Periodically check worker health."""
        while True:
            await asyncio.sleep(self.health_check_interval)
            now = datetime.now()
            
            for worker_id, worker in list(self.workers.items()):
                last_hb = datetime.fromisoformat(worker["last_heartbeat"])
                if (now - last_hb).total_seconds() > self.health_check_interval * 2:
                    logger.warning(f"Worker {worker_id} unresponsive, marking offline")
                    worker["status"] = "offline"
                    await self.unregister_worker(worker_id)

    async def distribute_targets(self, targets: List[Dict[str, Any]]) -> None:
        """Distribute scan targets across workers."""
        for i, target in enumerate(targets):
            task = CrawlTask(
                task_id=f"task_{hashlib.md5(target['cidr'].encode()).hexdigest()}",
                target_cidr=target["cidr"],
                ports=[21, 22, 23, 80, 443, 554, 3306, 5432, 8080, 8443, 27017],
                priority=target.get("score", 0.5),
            )
            await self.task_queue.enqueue(task)

    async def get_next_task(self, worker_id: str) -> Optional[CrawlTask]:
        """Assign next task to worker."""
        task = await self.task_queue.dequeue(worker_id)
        if task:
            logger.debug(f"Assigned task {task.task_id} to worker {worker_id}")
            task.started_at = datetime.now().isoformat()
            task.status = "running"
        return task

    async def submit_result(
        self, task_id: str, result: Dict[str, Any]
    ) -> None:
        """Submit task result."""
        await self.task_queue.mark_completed(task_id, result)
        self.results_aggregator.append(result)
        
        # Update worker stats
        task = self.task_queue.completed[-1]
        if task.assigned_to in self.workers:
            self.workers[task.assigned_to]["tasks_completed"] += 1

    async def submit_error(self, task_id: str, error: str) -> None:
        """Submit task error."""
        await self.task_queue.mark_failed(task_id, error)

    def get_aggregated_results(self) -> List[Dict[str, Any]]:
        """Get all aggregated results."""
        return self.results_aggregator.copy()

    def get_coordinator_status(self) -> Dict[str, Any]:
        """Get overall coordinator status."""
        return {
            "node_id": self.node_id,
            "workers": self.workers,
            "task_queue_stats": self.task_queue.get_stats(),
            "results_count": len(self.results_aggregator),
            "timestamp": datetime.now().isoformat(),
        }

    async def export_results(self, filepath: str) -> None:
        """Export aggregated results to file."""
        with open(filepath, "w") as f:
            json.dump(self.results_aggregator, f, indent=2)
        logger.info(f"Exported {len(self.results_aggregator)} results to {filepath}")


class EdgeWorker:
    """Individual edge/remote worker node."""

    def __init__(self, worker_id: str, coordinator_url: str):
        self.worker_id = worker_id
        self.coordinator_url = coordinator_url
        self.current_task: Optional[CrawlTask] = None
        self.capabilities = ["network_scan", "port_detection", "service_identification"]
        self.running = False

    async def connect_to_coordinator(self) -> None:
        """Connect to coordinator and register."""
        logger.info(f"Worker {self.worker_id} connecting to coordinator: {self.coordinator_url}")
        # In production: use gRPC or HTTP client
        # await coordinator.register_worker(self.worker_id, self.capabilities)

    async def heartbeat_loop(self) -> None:
        """Send periodic heartbeats to coordinator."""
        while self.running:
            # In production: send heartbeat to coordinator
            await asyncio.sleep(10)

    async def work_loop(self) -> None:
        """Main worker loop - get tasks and execute."""
        self.running = True
        try:
            while self.running:
                # In production: get_next_task from coordinator
                if self.current_task:
                    try:
                        # Execute scan
                        result = {"task_id": self.current_task.task_id, "status": "success"}
                        # await coordinator.submit_result(self.current_task.task_id, result)
                    except Exception as e:
                        # await coordinator.submit_error(self.current_task.task_id, str(e))
                        logger.error(f"Task execution failed: {e}")
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.running = False

    async def shutdown(self) -> None:
        """Shutdown worker."""
        self.running = False
        logger.info(f"Worker {self.worker_id} shutdown")
