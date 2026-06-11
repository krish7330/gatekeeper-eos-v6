"""Queue worker daemon for Jarvis v2.1.

Polls the action queue for approved commands, dispatches them to the
appropriate executor adapter, records results, and writes audit events
through every lifecycle step.

Usage::

    from jarvis.worker import QueueWorker

    worker = QueueWorker(poll_interval=1.0)
    worker.run()  # blocks until SIGINT/SIGTERM

Or as a module::

    python -m jarvis.worker
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jarvis.audit import AuditLog
from jarvis.executors import ExecutorRegistry
from jarvis.queue import ActionQueue, CommandNotFoundError
from jarvis.types import AuditEventType, Command

logger = logging.getLogger("jarvis.worker")


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent.parent
DEFAULT_POLL_INTERVAL = 1.0  # seconds


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@dataclass
class WorkerStats:
    """Runtime statistics for the queue worker.

    Attributes:
        total_dequeued: Total commands dequeued since start.
        total_succeeded: Total commands that executed successfully.
        total_failed: Total commands that failed execution.
        total_dead_letter: Total commands that reached dead-letter.
        total_ticks: Total poll cycles completed.
        started_at: ISO-8601 timestamp when the worker started.
    """

    total_dequeued: int = 0
    total_succeeded: int = 0
    total_failed: int = 0
    total_dead_letter: int = 0
    total_ticks: int = 0
    started_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_dequeued": self.total_dequeued,
            "total_succeeded": self.total_succeeded,
            "total_failed": self.total_failed,
            "total_dead_letter": self.total_dead_letter,
            "total_ticks": self.total_ticks,
            "started_at": self.started_at,
            "uptime_seconds": (datetime.now(timezone.utc) - datetime.fromisoformat(self.started_at)).total_seconds()
            if self.started_at else 0,
        }


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class QueueWorker:
    """Poll-loop daemon that processes the action queue.

    On each tick the worker:
    1. Attempts to dequeue the next approved command.
    2. Resolves the appropriate executor for (target, action).
    3. Executes the command.
    4. On success: calls ``queue.succeed()``, writes ``COMMAND_SUCCEEDED`` audit.
    5. On failure: calls ``queue.fail()``, writes ``COMMAND_FAILED`` audit.
       If the command reaches dead-letter, also writes ``COMMAND_DEAD_LETTER``.
    6. Waits ``poll_interval`` seconds before the next tick.

    Graceful shutdown is handled via SIGINT and SIGTERM.
    """

    def __init__(
        self,
        queue: ActionQueue | None = None,
        audit_log: AuditLog | None = None,
        executor_registry: ExecutorRegistry | None = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        worker_name: str = "jarvis-worker",
    ) -> None:
        self._queue = queue or ActionQueue()
        self._audit = audit_log or AuditLog()
        self._registry = executor_registry or ExecutorRegistry()
        self._poll_interval = poll_interval
        self._name = worker_name
        self._running = False
        self._stats = WorkerStats()
        self._last_health_check = 0.0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def stats(self) -> WorkerStats:
        return self._stats

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def name(self) -> str:
        return self._name

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Mark the worker as running and register signal handlers.

        Call ``run()`` after this to enter the main loop.
        """
        self._running = True
        self._stats.started_at = datetime.now(timezone.utc).isoformat()

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        logger.info("Worker '%s' started (poll_interval=%ss)", self._name, self._poll_interval)
        logger.info("Queue DB: %s", self._queue._db_path)
        logger.info("Audit dir: %s", self._audit._hot_dir)

    def stop(self) -> None:
        """Gracefully stop the worker after the current tick completes."""
        if self._running:
            self._running = False
            logger.info(
                "Worker '%s' stopped. Processed %d commands (%d success, %d fail, %d dead-letter) in %d ticks.",
                self._name,
                self._stats.total_dequeued,
                self._stats.total_succeeded,
                self._stats.total_failed,
                self._stats.total_dead_letter,
                self._stats.total_ticks,
            )

    def run(self) -> None:
        """Run the main poll loop. Blocks until ``stop()`` is called
        or a signal is received.

        To use without blocking (e.g. in tests), call ``start()`` then
        ``poll_once()`` in a loop.
        """
        self.start()
        try:
            while self._running:
                self.poll_once()
                time.sleep(self._poll_interval)
        finally:
            self.stop()

    def poll_once(self) -> int:
        """Execute a single poll cycle.

        Dequeues one command (if available), dispatches it, and records
        the result. Returns the number of commands processed (0 or 1).

        This is safe to call from tests — it does not block on the queue.
        """
        self._stats.total_ticks += 1
        command = self._queue.dequeue()
        if command is None:
            return 0

        command_id = command["command_id"]
        target = command["target"]
        action = command["action"]
        parameter = command["parameter"]
        self._stats.total_dequeued += 1

        # Reconstruct a Command object for the executor
        cmd = Command(
            target=target,
            action=action,
            parameter=parameter,
            idempotency_key=command.get("idempotency_key", ""),
            requested_at=command.get("requested_at", ""),
            source=command.get("source", "api"),
            priority=command.get("priority", 5),
            command_id=command_id,
        )

        target_action = f"{target}:{action}"

        # Write COMMAND_DEQUEUED audit
        self._audit.append(
            event_type=AuditEventType.COMMAND_DEQUEUED.value,
            command_id=command_id,
            target_action=target_action,
            status="running",
            detail=f"Dequeued for execution (tick={self._stats.total_ticks})",
        )

        # Resolve executor and execute
        executor = self._registry.resolve(target, action)
        logger.debug("Tick %d: dispatching %s to %s", self._stats.total_ticks, command_id, executor.name)

        # Write COMMAND_EXECUTING audit
        self._audit.append(
            event_type=AuditEventType.COMMAND_EXECUTING.value,
            command_id=command_id,
            target_action=target_action,
            status="running",
            detail=f"Executor={executor.name}",
        )

        try:
            result = executor.execute(cmd)
        except Exception as e:
            # Catastrophic executor failure (e.g. bug in executor itself)
            logger.exception("Executor %s raised unexpected exception for %s", executor.name, command_id)
            try:
                self._queue.fail(command_id, error=f"Executor error: {e}")
            except CommandNotFoundError:
                pass
            self._stats.total_failed += 1
            self._audit.append(
                event_type=AuditEventType.COMMAND_FAILED.value,
                command_id=command_id,
                target_action=target_action,
                status="failed",
                detail=f"Executor exception: {e}",
            )
            return 1

        if result.success:
            self._handle_success(command_id, target_action, result)
        else:
            self._handle_failure(command_id, target_action, result)

        return 1

    # ------------------------------------------------------------------
    # Result handlers
    # ------------------------------------------------------------------

    def _handle_success(
        self,
        command_id: str,
        _target_action: str,
        result: Any,
    ) -> None:
        """Handle a successful execution result."""
        self._stats.total_succeeded += 1

        # Compute a simple result hash from the result dict
        result_hash = hashlib.sha256(
            json.dumps(result.result or {}, sort_keys=True).encode()
        ).hexdigest()[:16]

        try:
            entry = self._queue.succeed(command_id, result_hash=result_hash)
        except CommandNotFoundError:
            logger.warning("Command %s not found during succeed", command_id)
            return

        target_action = f"{entry['target']}:{entry['action']}"
        self._audit.append(
            event_type=AuditEventType.COMMAND_SUCCEEDED.value,
            command_id=command_id,
            target_action=target_action,
            status="succeeded",
            detail=f"result_hash={result_hash}",
        )
        logger.info("SUCCEEDED %s (%s)", command_id, target_action)

    def _handle_failure(
        self,
        command_id: str,
        target_action: str,
        result: Any,
    ) -> None:
        """Handle a failed execution result."""
        error_msg = result.error or "Unknown error"

        try:
            entry = self._queue.fail(command_id, error=error_msg)
        except CommandNotFoundError:
            logger.warning("Command %s not found during fail", command_id)
            return

        target_action = f"{entry['target']}:{entry['action']}"
        new_status = entry["status"]

        self._audit.append(
            event_type=AuditEventType.COMMAND_FAILED.value,
            command_id=command_id,
            target_action=target_action,
            status=new_status,
            detail=f"error={error_msg}",
        )

        if new_status == "dead_letter":
            self._stats.total_dead_letter += 1
            self._audit.append(
                event_type=AuditEventType.COMMAND_DEAD_LETTER.value,
                command_id=command_id,
                target_action=target_action,
                status="dead_letter",
                detail=f"Max retries exhausted. Last error: {error_msg}",
            )
            logger.warning("DEAD_LETTER %s (%s) — %s", command_id, target_action, error_msg)
        else:
            self._stats.total_failed += 1
            logger.warning("FAILED %s (%s) — %s (retry #%d)",
                           command_id, target_action, error_msg, entry["retry_count"])

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        signal_name = signal.Signals(signum).name
        logger.info("Received %s — shutting down gracefully...", signal_name)
        self._running = False
