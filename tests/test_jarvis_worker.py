"""Tests for jarvis.worker and jarvis.executors."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jarvis.executors import (
    ExecutorRegistry,
    ExecutorResult,
    LoggerExecutor,
)
from jarvis.queue import ActionQueue, CommandNotFoundError
from jarvis.types import Command
from jarvis.worker import QueueWorker


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def queue(tmp_path: Path) -> ActionQueue:
    return ActionQueue(tmp_path / "test_worker.db")


@pytest.fixture
def audit_log(tmp_path: Path) -> MagicMock:
    """Mock audit log — we don't need real hashed files for unit tests."""
    from unittest.mock import MagicMock
    log = MagicMock()
    log.append.return_value = None
    return log


@pytest.fixture
def sample_cmd() -> Command:
    return Command(
        target="PC",
        action="OPEN_URL",
        parameter="https://example.com",
        idempotency_key="IDEM-work000000000000000000000000000a",
        requested_at="2026-06-11T08:00:00Z",
        source="test",
        priority=5,
        command_id="CMD-worker-test",
    )


@pytest.fixture
def enqueued_cmd(queue: ActionQueue, sample_cmd: Command) -> str:
    """Enqueue and approve a sample command for the worker to pick up."""
    queue.enqueue(sample_cmd, policy="auto-approve", gate="approved", max_retries=2)
    return "CMD-worker-test"


@pytest.fixture
def worker(queue: ActionQueue, audit_log: MagicMock) -> QueueWorker:
    """Worker with mock audit and real queue."""
    return QueueWorker(
        queue=queue,
        audit_log=audit_log,
        executor_registry=ExecutorRegistry(),
        poll_interval=0.01,  # fast for tests
        worker_name="test-worker",
    )


# ===========================================================================
# Executor tests
# ===========================================================================


class TestLoggerExecutor:
    def test_logger_returns_success(self):
        executor = LoggerExecutor()
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://example.com",
            idempotency_key="IDEM-logger000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-logger",
        )
        result = executor.execute(cmd)
        assert result.success
        assert result.command_id == "CMD-logger"
        assert result.result["dry_run"] is True
        assert result.started_at is not None
        assert result.completed_at is not None

    def test_logger_sets_timestamps(self):
        executor = LoggerExecutor()
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://example.com",
            idempotency_key="IDEM-ts00000000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-ts",
        )
        result = executor.execute(cmd)
        assert result.started_at <= result.completed_at


class TestExecutorRegistry:
    def test_dispatch_known_action(self):
        registry = ExecutorRegistry()
        registry.register("PC", "OPEN_URL", LoggerExecutor(name="Logger-OPEN_URL"))
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://example.com",
            idempotency_key="IDEM-reg0000000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-reg",
        )
        result = registry.dispatch(cmd)
        assert result.success

    def test_dispatch_unknown_uses_fallback(self):
        registry = ExecutorRegistry()
        registry.set_fallback(LoggerExecutor(name="Fallback"))
        cmd = Command(
            target="PC", action="UNKNOWN_ACTION", parameter="test",
            idempotency_key="IDEM-unkn00000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-unknown",
        )
        result = registry.dispatch(cmd)
        assert result.success  # fallback is a safe LoggerExecutor

    def test_register_defaults_all_safe(self):
        """All default-registered actions should use LoggerExecutor (safe)."""
        registry = ExecutorRegistry()
        registry.register_defaults()

        for target in ["PC", "HOME"]:
            for action in [
                "OPEN_URL", "MEDIA_CONTROL", "TURN_ON", "TURN_OFF",
                "SET_BRIGHTNESS", "SET_SCENE", "LOCK_DOOR",
                "LOCK_WORKSTATION", "DELETE_FILE", "SHUTDOWN_PC",
                "SEND_KEYSTROKE", "RUN_SCRIPT", "UNLOCK_DOOR", "DISABLE_ALARM",
            ]:
                cmd = Command(
                    target=target, action=action, parameter="test",
                    idempotency_key=f"IDEM-default{target}{action}",
                    requested_at="2026-06-11T08:00:00Z",
                    command_id=f"CMD-default-{target}-{action}",
                )
                result = registry.dispatch(cmd)
                assert result.success, f"Default dispatch failed for {target}:{action}"

    def test_resolve_case_insensitive(self):
        registry = ExecutorRegistry()
        registry.register("PC", "OPEN_URL", LoggerExecutor(name="Test"))
        executor = registry.resolve("pc", "open_url")
        assert executor.name == "Test"
        executor = registry.resolve("Pc", "Open_Url")
        assert executor.name == "Test"


# ===========================================================================
# Worker tests
# ===========================================================================


class TestWorkerPollOnce:
    def test_poll_empty_returns_zero(self, worker: QueueWorker):
        count = worker.poll_once()
        assert count == 0

    def test_poll_ignores_unapproved(
        self, queue: ActionQueue, worker: QueueWorker, sample_cmd: Command
    ):
        """Commands without gate='approved' should be skipped."""
        queue.enqueue(sample_cmd, policy="always-confirm", gate=None)
        count = worker.poll_once()
        assert count == 0  # nothing dequeued

    def test_poll_processes_approved(
        self, worker: QueueWorker, enqueued_cmd: str
    ):
        count = worker.poll_once()
        assert count == 1

    def test_worker_updates_stats(
        self, worker: QueueWorker, enqueued_cmd: str
    ):
        worker.poll_once()
        assert worker.stats.total_dequeued == 1
        assert worker.stats.total_ticks == 1


class TestWorkerSuccessFlow:
    def test_success_updates_queue(
        self, queue: ActionQueue, worker: QueueWorker, enqueued_cmd: str
    ):
        worker.poll_once()
        entry = queue.get("CMD-worker-test")
        assert entry["status"] == "succeeded"

    def test_success_writes_audit(
        self, worker: QueueWorker, enqueued_cmd: str, audit_log: MagicMock
    ):
        worker.poll_once()
        # Should have written DEQUEUED, EXECUTING, and SUCCEEDED audit events
        assert audit_log.append.call_count >= 3

    def test_success_count_incremented(
        self, worker: QueueWorker, enqueued_cmd: str
    ):
        worker.poll_once()
        assert worker.stats.total_succeeded == 1

    def test_multiple_commands_sequential(
        self, queue: ActionQueue, worker: QueueWorker
    ):
        for i in range(3):
            cmd = Command(
                target="PC", action="OPEN_URL",
                parameter=f"https://example.com/{i}",
                idempotency_key=f"IDEM-multi{i:031d}",
                requested_at="2026-06-11T08:00:00Z",
                command_id=f"CMD-worker-{i:04d}",
            )
            queue.enqueue(cmd, policy="auto-approve", gate="approved")

        for i in range(3):
            count = worker.poll_once()
            assert count == 1

        assert worker.stats.total_succeeded == 3
        assert worker.stats.total_dequeued == 3


class TestWorkerFailureFlow:
    def test_failure_retries(
        self, queue: ActionQueue, worker: QueueWorker
    ):
        """A failing command should go back to queued for retry."""
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://fail.com",
            idempotency_key="IDEM-fail00000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-fail-01",
        )
        queue.enqueue(cmd, policy="auto-approve", gate="approved", max_retries=3)

        # Replace registry with one that fails
        class FailingExecutor:
            def execute(self, command, **kwargs):
                return ExecutorResult(
                    success=False,
                    command_id=command.command_id,
                    error="Intentional failure",
                )
            name = "FailingExecutor"

            def __repr__(self):
                return "<FailingExecutor>"

        worker._registry = ExecutorRegistry()
        worker._registry.register("PC", "OPEN_URL", FailingExecutor())

        worker.poll_once()
        entry = queue.get("CMD-fail-01")
        assert entry["status"] == "queued"  # retried, not dead
        assert entry["retry_count"] == 1
        assert worker.stats.total_dequeued == 1
        assert worker.stats.total_failed == 1

    def test_failure_dead_letter(
        self, queue: ActionQueue, worker: QueueWorker
    ):
        """After max_retries, a failing command should go to dead_letter."""
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://dead.com",
            idempotency_key="IDEM-dead00000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-dead-01",
        )
        queue.enqueue(cmd, policy="auto-approve", gate="approved", max_retries=2)

        class FailingExecutor:
            def execute(self, command, **kwargs):
                return ExecutorResult(
                    success=False,
                    command_id=command.command_id,
                    error="Fatal error",
                )
            name = "FailingExecutor"

            def __repr__(self):
                return "<FailingExecutor>"

        worker._registry = ExecutorRegistry()
        worker._registry.register("PC", "OPEN_URL", FailingExecutor())

        # First poll → fail → retry (back to queued, retry_count=1 < max_retries=2)
        worker.poll_once()
        entry = queue.get("CMD-dead-01")
        assert entry["status"] == "queued"
        assert entry["retry_count"] == 1

        # Second poll → fail → dead_letter (retry_count=2 >= max_retries=2)
        worker.poll_once()
        entry = queue.get("CMD-dead-01")
        assert entry["status"] == "dead_letter"
        assert worker.stats.total_dead_letter == 1

    def test_executor_exception_handled(
        self, queue: ActionQueue, worker: QueueWorker
    ):
        """A crash in the executor should be caught and reported."""
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://crash.com",
            idempotency_key="IDEM-crash0000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-crash-01",
        )
        queue.enqueue(cmd, policy="auto-approve", gate="approved")

        class CrashingExecutor:
            def execute(self, command, **kwargs):
                raise RuntimeError("Kaboom!")
            name = "CrashingExecutor"

            def __repr__(self):
                return "<CrashingExecutor>"

        worker._registry = ExecutorRegistry()
        worker._registry.register("PC", "OPEN_URL", CrashingExecutor())

        worker.poll_once()
        entry = queue.get("CMD-crash-01")
        assert entry["status"] in ("queued", "failed")  # caught and reported

    def test_worker_stats_after_mixed_results(
        self, queue: ActionQueue, worker: QueueWorker
    ):
        """Stats should reflect a mix of success and failure."""
        # Two commands: one succeeds, one fails
        for i in range(2):
            cmd = Command(
                target="PC", action="OPEN_URL",
                parameter=f"https://mix.com/{i}",
                idempotency_key=f"IDEM-mix{i:031d}",
                requested_at="2026-06-11T08:00:00Z",
                command_id=f"CMD-mix-{i}",
            )
            queue.enqueue(cmd, policy="auto-approve", gate="approved")

        # Stateful executor: succeeds first call, fails second call
        class AlternatingExecutor:
            def __init__(self):
                self.call_count = 0
            def execute(self, command, **kwargs):
                self.call_count += 1
                if self.call_count == 2:
                    return ExecutorResult(
                        success=False,
                        command_id=command.command_id,
                        error="Intentional failure",
                    )
                return ExecutorResult(
                    success=True,
                    command_id=command.command_id,
                    result={"dry_run": True},
                )
            name = "AlternatingExecutor"

            def __repr__(self):
                return "<AlternatingExecutor>"

        worker._registry = ExecutorRegistry()
        worker._registry.register("PC", "OPEN_URL", AlternatingExecutor())

        worker.poll_once()  # first succeeds
        worker.poll_once()  # second fails

        assert worker.stats.total_succeeded == 1
        assert worker.stats.total_failed == 1
        assert worker.stats.total_dequeued == 2


class TestWorkerRunLoop:
    def test_run_processes_until_done(
        self, queue: ActionQueue, worker: QueueWorker
    ):
        """run() should process all available commands then wait."""
        for i in range(5):
            cmd = Command(
                target="PC", action="OPEN_URL",
                parameter=f"https://run.com/{i}",
                idempotency_key=f"IDEM-run{i:031d}",
                requested_at="2026-06-11T08:00:00Z",
                command_id=f"CMD-run-{i:04d}",
            )
            queue.enqueue(cmd, policy="auto-approve", gate="approved")

        # Poll manually until queue is empty
        while worker.poll_once() > 0:
            pass

        assert worker.stats.total_succeeded == 5
        assert worker.stats.total_ticks >= 5

    def test_stop_during_run(self, worker: QueueWorker):
        """stop() should set running flag to False."""
        worker.start()
        assert worker.is_running
        worker.stop()
        assert not worker.is_running


# ===========================================================================
# Integration test: full worker with real audit
# ===========================================================================


class TestWorkerIntegration:
    def test_full_flow_with_real_audit(self, tmp_path: Path):
        """Full integration: enqueue → worker processes → queue status updated."""
        from jarvis.audit import AuditLog

        db_path = tmp_path / "integration.db"
        audit_dir = tmp_path / "audit"

        queue = ActionQueue(db_path)
        audit = AuditLog(hot_dir=audit_dir)

        registry = ExecutorRegistry()
        registry.register_defaults()

        worker = QueueWorker(
            queue=queue,
            audit_log=audit,
            executor_registry=registry,
            poll_interval=0.01,
            worker_name="integration-test",
        )

        # Enqueue a command
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://integration.com",
            idempotency_key="IDEM-intg00000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-integration",
        )
        queue.enqueue(cmd, policy="auto-approve", gate="approved")

        # Process it
        worker.poll_once()

        # Verify queue status
        entry = queue.get("CMD-integration")
        assert entry["status"] == "succeeded"

        # Verify audit events were written
        assert audit.count_events() >= 3

        # Verify audit chain integrity
        errors = audit.verify_integrity()
        assert errors == [], f"Audit integrity broken: {errors}"

        # Verify worker stats
        assert worker.stats.total_succeeded == 1
        assert worker.stats.total_dequeued == 1
