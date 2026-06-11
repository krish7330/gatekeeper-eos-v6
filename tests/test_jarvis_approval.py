"""Tests for approval endpoints (POST /v1/interactions/approve, reject)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from jarvis.queue import ActionQueue
from jarvis.receiver import JarvisReceiver
from jarvis.types import Command


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def queue(tmp_path: Path) -> ActionQueue:
    return ActionQueue(tmp_path / "test_approval.db")


@pytest.fixture
def audit_log(tmp_path: Path) -> MagicMock:
    log = MagicMock()
    log.append.return_value = None
    return log


@pytest.fixture
def receiver(queue: ActionQueue, audit_log: MagicMock) -> JarvisReceiver:
    return JarvisReceiver(
        api_token="test-token",
        queue=queue,
        audit_log=audit_log,
        no_queue=False,
    )


@pytest.fixture
def receiver_no_queue(audit_log: MagicMock) -> JarvisReceiver:
    return JarvisReceiver(
        api_token="test-token",
        audit_log=audit_log,
        no_queue=True,
    )


@pytest.fixture
def pending_command(queue: ActionQueue) -> str:
    """Enqueue a command awaiting approval (always-confirm, gate=None)."""
    cmd = Command(
        target="PC",
        action="RUN_SCRIPT",
        parameter="daily-backup",
        idempotency_key="IDEM-appr00000000000000000000000000a",
        requested_at="2026-06-11T08:00:00Z",
        source="test",
        command_id="CMD-approve-test",
    )
    queue.enqueue(cmd, policy="always-confirm", gate=None)
    return "CMD-approve-test"


valid_headers = {"Authorization": "Bearer test-token"}


# ===========================================================================
# Approve endpoint
# ===========================================================================


class TestApprove:
    def test_approve_pending_command(
        self, receiver: JarvisReceiver, pending_command: str
    ):
        s, h, b = receiver.handle_approve(
            body={"command_id": "CMD-approve-test"},
            headers=valid_headers,
        )
        assert s == 200
        r = json.loads(b)
        assert r["status"] == "approved"
        assert r["command_id"] == "CMD-approve-test"

    def test_approve_updates_queue_status(
        self, queue: ActionQueue, receiver: JarvisReceiver, pending_command: str
    ):
        receiver.handle_approve(
            body={"command_id": "CMD-approve-test"},
            headers=valid_headers,
        )
        entry = queue.get("CMD-approve-test")
        assert entry["gate"] == "approved"
        assert entry["status"] == "queued"

    def test_approve_writes_audit(
        self, receiver: JarvisReceiver, pending_command: str, audit_log: MagicMock
    ):
        receiver.handle_approve(
            body={"command_id": "CMD-approve-test"},
            headers=valid_headers,
        )
        # Should have written APPROVAL_GRANTED event
        approve_events = [
            call for call in audit_log.append.call_args_list
            if call.kwargs.get("event_type") == "APPROVAL_GRANTED"
        ]
        assert len(approve_events) == 1

    def test_approve_allows_dequeue(
        self, queue: ActionQueue, receiver: JarvisReceiver, pending_command: str
    ):
        """After approval, the queue worker should be able to dequeue."""
        receiver.handle_approve(
            body={"command_id": "CMD-approve-test"},
            headers=valid_headers,
        )
        entry = queue.dequeue()
        assert entry is not None
        assert entry["command_id"] == "CMD-approve-test"

    def test_approve_missing_command_id(
        self, receiver: JarvisReceiver
    ):
        s, h, b = receiver.handle_approve(
            body={},
            headers=valid_headers,
        )
        assert s == 400
        r = json.loads(b)
        assert "command_id" in r["error"].lower()

    def test_approve_unknown_command(
        self, receiver: JarvisReceiver
    ):
        s, h, b = receiver.handle_approve(
            body={"command_id": "CMD-nonexistent"},
            headers=valid_headers,
        )
        assert s == 404
        r = json.loads(b)
        assert "not found" in r["error"].lower()

    def test_approve_no_auth(
        self, receiver: JarvisReceiver, pending_command: str
    ):
        s, h, b = receiver.handle_approve(
            body={"command_id": "CMD-approve-test"},
            headers={},
        )
        assert s == 401

    def test_approve_no_queue_mode(self, receiver_no_queue: JarvisReceiver):
        s, h, b = receiver_no_queue.handle_approve(
            body={"command_id": "CMD-test"},
            headers=valid_headers,
        )
        assert s == 400
        r = json.loads(b)
        assert "no-queue" in r["error"].lower()


# ===========================================================================
# Reject endpoint
# ===========================================================================


class TestReject:
    def test_reject_pending_command(
        self, receiver: JarvisReceiver, pending_command: str
    ):
        s, h, b = receiver.handle_reject(
            body={"command_id": "CMD-approve-test", "reason": "Not needed"},
            headers=valid_headers,
        )
        assert s == 200
        r = json.loads(b)
        assert r["status"] == "rejected"
        assert r["command_id"] == "CMD-approve-test"

    def test_reject_updates_queue_status(
        self, queue: ActionQueue, receiver: JarvisReceiver, pending_command: str
    ):
        receiver.handle_reject(
            body={"command_id": "CMD-approve-test", "reason": "Not needed"},
            headers=valid_headers,
        )
        entry = queue.get("CMD-approve-test")
        assert entry["gate"] == "rejected"
        assert entry["status"] == "failed"

    def test_reject_writes_audit(
        self, receiver: JarvisReceiver, pending_command: str, audit_log: MagicMock
    ):
        receiver.handle_reject(
            body={"command_id": "CMD-approve-test", "reason": "User said no"},
            headers=valid_headers,
        )
        reject_events = [
            call for call in audit_log.append.call_args_list
            if call.kwargs.get("event_type") == "APPROVAL_REJECTED"
        ]
        assert len(reject_events) == 1

    def test_reject_prevents_dequeue(
        self, queue: ActionQueue, receiver: JarvisReceiver, pending_command: str
    ):
        """After rejection, the queue worker should NOT dequeue it."""
        receiver.handle_reject(
            body={"command_id": "CMD-approve-test", "reason": "Not needed"},
            headers=valid_headers,
        )
        entry = queue.dequeue()
        assert entry is None  # gate='rejected' prevents dequeue

    def test_reject_default_reason(
        self, receiver: JarvisReceiver, pending_command: str
    ):
        """Should use a default reason when none is provided."""
        s, h, b = receiver.handle_reject(
            body={"command_id": "CMD-approve-test"},
            headers=valid_headers,
        )
        assert s == 200

    def test_reject_missing_command_id(
        self, receiver: JarvisReceiver
    ):
        s, h, b = receiver.handle_reject(
            body={},
            headers=valid_headers,
        )
        assert s == 400

    def test_reject_unknown_command(
        self, receiver: JarvisReceiver
    ):
        s, h, b = receiver.handle_reject(
            body={"command_id": "CMD-nonexistent"},
            headers=valid_headers,
        )
        assert s == 404

    def test_reject_no_auth(
        self, receiver: JarvisReceiver, pending_command: str
    ):
        s, h, b = receiver.handle_reject(
            body={"command_id": "CMD-approve-test"},
            headers={},
        )
        assert s == 401

    def test_reject_no_queue_mode(self, receiver_no_queue: JarvisReceiver):
        s, h, b = receiver_no_queue.handle_reject(
            body={"command_id": "CMD-test"},
            headers=valid_headers,
        )
        assert s == 400
        r = json.loads(b)
        assert "no-queue" in r["error"].lower()


# ===========================================================================
# Integration: full approve → worker pipeline
# ===========================================================================


class TestApprovalIntegration:
    def test_approve_then_worker_processes(
        self, tmp_path: Path
    ):
        from jarvis.audit import AuditLog
        from jarvis.executors import ExecutorRegistry
        from jarvis.worker import QueueWorker

        db_path = tmp_path / "integrate.db"
        audit_dir = tmp_path / "audit"

        queue = ActionQueue(db_path)
        audit = AuditLog(hot_dir=audit_dir)
        registry = ExecutorRegistry()
        registry.register_defaults()

        receiver = JarvisReceiver(
            api_token="int-token",
            queue=queue,
            audit_log=audit,
            no_queue=False,
        )

        worker = QueueWorker(
            queue=queue,
            audit_log=audit,
            executor_registry=registry,
            poll_interval=0.01,
            worker_name="int-worker",
        )

        # Step 1: Submit a command that requires approval
        from jarvis.types import Policy
        cmd = Command(
            target="PC", action="RUN_SCRIPT", parameter="daily-backup",
            idempotency_key="IDEM-int0000000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-int-approve",
        )
        queue.enqueue(cmd, policy=Policy.ALWAYS_CONFIRM.value, gate=None)

        # Step 2: Verify it's pending (not dequeable)
        assert queue.dequeue() is None

        # Step 3: Approve via endpoint
        s, h, b = receiver.handle_approve(
            body={"command_id": "CMD-int-approve"},
            headers={"Authorization": "Bearer int-token"},
        )
        assert s == 200

        # Step 4: Worker dequeues and processes it
        worker.poll_once()

        # Step 5: Verify it succeeded
        final = queue.get("CMD-int-approve")
        assert final["status"] == "succeeded"

        # Step 6: Verify audit chain integrity
        errors = audit.verify_integrity()
        assert errors == [], f"Audit integrity broken: {errors}"
