"""Tests for jarvis.queue: SQLite-backed action queue."""

import json
from pathlib import Path

import pytest

from jarvis.queue import (
    ActionQueue,
    QueueError,
    CommandNotFoundError,
    DuplicateIdempotencyKeyError,
)
from jarvis.types import Command


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test_queue.db"


@pytest.fixture
def queue(db_path: Path) -> ActionQueue:
    return ActionQueue(db_path)


@pytest.fixture
def sample_command() -> Command:
    return Command(
        target="PC",
        action="OPEN_URL",
        parameter="https://example.com",
        idempotency_key="IDEM-aaaa0000000000000000000000000000",
        requested_at="2026-06-11T08:00:00Z",
        source="web_ui",
        priority=5,
        command_id="CMD-test-a1b2c3d4",
    )


# ===========================================================================
# Enqueue
# ===========================================================================


class TestEnqueue:
    def test_enqueue_returns_entry(self, queue: ActionQueue, sample_command: Command):
        entry = queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        assert entry["command_id"] == "CMD-test-a1b2c3d4"
        assert entry["target"] == "PC"
        assert entry["action"] == "OPEN_URL"
        assert entry["status"] == "queued"
        assert entry["policy"] == "auto-approve"
        assert entry["gate"] == "approved"

    def test_enqueue_auto_generates_id(self, queue: ActionQueue):
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://example.com",
            idempotency_key="IDEM-bbbb0000000000000000000000000000",
            requested_at="2026-06-11T08:00:00Z",
        )
        entry = queue.enqueue(cmd, policy="auto-approve", gate="approved")
        assert entry["command_id"].startswith("CMD-")
        assert len(entry["command_id"]) == 16  # CMD- + 12 hex chars

    def test_duplicate_idempotency_key_raises(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        with pytest.raises(DuplicateIdempotencyKeyError):
            queue.enqueue(sample_command, policy="auto-approve", gate="approved")

    def test_duplicate_idempotency_returns_existing_status(self, queue: ActionQueue, sample_command: Command):
        """The duplicate error message should reference the existing command."""
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        try:
            queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        except DuplicateIdempotencyKeyError as e:
            assert "CMD-test-a1b2c3d4" in str(e)
            assert "queued" in str(e)

    def test_enqueue_different_keys_succeeds(self, queue: ActionQueue):
        for i in range(3):
            cmd = Command(
                target="PC", action="OPEN_URL", parameter=f"https://example.com/{i}",
                idempotency_key=f"IDEM-cccc{i:031d}",
                requested_at="2026-06-11T08:00:00Z",
                command_id=f"CMD-multi-{i:04d}",
            )
            entry = queue.enqueue(cmd, policy="auto-approve", gate="approved")
            assert entry["command_id"] == f"CMD-multi-{i:04d}"

    def test_enqueue_stores_all_fields(self, queue: ActionQueue, sample_command: Command):
        entry = queue.enqueue(sample_command, policy="always-confirm", gate=None)
        assert entry["source"] == sample_command.source
        assert entry["priority"] == sample_command.priority
        assert entry["requested_at"] == sample_command.requested_at
        assert entry["policy"] == "always-confirm"
        assert entry["gate"] is None
        assert entry["retry_count"] == 0
        assert entry["max_retries"] == 3


# ===========================================================================
# Dequeue
# ===========================================================================


class TestDequeue:
    def test_dequeue_returns_approved_queued(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        entry = queue.dequeue()
        assert entry is not None
        assert entry["command_id"] == "CMD-test-a1b2c3d4"
        assert entry["status"] == "running"
        assert entry["started_at"] is not None

    def test_dequeue_skips_non_approved(self, queue: ActionQueue, sample_command: Command):
        """Commands without gate='approved' should not be dequeued."""
        queue.enqueue(sample_command, policy="always-confirm", gate=None)
        entry = queue.dequeue()
        assert entry is None

    def test_dequeue_with_target_filter(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        # Should find PC command
        entry = queue.dequeue(target="PC")
        assert entry is not None
        # Should not find HOME command
        entry = queue.dequeue(target="HOME")
        assert entry is None

    def test_dequeue_priority_order(self, queue: ActionQueue):
        """Higher priority commands should be dequeued first."""
        high = Command(
            target="PC", action="OPEN_URL", parameter="https://high.com",
            idempotency_key="IDEM-high00000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            priority=10, command_id="CMD-high",
        )
        low = Command(
            target="PC", action="OPEN_URL", parameter="https://low.com",
            idempotency_key="IDEM-low000000000000000000000000002",
            requested_at="2026-06-11T08:00:00Z",
            priority=1, command_id="CMD-low",
        )
        queue.enqueue(low, policy="auto-approve", gate="approved")
        queue.enqueue(high, policy="auto-approve", gate="approved")

        first = queue.dequeue()
        assert first["command_id"] == "CMD-high"

    def test_dequeue_empty_returns_none(self, queue: ActionQueue):
        entry = queue.dequeue()
        assert entry is None

    def test_dequeue_fifo_within_priority(self, queue: ActionQueue):
        """Same priority commands should be dequeued FIFO."""
        for i in range(3):
            cmd = Command(
                target="PC", action="OPEN_URL", parameter=f"https://fifo.com/{i}",
                idempotency_key=f"IDEM-fifo{i:028d}000",
                requested_at="2026-06-11T08:00:00Z",
                priority=5, command_id=f"CMD-fifo-{i:04d}",
            )
            queue.enqueue(cmd, policy="auto-approve", gate="approved")

        for expected_id in ["CMD-fifo-0000", "CMD-fifo-0001", "CMD-fifo-0002"]:
            entry = queue.dequeue()
            assert entry["command_id"] == expected_id


# ===========================================================================
# Status transitions
# ===========================================================================


class TestSucceed:
    def test_succeed_updates_status(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        entry = queue.succeed("CMD-test-a1b2c3d4", result_hash="abc123")
        assert entry["status"] == "succeeded"
        assert entry["result_hash"] == "abc123"
        assert entry["completed_at"] is not None

    def test_succeed_unknown_raises(self, queue: ActionQueue):
        with pytest.raises(CommandNotFoundError):
            queue.succeed("CMD-nonexistent")


class TestFail:
    def test_fail_retries_when_below_max(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        entry = queue.fail("CMD-test-a1b2c3d4", error="connection timeout")
        assert entry["status"] == "queued"  # back for retry
        assert entry["retry_count"] == 1
        assert entry["error"] == "connection timeout"

    def test_fail_dead_letter_when_max_reached(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved", max_retries=2)
        # First fail → retry
        queue.fail("CMD-test-a1b2c3d4", error="attempt 1")
        # Second fail → dead_letter
        entry = queue.fail("CMD-test-a1b2c3d4", error="attempt 2")
        assert entry["status"] == "dead_letter"
        assert entry["retry_count"] == 2

    def test_fail_unknown_raises(self, queue: ActionQueue):
        with pytest.raises(CommandNotFoundError):
            queue.fail("CMD-nonexistent")


class TestReject:
    def test_reject_records_reason(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="always-confirm", gate=None)
        entry = queue.reject("CMD-test-a1b2c3d4", reason="user declined")
        assert entry["status"] in ("failed", "dead_letter")
        assert "rejected" in entry["error"]
        assert "user declined" in entry["error"]

    def test_reject_sets_gate_rejected(self, queue: ActionQueue, sample_command: Command):
        """Reject should update the gate field to 'rejected' for audit consistency."""
        queue.enqueue(sample_command, policy="always-confirm", gate=None)
        queue.reject("CMD-test-a1b2c3d4", reason="user declined")
        entry = queue.get("CMD-test-a1b2c3d4")
        assert entry["gate"] == "rejected"


class TestApprove:
    def test_approve_sets_gate_and_queues(self, queue: ActionQueue, sample_command: Command):
        """approve() should set gate='approved' and status='queued' for queue worker pickup."""
        queue.enqueue(sample_command, policy="always-confirm", gate=None)
        entry = queue.approve("CMD-test-a1b2c3d4")
        assert entry["gate"] == "approved"
        assert entry["status"] == "queued"

    def test_approved_command_can_be_dequeued(self, queue: ActionQueue, sample_command: Command):
        """After approve(), the command should be pickable by the queue worker."""
        queue.enqueue(sample_command, policy="always-confirm", gate=None)
        queue.approve("CMD-test-a1b2c3d4")
        entry = queue.dequeue()
        assert entry is not None
        assert entry["command_id"] == "CMD-test-a1b2c3d4"

    def test_approve_unknown_raises(self, queue: ActionQueue):
        with pytest.raises(CommandNotFoundError):
            queue.approve("CMD-nonexistent")


class TestRetry:
    def test_retry_dead_letter(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved", max_retries=1)
        queue.fail("CMD-test-a1b2c3d4", error="failed")  # goes to dead_letter
        entry = queue.retry("CMD-test-a1b2c3d4")
        assert entry["status"] == "queued"
        assert entry["retry_count"] == 0
        assert entry["error"] is None

    def test_retry_raises_if_not_dead_letter(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        with pytest.raises(QueueError, match="not.*dead_letter"):
            queue.retry("CMD-test-a1b2c3d4")

    def test_retry_unknown_raises(self, queue: ActionQueue):
        with pytest.raises(CommandNotFoundError):
            queue.retry("CMD-nonexistent")


# ===========================================================================
# Lookups
# ===========================================================================


class TestLookups:
    def test_get_returns_entry(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        entry = queue.get("CMD-test-a1b2c3d4")
        assert entry["command_id"] == "CMD-test-a1b2c3d4"

    def test_get_unknown_raises(self, queue: ActionQueue):
        with pytest.raises(CommandNotFoundError):
            queue.get("CMD-nonexistent")

    def test_get_by_idempotency_key_found(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        entry = queue.get_by_idempotency_key("IDEM-aaaa0000000000000000000000000000")
        assert entry is not None
        assert entry["command_id"] == "CMD-test-a1b2c3d4"

    def test_get_by_idempotency_key_not_found(self, queue: ActionQueue):
        entry = queue.get_by_idempotency_key("IDEM-nonexistent")
        assert entry is None

    def test_list_by_status(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        entries = queue.list_by_status("queued")
        assert len(entries) >= 1
        assert entries[0]["command_id"] == "CMD-test-a1b2c3d4"

    def test_list_by_status_empty(self, queue: ActionQueue):
        entries = queue.list_by_status("running")
        assert entries == []

    def test_list_all(self, queue: ActionQueue):
        for i in range(3):
            cmd = Command(
                target="PC", action="OPEN_URL", parameter=f"https://list.com/{i}",
                idempotency_key=f"IDEM-list{i:028d}000",
                requested_at="2026-06-11T08:00:00Z",
                command_id=f"CMD-list-{i:04d}",
            )
            queue.enqueue(cmd, policy="auto-approve", gate="approved")
        entries = queue.list_all(limit=10)
        assert len(entries) == 3

    def test_count_by_status(self, queue: ActionQueue):
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://count.com",
            idempotency_key="IDEM-count00000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-count",
        )
        queue.enqueue(cmd, policy="auto-approve", gate="approved")
        counts = queue.count_by_status()
        assert counts["queued"] == 1
        assert counts["running"] == 0
        assert counts["succeeded"] == 0

    def test_count_pending(self, queue: ActionQueue):
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://pending.com",
            idempotency_key="IDEM-pending00000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-pending",
        )
        queue.enqueue(cmd, policy="auto-approve", gate="approved")
        assert queue.count_pending() == 1


# ===========================================================================
# Maintenance
# ===========================================================================


class TestMaintenance:
    def test_flush_removes_entry(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        queue.flush("CMD-test-a1b2c3d4")
        with pytest.raises(CommandNotFoundError):
            queue.get("CMD-test-a1b2c3d4")

    def test_clear_removes_completed_and_dead(self, queue: ActionQueue):
        # Add and complete a command
        cmd1 = Command(
            target="PC", action="OPEN_URL", parameter="https://clear.com",
            idempotency_key="IDEM-clear100000000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-clear-1",
        )
        queue.enqueue(cmd1, policy="auto-approve", gate="approved")
        queue.succeed("CMD-clear-1")

        # Add a running command (should NOT be removed)
        cmd2 = Command(
            target="PC", action="OPEN_URL", parameter="https://clear.com/2",
            idempotency_key="IDEM-clear200000000000000000000000002",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-clear-2",
        )
        queue.enqueue(cmd2, policy="auto-approve", gate="approved")

        removed = queue.clear()
        assert removed >= 1
        # cmd2 should still exist
        entry = queue.get("CMD-clear-2")
        assert entry["status"] == "queued"

    def test_clear_all_removes_everything(self, queue: ActionQueue, sample_command: Command):
        queue.enqueue(sample_command, policy="auto-approve", gate="approved")
        removed = queue.clear_all()
        assert removed >= 1
        assert queue.count_pending() == 0

    def test_vacuum(self, queue: ActionQueue):
        """vacuum should run without error."""
        queue.enqueue(
            Command(
                target="PC", action="OPEN_URL", parameter="https://vacuum.com",
                idempotency_key="IDEM-vacuum000000000000000000000001",
                requested_at="2026-06-11T08:00:00Z",
            ),
            policy="auto-approve", gate="approved",
        )
        queue.vacuum()  # should not raise


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_multiple_queues_independent(self, tmp_path: Path):
        """Two queues with different DBs should be independent."""
        db1 = tmp_path / "q1.db"
        db2 = tmp_path / "q2.db"
        q1 = ActionQueue(db1)
        q2 = ActionQueue(db2)

        q1.enqueue(
            Command(
                target="PC", action="OPEN_URL", parameter="https://q1.com",
                idempotency_key="IDEM-qqq1000000000000000000000000001",
                requested_at="2026-06-11T08:00:00Z",
                command_id="CMD-q1",
            ),
            policy="auto-approve", gate="approved",
        )
        # q2 should be empty
        assert q2.dequeue() is None
        q1.close()
        q2.close()

    def test_reopening_persists(self, db_path: Path):
        """Data should persist across queue instances."""
        q1 = ActionQueue(db_path)
        q1.enqueue(
            Command(
                target="PC", action="OPEN_URL", parameter="https://persist.com",
                idempotency_key="IDEM-persist00000000000000000000001",
                requested_at="2026-06-11T08:00:00Z",
                command_id="CMD-persist",
            ),
            policy="auto-approve", gate="approved",
        )
        q1.close()

        q2 = ActionQueue(db_path)
        entry = q2.get("CMD-persist")
        assert entry["target"] == "PC"
        q2.close()

    def test_unicode_parameter(self, queue: ActionQueue):
        cmd = Command(
            target="HOME", action="SET_SCENE", parameter="リビング",
            idempotency_key="IDEM-unicode00000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-unicode",
        )
        entry = queue.enqueue(cmd, policy="auto-approve", gate="approved")
        assert entry["parameter"] == "リビング"

    def test_special_chars_in_parameter(self, queue: ActionQueue):
        cmd = Command(
            target="PC", action="RUN_SCRIPT", parameter="hello; world | test",
            idempotency_key="IDEM-special00000000000000000000001",
            requested_at="2026-06-11T08:00:00Z",
            command_id="CMD-special",
        )
        entry = queue.enqueue(cmd, policy="always-confirm", gate=None)
        assert entry["parameter"] == "hello; world | test"
