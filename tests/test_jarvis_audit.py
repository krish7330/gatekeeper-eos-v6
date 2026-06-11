"""Tests for jarvis.audit: append-only hash-chained audit log."""

import json
from pathlib import Path

import pytest

from jarvis.audit import (
    AuditLog,
    AuditError,
    AuditIntegrityError,
    audit_append,
    audit_get_trace,
)
from jarvis.types import AuditEvent, AuditEventType


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def log_dir(tmp_path: Path) -> Path:
    """Temporary directory for audit log files."""
    d = tmp_path / "audit_logs"
    d.mkdir()
    return d


@pytest.fixture
def audit_log(log_dir: Path) -> AuditLog:
    return AuditLog(hot_dir=log_dir)


# ===========================================================================
# Basic append
# ===========================================================================


class TestAppend:
    def test_append_returns_event(self, audit_log: AuditLog):
        event = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-a1b2c3d4",
            target_action="HOME:TURN_ON",
            status="queued",
            detail="source=voice",
        )
        assert isinstance(event, AuditEvent)
        assert event.event_type == "COMMAND_SUBMITTED"
        assert event.command_id == "CMD-a1b2c3d4"
        assert event.target_action == "HOME:TURN_ON"
        assert event.status == "queued"
        assert event.detail == "source=voice"

    def test_append_creates_log_file(self, audit_log: AuditLog, log_dir: Path):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        log_files = list(log_dir.glob("audit_*.jsonl"))
        assert len(log_files) == 1
        assert log_files[0].exists()

    def test_append_includes_hash(self, audit_log: AuditLog):
        event = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        assert len(event.hash) == 64  # SHA-256 hex
        assert event.hash != event.prev_hash

    def test_first_entry_has_zero_prev_hash(self, audit_log: AuditLog):
        event = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-first",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        assert event.prev_hash == "0" * 64

    def test_second_entry_links_to_first(self, audit_log: AuditLog):
        e1 = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        e2 = audit_log.append(
            event_type="COMMAND_QUEUED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="approved",
        )
        assert e2.prev_hash == e1.hash


# ===========================================================================
# Append with enum
# ===========================================================================


class TestAppendEvent:
    def test_append_with_enum(self, audit_log: AuditLog):
        event = audit_log.append_event(
            event_type=AuditEventType.COMMAND_SUBMITTED,
            command_id="CMD-test",
            target_action="HOME:TURN_OFF",
            status="queued",
        )
        assert event.event_type == "COMMAND_SUBMITTED"
        assert isinstance(event, AuditEvent)


# ===========================================================================
# Reading
# ===========================================================================


class TestRead:
    def test_empty_log_returns_empty_tail(self, audit_log: AuditLog):
        entries = audit_log.tail(10)
        assert entries == []

    def test_tail_returns_n_entries(self, audit_log: AuditLog):
        for i in range(5):
            audit_log.append(
                event_type="COMMAND_SUBMITTED",
                command_id=f"CMD-{i}",
                target_action="PC:OPEN_URL",
                status="queued",
            )
        entries = audit_log.tail(3)
        assert len(entries) == 3

    def test_tail_returns_newest_first(self, audit_log: AuditLog):
        for i in range(3):
            audit_log.append(
                event_type="COMMAND_SUBMITTED",
                command_id=f"CMD-{i}",
                target_action="PC:OPEN_URL",
                status="queued",
            )
        entries = audit_log.tail(3)
        # Most recent command should be first
        assert entries[0].command_id == "CMD-2"

    def test_tail_less_than_total(self, audit_log: AuditLog):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-0",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        entries = audit_log.tail(100)
        assert len(entries) == 1

    def test_get_trace_returns_all_for_command(self, audit_log: AuditLog):
        # Mix of events for different commands
        for i in range(3):
            audit_log.append(
                event_type="COMMAND_SUBMITTED",
                command_id=f"CMD-{i}",
                target_action="PC:OPEN_URL",
                status="queued",
            )
        # One more for CMD-1
        audit_log.append(
            event_type="COMMAND_QUEUED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        trace = audit_log.get_trace("CMD-1")
        assert len(trace) == 2
        assert all(e.command_id == "CMD-1" for e in trace)

    def test_get_trace_empty_for_unknown(self, audit_log: AuditLog):
        trace = audit_log.get_trace("CMD-nonexistent")
        assert trace == []

    def test_get_by_event_type(self, audit_log: AuditLog):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        audit_log.append(
            event_type="COMMAND_FAILED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="failed",
        )
        failed = audit_log.get_by_event_type("COMMAND_FAILED")
        assert len(failed) == 1
        assert failed[0].command_id == "CMD-1"


# ===========================================================================
# Integrity
# ===========================================================================


class TestIntegrity:
    def test_verify_clean_log(self, audit_log: AuditLog):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        errors = audit_log.verify_integrity()
        assert errors == []

    def test_verify_multi_entry_log(self, audit_log: AuditLog):
        for i in range(5):
            audit_log.append(
                event_type="COMMAND_SUBMITTED",
                command_id=f"CMD-{i}",
                target_action="PC:OPEN_URL",
                status="queued",
            )
        errors = audit_log.verify_integrity()
        assert errors == []

    def test_assert_integrity_passes(self, audit_log: AuditLog):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        audit_log.assert_integrity()  # should not raise

    def test_tampered_hash_detected(self, audit_log: AuditLog, log_dir: Path):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        # Tamper with the log file
        log_file = list(log_dir.glob("audit_*.jsonl"))[0]
        lines = log_file.read_text().strip().split("\n")
        data = json.loads(lines[0])
        data["status"] = "succeeded"  # Tampered!
        log_file.write_text(json.dumps(data, ensure_ascii=False) + "\n")

        errors = audit_log.verify_integrity()
        assert len(errors) >= 1
        assert any("hash mismatch" in e for e in errors)

    def test_tampered_prev_hash_detected(self, audit_log: AuditLog, log_dir: Path):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        audit_log.append(
            event_type="COMMAND_QUEUED",
            command_id="CMD-1",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        # Tamper the second entry's prev_hash
        log_file = list(log_dir.glob("audit_*.jsonl"))[0]
        lines = log_file.read_text().strip().split("\n")
        data = json.loads(lines[1])
        data["prev_hash"] = "0" * 64  # Point to a wrong previous hash
        log_file.write_text(
            lines[0] + "\n" + json.dumps(data, ensure_ascii=False) + "\n"
        )

        errors = audit_log.verify_integrity()
        assert any("prev_hash" in e for e in errors)

    def test_assert_integrity_raises_on_tamper(self, audit_log: AuditLog, log_dir: Path):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        log_file = list(log_dir.glob("audit_*.jsonl"))[0]
        data = json.loads(log_file.read_text().strip().split("\n")[0])
        data["status"] = "succeeded"
        log_file.write_text(json.dumps(data, ensure_ascii=False) + "\n")

        with pytest.raises(AuditIntegrityError):
            audit_log.assert_integrity()


# ===========================================================================
# Storage
# ===========================================================================


class TestStorage:
    def test_events_persist_across_reload(self, audit_log: AuditLog, log_dir: Path):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-persist",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        # Create a new AuditLog instance pointing to the same directory
        log2 = AuditLog(hot_dir=log_dir)
        assert log2.count_events() == 1

    def test_multiple_daily_files(self, audit_log: AuditLog, log_dir: Path):
        """Multiple append calls should accumulate in the same daily file."""
        for i in range(10):
            audit_log.append(
                event_type="COMMAND_SUBMITTED",
                command_id=f"CMD-{i}",
                target_action="PC:OPEN_URL",
                status="queued",
            )
        log_files = list(log_dir.glob("audit_*.jsonl"))
        assert len(log_files) == 1  # Same day, same file

    def test_clear_hot_removes_files(self, audit_log: AuditLog, log_dir: Path):
        audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-clear",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        assert audit_log.count_events() == 1
        count = audit_log.clear_hot()
        assert count >= 1
        assert audit_log.count_events() == 0

    def test_clear_empty_log(self, audit_log: AuditLog):
        count = audit_log.clear_hot()
        assert count == 0


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_append_no_detail(self, audit_log: AuditLog):
        event = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        assert event.detail == ""

    def test_append_special_characters(self, audit_log: AuditLog):
        """Parameters with special characters should be handled."""
        event = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-special",
            target_action="PC:RUN_SCRIPT",
            status="queued",
            detail="param=hello; world & more | test",
        )
        assert event.detail == "param=hello; world & more | test"
        # Verify it was stored correctly
        trace = audit_log.get_trace("CMD-special")
        assert len(trace) == 1
        assert trace[0].detail == "param=hello; world & more | test"

    def test_append_unicode(self, audit_log: AuditLog):
        event = audit_log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-unicode",
            target_action="HOME:SET_SCENE",
            status="queued",
            detail="灯をつける",
        )
        trace = audit_log.get_trace("CMD-unicode")
        assert trace[0].detail == "灯をつける"

    def test_append_and_verify_empty_log(self, audit_log: AuditLog):
        """Empty log should verify cleanly."""
        errors = audit_log.verify_integrity()
        assert errors == []


# ===========================================================================
# Convenience functions
# ===========================================================================


class TestConvenienceFunctions:
    def test_audit_append_function(self):
        # Uses the global default log — just verify it returns an event
        # Note: this writes to the real logs/audit directory
        event = audit_append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-global-test",
            target_action="PC:OPEN_URL",
            status="queued",
            detail="test",
        )
        assert event.command_id == "CMD-global-test"
        # Clean up
        from jarvis.audit import _get_log
        _get_log().clear_hot()

    def test_audit_get_trace_function(self):
        event = audit_append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-trace-test",
            target_action="PC:OPEN_URL",
            status="queued",
        )
        trace = audit_get_trace("CMD-trace-test")
        assert len(trace) >= 1
        assert trace[0].command_id == "CMD-trace-test"
        # Clean up
        from jarvis.audit import _get_log
        _get_log().clear_hot()
