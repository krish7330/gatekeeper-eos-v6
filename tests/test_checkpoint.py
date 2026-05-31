"""Tests for checkpoint module: writer, loader, resume, rollback."""

import json
from pathlib import Path

import pytest

from gatekeeper_eos_v6.checkpoint import (
    CheckpointError,
    CheckpointNotFoundError,
    CheckpointParseError,
    CheckpointSchemaError,
    CheckpointLockError,
    CHECKPOINT_FIELDS,
    validate_checkpoint,
    assert_checkpoint_valid,
    write_checkpoint,
    load_checkpoint,
    get_resume_state,
    rollback_checkpoint,
    list_checkpoints,
    clear_checkpoints,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def checkpoint_dir(tmp_path: Path) -> Path:
    """Use a temporary directory for checkpoint files."""
    d = tmp_path / "checkpoints"
    d.mkdir()
    return d


@pytest.fixture
def valid_checkpoint_data() -> dict:
    return {
        "plan_id": "PTO-001",
        "session_id": "recon-01",
        "step_id": "recon-1",
        "status": "completed",
        "last_action": "DNS enumeration on example.com",
        "last_output_hash": "abc123",
        "drift_status": "clean",
        "updated_at": "2026-06-01T00:00:00Z",
        "next_resume_token": "recon-01:recon-1:2026-06-01T00:00:00Z",
    }


# ===========================================================================
# Schema validation
# ===========================================================================


class TestCheckpointValidation:
    """validate_checkpoint and assert_checkpoint_valid."""

    def test_valid_checkpoint_passes(self, valid_checkpoint_data):
        errors = validate_checkpoint(valid_checkpoint_data)
        assert errors == []

    def test_assert_valid_does_not_raise(self, valid_checkpoint_data):
        assert_checkpoint_valid(valid_checkpoint_data)

    def test_missing_plan_id_fails(self, valid_checkpoint_data):
        data = {k: v for k, v in valid_checkpoint_data.items() if k != "plan_id"}
        errors = validate_checkpoint(data)
        assert any("plan_id" in e for e in errors)

    def test_missing_multiple_fields_fails(self, valid_checkpoint_data):
        data = {}
        errors = validate_checkpoint(data)
        # 9 missing-field errors + 3 type-check errors (plan_id, session_id, step_id)
        assert len(errors) == len(CHECKPOINT_FIELDS) + 3

    def test_invalid_status_fails(self, valid_checkpoint_data):
        data = dict(valid_checkpoint_data)
        data["status"] = "unknown_status"
        errors = validate_checkpoint(data)
        assert any("status" in e for e in errors)

    def test_all_valid_statuses_pass(self, valid_checkpoint_data):
        for status in ["pending", "running", "completed", "failed", "halted", "rolled_back"]:
            data = dict(valid_checkpoint_data)
            data["status"] = status
            errors = validate_checkpoint(data)
            assert errors == [] or all("status" not in e for e in errors)

    def test_invalid_drift_status_fails(self, valid_checkpoint_data):
        data = dict(valid_checkpoint_data)
        data["drift_status"] = "invalid_drift"
        errors = validate_checkpoint(data)
        assert any("drift_status" in e for e in errors)

    def test_assert_raises_on_invalid(self, valid_checkpoint_data):
        data = dict(valid_checkpoint_data)
        data["status"] = "bogus"
        with pytest.raises(CheckpointSchemaError):
            assert_checkpoint_valid(data)

    def test_assert_error_message_includes_count(self, valid_checkpoint_data):
        data = {"plan_id": "ok"}
        with pytest.raises(CheckpointSchemaError) as exc:
            assert_checkpoint_valid(data)
        assert "errors" in str(exc.value).lower()

    def test_empty_data_returns_correct_error_count(self):
        errors = validate_checkpoint({})
        # 9 missing-field errors + 3 type-check errors (plan_id, session_id, step_id)
        assert len(errors) == len(CHECKPOINT_FIELDS) + 3

    def test_none_values_fail(self, valid_checkpoint_data):
        data = dict(valid_checkpoint_data)
        data["plan_id"] = None
        errors = validate_checkpoint(data)
        assert any("plan_id" in e for e in errors)

    def test_non_string_updated_at_fails(self, valid_checkpoint_data):
        data = dict(valid_checkpoint_data)
        data["updated_at"] = 12345
        errors = validate_checkpoint(data)
        assert any("updated_at" in e for e in errors)


# ===========================================================================
# Writer
# ===========================================================================


class TestWriteCheckpoint:
    """write_checkpoint writes valid checkpoint files."""

    def test_write_creates_file(self, checkpoint_dir):
        path = write_checkpoint(
            session_id="recon-01",
            plan_id="PTO-001",
            step_id="recon-1",
            status="running",
            checkpoint_dir=checkpoint_dir,
        )
        assert path.exists()
        assert path.name == "recon-01.json"

    def test_written_file_is_valid_json(self, checkpoint_dir):
        path = write_checkpoint(
            session_id="scan-01", plan_id="PTO-001",
            step_id="scan-1", status="pending",
            checkpoint_dir=checkpoint_dir,
        )
        data = json.loads(path.read_text())
        assert data["session_id"] == "scan-01"
        assert data["plan_id"] == "PTO-001"
        assert data["step_id"] == "scan-1"

    def test_write_includes_all_required_fields(self, checkpoint_dir):
        path = write_checkpoint(
            session_id="test-01", plan_id="PTO-001",
            step_id="step-1", status="completed",
            last_action="Ran test", output={"key": "value"},
            checkpoint_dir=checkpoint_dir,
        )
        data = json.loads(path.read_text())
        for field in CHECKPOINT_FIELDS:
            assert field in data, f"Missing field: {field}"

    def test_write_output_hash_computed(self, checkpoint_dir):
        path = write_checkpoint(
            session_id="hash-test", plan_id="PTO-001",
            step_id="step-1", status="completed",
            output={"key": "value"},
            checkpoint_dir=checkpoint_dir,
        )
        data = json.loads(path.read_text())
        assert data["last_output_hash"] != ""
        assert len(data["last_output_hash"]) == 64  # SHA-256 hex

    def test_write_creates_directory(self, tmp_path):
        """write_checkpoint creates the checkpoint directory if needed."""
        nested = tmp_path / "a" / "b" / "c"
        path = write_checkpoint(
            session_id="mkdir-test", plan_id="PTO-001",
            step_id="step-1", status="pending",
            checkpoint_dir=nested,
        )
        assert path.exists()
        assert nested.exists()

    def test_write_invalid_status_raises(self, checkpoint_dir):
        with pytest.raises(CheckpointSchemaError):
            write_checkpoint(
                session_id="bad", plan_id="PTO-001",
                step_id="step-1", status="invalid_status",
                checkpoint_dir=checkpoint_dir,
            )

    def test_write_empty_output_hash_when_no_output(self, checkpoint_dir):
        path = write_checkpoint(
            session_id="no-output", plan_id="PTO-001",
            step_id="step-1", status="pending",
            checkpoint_dir=checkpoint_dir,
        )
        data = json.loads(path.read_text())
        assert data["last_output_hash"] == ""

    def test_drift_status_defaults_to_clean(self, checkpoint_dir):
        path = write_checkpoint(
            session_id="default-drift", plan_id="PTO-001",
            step_id="step-1", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        data = json.loads(path.read_text())
        assert data["drift_status"] == "clean"


# ===========================================================================
# Loader
# ===========================================================================


class TestLoadCheckpoint:
    """load_checkpoint loads and validates checkpoint files."""

    def test_load_returns_data(self, checkpoint_dir):
        write_checkpoint(
            session_id="load-test", plan_id="PTO-001",
            step_id="step-1", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        data = load_checkpoint("load-test", checkpoint_dir)
        assert data["session_id"] == "load-test"
        assert data["plan_id"] == "PTO-001"
        assert data["status"] == "completed"

    def test_load_not_found_raises(self, checkpoint_dir):
        with pytest.raises(CheckpointNotFoundError):
            load_checkpoint("nonexistent", checkpoint_dir)

    def test_load_corrupted_file_raises(self, checkpoint_dir):
        bad_file = checkpoint_dir / "corrupt.json"
        bad_file.write_text("not valid json {")
        with pytest.raises(CheckpointParseError):
            load_checkpoint("corrupt", checkpoint_dir)

    def test_load_invalid_schema_raises(self, checkpoint_dir):
        bad_data = {"plan_id": "incomplete"}
        bad_file = checkpoint_dir / "bad-schema.json"
        bad_file.write_text(json.dumps(bad_data))
        with pytest.raises(CheckpointSchemaError):
            load_checkpoint("bad-schema", checkpoint_dir)

    def test_load_round_trip(self, checkpoint_dir):
        """Write then load should return identical fields."""
        write_checkpoint(
            session_id="round-trip", plan_id="PTO-001",
            step_id="step-1", status="running",
            last_action="Scanning ports",
            output={"port": 443, "open": True},
            checkpoint_dir=checkpoint_dir,
        )
        data = load_checkpoint("round-trip", checkpoint_dir)
        assert data["session_id"] == "round-trip"
        assert data["step_id"] == "step-1"
        assert data["last_action"] == "Scanning ports"
        assert data["last_output_hash"]
        assert data["drift_status"] == "clean"
        assert data["next_resume_token"].startswith("round-trip:step-1:")

    def test_load_without_drift_field_defaults(self, checkpoint_dir):
        """If drift_status was written by old code that didn't set it."""
        write_checkpoint(
            session_id="drift-default", plan_id="PTO-001",
            step_id="step-1", status="completed",
            drift_status="clean",
            checkpoint_dir=checkpoint_dir,
        )
        data = load_checkpoint("drift-default", checkpoint_dir)
        assert data["drift_status"] == "clean"


# ===========================================================================
# Resume
# ===========================================================================


class TestResumeState:
    """get_resume_state returns handoff metadata."""

    def test_resume_returns_all_keys(self, checkpoint_dir):
        write_checkpoint(
            session_id="resume-test", plan_id="PTO-001",
            step_id="step-1", status="halted",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("resume-test", checkpoint_dir)
        expected_keys = {
            "session_id", "plan_id", "step_id", "status",
            "last_output_hash", "drift_status", "next_resume_token",
            "can_resume", "can_rollback",
        }
        assert set(state.keys()) == expected_keys

    def test_halted_session_can_resume_and_rollback(self, checkpoint_dir):
        write_checkpoint(
            session_id="halted-session", plan_id="PTO-001",
            step_id="step-1", status="halted",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("halted-session", checkpoint_dir)
        assert state["can_resume"] is True
        assert state["can_rollback"] is True

    def test_completed_session_cannot_resume(self, checkpoint_dir):
        write_checkpoint(
            session_id="done", plan_id="PTO-001",
            step_id="step-3", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("done", checkpoint_dir)
        assert state["can_resume"] is False

    def test_completed_session_can_rollback(self, checkpoint_dir):
        write_checkpoint(
            session_id="done-rollback", plan_id="PTO-001",
            step_id="step-3", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("done-rollback", checkpoint_dir)
        assert state["can_rollback"] is True

    def test_failed_session_cannot_resume(self, checkpoint_dir):
        write_checkpoint(
            session_id="failed", plan_id="PTO-001",
            step_id="step-2", status="failed",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("failed", checkpoint_dir)
        assert state["can_resume"] is False
        assert state["can_rollback"] is False

    def test_running_session_can_resume(self, checkpoint_dir):
        write_checkpoint(
            session_id="still-running", plan_id="PTO-001",
            step_id="step-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("still-running", checkpoint_dir)
        assert state["can_resume"] is True
        assert state["can_rollback"] is True

    def test_pending_session_can_resume(self, checkpoint_dir):
        write_checkpoint(
            session_id="pending-session", plan_id="PTO-001",
            step_id="step-0", status="pending",
            checkpoint_dir=checkpoint_dir,
        )
        state = get_resume_state("pending-session", checkpoint_dir)
        assert state["can_resume"] is True

    def test_resume_raises_on_not_found(self, checkpoint_dir):
        with pytest.raises(CheckpointNotFoundError):
            get_resume_state("ghost", checkpoint_dir)

    def test_resume_raises_on_parse_error(self, checkpoint_dir):
        bad_file = checkpoint_dir / "parse-error.json"
        bad_file.write_text("{broken")
        with pytest.raises(CheckpointParseError):
            get_resume_state("parse-error", checkpoint_dir)


# ===========================================================================
# Rollback
# ===========================================================================


class TestRollback:
    """rollback_checkpoint saves backup and marks as rolled_back."""

    def test_rollback_creates_backup(self, checkpoint_dir):
        write_checkpoint(
            session_id="rollback-target", plan_id="PTO-001",
            step_id="step-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        backup = checkpoint_dir / "rollback-target.json.bak"
        assert not backup.exists()

        rollback_checkpoint("rollback-target", "drift detected", checkpoint_dir)
        assert backup.exists()

    def test_rollback_updates_status(self, checkpoint_dir):
        write_checkpoint(
            session_id="rollback-status", plan_id="PTO-001",
            step_id="step-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("rollback-status", "target scope changed", checkpoint_dir)
        data = load_checkpoint("rollback-status", checkpoint_dir)
        assert data["status"] == "rolled_back"
        assert data["drift_status"] == "rolled_back"

    def test_rollback_records_reason(self, checkpoint_dir):
        write_checkpoint(
            session_id="rollback-reason", plan_id="PTO-001",
            step_id="step-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("rollback-reason", "expired", checkpoint_dir)
        data = load_checkpoint("rollback-reason", checkpoint_dir)
        assert "ROLLED_BACK" in data["last_action"]
        assert "expired" in data["last_action"]

    def test_rollback_not_found_raises(self, checkpoint_dir):
        with pytest.raises(CheckpointNotFoundError):
            rollback_checkpoint("nonexistent", "test", checkpoint_dir)

    def test_rollback_preserves_original_in_backup(self, checkpoint_dir):
        write_checkpoint(
            session_id="preserve", plan_id="PTO-001",
            step_id="step-1", status="running",
            last_action="Original action",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("preserve", "drift", checkpoint_dir)

        backup_data = json.loads((checkpoint_dir / "preserve.json.bak").read_text())
        assert backup_data["status"] == "running"
        assert backup_data["last_action"] == "Original action"

    def test_rollback_twice_updates_backup(self, checkpoint_dir):
        """Second rollback overwrites the backup with the new pre-rollback state."""
        write_checkpoint(
            session_id="double-roll", plan_id="PTO-001",
            step_id="step-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("double-roll", "first drift", checkpoint_dir)
        rollback_checkpoint("double-roll", "second drift", checkpoint_dir)

        data = load_checkpoint("double-roll", checkpoint_dir)
        assert data["status"] == "rolled_back"
        assert "second drift" in data["last_action"]

    def test_rollback_of_rolled_back_state(self, checkpoint_dir):
        write_checkpoint(
            session_id="already-rolled", plan_id="PTO-001",
            step_id="step-1", status="rolled_back",
            checkpoint_dir=checkpoint_dir,
        )
        # Rolling back an already-rolled-back state should work (re-records)
        rollback_checkpoint("already-rolled", "another reason", checkpoint_dir)
        data = load_checkpoint("already-rolled", checkpoint_dir)
        assert data["status"] == "rolled_back"


# ===========================================================================
# List and clear
# ===========================================================================


class TestListCheckpoints:
    """list_checkpoints enumerates checkpoint files."""

    def test_empty_directory_returns_empty_list(self, checkpoint_dir):
        assert list_checkpoints(checkpoint_dir) == []

    def test_lists_all_checkpoints(self, checkpoint_dir):
        for sid in ["recon-01", "scan-01", "report-01"]:
            write_checkpoint(
                session_id=sid, plan_id="PTO-001",
                step_id=f"{sid.split('-')[0]}-1",
                status="completed",
                checkpoint_dir=checkpoint_dir,
            )
        result = list_checkpoints(checkpoint_dir)
        assert len(result) == 3

    def test_skips_bak_files(self, checkpoint_dir):
        """Backup files (.json.bak) should not appear in listings."""
        write_checkpoint(
            session_id="skip-bak", plan_id="PTO-001",
            step_id="step-1", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("skip-bak", "test", checkpoint_dir)
        result = list_checkpoints(checkpoint_dir)
        # Should still show the checkpoint, not the .bak
        session_ids = [c["session_id"] for c in result]
        assert "skip-bak" in session_ids
        assert len(result) == 1

    def test_skips_broken_files_gracefully(self, checkpoint_dir):
        """Checkpoints that fail validation are skipped, not raised."""
        write_checkpoint(
            session_id="good", plan_id="PTO-001",
            step_id="step-1", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        bad_file = checkpoint_dir / "bad.json"
        bad_file.write_text("not json")
        result = list_checkpoints(checkpoint_dir)
        assert len(result) == 1
        assert result[0]["session_id"] == "good"

    def test_sorted_by_updated_at_descending(self, checkpoint_dir):
        """Most recent checkpoints should appear first."""
        import time
        for sid in ["first", "second", "third"]:
            write_checkpoint(
                session_id=sid, plan_id="PTO-001",
                step_id="step-1", status="completed",
                checkpoint_dir=checkpoint_dir,
            )
            time.sleep(0.01)

        result = list_checkpoints(checkpoint_dir)
        assert len(result) == 3
        # third was written last, should be first
        assert result[0]["session_id"] == "third"
        assert result[-1]["session_id"] == "first"


class TestClearCheckpoints:
    """clear_checkpoints removes checkpoint files."""

    def test_clear_removes_all(self, checkpoint_dir):
        for sid in ["a", "b", "c"]:
            write_checkpoint(
                session_id=sid, plan_id="PTO-001",
                step_id="step-1", status="completed",
                checkpoint_dir=checkpoint_dir,
            )
        count = clear_checkpoints(checkpoint_dir)
        assert count == 3
        assert list_checkpoints(checkpoint_dir) == []

    def test_clear_preserves_bak_files(self, checkpoint_dir):
        write_checkpoint(
            session_id="preserve-bak", plan_id="PTO-001",
            step_id="step-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("preserve-bak", "test", checkpoint_dir)

        # There should be a .bak file
        bak_files = list(checkpoint_dir.glob("*.bak"))
        assert len(bak_files) >= 1

        count = clear_checkpoints(checkpoint_dir)
        # Only the .json should be removed
        remaining_bak = list(checkpoint_dir.glob("*.bak"))
        assert len(remaining_bak) >= 1
        assert count >= 1

    def test_nonexistent_dir_returns_zero(self, tmp_path):
        non_existent = tmp_path / "no-such-dir"
        count = clear_checkpoints(non_existent)
        assert count == 0

    def test_clear_empty_dir_returns_zero(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        count = clear_checkpoints(empty_dir)
        assert count == 0


# ===========================================================================
# Fail-closed behavior
# ===========================================================================


class TestFailClosed:
    """System must fail closed on missing schema, parse errors, lock violations."""

    def test_fail_closed_on_missing_schema(self, checkpoint_dir):
        """Writing a checkpoint with missing fields must raise."""
        with pytest.raises(CheckpointSchemaError):
            write_checkpoint(
                session_id="",  # empty string passes type check but is invalid
                plan_id="",
                step_id="",
                status="invalid",
                checkpoint_dir=checkpoint_dir,
            )

    def test_fail_closed_on_parse_error(self, checkpoint_dir):
        """Loading a corrupt file must raise."""
        bad_file = checkpoint_dir / "corrupt.json"
        bad_file.write_text("{invalid")
        with pytest.raises(CheckpointParseError):
            load_checkpoint("corrupt", checkpoint_dir)

    def test_fail_closed_on_io_error(self, checkpoint_dir):
        """Writing to a read-only directory must raise CheckpointError."""
        read_only = checkpoint_dir / "readonly"
        read_only.mkdir()
        read_only.chmod(0o444)
        with pytest.raises(CheckpointError):
            write_checkpoint(
                session_id="ro-test", plan_id="PTO-001",
                step_id="step-1", status="running",
                checkpoint_dir=read_only,
            )


# ===========================================================================
# Integration: resume from saved state
# ===========================================================================


class TestIntegrationResume:
    """End-to-end: write checkpoint, resume, continue."""

    def test_write_then_resume(self, checkpoint_dir):
        """Write a checkpoint mid-session, then resume."""
        write_checkpoint(
            session_id="integration-recon", plan_id="PTO-001",
            step_id="recon-2", status="running",
            last_action="Port scan in progress",
            output={"ports_scanned": 100},
            checkpoint_dir=checkpoint_dir,
        )
        resume = get_resume_state("integration-recon", checkpoint_dir)
        assert resume["session_id"] == "integration-recon"
        assert resume["step_id"] == "recon-2"
        assert resume["can_resume"] is True
        assert resume["can_rollback"] is True
        assert resume["next_resume_token"].startswith("integration-recon:recon-2:")

    def test_resume_after_interruption(self, checkpoint_dir):
        """Simulate an interrupted session and verify resume state."""
        write_checkpoint(
            session_id="interrupted", plan_id="PTO-001",
            step_id="scan-2", status="halted",
            last_action="Scan halted mid-execution",
            output={"partial_results": {"hosts": ["10.0.0.1"]}},
            checkpoint_dir=checkpoint_dir,
        )
        resume = get_resume_state("interrupted", checkpoint_dir)
        assert resume["can_resume"] is True
        assert resume["status"] == "halted"

    def test_completed_session_cannot_resume(self, checkpoint_dir):
        """A completed session should not allow resume (no more steps)."""
        write_checkpoint(
            session_id="fully-done", plan_id="PTO-001",
            step_id="report-5", status="completed",
            checkpoint_dir=checkpoint_dir,
        )
        resume = get_resume_state("fully-done", checkpoint_dir)
        assert resume["can_resume"] is False


# ===========================================================================
# Integration: rollback after drift or failure
# ===========================================================================


class TestIntegrationRollback:
    """End-to-end: write checkpoint, drift, rollback."""

    def test_rollback_after_drift(self, checkpoint_dir):
        """Simulate drift detection and rollback."""
        write_checkpoint(
            session_id="drifted-session", plan_id="PTO-001",
            step_id="recon-3", status="running",
            drift_status="clean",
            checkpoint_dir=checkpoint_dir,
        )
        # Drift detected
        rollback_checkpoint("drifted-session", "DRIFT-TARGET: scope expanded", checkpoint_dir)
        data = load_checkpoint("drifted-session", checkpoint_dir)
        assert data["status"] == "rolled_back"
        assert data["drift_status"] == "rolled_back"
        assert "DRIFT-TARGET" in data["last_action"]

    def test_rollback_after_expiry(self, checkpoint_dir):
        """Simulate expiry and rollback."""
        write_checkpoint(
            session_id="expired-session", plan_id="PTO-001",
            step_id="scan-1", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint("expired-session", "DRIFT-EXPIRY: now > expiry", checkpoint_dir)
        data = load_checkpoint("expired-session", checkpoint_dir)
        assert data["status"] == "rolled_back"
        assert "DRIFT-EXPIRY" in data["last_action"]

    def test_rollback_after_tool_hash_mismatch(self, checkpoint_dir):
        """Simulate tool integrity violation."""
        write_checkpoint(
            session_id="tool-violation", plan_id="PTO-001",
            step_id="scan-2", status="running",
            checkpoint_dir=checkpoint_dir,
        )
        rollback_checkpoint(
            "tool-violation",
            "DRIFT-TOOLS: tool hash mismatch for scanner v1.0",
            checkpoint_dir,
        )
        data = load_checkpoint("tool-violation", checkpoint_dir)
        assert data["status"] == "rolled_back"
        assert "DRIFT-TOOLS" in data["last_action"]

    def test_rollback_preserves_evidence_hash(self, checkpoint_dir):
        """After rollback, the backup should have the original output hash."""
        write_checkpoint(
            session_id="ev-hash", plan_id="PTO-001",
            step_id="step-1", status="running",
            output={"data": "sensitive"},
            checkpoint_dir=checkpoint_dir,
        )
        original_hash = load_checkpoint("ev-hash", checkpoint_dir)["last_output_hash"]
        rollback_checkpoint("ev-hash", "drift", checkpoint_dir)

        backup = json.loads((checkpoint_dir / "ev-hash.json.bak").read_text())
        assert backup["last_output_hash"] == original_hash

    def test_multi_session_rollback_independent(self, checkpoint_dir):
        """Rolling back one session should not affect another."""
        for sid in ["session-a", "session-b"]:
            write_checkpoint(
                session_id=sid, plan_id="PTO-001",
                step_id="step-1", status="running",
                checkpoint_dir=checkpoint_dir,
            )
        rollback_checkpoint("session-a", "drift", checkpoint_dir)

        a = load_checkpoint("session-a", checkpoint_dir)
        b = load_checkpoint("session-b", checkpoint_dir)
        assert a["status"] == "rolled_back"
        assert b["status"] == "running"
