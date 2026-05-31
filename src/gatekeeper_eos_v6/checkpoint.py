"""Checkpoint writer, loader, resume, and rollback for multi-session orchestration.

Checkpoints capture session state at each step so sessions can be resumed
after interruption or rolled back after drift or failure.

Safe rules:
  - Fail closed on any checkpoint parse error.
  - Fail closed on any missing schema.
  - Fail closed on any lock-order violation.
"""

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CheckpointError(Exception):
    """Base error for checkpoint operations."""


class CheckpointParseError(CheckpointError):
    """Raised when a checkpoint file cannot be parsed."""


class CheckpointSchemaError(CheckpointError):
    """Raised when checkpoint data fails schema validation."""


class CheckpointNotFoundError(CheckpointError):
    """Raised when a requested checkpoint does not exist."""


class CheckpointLockError(CheckpointError):
    """Raised on lock-order violation during checkpoint operations."""


# ---------------------------------------------------------------------------
# Checkpoint schema (corresponds to state_schema in the orchestrator YAML)
# ---------------------------------------------------------------------------

CHECKPOINT_FIELDS = {
    "plan_id",
    "session_id",
    "step_id",
    "status",
    "last_action",
    "last_output_hash",
    "drift_status",
    "updated_at",
    "next_resume_token",
}

CHECKPOINT_DIR = Path(__file__).resolve().parent.parent.parent / "checkpoints"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_dir(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


def _hash_output(output: dict[str, Any]) -> str:
    """Produce a SHA-256 hash of session output for integrity checks."""
    raw = json.dumps(output, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Validate checkpoint structure
# ---------------------------------------------------------------------------


def validate_checkpoint(data: dict[str, Any]) -> list[str]:
    """Validate a checkpoint dict against the required schema.

    Returns a list of error messages (empty = valid).
    When empty, the checkpoint can be used safely.
    """
    errors: list[str] = []

    # Every required field must be present
    for field in CHECKPOINT_FIELDS:
        if field not in data:
            errors.append(f"missing required field: {field}")

    # Type checks for critical fields
    if not isinstance(data.get("plan_id"), str):
        errors.append("plan_id must be a string")
    if not isinstance(data.get("session_id"), str):
        errors.append("session_id must be a string")
    if not isinstance(data.get("step_id"), str):
        errors.append("step_id must be a string")

    # Status must be one of the known states
    valid_statuses = {"pending", "running", "completed", "failed", "halted", "rolled_back"}
    status = data.get("status")
    if status is not None and status not in valid_statuses:
        errors.append(f"invalid status '{status}'; must be one of {valid_statuses}")

    # drift_status must be valid
    valid_drift = {"clean", "drift_detected", "expired", "rolled_back"}
    drift = data.get("drift_status")
    if drift is not None and drift not in valid_drift:
        errors.append(f"invalid drift_status '{drift}'; must be one of {valid_drift}")

    # updated_at should be parseable if present
    updated_at = data.get("updated_at")
    if updated_at is not None and not isinstance(updated_at, str):
        errors.append("updated_at must be a string (ISO 8601)")

    return errors


def assert_checkpoint_valid(data: dict[str, Any]) -> None:
    """Raise CheckpointSchemaError if checkpoint is invalid."""
    errors = validate_checkpoint(data)
    if errors:
        raise CheckpointSchemaError(
            f"Checkpoint validation failed ({len(errors)} errors): {'; '.join(errors)}"
        )


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def write_checkpoint(
    session_id: str,
    plan_id: str,
    step_id: str,
    status: str,
    last_action: str = "",
    output: dict[str, Any] | None = None,
    drift_status: str = "clean",
    checkpoint_dir: str | Path | None = None,
) -> Path:
    """Write a checkpoint file for a session step.

    Args:
        session_id: Unique session identifier (e.g. recon-01).
        plan_id: Signed plan identifier (e.g. PTO-001).
        step_id: Current step identifier (e.g. recon-1).
        status: Session status (pending, running, completed, failed, halted, rolled_back).
        last_action: Description of the last action taken.
        output: Optional session output dict (used to compute output hash).
        drift_status: Drift status (clean, drift_detected, expired, rolled_back).
        checkpoint_dir: Override checkpoint directory (default: checkpoints/).

    Returns:
        Path to the written checkpoint file.

    Raises:
        CheckpointError: On any write failure.
    """
    out_dir = Path(checkpoint_dir) if checkpoint_dir else CHECKPOINT_DIR
    _ensure_dir(out_dir)

    output_hash = _hash_output(output) if output else ""

    checkpoint: dict[str, Any] = {
        "plan_id": plan_id,
        "session_id": session_id,
        "step_id": step_id,
        "status": status,
        "last_action": last_action,
        "last_output_hash": output_hash,
        "drift_status": drift_status,
        "updated_at": _now_iso(),
        "next_resume_token": f"{session_id}:{step_id}:{_now_iso()}",
    }

    # Validate before writing
    assert_checkpoint_valid(checkpoint)

    checkpoint_path = out_dir / f"{session_id}.json"
    try:
        with open(checkpoint_path, "w") as f:
            json.dump(checkpoint, f, indent=2, ensure_ascii=False)
    except OSError as e:
        raise CheckpointError(f"Failed to write checkpoint to {checkpoint_path}: {e}") from e

    return checkpoint_path


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_checkpoint(
    session_id: str,
    checkpoint_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Load and validate a checkpoint file for the given session.

    Args:
        session_id: Session identifier to load.
        checkpoint_dir: Override checkpoint directory.

    Returns:
        Validated checkpoint dict.

    Raises:
        CheckpointNotFoundError: If checkpoint file doesn't exist.
        CheckpointParseError: If file can't be parsed.
        CheckpointSchemaError: If checkpoint data is invalid.
    """
    out_dir = Path(checkpoint_dir) if checkpoint_dir else CHECKPOINT_DIR
    checkpoint_path = out_dir / f"{session_id}.json"

    if not checkpoint_path.exists():
        raise CheckpointNotFoundError(f"Checkpoint not found: {checkpoint_path}")

    try:
        with open(checkpoint_path) as f:
            data: dict[str, Any] = json.load(f)
    except json.JSONDecodeError as e:
        raise CheckpointParseError(
            f"Failed to parse checkpoint {checkpoint_path}: {e}"
        ) from e
    except OSError as e:
        raise CheckpointParseError(
            f"Failed to read checkpoint {checkpoint_path}: {e}"
        ) from e

    # Validate the loaded data
    assert_checkpoint_valid(data)

    return data


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


def get_resume_state(
    session_id: str,
    checkpoint_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Load a checkpoint and return resume metadata for session handoff.

    Returns a dict with:
      - session_id, plan_id, step_id: identifiers
      - status: last known status
      - last_output_hash: hash of the last output for integrity checking
      - drift_status: last known drift status
      - next_resume_token: token for the next step
      - can_resume: boolean, true if status allows resuming
      - can_rollback: boolean, true if status allows rollback

    Raises the same errors as load_checkpoint.
    """
    checkpoint = load_checkpoint(session_id, checkpoint_dir)

    can_resume = checkpoint["status"] in {"pending", "running", "halted"}
    can_rollback = checkpoint["status"] in {"running", "halted", "completed"}

    return {
        "session_id": checkpoint["session_id"],
        "plan_id": checkpoint["plan_id"],
        "step_id": checkpoint["step_id"],
        "status": checkpoint["status"],
        "last_output_hash": checkpoint["last_output_hash"],
        "drift_status": checkpoint["drift_status"],
        "next_resume_token": checkpoint["next_resume_token"],
        "can_resume": can_resume,
        "can_rollback": can_rollback,
    }


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def rollback_checkpoint(
    session_id: str,
    reason: str,
    checkpoint_dir: str | Path | None = None,
) -> Path:
    """Roll back a session checkpoint, marking it as rolled_back.

    Reads the current checkpoint, saves a backup, then writes the
    rolled-back state. The backup file is named {session_id}.json.bak.

    Args:
        session_id: Session to roll back.
        reason: Reason for the rollback (drift, failure, expiry, etc.).
        checkpoint_dir: Override checkpoint directory.

    Returns:
        Path to the updated checkpoint file.

    Raises:
        CheckpointNotFoundError: If session has no checkpoint.
        CheckpointError: On write failure.
    """
    checkpoint = load_checkpoint(session_id, checkpoint_dir)
    out_dir = Path(checkpoint_dir) if checkpoint_dir else CHECKPOINT_DIR

    # Create backup
    checkpoint_path = out_dir / f"{session_id}.json"
    backup_path = out_dir / f"{session_id}.json.bak"
    try:
        import shutil
        shutil.copy2(str(checkpoint_path), str(backup_path))
    except OSError as e:
        raise CheckpointError(f"Failed to create backup {backup_path}: {e}") from e

    checkpoint["status"] = "rolled_back"
    checkpoint["drift_status"] = "rolled_back"
    checkpoint["last_action"] = f"ROLLED_BACK: {reason}"
    checkpoint["updated_at"] = _now_iso()

    # Re-validate after mutation
    assert_checkpoint_valid(checkpoint)

    try:
        with open(checkpoint_path, "w") as f:
            json.dump(checkpoint, f, indent=2, ensure_ascii=False)
    except OSError as e:
        raise CheckpointError(f"Failed to write rolled-back checkpoint: {e}") from e

    return checkpoint_path


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def list_checkpoints(
    checkpoint_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """List all checkpoints in the checkpoint directory.

    Returns a list of checkpoint dicts sorted by updated_at descending.
    Skips any files that fail validation (they are logged but not returned).
    """
    out_dir = Path(checkpoint_dir) if checkpoint_dir else CHECKPOINT_DIR
    if not out_dir.exists():
        return []

    checkpoints: list[dict[str, Any]] = []
    for path in sorted(out_dir.glob("*.json")):
        if path.name.endswith(".bak"):
            continue
        try:
            data = load_checkpoint(path.stem, checkpoint_dir)
            checkpoints.append(data)
        except (CheckpointError, json.JSONDecodeError):
            continue

    # Sort by updated_at descending
    checkpoints.sort(
        key=lambda c: c.get("updated_at", ""),
        reverse=True,
    )
    return checkpoints


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def clear_checkpoints(
    checkpoint_dir: str | Path | None = None,
) -> int:
    """Remove all checkpoint files from the checkpoint directory.

    Returns the number of files removed.
    Does NOT remove .bak backup files.
    """
    out_dir = Path(checkpoint_dir) if checkpoint_dir else CHECKPOINT_DIR
    if not out_dir.exists():
        return 0

    count = 0
    for path in list(out_dir.glob("*.json")):
        try:
            path.unlink()
            count += 1
        except OSError:
            continue
    return count
