"""SQLite-backed action queue for Jarvis v2.1.

Canonical 5-state model::

    queued → running → succeeded
               ↓
            failed → dead_letter
               ↓
            queued (retry)

See JARVIS_V2_1_SPEC.md §4 for the full design.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jarvis.types import Command, GateOutcome, Policy, QueueStatus


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = HERE / "data" / "jarvis_queue.db"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class QueueError(Exception):
    """Base error for queue operations."""


class QueueFullError(QueueError):
    """Raised when the queue cannot accept more commands."""


class CommandNotFoundError(QueueError):
    """Raised when a command_id is not found in the queue."""


class DuplicateIdempotencyKeyError(QueueError):
    """Raised when a duplicate idempotency key is submitted within the TTL.

    Attributes:
        existing_entry: The existing queue entry dict, if available.
    """

    def __init__(
        self,
        message: str,
        existing_entry: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.existing_entry = existing_entry


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


class ActionQueue:
    """SQLite-backed action queue with 5-state canonical model.

    Usage::

        queue = ActionQueue()
        cmd = Command(target="PC", action="OPEN_URL", ...)
        entry = queue.enqueue(cmd, policy="auto-approve", gate="approved")
        queue.dequeue()  # returns next command to execute
        queue.succeed("CMD-...")
        queue.fail("CMD-...", "connection timeout")
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._ensure_db_dir()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    @property
    def conn(self) -> sqlite3.Connection:
        """Get or create the database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _ensure_db_dir(self) -> None:
        """Create the database directory if it doesn't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Initialize the database schema."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS action_queue (
                command_id       TEXT PRIMARY KEY,
                source           TEXT NOT NULL,
                target           TEXT NOT NULL,
                action           TEXT NOT NULL,
                parameter        TEXT NOT NULL,
                priority         INTEGER DEFAULT 5,
                idempotency_key  TEXT NOT NULL UNIQUE,
                requested_at     TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','succeeded','failed','dead_letter')),
                policy           TEXT NOT NULL DEFAULT 'auto-approve'
                    CHECK (policy IN ('auto-approve','auto-approve-audit','always-confirm','blocked')),
                gate             TEXT
                    CHECK (gate IS NULL OR gate IN ('approved','rejected','timed_out','blocked')),
                retry_count      INTEGER DEFAULT 0,
                max_retries      INTEGER DEFAULT 3,
                created_at       TEXT DEFAULT (datetime('now')),
                started_at       TEXT,
                completed_at     TEXT,
                error            TEXT,
                result_hash      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_queue_status ON action_queue(status);
            CREATE INDEX IF NOT EXISTS idx_queue_idempotency ON action_queue(idempotency_key);
            CREATE INDEX IF NOT EXISTS idx_queue_priority ON action_queue(priority DESC);
        """)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue(
        self,
        command: Command,
        policy: str = "auto-approve",
        gate: str | None = "approved",
        max_retries: int = 3,
    ) -> dict[str, Any]:
        """Enqueue a command into the action queue.

        Args:
            command: The validated command to enqueue.
            policy: The classified policy name (auto-approve, etc.).
            gate: The gate outcome (approved, rejected, etc.). None if not yet classified.
            max_retries: Maximum retry attempts before dead_letter. Default 3.

        Returns:
            The queue entry as a dict.

        Raises:
            DuplicateIdempotencyKeyError: If the idempotency key already exists.
            QueueError: On database errors.
        """
        command_id = command.command_id or f"CMD-{uuid.uuid4().hex[:12]}"

        try:
            self.conn.execute(
                """INSERT INTO action_queue
                   (command_id, source, target, action, parameter, priority,
                    idempotency_key, requested_at, status, policy, gate, max_retries)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)""",
                (
                    command_id,
                    command.source,
                    command.target,
                    command.action,
                    command.parameter,
                    command.priority,
                    command.idempotency_key,
                    command.requested_at,
                    policy,
                    gate,
                    max_retries,
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            if "UNIQUE" in str(e):
                existing = self.get_by_idempotency_key(command.idempotency_key)
                if existing:
                    raise DuplicateIdempotencyKeyError(
                        f"Duplicate idempotency_key '{command.idempotency_key}': "
                        f"command {existing['command_id']} is in status '{existing['status']}'",
                        existing_entry=existing,
                    ) from e
            raise QueueError(f"Failed to enqueue command: {e}") from e

        return self.get(command_id)

    # ------------------------------------------------------------------
    # Dequeue
    # ------------------------------------------------------------------

    def dequeue(self, target: str | None = None) -> dict[str, Any] | None:
        """Dequeue the next command for execution.

        Returns the highest-priority queued command. If *target* is specified,
        only returns commands for that target.

        Returns:
            The next command entry dict, or None if the queue is empty.
        """
        if target:
            row = self.conn.execute(
                """SELECT * FROM action_queue
                   WHERE status = 'queued' AND gate = 'approved' AND target = ?
                   ORDER BY priority DESC, created_at ASC
                   LIMIT 1""",
                (target,),
            ).fetchone()
        else:
            row = self.conn.execute(
                """SELECT * FROM action_queue
                   WHERE status = 'queued' AND gate = 'approved'
                   ORDER BY priority DESC, created_at ASC
                   LIMIT 1""",
            ).fetchone()

        if row is None:
            return None

        command_id = row["command_id"]
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE action_queue SET status = 'running', started_at = ? WHERE command_id = ?",
            (now, command_id),
        )
        self.conn.commit()

        return dict(row) | {"status": "running", "started_at": now}

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def succeed(self, command_id: str, result_hash: str = "") -> dict[str, Any]:
        """Mark a command as succeeded.

        Args:
            command_id: The command ID to update.
            result_hash: Optional SHA-256 hash of the execution result.

        Returns:
            The updated queue entry.

        Raises:
            CommandNotFoundError: If the command_id is not found.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise CommandNotFoundError(f"Command not found: {command_id}")

        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """UPDATE action_queue
               SET status = 'succeeded', completed_at = ?, result_hash = ?
               WHERE command_id = ?""",
            (now, result_hash, command_id),
        )
        self.conn.commit()
        return self.get(command_id)

    def fail(
        self,
        command_id: str,
        error: str = "",
    ) -> dict[str, Any]:
        """Mark a command as failed, with automatic retry logic.

        If retry_count < max_retries, the command goes back to 'queued'.
        Otherwise, it goes to 'dead_letter'.

        Args:
            command_id: The command ID to update.
            error: Error message describing the failure.

        Returns:
            The updated queue entry.

        Raises:
            CommandNotFoundError: If the command_id is not found.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise CommandNotFoundError(f"Command not found: {command_id}")

        retry_count = row["retry_count"] + 1
        max_retries = row["max_retries"]
        now = datetime.now(timezone.utc).isoformat()

        if retry_count >= max_retries:
            # Dead letter
            self.conn.execute(
                """UPDATE action_queue
                   SET status = 'dead_letter', completed_at = ?,
                       retry_count = ?, error = ?
                   WHERE command_id = ?""",
                (now, retry_count, error, command_id),
            )
        else:
            # Back to queued for retry
            self.conn.execute(
                """UPDATE action_queue
                   SET status = 'queued', retry_count = ?, error = ?
                   WHERE command_id = ?""",
                (retry_count, error, command_id),
            )
        self.conn.commit()
        return self.get(command_id)

    def approve(self, command_id: str) -> dict[str, Any]:
        """Approve a command awaiting user confirmation.

        Sets ``gate = 'approved'`` and restores status to ``'queued'``
        so the queue worker can dequeue and execute it.

        Args:
            command_id: The command ID to approve.

        Returns:
            The updated queue entry.

        Raises:
            CommandNotFoundError: If the command_id is not found.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise CommandNotFoundError(f"Command not found: {command_id}")

        self.conn.execute(
            """UPDATE action_queue
               SET gate = 'approved', status = 'queued', error = NULL
               WHERE command_id = ?""",
            (command_id,),
        )
        self.conn.commit()
        return self.get(command_id)

    def reject(self, command_id: str, reason: str = "") -> dict[str, Any]:
        """Mark a command as failed due to rejection (gate = rejected/timed_out/blocked).

        Unlike :meth:`fail`, rejection never retries — the user explicitly
        declined the command or it was blocked by policy.
        Sets ``gate = 'rejected'`` for audit consistency.

        Args:
            command_id: The command ID to update.
            reason: Reason for rejection.

        Returns:
            The updated queue entry.

        Raises:
            CommandNotFoundError: If the command_id is not found.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise CommandNotFoundError(f"Command not found: {command_id}")

        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """UPDATE action_queue
               SET status = 'failed', gate = 'rejected', completed_at = ?, error = ?
               WHERE command_id = ?""",
            (now, f"rejected: {reason}", command_id),
        )
        self.conn.commit()
        return self.get(command_id)

    def retry(self, command_id: str) -> dict[str, Any]:
        """Force a retry of a dead_letter command.

        Args:
            command_id: The command ID to retry.

        Returns:
            The updated queue entry.

        Raises:
            CommandNotFoundError: If the command_id is not found or not in dead_letter.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise CommandNotFoundError(f"Command not found: {command_id}")
        if row["status"] != "dead_letter":
            raise QueueError(f"Cannot retry command '{command_id}': status is '{row['status']}', not 'dead_letter'")

        self.conn.execute(
            """UPDATE action_queue
               SET status = 'queued', retry_count = 0, error = NULL, completed_at = NULL
               WHERE command_id = ?""",
            (command_id,),
        )
        self.conn.commit()
        return self.get(command_id)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get(self, command_id: str) -> dict[str, Any]:
        """Get a queue entry by command_id.

        Raises:
            CommandNotFoundError: If not found.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise CommandNotFoundError(f"Command not found: {command_id}")
        return dict(row)

    def get_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        """Get a queue entry by idempotency_key.

        Returns:
            The entry dict, or None if not found.
        """
        row = self.conn.execute(
            "SELECT * FROM action_queue WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        return dict(row) if row else None

    def list_by_status(self, status: str, limit: int = 50) -> list[dict[str, Any]]:
        """List queue entries with a specific status.

        Args:
            status: One of: queued, running, succeeded, failed, dead_letter.
            limit: Maximum number of entries to return.

        Returns:
            List of queue entry dicts.
        """
        rows = self.conn.execute(
            "SELECT * FROM action_queue WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_all(self, limit: int = 50) -> list[dict[str, Any]]:
        """List all queue entries, newest first.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of queue entry dicts.
        """
        rows = self.conn.execute(
            "SELECT * FROM action_queue ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        """Return a count of entries grouped by status."""
        rows = self.conn.execute(
            "SELECT status, COUNT(*) as count FROM action_queue GROUP BY status",
        ).fetchall()
        counts = {s: 0 for s in ["queued", "running", "succeeded", "failed", "dead_letter"]}
        for row in rows:
            counts[row["status"]] = row["count"]
        return counts

    def count_pending(self) -> int:
        """Return the number of queued and approved commands waiting for execution."""
        row = self.conn.execute(
            "SELECT COUNT(*) as count FROM action_queue WHERE status = 'queued' AND gate = 'approved'",
        ).fetchone()
        return row["count"]

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def flush(self, command_id: str) -> None:
        """Remove a command from the queue entirely.

        Args:
            command_id: The command ID to remove.
        """
        self.conn.execute("DELETE FROM action_queue WHERE command_id = ?", (command_id,))
        self.conn.commit()

    def clear(self) -> int:
        """Remove all completed and dead_letter commands.

        Returns:
            Number of rows removed.
        """
        cursor = self.conn.execute(
            "DELETE FROM action_queue WHERE status IN ('succeeded', 'dead_letter')",
        )
        self.conn.commit()
        return cursor.rowcount

    def clear_all(self) -> int:
        """Remove ALL commands from the queue (use with caution).

        Returns:
            Number of rows removed.
        """
        cursor = self.conn.execute("DELETE FROM action_queue")
        self.conn.commit()
        return cursor.rowcount

    def vacuum(self) -> None:
        """Reclaim disk space by vacuuming the database."""
        self.conn.execute("VACUUM")
        self.conn.commit()
