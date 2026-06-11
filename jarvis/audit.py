"""Append-only audit log for Jarvis v2.1.

Records every command lifecycle event in a hash-chained, tamper-evident log.
Supports hot storage (local file, rotated daily) and cold storage (S3-compatible
bucket) tiers.

See JARVIS_V2_1_SPEC.md §5 for the full design.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jarvis.types import AuditEvent, AuditEventType


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent.parent
DEFAULT_HOT_DIR = HERE / "logs" / "audit"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuditError(Exception):
    """Base error for audit log operations."""


class AuditIntegrityError(AuditError):
    """Raised when the audit log hash chain is broken."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: str) -> str:
    """Return SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _ensure_dir(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only, hash-chained audit log.

    Usage::

        log = AuditLog()
        log.append(
            event_type="COMMAND_SUBMITTED",
            command_id="CMD-a1b2c3d4",
            target_action="HOME:TURN_ON",
            status="queued",
            detail="source=voice, param=living_room_lamp",
        )
        entries = log.tail(10)
        trace = log.get_trace("CMD-a1b2c3d4")
    """

    def __init__(
        self,
        hot_dir: str | Path | None = None,
    ) -> None:
        self._hot_dir = Path(hot_dir) if hot_dir else DEFAULT_HOT_DIR
        _ensure_dir(self._hot_dir)
        self._cached_last_hash: str | None = None  # O(1) cache for append hot path

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def _get_last_hash(self) -> str:
        """Return the hash of the last entry in the log, or 64 zeros if empty.

        Uses an in-memory cache for O(1) performance on the append hot path.
        The cache is invalidated on writes and cleared on maintenance operations.
        """
        if self._cached_last_hash is not None:
            return self._cached_last_hash
        all_events = self._read_hot()
        if not all_events:
            self._cached_last_hash = "0" * 64
        else:
            self._cached_last_hash = all_events[-1].hash
        return self._cached_last_hash

    def append(
        self,
        event_type: str,
        command_id: str,
        target_action: str,
        status: str,
        detail: str = "",
    ) -> AuditEvent:
        """Append a new event to the audit log.

        Args:
            event_type: AuditEventType value (e.g. ``COMMAND_SUBMITTED``).
            command_id: The command's unique identifier.
            target_action: ``{target}:{action}`` string.
            status: Queue status at the time of the event.
            detail: Optional human-readable detail.

        Returns:
            The created AuditEvent.
        """
        # Get the previous hash (hash of the last entry in the chain)
        prev_hash = self._get_last_hash()

        # Build the entry content (without hash first)
        timestamp = _now_iso()
        entry_data = {
            "timestamp": timestamp,
            "event_type": event_type,
            "command_id": command_id,
            "target_action": target_action,
            "status": status,
            "detail": detail,
            "prev_hash": prev_hash,
        }

        # Compute the hash of this entry (includes prev_hash)
        entry_json = json.dumps(entry_data, sort_keys=True, ensure_ascii=False)
        entry_hash = _sha256(entry_json)

        # Create the full event
        event = AuditEvent(
            timestamp=timestamp,
            event_type=event_type,
            command_id=command_id,
            target_action=target_action,
            status=status,
            detail=detail,
            prev_hash=prev_hash,
            hash=entry_hash,
        )

        # Write to hot storage and update cache
        self._write_hot(event)
        self._cached_last_hash = entry_hash

        return event

    def append_event(
        self,
        event_type: AuditEventType,
        command_id: str,
        target_action: str,
        status: str,
        detail: str = "",
    ) -> AuditEvent:
        """Append an event using the AuditEventType enum.

        Wrapper around :meth:`append` that accepts the enum directly.
        """
        return self.append(
            event_type=event_type.value,
            command_id=command_id,
            target_action=target_action,
            status=status,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def tail(self, n: int = 10) -> list[AuditEvent]:
        """Return the last *n* audit events, newest first.

        Reads from hot storage and returns events in reverse chronological
        order (most recent first).
        """
        all_events = self._read_hot()
        return all_events[-n:][::-1]

    def get_trace(self, command_id: str) -> list[AuditEvent]:
        """Return all audit events for a specific command_id.

        Args:
            command_id: The command ID to search for.

        Returns:
            List of AuditEvent objects in chronological order.
        """
        all_events = self._read_hot()
        return [e for e in all_events if e.command_id == command_id]

    def get_by_event_type(self, event_type: str) -> list[AuditEvent]:
        """Return all events of a given type.

        Args:
            event_type: The event type string (e.g. ``COMMAND_FAILED``).

        Returns:
            List of matching AuditEvent objects in chronological order.
        """
        all_events = self._read_hot()
        return [e for e in all_events if e.event_type == event_type]

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------

    def verify_integrity(self) -> list[str]:
        """Verify the hash chain of the entire audit log.

        Returns:
            List of integrity error messages. Empty list = chain is intact.
        """
        all_events = self._read_hot()
        errors: list[str] = []

        for i, event in enumerate(all_events):
            # Recompute hash
            entry_data = {
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "command_id": event.command_id,
                "target_action": event.target_action,
                "status": event.status,
                "detail": event.detail,
                "prev_hash": event.prev_hash,
            }
            entry_json = json.dumps(entry_data, sort_keys=True, ensure_ascii=False)
            computed_hash = _sha256(entry_json)

            if computed_hash != event.hash:
                errors.append(
                    f"Entry {i}: hash mismatch. "
                    f"Expected {computed_hash}, got {event.hash}"
                )

            # Check prev_hash chain
            if i > 0:
                expected_prev = all_events[i - 1].hash
                if event.prev_hash != expected_prev:
                    errors.append(
                        f"Entry {i}: prev_hash mismatch. "
                        f"Expected {expected_prev}, got {event.prev_hash}"
                    )
            else:
                # First entry should have prev_hash of 64 zeros (or empty)
                if event.prev_hash != "0" * 64:
                    errors.append(
                        f"Entry 0: first entry should have prev_hash of "
                        f"64 zeros, got '{event.prev_hash}'"
                    )

        return errors

    def assert_integrity(self) -> None:
        """Raise AuditIntegrityError if the hash chain is broken."""
        errors = self.verify_integrity()
        if errors:
            raise AuditIntegrityError(
                f"Audit log integrity check failed ({len(errors)} errors): "
                f"{'; '.join(errors[:3])}"
            )

    # ------------------------------------------------------------------
    # Storage: Hot (local file)
    # ------------------------------------------------------------------

    def _hot_path(self) -> Path:
        """Return the path to the current hot storage file."""
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self._hot_dir / f"audit_{today}.jsonl"

    def _write_hot(self, event: AuditEvent) -> None:
        """Append an event as a JSON line to the hot storage file."""
        path = self._hot_path()
        line = json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            raise AuditError(f"Failed to write audit event to {path}: {e}") from e

    def _read_hot(self) -> list[AuditEvent]:
        """Read all events from hot storage (all daily files)."""
        events: list[AuditEvent] = []
        for path in sorted(self._hot_dir.glob("audit_*.jsonl")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                events.append(AuditEvent.from_dict(data))
                            except (json.JSONDecodeError, KeyError):
                                continue
            except OSError:
                continue
        return events

    # ------------------------------------------------------------------
    # Storage: Cold (S3-compatible — stub)
    # ------------------------------------------------------------------

    def archive_to_cold(self, days_old: int = 30) -> int:
        """Archive hot log files older than *days_old* to cold storage.

        This is a stub. Actual implementation would upload to S3-compatible
        storage and remove the local file.

        Args:
            days_old: Archive files older than this many days.

        Returns:
            Number of files archived.
        """
        # TODO: Implement S3-compatible upload
        return 0

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def count_events(self) -> int:
        """Return the total number of events in hot storage."""
        return len(self._read_hot())

    def clear_hot(self) -> int:
        """Remove all hot audit log files.

        Returns:
            Number of files removed.
        """
        self._cached_last_hash = None  # invalidate cache
        count = 0
        for path in list(self._hot_dir.glob("audit_*.jsonl")):
            try:
                path.unlink()
                count += 1
            except OSError:
                continue
        return count

    def rotate(self) -> None:
        """Rotate the hot log file. Called daily by the logger.

        Since files are already date-rotated (audit_YYYYMMDD.jsonl), this is
        a no-op. The daily rotation happens naturally via _hot_path().
        """
        pass


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

_DEFAULT_LOG: AuditLog | None = None


def _get_log() -> AuditLog:
    """Get or create the default audit log."""
    global _DEFAULT_LOG
    if _DEFAULT_LOG is None:
        _DEFAULT_LOG = AuditLog()
    return _DEFAULT_LOG


def audit_append(
    event_type: str,
    command_id: str,
    target_action: str,
    status: str,
    detail: str = "",
) -> AuditEvent:
    """Append an event to the default audit log.

    Args:
        event_type: Event type string (e.g. ``COMMAND_SUBMITTED``).
        command_id: The command's unique identifier.
        target_action: ``{target}:{action}`` string.
        status: Queue status at the time of the event.
        detail: Optional human-readable detail.

    Returns:
        The created AuditEvent.
    """
    return _get_log().append(
        event_type=event_type,
        command_id=command_id,
        target_action=target_action,
        status=status,
        detail=detail,
    )


def audit_get_trace(command_id: str) -> list[AuditEvent]:
    """Get the full audit trace for a command.

    Args:
        command_id: The command ID to search for.

    Returns:
        List of AuditEvent objects in chronological order.
    """
    return _get_log().get_trace(command_id)
