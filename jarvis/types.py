"""Shared data types for Jarvis v2.1 command-control runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Policy(Enum):
    """Risk policy classification for a command action."""

    AUTO_APPROVE = "auto-approve"
    AUTO_APPROVE_AUDIT = "auto-approve-audit"
    ALWAYS_CONFIRM = "always-confirm"
    BLOCKED = "blocked"


class GateOutcome(Enum):
    """Outcome of the risk policy gate."""

    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"


class QueueStatus(Enum):
    """Canonical queue status for a command (5 states)."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class AuditEventType(Enum):
    """Audit log event types aligned to the canonical status model."""

    COMMAND_SUBMITTED = "COMMAND_SUBMITTED"
    COMMAND_VALIDATED = "COMMAND_VALIDATED"
    COMMAND_REJECTED_SCHEMA = "COMMAND_REJECTED_SCHEMA"
    COMMAND_POLICY_CLASSIFIED = "COMMAND_POLICY_CLASSIFIED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_TIMED_OUT = "APPROVAL_TIMED_OUT"
    COMMAND_QUEUED = "COMMAND_QUEUED"
    COMMAND_DEQUEUED = "COMMAND_DEQUEUED"
    COMMAND_EXECUTING = "COMMAND_EXECUTING"
    COMMAND_SUCCEEDED = "COMMAND_SUCCEEDED"
    COMMAND_FAILED = "COMMAND_FAILED"
    COMMAND_RETRYING = "COMMAND_RETRYING"
    COMMAND_DEAD_LETTER = "COMMAND_DEAD_LETTER"
    COMMAND_ROLLED_BACK = "COMMAND_ROLLED_BACK"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Command:
    """A validated Jarvis v2.1 command ready for the queue.

    Maps to the JSON schema from JARVIS_V2_1_SPEC.md §2.1.
    """

    target: str
    action: str
    parameter: str
    idempotency_key: str
    requested_at: str  # ISO 8601
    source: str = "api"
    priority: int = 5
    command_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "action": self.action,
            "parameter": self.parameter,
            "idempotency_key": self.idempotency_key,
            "requested_at": self.requested_at,
            "source": self.source,
            "priority": self.priority,
            "command_id": self.command_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Command:
        return cls(
            target=data["target"],
            action=data["action"],
            parameter=data["parameter"],
            idempotency_key=data["idempotency_key"],
            requested_at=data["requested_at"],
            source=data.get("source", "api"),
            priority=data.get("priority", 5),
            command_id=data.get("command_id", ""),
        )


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating a command against the schema and policy."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuditEvent:
    """A single entry in the append-only audit log."""

    timestamp: str  # ISO 8601
    event_type: str
    command_id: str
    target_action: str  # e.g. "HOME:TURN_ON"
    status: str
    detail: str
    prev_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "command_id": self.command_id,
            "target_action": self.target_action,
            "status": self.status,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        return cls(
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            command_id=data["command_id"],
            target_action=data["target_action"],
            status=data["status"],
            detail=data["detail"],
            prev_hash=data["prev_hash"],
            hash=data["hash"],
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
