"""Jarvis v2.1 — Command-control runtime for PC and home automation.

Phase 1: Schema validator, policy classifier, and audit log.

See JARVIS_V2_1_SPEC.md for the full spec.
"""

from jarvis.types import (
    Command,
    ValidationResult,
    Policy,
    GateOutcome,
    QueueStatus,
    AuditEvent,
)

from jarvis.policy import (
    PolicyEngine,
    classify_command,
    load_policy,
)

from jarvis.validator import (
    CommandValidator,
    validate_command,
)

from jarvis.audit import (
    AuditLog,
)

__version__ = "2.1.0"
__all__ = [
    "Command",
    "ValidationResult",
    "Policy",
    "GateOutcome",
    "QueueStatus",
    "AuditEvent",
    "PolicyEngine",
    "classify_command",
    "load_policy",
    "CommandValidator",
    "validate_command",
    "AuditLog",
]
