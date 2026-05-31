"""Lock acquisition order enforcement for multi-session orchestration.

Prevents deadlocks by enforcing a strict acquire order across all
session mutexes. The lock order is defined in the orchestrator YAML
and must be respected by all sessions.

Safe rules:
  - Fail closed on any lock-order violation.
  - All mutexes must be acquired in ascending order.
  - A session cannot hold a lock with a higher order while requesting
    a lower-order lock.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class LockType(Enum):
    EXCLUSIVE = auto()
    SHARED = auto()
    APPEND_ONLY = auto()


class LockError(Exception):
    """Base error for lock operations."""


class LockOrderViolation(LockError):
    """Raised when a lock is acquired out of order (deadlock risk)."""


class LockNotHeld(LockError):
    """Raised when releasing a lock that is not held."""


# ---------------------------------------------------------------------------
# Mutex definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Mutex:
    """Definition of a named mutex with type and acquisition order.

    Matches the mutexes section of the orchestrator YAML:
      mutexes:
        scope_mutex:
          type: exclusive
          owner: orchestrator
          acquire_order: 1
    """

    name: str
    lock_type: LockType
    owner: str  # e.g. "orchestrator", "policy_gate", "session", "logger"
    acquire_order: int

    def __post_init__(self) -> None:
        if self.acquire_order < 1:
            raise ValueError(f"acquire_order must be >= 1, got {self.acquire_order}")


# ---------------------------------------------------------------------------
# Standard mutex set (from the orchestrator YAML)
# ---------------------------------------------------------------------------

STANDARD_MUTEXES = [
    Mutex(name="scope_mutex", lock_type=LockType.EXCLUSIVE, owner="orchestrator", acquire_order=1),
    Mutex(name="tool_mutex", lock_type=LockType.SHARED, owner="policy_gate", acquire_order=2),
    Mutex(name="checkpoint_mutex", lock_type=LockType.EXCLUSIVE, owner="session", acquire_order=3),
    Mutex(name="evidence_mutex", lock_type=LockType.APPEND_ONLY, owner="logger", acquire_order=4),
]

# Build lookup by name
MUTEX_REGISTRY: dict[str, Mutex] = {m.name: m for m in STANDARD_MUTEXES}


# ---------------------------------------------------------------------------
# Lock manager
# ---------------------------------------------------------------------------


@dataclass
class LockManager:
    """Manages lock acquisition with deadlock prevention via order enforcement.

    Usage:
        mgr = LockManager()
        with mgr.acquire("scope_mutex") as held:
            # critical section
            pass
    """

    _held: dict[str, int] = field(default_factory=dict)
    _on_violation: Callable[[str, int, int], None] | None = None

    @staticmethod
    def default() -> LockManager:
        """Return a LockManager with the standard mutex set."""
        return LockManager()

    def register(self, mutex: Mutex) -> None:
        """Register a mutex definition."""
        MUTEX_REGISTRY[mutex.name] = mutex

    def acquire(self, name: str) -> "_LockContext":
        """Acquire a lock by name, enforcing order.

        Returns a context manager that releases the lock on exit.
        Raises LockOrderViolation if acquisition would violate order.
        """
        mutex = MUTEX_REGISTRY.get(name)
        if mutex is None:
            raise LockError(f"Unknown mutex: {name}")

        order = mutex.acquire_order

        # Enforce acquisition order: must acquire in strictly ascending order.
        # Same-order re-acquire is also a violation (can't hold the same lock twice).
        for held_name, held_order in self._held.items():
            if order <= held_order:
                viol_msg = (
                    f"Lock-order violation: cannot acquire '{name}' (order {order}) "
                    f"while holding '{held_name}' (order {held_order}). "
                    f"Locks must be acquired in ascending order."
                )
                if self._on_violation:
                    self._on_violation(name, order, held_order)
                raise LockOrderViolation(viol_msg)

        self._held[name] = order
        return _LockContext(self, name)

    def release(self, name: str) -> None:
        """Release a held lock."""
        if name not in self._held:
            raise LockNotHeld(f"Cannot release '{name}': not held")
        del self._held[name]

    def is_held(self, name: str) -> bool:
        """Check whether a lock is currently held."""
        return name in self._held

    @property
    def held_locks(self) -> list[str]:
        """Return list of currently held lock names, in acquisition order."""
        return sorted(self._held.keys(), key=lambda n: self._held[n])

    @property
    def is_clean(self) -> bool:
        """True when no locks are held."""
        return len(self._held) == 0


# ---------------------------------------------------------------------------
# Lock context manager
# ---------------------------------------------------------------------------


class _LockContext:
    """Context manager returned by LockManager.acquire()."""

    def __init__(self, manager: LockManager, name: str) -> None:
        self._manager = manager
        self._name = name

    def __enter__(self) -> str:
        return self._name

    def __exit__(self, *args: object) -> None:
        self._manager.release(self._name)


# ---------------------------------------------------------------------------
# Deadlock detection utilities
# ---------------------------------------------------------------------------


def check_acquisition_order(
    sequence: list[str],
) -> list[str]:
    """Check a lock acquisition sequence for order violations.

    Args:
        sequence: List of lock names in the order they would be acquired.

    Returns:
        List of error messages (empty = sequence is valid).
    """
    errors: list[str] = []
    held: dict[str, int] = {}

    for name in sequence:
        mutex = MUTEX_REGISTRY.get(name)
        if mutex is None:
            errors.append(f"Unknown mutex: {name}")
            continue

        order = mutex.acquire_order
        for held_name, held_order in held.items():
            if order < held_order:
                errors.append(
                    f"Cannot acquire '{name}' (order {order}) after "
                    f"'{held_name}' (order {held_order})"
                )
        held[name] = order

    return errors


def validate_lock_mapping(
    owner_sequence: dict[str, list[str]],
) -> list[str]:
    """Validate lock acquisition sequences for each session/owner.

    Args:
        owner_sequence: Map of owner name to list of lock names
                        in the order they would be acquired.

    Returns:
        List of error messages (empty = all sequences are valid).
    """
    all_errors: list[str] = []
    for owner, sequence in owner_sequence.items():
        errors = check_acquisition_order(sequence)
        for err in errors:
            all_errors.append(f"[{owner}] {err}")
    return all_errors
