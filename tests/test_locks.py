"""Tests for lock acquisition order enforcement and deadlock prevention."""

import pytest

from gatekeeper_eos_v6.locks import (
    LockType,
    LockError,
    LockOrderViolation,
    LockNotHeld,
    Mutex,
    LockManager,
    STANDARD_MUTEXES,
    MUTEX_REGISTRY,
    check_acquisition_order,
    validate_lock_mapping,
)


# ===========================================================================
# Mutex definition
# ===========================================================================


class TestMutexDefinition:
    """Mutex dataclass construction and validation."""

    def test_create_mutex(self):
        m = Mutex(name="test_mutex", lock_type=LockType.EXCLUSIVE, owner="test", acquire_order=1)
        assert m.name == "test_mutex"
        assert m.lock_type == LockType.EXCLUSIVE
        assert m.owner == "test"
        assert m.acquire_order == 1

    def test_zero_acquire_order_raises(self):
        with pytest.raises(ValueError, match="acquire_order"):
            Mutex(name="bad", lock_type=LockType.SHARED, owner="test", acquire_order=0)

    def test_negative_acquire_order_raises(self):
        with pytest.raises(ValueError, match="acquire_order"):
            Mutex(name="bad", lock_type=LockType.SHARED, owner="test", acquire_order=-1)

    def test_mutex_is_frozen(self):
        m = Mutex(name="frozen", lock_type=LockType.EXCLUSIVE, owner="test", acquire_order=1)
        with pytest.raises(AttributeError):
            m.name = "changed"

    def test_lock_type_enum_values(self):
        assert LockType.EXCLUSIVE.value == 1
        assert LockType.SHARED.value == 2
        assert LockType.APPEND_ONLY.value == 3

    def test_standard_mutexes_defined(self):
        assert len(STANDARD_MUTEXES) == 4
        names = [m.name for m in STANDARD_MUTEXES]
        assert names == ["scope_mutex", "tool_mutex", "checkpoint_mutex", "evidence_mutex"]

    def test_standard_mutexes_have_unique_orders(self):
        orders = [m.acquire_order for m in STANDARD_MUTEXES]
        assert len(orders) == len(set(orders))

    def test_registry_has_all_standard(self):
        for m in STANDARD_MUTEXES:
            assert m.name in MUTEX_REGISTRY
            assert MUTEX_REGISTRY[m.name] is m


# ===========================================================================
# LockManager — acquire and release in order
# ===========================================================================


class TestLockManagerAcquireRelease:
    """LockManager acquire/release with correct order."""

    def test_acquire_single_lock(self):
        mgr = LockManager.default()
        with mgr.acquire("scope_mutex") as name:
            assert name == "scope_mutex"
            assert mgr.is_held("scope_mutex")
        assert mgr.is_clean

    def test_acquire_in_order(self):
        mgr = LockManager.default()
        with mgr.acquire("scope_mutex"):
            assert mgr.held_locks == ["scope_mutex"]
            with mgr.acquire("tool_mutex"):
                assert mgr.held_locks == ["scope_mutex", "tool_mutex"]
                with mgr.acquire("checkpoint_mutex"):
                    assert mgr.held_locks == ["scope_mutex", "tool_mutex", "checkpoint_mutex"]
                # After checkpoint_mutex released, tool_mutex still held
                assert mgr.held_locks == ["scope_mutex", "tool_mutex"]
            # After tool_mutex released, only scope_mutex held
            assert mgr.held_locks == ["scope_mutex"]
        assert mgr.is_clean

    def test_acquire_all_four_in_order(self):
        mgr = LockManager.default()
        with mgr.acquire("scope_mutex"):
            with mgr.acquire("tool_mutex"):
                with mgr.acquire("checkpoint_mutex"):
                    with mgr.acquire("evidence_mutex"):
                        assert len(mgr.held_locks) == 4
        assert mgr.is_clean

    def test_release_specific_lock(self):
        mgr = LockManager.default()
        mgr.acquire("scope_mutex").__enter__()
        assert mgr.is_held("scope_mutex")
        mgr.release("scope_mutex")
        assert not mgr.is_held("scope_mutex")

    def test_context_manager_releases_on_exit(self):
        mgr = LockManager.default()
        with mgr.acquire("tool_mutex"):
            assert mgr.is_held("tool_mutex")
        assert not mgr.is_held("tool_mutex")

    def test_context_manager_handles_exception(self):
        mgr = LockManager.default()
        try:
            with mgr.acquire("scope_mutex"):
                assert mgr.is_held("scope_mutex")
                raise ValueError("test error")
        except ValueError:
            pass
        assert mgr.is_clean

    def test_is_held_returns_false_for_unheld(self):
        mgr = LockManager.default()
        assert not mgr.is_held("nonexistent")
        assert not mgr.is_held("scope_mutex")

    def test_is_clean_on_empty(self):
        mgr = LockManager.default()
        assert mgr.is_clean

    def test_is_clean_after_acquire_release(self):
        mgr = LockManager.default()
        mgr.acquire("scope_mutex").__enter__()
        assert not mgr.is_clean
        mgr.release("scope_mutex")
        assert mgr.is_clean

    def test_acquire_unknown_mutex_raises(self):
        mgr = LockManager.default()
        with pytest.raises(LockError, match="Unknown"):
            mgr.acquire("nonexistent_mutex")

    def test_register_new_mutex(self):
        mgr = LockManager()
        new_mutex = Mutex(name="custom_lock", lock_type=LockType.EXCLUSIVE, owner="custom", acquire_order=10)
        mgr.register(new_mutex)
        # Verify it's in the global registry
        assert "custom_lock" in MUTEX_REGISTRY
        assert MUTEX_REGISTRY["custom_lock"] is new_mutex

    def test_release_not_held_raises(self):
        mgr = LockManager.default()
        with pytest.raises(LockNotHeld):
            mgr.release("scope_mutex")

    def test_held_locks_returns_empty_when_none(self):
        mgr = LockManager.default()
        assert mgr.held_locks == []

    def test_held_locks_in_order(self):
        mgr = LockManager.default()
        with mgr.acquire("scope_mutex"):
            with mgr.acquire("checkpoint_mutex"):
                held = mgr.held_locks
                assert held == ["scope_mutex", "checkpoint_mutex"]


# ===========================================================================
# Lock-order violations
# ===========================================================================


class TestLockOrderViolations:
    """Acquiring locks out of order must raise."""

    def test_acquire_out_of_order_raises(self):
        mgr = LockManager.default()
        with mgr.acquire("tool_mutex"):  # order 2
            with pytest.raises(LockOrderViolation):
                mgr.acquire("scope_mutex")  # order 1 — lower

    def test_skip_order_and_go_back_raises(self):
        mgr = LockManager.default()
        with mgr.acquire("scope_mutex"):  # order 1
            with mgr.acquire("checkpoint_mutex"):  # order 3 — skipping 2
                with pytest.raises(LockOrderViolation):
                    mgr.acquire("tool_mutex")  # order 2 — lower

    def test_violation_message_includes_names_and_orders(self):
        mgr = LockManager.default()
        with mgr.acquire("checkpoint_mutex"):  # order 3
            try:
                mgr.acquire("scope_mutex")  # order 1
                pytest.fail("Expected LockOrderViolation")
            except LockOrderViolation as e:
                msg = str(e)
                assert "scope_mutex" in msg
                assert "checkpoint_mutex" in msg
                assert "1" in msg
                assert "3" in msg

    def test_violation_still_releases_on_context_exit(self):
        """After a violation, exiting the outer context still releases the held lock."""
        mgr = LockManager.default()
        try:
            with mgr.acquire("evidence_mutex"):  # order 4
                with mgr.acquire("scope_mutex"):  # order 1 — violation
                    pytest.fail("Should have raised")
        except LockOrderViolation:
            pass
        assert mgr.is_clean

    def test_register_then_violation(self):
        mgr = LockManager.default()
        high = Mutex(name="high_mutex", lock_type=LockType.EXCLUSIVE, owner="test", acquire_order=100)
        low = Mutex(name="low_mutex", lock_type=LockType.SHARED, owner="test", acquire_order=1)
        mgr.register(high)
        mgr.register(low)

        with mgr.acquire("high_mutex"):
            with pytest.raises(LockOrderViolation):
                mgr.acquire("low_mutex")

    def test_on_violation_callback(self):
        """The _on_violation callback should be invoked on violation."""
        violations = []

        def callback(name, order, held_order):
            violations.append((name, order, held_order))

        mgr = LockManager.default()
        mgr._on_violation = callback
        with mgr.acquire("evidence_mutex"):  # order 4
            try:
                mgr.acquire("scope_mutex")  # order 1
            except LockOrderViolation:
                pass
        assert len(violations) == 1
        assert violations[0][0] == "scope_mutex"
        assert violations[0][1] == 1


# ===========================================================================
# Concurrent access simulation
# ===========================================================================


class TestConcurrentAccess:
    """Multiple LockManagers handle concurrent access independently."""

    def test_two_managers_independent(self):
        mgr_a = LockManager.default()
        mgr_b = LockManager.default()

        with mgr_a.acquire("scope_mutex"):
            assert mgr_a.is_held("scope_mutex")
            assert not mgr_b.is_held("scope_mutex")

            with mgr_b.acquire("scope_mutex"):
                # Both hold their own scope_mutex
                assert mgr_b.is_held("scope_mutex")
                assert mgr_a.is_held("scope_mutex")

        assert mgr_a.is_clean
        assert mgr_b.is_clean

    def test_interleaved_ordering(self):
        """Each manager independently enforces its own order."""
        mgr1 = LockManager.default()
        mgr2 = LockManager.default()

        with mgr1.acquire("scope_mutex"):  # order 1
            with mgr2.acquire("tool_mutex"):  # order 2 — starts fresh within mgr2
                # mgr1 has order 1, mgr2 has order 2 — no conflict
                assert mgr1.is_held("scope_mutex")
                assert mgr2.is_held("tool_mutex")

                with mgr1.acquire("checkpoint_mutex"):  # order 3 > 1
                    assert mgr1.held_locks == ["scope_mutex", "checkpoint_mutex"]

                with mgr2.acquire("evidence_mutex"):  # order 4 > 2
                    assert mgr2.held_locks == ["tool_mutex", "evidence_mutex"]


# ===========================================================================
# Static analysis utilities
# ===========================================================================


class TestCheckAcquisitionOrder:
    """check_acquisition_order statically validates lock sequences."""

    def test_valid_sequence(self):
        errors = check_acquisition_order(["scope_mutex", "tool_mutex", "checkpoint_mutex"])
        assert errors == []

    def test_invalid_sequence(self):
        errors = check_acquisition_order(["evidence_mutex", "scope_mutex"])
        assert len(errors) >= 1
        assert "evidence_mutex" in errors[0]
        assert "scope_mutex" in errors[0]

    def test_unknown_mutex_flagged(self):
        errors = check_acquisition_order(["scope_mutex", "unknown_mutex"])
        assert any("unknown_mutex" in e for e in errors)

    def test_single_lock_is_valid(self):
        errors = check_acquisition_order(["scope_mutex"])
        assert errors == []

    def test_empty_sequence_is_valid(self):
        errors = check_acquisition_order([])
        assert errors == []

    def test_all_four_valid(self):
        errors = check_acquisition_order(["scope_mutex", "tool_mutex", "checkpoint_mutex", "evidence_mutex"])
        assert errors == []

    def test_reverse_all_four_invalid(self):
        errors = check_acquisition_order(["evidence_mutex", "checkpoint_mutex", "tool_mutex", "scope_mutex"])
        assert len(errors) >= 3


class TestValidateLockMapping:
    """validate_lock_mapping checks sequences for multiple owners."""

    def test_all_valid(self):
        mapping = {
            "orchestrator": ["scope_mutex", "tool_mutex"],
            "session": ["scope_mutex", "tool_mutex", "checkpoint_mutex"],
            "logger": ["scope_mutex", "evidence_mutex"],
        }
        errors = validate_lock_mapping(mapping)
        assert errors == []

    def test_one_invalid(self):
        mapping = {
            "orchestrator": ["scope_mutex", "tool_mutex"],
            "session": ["checkpoint_mutex", "scope_mutex"],  # reverse order
        }
        errors = validate_lock_mapping(mapping)
        assert len(errors) >= 1
        assert any("[session]" in e for e in errors)

    def test_all_invalid_returns_all_errors(self):
        mapping = {
            "owner_a": ["evidence_mutex", "scope_mutex"],
            "owner_b": ["checkpoint_mutex", "scope_mutex"],
        }
        errors = validate_lock_mapping(mapping)
        assert len(errors) >= 2

    def test_empty_mapping(self):
        errors = validate_lock_mapping({})
        assert errors == []

    def test_unknown_mutex_reported_with_owner_prefix(self):
        mapping = {
            "rogue": ["scope_mutex", "nonexistent_lock"],
        }
        errors = validate_lock_mapping(mapping)
        assert any("[rogue]" in e for e in errors)
        assert any("nonexistent_lock" in e for e in errors)


# ===========================================================================
# Deadlock prevention
# ===========================================================================


class TestDeadlockPrevention:
    """Scenarios that would cause deadlocks must be caught statically."""

    def test_cyclic_dependency_detected(self):
        """Two owners trying to acquire locks in opposite orders."""
        mapping = {
            "session_a": ["scope_mutex", "evidence_mutex"],  # order 1, then 4
            "session_b": ["evidence_mutex", "scope_mutex"],  # order 4, then 1 - BAD
        }
        errors = validate_lock_mapping(mapping)
        assert len(errors) >= 1
        # session_b should have the error
        assert any("[session_b]" in e for e in errors)

    def test_nested_skip_and_reverse(self):
        """More complex deadlock pattern with 3 locks."""
        from gatekeeper_eos_v6.locks import LockManager

        mgr = LockManager.default()
        mgr.register(Mutex(name="lock_a", lock_type=LockType.EXCLUSIVE, owner="test", acquire_order=5))
        mgr.register(Mutex(name="lock_b", lock_type=LockType.SHARED, owner="test", acquire_order=6))

        # Attempt: scope(1) → lock_a(5) → scope(1) — reverse!
        with mgr.acquire("scope_mutex"):
            with mgr.acquire("lock_a"):
                with pytest.raises(LockOrderViolation):
                    mgr.acquire("scope_mutex")  # order 1 < 5 held

    def test_same_order_cannot_reacquire(self):
        """Re-acquiring the same lock is not supported."""
        mgr = LockManager.default()
        with mgr.acquire("scope_mutex"):
            with pytest.raises(LockOrderViolation):
                mgr.acquire("scope_mutex")  # same name, can't re-acquire


# ===========================================================================
# Allowlist rejection enforcement (lock-level)
# ===========================================================================


class TestAllowlistRejection:
    """Lock manager enforces that unauthorized operations are rejected."""

    def test_unauthorized_mutex_rejected(self):
        """Acquiring a mutex not in the registry should be rejected."""
        mgr = LockManager()
        with pytest.raises(LockError, match="Unknown"):
            mgr.acquire("truly_unknown_mutex")

    def test_owner_check_not_enforced_by_locks(self):
        """Locks don't enforce ownership — that's a policy-layer concern."""
        mgr = LockManager.default()
        # Any caller can acquire any registered lock; ownership is advisory
        with mgr.acquire("evidence_mutex"):
            assert mgr.is_held("evidence_mutex")

    def test_allowlist_rejection_via_static_analysis(self):
        """Static analysis can reject sequences that include unregistered mutexes."""
        from gatekeeper_eos_v6.locks import check_acquisition_order
        errors = check_acquisition_order(["scope_mutex", "unregistered_lock"])
        assert any("unregistered_lock" in e for e in errors)
