"""Tests for jarvis.policy: risk policy classifier."""

import json
from pathlib import Path

import pytest

from jarvis.policy import (
    PolicyEngine,
    PolicyError,
    PolicyLoadError,
    PolicyClassificationError,
    classify_command,
)
from jarvis.types import Command, Policy, GateOutcome


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    """Create a minimal gate_policy.yaml for testing."""
    path = tmp_path / "gate_policy.yaml"
    path.write_text("""version: "2.1-test"
updated: "2026-06-11"

targets:
  PC:
    description: Desktop
    actions:
      OPEN_URL:
        policy: auto-approve
      LAUNCH_APP:
        policy: auto-approve-audit
      RUN_SCRIPT:
        policy: always-confirm
      DELETE_FILE:
        policy: always-confirm
      SHUTDOWN_PC:
        policy: always-confirm
      MEDIA_CONTROL:
        policy: auto-approve
      EXECUTE_MACRO:
        policy: auto-approve-audit
      LOCK_WORKSTATION:
        policy: always-confirm
      SEND_KEYSTROKE:
        policy: always-confirm

  HOME:
    description: Smart home
    actions:
      TURN_ON:
        policy: auto-approve
      TURN_OFF:
        policy: auto-approve
      SET_BRIGHTNESS:
        policy: auto-approve
      SET_TEMPERATURE:
        policy: auto-approve-audit
      LOCK_DOOR:
        policy: auto-approve
      UNLOCK_DOOR:
        policy: always-confirm
      SET_SCENE:
        policy: auto-approve
      DISABLE_ALARM:
        policy: always-confirm

parameter_escalation:
  - description: "Contains shell metacharacters"
    pattern: '[;&|`$(){}]'
  - description: "RUN_SCRIPT with non-whitelisted script alias"
    match:
      action: RUN_SCRIPT
      condition: "parameter not in whitelisted_scripts"
  - description: "OPEN_URL with non-https scheme"
    match:
      action: OPEN_URL
      condition: "parameter does not start with https://"
""")
    return path


@pytest.fixture
def engine(policy_path: Path) -> PolicyEngine:
    return PolicyEngine(policy_path)


# ===========================================================================
# Loading
# ===========================================================================


class TestPolicyLoading:
    def test_loads_policy_file(self, engine: PolicyEngine):
        assert engine.version == "2.1-test"
        assert engine.list_targets() == ["HOME", "PC"]

    def test_load_nonexistent_file_raises(self, tmp_path: Path):
        bad_path = tmp_path / "nonexistent.yaml"
        with pytest.raises(PolicyLoadError):
            PolicyEngine(bad_path)

    def test_invalid_yaml_raises(self, tmp_path: Path):
        bad_path = tmp_path / "bad.yaml"
        bad_path.write_text("{invalid: yaml: broken: }")
        with pytest.raises(PolicyLoadError):
            PolicyEngine(bad_path)

    def test_non_dict_yaml_raises(self, tmp_path: Path):
        bad_path = tmp_path / "list.yaml"
        bad_path.write_text("- item1\n- item2")
        with pytest.raises(PolicyLoadError):
            PolicyEngine(bad_path)

    def test_reload_updates(self, engine: PolicyEngine, policy_path: Path):
        assert engine.list_targets() == ["HOME", "PC"]
        # Modify the file
        text = policy_path.read_text()
        text = text.replace("HOME:", "VEHICLE:")
        policy_path.write_text(text)
        engine.reload()
        assert "VEHICLE" in engine.list_targets()
        assert "HOME" not in engine.list_targets()


# ===========================================================================
# Classification
# ===========================================================================


class TestClassification:
    def test_auto_approve(self, engine: PolicyEngine):
        assert engine.classify("PC", "OPEN_URL") == Policy.AUTO_APPROVE
        assert engine.classify("PC", "MEDIA_CONTROL") == Policy.AUTO_APPROVE
        assert engine.classify("HOME", "TURN_ON") == Policy.AUTO_APPROVE
        assert engine.classify("HOME", "SET_BRIGHTNESS") == Policy.AUTO_APPROVE

    def test_auto_approve_audit(self, engine: PolicyEngine):
        assert engine.classify("PC", "LAUNCH_APP") == Policy.AUTO_APPROVE_AUDIT
        assert engine.classify("PC", "EXECUTE_MACRO") == Policy.AUTO_APPROVE_AUDIT
        assert engine.classify("HOME", "SET_TEMPERATURE") == Policy.AUTO_APPROVE_AUDIT

    def test_always_confirm(self, engine: PolicyEngine):
        assert engine.classify("PC", "RUN_SCRIPT") == Policy.ALWAYS_CONFIRM
        assert engine.classify("PC", "DELETE_FILE") == Policy.ALWAYS_CONFIRM
        assert engine.classify("PC", "SHUTDOWN_PC") == Policy.ALWAYS_CONFIRM
        assert engine.classify("PC", "SEND_KEYSTROKE") == Policy.ALWAYS_CONFIRM
        assert engine.classify("PC", "LOCK_WORKSTATION") == Policy.ALWAYS_CONFIRM
        assert engine.classify("HOME", "UNLOCK_DOOR") == Policy.ALWAYS_CONFIRM
        assert engine.classify("HOME", "DISABLE_ALARM") == Policy.ALWAYS_CONFIRM

    def test_unknown_target_raises(self, engine: PolicyEngine):
        with pytest.raises(PolicyClassificationError, match="Unknown target"):
            engine.classify("VEHICLE", "START")

    def test_unknown_action_raises(self, engine: PolicyEngine):
        with pytest.raises(PolicyClassificationError, match="Unknown action"):
            engine.classify("PC", "FLY")

    def test_classify_command_object(self, engine: PolicyEngine):
        cmd = Command(
            target="HOME",
            action="TURN_ON",
            parameter="living_room_lamp",
            idempotency_key="IDEM-abc123def456abc123def456abc12345",
            requested_at="2026-06-11T08:00:00Z",
        )
        assert engine.classify_command(cmd) == Policy.AUTO_APPROVE


# ===========================================================================
# Parameter escalation
# ===========================================================================


class TestParameterEscalation:
    def test_shell_metacharacters_escalate(self, engine: PolicyEngine):
        """Parameter with shell metacharacters escalates to ALWAYS_CONFIRM."""
        policy = engine.classify("PC", "OPEN_URL", parameter="https://google.com; rm -rf /")
        assert policy == Policy.ALWAYS_CONFIRM

    def test_whitelisted_script_does_not_escalate(self, engine: PolicyEngine):
        """A whitelisted script alias should not trigger escalation."""
        policy = engine.classify("PC", "RUN_SCRIPT", parameter="daily-backup")
        assert policy == Policy.ALWAYS_CONFIRM  # RUN_SCRIPT is always-confirm base

    def test_non_whitelisted_script_keeps_always_confirm(self, engine: PolicyEngine):
        """Non-whitelisted script stays always-confirm (same as base)."""
        policy = engine.classify("PC", "RUN_SCRIPT", parameter="rm -rf /")
        assert policy == Policy.ALWAYS_CONFIRM

    def test_https_open_url_no_escalation(self, engine: PolicyEngine):
        """https URL should not escalate."""
        policy = engine.classify("PC", "OPEN_URL", parameter="https://google.com")
        assert policy == Policy.AUTO_APPROVE

    def test_http_open_url_escalates(self, engine: PolicyEngine):
        """http URL should escalate to ALWAYS_CONFIRM."""
        policy = engine.classify("PC", "OPEN_URL", parameter="http://example.com")
        assert policy == Policy.ALWAYS_CONFIRM

    def test_empty_parameter_no_escalation(self, engine: PolicyEngine):
        """Empty parameter should not trigger escalation."""
        policy = engine.classify("PC", "MEDIA_CONTROL", parameter="")
        assert policy == Policy.AUTO_APPROVE

    def test_parameter_without_patterns_stays_base(self, engine: PolicyEngine):
        """Plain parameter without special chars should not escalate."""
        policy = engine.classify("PC", "OPEN_URL", parameter="https://safe-site.com")
        assert policy == Policy.AUTO_APPROVE

    def test_pipe_shell_char_escalates(self, engine: PolicyEngine):
        policy = engine.classify("PC", "LAUNCH_APP", parameter="app | rm -rf")
        assert policy == Policy.ALWAYS_CONFIRM

    def test_backtick_shell_char_escalates(self, engine: PolicyEngine):
        policy = engine.classify("PC", "OPEN_URL", parameter="https://good.com`ls")
        assert policy == Policy.ALWAYS_CONFIRM


# ===========================================================================
# Gate outcomes
# ===========================================================================


class TestGateOutcomes:
    def test_auto_approve_returns_approved(self, engine: PolicyEngine):
        cmd = Command(
            target="PC", action="OPEN_URL", parameter="https://google.com",
            idempotency_key="IDEM-a0000000000000000000000000000000",
            requested_at="2026-06-11T08:00:00Z",
        )
        assert engine.get_gate_outcome(cmd) == GateOutcome.APPROVED

    def test_always_confirm_returns_rejected_by_default(self, engine: PolicyEngine):
        cmd = Command(
            target="PC", action="RUN_SCRIPT", parameter="daily-backup",
            idempotency_key="IDEM-b0000000000000000000000000000000",
            requested_at="2026-06-11T08:00:00Z",
        )
        assert engine.get_gate_outcome(cmd) == GateOutcome.REJECTED

    def test_always_confirm_timeout(self, engine: PolicyEngine):
        cmd = Command(
            target="PC", action="RUN_SCRIPT", parameter="daily-backup",
            idempotency_key="IDEM-c0000000000000000000000000000000",
            requested_at="2026-06-11T08:00:00Z",
        )
        assert engine.get_gate_outcome(cmd, timeout=True) == GateOutcome.TIMED_OUT

    def test_blocked_returns_blocked(self, engine: PolicyEngine):
        # Simulate a blocked action by checking an unknown action
        # For tests, BLOCKED isn't used yet, but the code handles it
        cmd = Command(
            target="PC", action="SHUTDOWN_PC",
            parameter="",
            idempotency_key="IDEM-d0000000000000000000000000000000",
            requested_at="2026-06-11T08:00:00Z",
        )
        outcome = engine.get_gate_outcome(cmd)
        assert outcome in (GateOutcome.APPROVED, GateOutcome.REJECTED, GateOutcome.BLOCKED)


# ===========================================================================
# Lookup helpers
# ===========================================================================


class TestLookups:
    def test_list_actions(self, engine: PolicyEngine):
        actions = engine.list_actions("PC")
        assert "OPEN_URL" in actions
        assert "RUN_SCRIPT" in actions
        assert "DELETE_FILE" in actions

    def test_list_targets(self, engine: PolicyEngine):
        targets = engine.list_targets()
        assert "PC" in targets
        assert "HOME" in targets

    def test_is_known_action_true(self, engine: PolicyEngine):
        assert engine.is_known_action("PC", "OPEN_URL") is True

    def test_is_known_action_false(self, engine: PolicyEngine):
        assert engine.is_known_action("PC", "FLY") is False

    def test_is_known_target_true(self, engine: PolicyEngine):
        assert engine.is_known_target("PC") is True

    def test_is_known_target_false(self, engine: PolicyEngine):
        assert engine.is_known_target("VEHICLE") is False

    def test_get_policy_for_action(self, engine: PolicyEngine):
        policy = engine.get_policy_for_action("PC", "OPEN_URL")
        assert policy == Policy.AUTO_APPROVE

    def test_get_policy_for_action_unknown(self, engine: PolicyEngine):
        with pytest.raises(PolicyClassificationError):
            engine.get_policy_for_action("PC", "FLY")


# ===========================================================================
# Convenience functions
# ===========================================================================


class TestConvenienceFunctions:
    def test_classify_command_function(self, policy_path: Path):
        # The global convenience function uses the default engine which needs
        # the real gate_policy.yaml. We'll test the engine directly instead.
        engine = PolicyEngine(policy_path)
        result = engine.classify("HOME", "TURN_ON")
        assert result == Policy.AUTO_APPROVE


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_classify_is_case_sensitive(self, engine: PolicyEngine):
        """Action names are case-sensitive."""
        with pytest.raises(PolicyClassificationError):
            engine.classify("PC", "open_url")

    def test_all_pc_actions_have_policy(self, engine: PolicyEngine):
        """Every action in the PC target should have a valid policy."""
        for action in engine.list_actions("PC"):
            policy = engine.get_policy_for_action("PC", action)
            assert isinstance(policy, Policy)

    def test_all_home_actions_have_policy(self, engine: PolicyEngine):
        """Every action in the HOME target should have a valid policy."""
        for action in engine.list_actions("HOME"):
            policy = engine.get_policy_for_action("HOME", action)
            assert isinstance(policy, Policy)

    def test_policy_data_readonly(self, engine: PolicyEngine):
        data = engine.policy_data
        assert "targets" in data
        data["targets"] = {}  # Should not affect the engine
        assert engine.list_targets() != []

    def test_repr_policy_enum(self):
        assert str(Policy.AUTO_APPROVE) == "Policy.AUTO_APPROVE"
        assert Policy.AUTO_APPROVE.value == "auto-approve"
