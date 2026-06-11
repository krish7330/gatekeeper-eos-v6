"""Tests for jarvis.validator: command schema validation."""

from pathlib import Path

import pytest

from jarvis.policy import PolicyEngine
from jarvis.validator import CommandValidator, ValidationError
from jarvis.types import Command


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    """Create a minimal gate_policy.yaml for testing."""
    path = tmp_path / "gate_policy.yaml"
    path.write_text("""version: "2.1-test"
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
      MEDIA_CONTROL:
        policy: auto-approve
  HOME:
    description: Smart home
    actions:
      TURN_ON:
        policy: auto-approve
      TURN_OFF:
        policy: auto-approve
      UNLOCK_DOOR:
        policy: always-confirm
parameter_escalation: []
""")
    return path


@pytest.fixture
def validator(policy_path: Path) -> CommandValidator:
    engine = PolicyEngine(policy_path)
    return CommandValidator(engine)


@pytest.fixture
def valid_command() -> dict:
    return {
        "target": "PC",
        "action": "OPEN_URL",
        "parameter": "https://example.com",
        "idempotency_key": "IDEM-abcdef1234567890abcdef1234567890",
        "requested_at": "2026-06-11T08:00:00Z",
        "source": "web_ui",
        "priority": 5,
    }


# ===========================================================================
# Basic validation
# ===========================================================================


class TestBasicValidation:
    def test_valid_command_passes(self, validator: CommandValidator, valid_command: dict):
        result = validator.validate(valid_command)
        assert result.valid is True
        assert result.errors == []

    def test_non_dict_fails(self, validator: CommandValidator):
        result = validator.validate("not a dict")
        assert result.valid is False
        assert any("JSON object" in e for e in result.errors)

    def test_empty_dict_fails(self, validator: CommandValidator):
        result = validator.validate({})
        assert result.valid is False
        assert any("target" in e for e in result.errors)

    def test_none_values_fail(self, validator: CommandValidator):
        result = validator.validate({
            "target": None,
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "idempotency_key": "IDEM-abcdef1234567890abcdef1234567890",
            "requested_at": "2026-06-11T08:00:00Z",
        })
        assert result.valid is False
        assert any("target" in e for e in result.errors)


# ===========================================================================
# Required fields
# ===========================================================================


class TestRequiredFields:
    def test_missing_target_fails(self, validator: CommandValidator):
        data = {
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "idempotency_key": "IDEM-abcdef1234567890abcdef1234567890",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        result = validator.validate(data)
        assert result.valid is False
        assert any("target" in e for e in result.errors)

    def test_missing_idempotency_key_fails(self, validator: CommandValidator):
        data = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        result = validator.validate(data)
        assert result.valid is False
        assert any("idempotency_key" in e for e in result.errors)

    def test_missing_requested_at_fails(self, validator: CommandValidator):
        data = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "idempotency_key": "IDEM-abcdef1234567890abcdef1234567890",
        }
        result = validator.validate(data)
        assert result.valid is False
        assert any("requested_at" in e for e in result.errors)

    def test_missing_all_required_fails(self, validator: CommandValidator):
        result = validator.validate({})
        required_fields = ["target", "action", "parameter", "idempotency_key", "requested_at"]
        missing_errors = [f"'{f}'" for f in required_fields]
        assert result.valid is False
        # At least some required field errors should be present
        assert len(result.errors) >= len(required_fields)


# ===========================================================================
# Target validation
# ===========================================================================


class TestTargetValidation:
    def test_valid_target_passes(self, validator: CommandValidator, valid_command: dict):
        result = validator.validate(valid_command)
        assert result.valid is True

    def test_invalid_target_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["target"] = "VEHICLE"
        result = validator.validate(data)
        assert result.valid is False
        assert any("target" in e for e in result.errors)


# ===========================================================================
# Action validation
# ===========================================================================


class TestActionValidation:
    def test_valid_action_passes(self, validator: CommandValidator, valid_command: dict):
        result = validator.validate(valid_command)
        assert result.valid is True

    def test_invalid_action_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["action"] = "FLY"
        result = validator.validate(data)
        assert result.valid is False
        assert any("action" in e for e in result.errors)

    def test_action_valid_for_target_but_wrong_target(self, validator: CommandValidator):
        # TURN_ON is valid for HOME but not PC
        data = {
            "target": "PC",
            "action": "TURN_ON",
            "parameter": "light",
            "idempotency_key": "IDEM-abcdef1234567890abcdef1234567890",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        result = validator.validate(data)
        assert result.valid is False
        assert any("action" in e for e in result.errors)


# ===========================================================================
# Parameter validation
# ===========================================================================


class TestParameterValidation:
    def test_parameter_too_long_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["parameter"] = "x" * 600
        result = validator.validate(data)
        assert result.valid is False
        assert any("max length" in e.lower() for e in result.errors)

    def test_non_string_parameter_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["parameter"] = 12345
        result = validator.validate(data)
        assert result.valid is False
        assert any("string" in e.lower() for e in result.errors)

    def test_empty_parameter_passes(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["parameter"] = ""
        result = validator.validate(data)
        assert result.valid is True


# ===========================================================================
# Idempotency key validation
# ===========================================================================


class TestIdempotencyKey:
    def test_valid_key_passes(self, validator: CommandValidator, valid_command: dict):
        result = validator.validate(valid_command)
        assert result.valid is True

    def test_invalid_key_format_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["idempotency_key"] = "bad-key"
        result = validator.validate(data)
        assert result.valid is False
        assert any("idempotency_key" in e for e in result.errors)

    def test_missing_key_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        del data["idempotency_key"]
        result = validator.validate(data)
        assert result.valid is False

    def test_key_without_idem_prefix_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["idempotency_key"] = "abcdef1234567890abcdef1234567890"
        result = validator.validate(data)
        assert result.valid is False


# ===========================================================================
# Priority validation
# ===========================================================================


class TestPriority:
    def test_priority_within_range_passes(self, validator: CommandValidator, valid_command: dict):
        for p in [0, 5, 10]:
            data = dict(valid_command)
            data["priority"] = p
            result = validator.validate(data)
            assert result.valid is True

    def test_priority_too_low_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["priority"] = -1
        result = validator.validate(data)
        assert result.valid is False

    def test_priority_too_high_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["priority"] = 11
        result = validator.validate(data)
        assert result.valid is False

    def test_non_int_priority_warns(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["priority"] = "high"
        result = validator.validate(data)
        # Non-integer priority produces an error (strict validation)
        assert result.valid is False


# ===========================================================================
# Unknown properties
# ===========================================================================


class TestUnknownProperties:
    def test_unknown_property_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["unknown_field"] = "value"
        result = validator.validate(data)
        assert result.valid is False
        assert any("unknown" in e.lower() for e in result.errors)


# ===========================================================================
# Command ID validation
# ===========================================================================


class TestCommandId:
    def test_valid_command_id_passes(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["command_id"] = "CMD-a1b2c3d4e5f6"
        result = validator.validate(data)
        assert result.valid is True

    def test_invalid_command_id_fails(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["command_id"] = "bad-id"
        result = validator.validate(data)
        assert result.valid is False

    def test_empty_command_id_skips_check(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["command_id"] = ""
        result = validator.validate(data)
        assert result.valid is True


# ===========================================================================
# Validate and parse
# ===========================================================================


class TestValidateAndParse:
    def test_valid_returns_command(self, validator: CommandValidator, valid_command: dict):
        result, cmd = validator.validate_and_parse(valid_command)
        assert result.valid is True
        assert isinstance(cmd, Command)
        assert cmd.target == "PC"
        assert cmd.action == "OPEN_URL"

    def test_invalid_returns_none(self, validator: CommandValidator, valid_command: dict):
        data = dict(valid_command)
        data["target"] = "BAD"
        result, cmd = validator.validate_and_parse(data)
        assert result.valid is False
        assert cmd is None
