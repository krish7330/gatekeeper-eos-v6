"""Command schema validator for Jarvis v2.1.

Validates incoming command dicts against the formal JSON schema (see
JARVIS_V2_1_SPEC.md §2.1). Checks required fields, target/action whitelists,
and parameter constraints.

Safe rules:
  - Fail closed: any unknown field, missing required field, or out-of-bounds
    value causes the command to be rejected before it reaches the queue.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from jarvis.policy import PolicyEngine
from jarvis.types import Command, ValidationResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pattern: CMD- followed by 8-16 alphanumeric chars
COMMAND_ID_PATTERN = re.compile(r"^CMD-[a-zA-Z0-9]{8,16}$")

# Pattern: IDEM- followed by 32 hex chars
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^IDEM-[a-f0-9]{32}$")

# Pattern: ISO 8601 date-time (basic check)
ISO_DATETIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
)

# Allowed sources
ALLOWED_SOURCES = {"voice", "phone_shortcut", "widget", "web_ui", "routine", "api"}

# Parameter max length
PARAMETER_MAX_LENGTH = 512

# Priority bounds
PRIORITY_MIN = 0
PRIORITY_MAX = 10


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    """Base error for command validation."""


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class CommandValidator:
    """Validates incoming command dicts against the Jarvis v2.1 schema.

    Usage::

        validator = CommandValidator()
        result = validator.validate({"target": "PC", "action": "OPEN_URL", ...})
        if result.valid:
            command = Command.from_dict(data)
    """

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self._policy = policy_engine or PolicyEngine()

    # ------------------------------------------------------------------
    # Main validation entry point
    # ------------------------------------------------------------------

    def validate(self, data: dict[str, Any]) -> ValidationResult:
        """Validate a raw command dict against the Jarvis v2.1 schema.

        Returns a ValidationResult with:
        - ``valid``: True if the command passes all checks.
        - ``errors``: List of error messages (empty if valid).
        - ``warnings``: List of non-blocking warnings.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Ensure it's a dict
        if not isinstance(data, dict):
            return ValidationResult(valid=False, errors=["Command must be a JSON object"])

        # 2. Check for unknown properties (additionalProperties: false)
        known_properties = {
            "target", "action", "parameter",
            "idempotency_key", "requested_at",
            "source", "priority", "command_id",
        }
        unknown = [k for k in data if k not in known_properties]
        for key in unknown:
            errors.append(f"Unknown property: '{key}'")

        # 3. Check required fields
        required_fields = ["target", "action", "parameter", "idempotency_key", "requested_at"]
        for field in required_fields:
            if field not in data or data[field] is None:
                errors.append(f"Missing required field: '{field}'")
            elif not isinstance(data[field], str):
                errors.append(f"Field '{field}' must be a string, got {type(data[field]).__name__}")

        # If required fields are missing, return early — no point in further checks
        if errors:
            return ValidationResult(valid=False, errors=errors)

        # 4. Validate target
        target = data["target"]
        if not isinstance(target, str) or not self._policy.is_known_target(target):
            errors.append(f"Unknown target: '{target}'. Allowed: {', '.join(self._policy.list_targets())}")

        # 5. Validate action (against the target's whitelist)
        action = data["action"]
        if isinstance(action, str) and isinstance(target, str):
            if not self._policy.is_known_action(target, action):
                known = self._policy.list_actions(target)
                errors.append(f"Unknown action '{action}' for target '{target}'. Allowed: {', '.join(known)}")

        # 6. Validate parameter constraints
        parameter = data.get("parameter", "")
        if isinstance(parameter, str):
            if len(parameter) > PARAMETER_MAX_LENGTH:
                errors.append(f"Parameter exceeds max length ({PARAMETER_MAX_LENGTH} chars)")
        else:
            errors.append("Parameter must be a string")

        # 7. Validate idempotency_key pattern
        idem_key = data["idempotency_key"]
        if isinstance(idem_key, str) and not IDEMPOTENCY_KEY_PATTERN.match(idem_key):
            errors.append(
                f"Invalid idempotency_key format: '{idem_key}'. "
                f"Must match pattern: IDEM-<32 hex chars>"
            )

        # 8. Validate requested_at format
        requested_at = data["requested_at"]
        if isinstance(requested_at, str):
            if not ISO_DATETIME_PATTERN.match(requested_at):
                warnings.append(
                    f"requested_at '{requested_at}' does not look like ISO 8601"
                )
        else:
            errors.append("requested_at must be a string (ISO 8601)")

        # 9. Validate source if present
        source = data.get("source", "api")
        if isinstance(source, str) and source not in ALLOWED_SOURCES:
            warnings.append(
                f"Unknown source: '{source}'. Allowed: {', '.join(sorted(ALLOWED_SOURCES))}"
            )

        # 10. Validate priority if present
        priority = data.get("priority", 5)
        if isinstance(priority, int):
            if priority < PRIORITY_MIN or priority > PRIORITY_MAX:
                errors.append(f"Priority must be between {PRIORITY_MIN} and {PRIORITY_MAX}")
        elif not isinstance(priority, int):
            errors.append("Priority must be an integer")

        # 11. Validate command_id if present
        command_id = data.get("command_id", "")
        if isinstance(command_id, str) and command_id and not COMMAND_ID_PATTERN.match(command_id):
            errors.append(
                f"Invalid command_id format: '{command_id}'. "
                f"Must match pattern: CMD-<8-16 alphanumeric chars>"
            )

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    def validate_and_parse(self, data: dict[str, Any]) -> tuple[ValidationResult, Command | None]:
        """Validate a command dict and return a parsed Command if valid.

        Returns:
            Tuple of (ValidationResult, Command or None).
        """
        result = self.validate(data)
        if not result.valid:
            return result, None

        command = Command.from_dict(data)
        return result, command


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


_DEFAULT_VALIDATOR: CommandValidator | None = None


def _get_validator() -> CommandValidator:
    """Get or create the default command validator."""
    global _DEFAULT_VALIDATOR
    if _DEFAULT_VALIDATOR is None:
        _DEFAULT_VALIDATOR = CommandValidator()
    return _DEFAULT_VALIDATOR


def validate_command(data: dict[str, Any]) -> ValidationResult:
    """Validate a command using the default validator.

    Args:
        data: Raw command dict to validate.

    Returns:
        A ValidationResult.
    """
    return _get_validator().validate(data)
