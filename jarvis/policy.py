"""Risk policy classifier for Jarvis v2.1.

Reads ``gate_policy.yaml`` and classifies incoming commands into one of four
policy outcomes: auto-approve, auto-approve-audit, always-confirm, or blocked.

See JARVIS_V2_1_SPEC.md §3 for the full design.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from jarvis.types import Command, GateOutcome, Policy


# ---------------------------------------------------------------------------
# Default policy path
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = HERE / "gate_policy.yaml"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PolicyError(Exception):
    """Base error for policy operations."""


class PolicyLoadError(PolicyError):
    """Raised when policy YAML cannot be loaded or parsed."""


class PolicyClassificationError(PolicyError):
    """Raised when a command cannot be classified."""


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Classifies commands using the gate_policy.yaml rules.

    Usage::

        engine = PolicyEngine()
        policy = engine.classify(target="PC", action="RUN_SCRIPT", parameter="rm -rf /")
        # → Policy.ALWAYS_CONFIRM
    """

    def __init__(self, policy_path: str | Path | None = None) -> None:
        self._path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        self._policy: dict[str, Any] = {}
        self._action_map: dict[str, dict[str, str]] = {}  # target -> {action: policy}
        self._parameter_patterns: list[dict[str, Any]] = []
        self.load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load and parse the policy YAML file."""
        path = self._path
        if not path.exists():
            raise PolicyLoadError(f"Policy file not found: {path}")

        raw = path.read_text(encoding="utf-8")
        try:
            data: dict[str, Any] = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise PolicyLoadError(f"Failed to parse policy YAML: {e}") from e

        if not isinstance(data, dict):
            raise PolicyLoadError("Policy file must contain a top-level mapping")

        self._policy = data
        self._build_action_map()
        self._build_parameter_patterns()

    def reload(self) -> None:
        """Reload the policy file from disk (useful after hot-update)."""
        self.load()

    def _build_action_map(self) -> None:
        """Build a fast lookup: target -> {action: policy_name}."""
        targets: dict[str, Any] = self._policy.get("targets", {})
        action_map: dict[str, dict[str, str]] = {}
        for target_name, target_config in targets.items():
            actions: dict[str, Any] = target_config.get("actions", {})
            action_map[target_name] = {}
            for action_name, action_config in actions.items():
                action_map[target_name][action_name] = action_config.get("policy", "blocked")
        self._action_map = action_map

    def _build_parameter_patterns(self) -> None:
        """Build a list of parameter escalation rules."""
        self._parameter_patterns = self._policy.get("parameter_escalation", [])

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(self, target: str, action: str, parameter: str = "") -> Policy:
        """Classify a command into one of the four policies.

        Args:
            target: Target device (e.g. ``PC``, ``HOME``).
            action: Action name (e.g. ``RUN_SCRIPT``).
            parameter: Action parameter string.

        Returns:
            The resolved Policy enum value.

        Raises:
            PolicyClassificationError: If the target or action is unknown.
        """
        # Look up action policy
        target_actions = self._action_map.get(target)
        if target_actions is None:
            raise PolicyClassificationError(f"Unknown target: {target}")

        action_policy_name = target_actions.get(action)
        if action_policy_name is None:
            raise PolicyClassificationError(f"Unknown action '{action}' for target '{target}'")

        action_policy = self._policy_from_name(action_policy_name)

        # Check parameter escalation
        if parameter and self._check_parameter_escalation(target, action, parameter):
            return Policy.ALWAYS_CONFIRM

        return action_policy

    def classify_command(self, command: Command) -> Policy:
        """Classify a Command object."""
        return self.classify(command.target, command.action, command.parameter)

    def get_gate_outcome(self, command: Command, timeout: bool = False) -> GateOutcome:
        """Determine the gate outcome for a command.

        For auto-approve policies, returns APPROVED.
        For always-confirm, returns APPROVED or REJECTED based on external input.
        For blocked, returns BLOCKED.

        Args:
            command: The command to evaluate.
            timeout: Whether the confirmation timed out.

        Returns:
            The gate outcome.
        """
        policy = self.classify_command(command)

        if policy in (Policy.AUTO_APPROVE, Policy.AUTO_APPROVE_AUDIT):
            return GateOutcome.APPROVED
        if policy == Policy.BLOCKED:
            return GateOutcome.BLOCKED
        if timeout:
            return GateOutcome.TIMED_OUT
        # Always-confirm — caller must supply the approval; returns REJECTED default
        return GateOutcome.REJECTED

    # ------------------------------------------------------------------
    # Parameter escalation
    # ------------------------------------------------------------------

    def _check_parameter_escalation(self, target: str, action: str, parameter: str) -> bool:
        """Check if a parameter triggers escalation to Always Confirm."""
        for rule in self._parameter_patterns:
            # Pattern-based rules (re.compile-style)
            pattern = rule.get("pattern")
            if pattern and re.search(pattern, parameter):
                return True

            # Match-based rules (specific action + condition)
            match_rule = rule.get("match")
            if match_rule:
                match_action = match_rule.get("action")
                condition = match_rule.get("condition", "")
                if match_action == action:
                    if self._evaluate_condition(condition, action, parameter):
                        return True

        return False

    def _get_whitelisted_scripts(self, action: str) -> set[str]:
        """Return the whitelisted scripts set for an action from the YAML config.

        Reads ``whitelisted_scripts`` from the action's configuration in
        ``gate_policy.yaml``. Falls back to an empty set if not configured.
        """
        targets: dict[str, Any] = self._policy.get("targets", {})
        for target_config in targets.values():
            actions: dict[str, Any] = target_config.get("actions", {})
            action_config = actions.get(action, {})
            if isinstance(action_config, dict):
                scripts = action_config.get("whitelisted_scripts", [])
                if scripts:
                    return set(scripts)
        return set()

    def _evaluate_condition(self, condition: str, action: str, parameter: str) -> bool:
        """Evaluate a simple condition expression for parameter escalation.

        Supports:
        - ``parameter not in whitelisted_scripts``
        - ``parameter does not start with https://``
        - ``parameter matches <pattern>``
        """
        cond = condition.strip()

        if cond == "parameter not in whitelisted_scripts":
            # Load whitelist from gate_policy.yaml — config-driven, not hardcoded
            whitelisted = self._get_whitelisted_scripts(action)
            return parameter not in whitelisted

        if cond.startswith("parameter does not start with "):
            prefix = cond.split("parameter does not start with ", 1)[1].strip()
            return not parameter.startswith(prefix)

        if cond.startswith("parameter matches "):
            pattern = cond.split("parameter matches ", 1)[1].strip()
            try:
                return bool(re.search(pattern, parameter))
            except re.error:
                return False

        return False

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def list_actions(self, target: str) -> list[str]:
        """List all known actions for a target."""
        target_actions = self._action_map.get(target, {})
        return sorted(target_actions.keys())

    def list_targets(self) -> list[str]:
        """List all known targets."""
        return sorted(self._action_map.keys())

    def is_known_action(self, target: str, action: str) -> bool:
        """Check if an action is registered for a target."""
        return action in self._action_map.get(target, {})

    def is_known_target(self, target: str) -> bool:
        """Check if a target is registered."""
        return target in self._action_map

    def get_policy_for_action(self, target: str, action: str) -> Policy:
        """Get the policy for a specific action without parameter escalation."""
        target_actions = self._action_map.get(target, {})
        policy_name = target_actions.get(action)
        if policy_name is None:
            raise PolicyClassificationError(f"Unknown action '{action}' for target '{target}'")
        return self._policy_from_name(policy_name)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _policy_from_name(name: str) -> Policy:
        """Convert a policy name string to a Policy enum."""
        mapping = {
            "auto-approve": Policy.AUTO_APPROVE,
            "auto-approve-audit": Policy.AUTO_APPROVE_AUDIT,
            "always-confirm": Policy.ALWAYS_CONFIRM,
            "blocked": Policy.BLOCKED,
        }
        result = mapping.get(name)
        if result is None:
            raise PolicyClassificationError(f"Unknown policy name: {name}")
        return result

    @property
    def version(self) -> str:
        """Return the policy version string."""
        return str(self._policy.get("version", "unknown"))

    @property
    def policy_data(self) -> dict[str, Any]:
        """Return the raw policy data (read-only view)."""
        return dict(self._policy)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

_DEFAULT_ENGINE: PolicyEngine | None = None


def _get_engine() -> PolicyEngine:
    """Get or create the default global policy engine."""
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = PolicyEngine()
    return _DEFAULT_ENGINE


def load_policy(policy_path: str | Path | None = None) -> PolicyEngine:
    """Load a policy file and return a PolicyEngine.

    Args:
        policy_path: Path to gate_policy.yaml. Defaults to ``./gate_policy.yaml``.

    Returns:
        A configured PolicyEngine instance.
    """
    return PolicyEngine(policy_path)


def classify_command(
    target: str,
    action: str,
    parameter: str = "",
) -> Policy:
    """Classify a command using the default policy engine.

    Args:
        target: Target device (e.g. ``PC``, ``HOME``).
        action: Action name (e.g. ``RUN_SCRIPT``).
        parameter: Action parameter string.

    Returns:
        The resolved Policy enum value.
    """
    return _get_engine().classify(target, action, parameter)
