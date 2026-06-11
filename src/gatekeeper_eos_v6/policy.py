"""Gatekeeper v0.4: Constitution-driven policy with audit logging.

Decision order:
1. Constitution rules (loaded from constitution.json) — first match wins
2. Policy config (loaded from policy.json) — whitelist + workspace boundary
3. Default deny — BLOCK

Every decision is recorded to the audit log with hash-chain integrity.
"""
import json
import os

from .audit_log import AuditLog

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "policy.json")
DEFAULT_CONSTITUTION_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "constitution.json")


class GatekeeperPolicy:
    """Constitution-driven binary whitelist policy with audit logging.

    Properties:
    - Constitution rules evaluated first (constitution.json)
    - Fallback to config-driven whitelist + workspace boundary (policy.json)
    - Every decision recorded to audit log with hash-chain integrity
    - Unknown tool → BLOCK
    - Missing tool → BLOCK
    - Missing config file → failsafe BLOCK ALL
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH,
                 constitution_path: str | None = DEFAULT_CONSTITUTION_PATH,
                 audit_log: AuditLog | None = None):
        self.allowed_tools: set[str] = set()
        self.workspace: str = ""
        self.constitution_rules: list[dict] = []
        self._audit = audit_log
        self._load_policy(config_path)
        self._load_constitution(constitution_path)

    def _load_policy(self, path: str) -> None:
        """Load configuration from JSON file. Failsafe: zero-trust if missing."""
        try:
            with open(path, "r") as f:
                config = json.load(f)
            self.allowed_tools = set(config.get("allowed_tools", []))
            self.workspace = config.get("workspace", "")
        except (FileNotFoundError, json.JSONDecodeError):
            self.allowed_tools = set()
            self.workspace = ""

    def _load_constitution(self, path: str | None) -> None:
        """Load constitution rules from JSON file. No-op if missing."""
        if path is None:
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
            self.constitution_rules = data.get("rules", [])
        except (FileNotFoundError, json.JSONDecodeError):
            self.constitution_rules = []

    @staticmethod
    def _normalize_condition(condition: str) -> str:
        """Normalize whitespace in condition string for robust matching."""
        return " ".join(condition.split())

    def _constitution_decision(self, tool: str | None, target: str) -> dict | None:
        """Evaluate constitution rules. Returns decision dict or None if no rule matches."""
        for rule in self.constitution_rules:
            rule_action = rule.get("action", "")
            # Match action (exact or wildcard *)
            if rule_action != "*" and rule_action != tool:
                continue

            condition = self._normalize_condition(rule.get("condition", ""))
            matched = False

            if condition == "target starts with workspace":
                matched = bool(self.workspace and target.startswith(self.workspace))
            elif condition == "target does not start with workspace":
                matched = bool(not self.workspace or not target.startswith(self.workspace))
            elif condition == "tool not in allowed_tools":
                matched = bool(tool not in self.allowed_tools)
            else:
                # Unknown condition — skip this rule
                continue

            if matched:
                effect = rule.get("effect", "BLOCK")
                return {
                    "status": effect,
                    "reason": f"Constitution rule '{rule.get('id', 'unknown')}': {effect}",
                }

        return None

    def evaluate_action(self, payload: dict) -> dict:
        """Evaluate an action payload against constitution + policy.

        Returns dict with 'status' (ALLOW/BLOCK) and 'reason'.
        Every decision is recorded to the audit log if configured.
        """
        tool = payload.get("tool")
        target = payload.get("target", "")
        decision: dict | None = None

        # 1. Constitution rules (first match wins)
        constitution = self._constitution_decision(tool, target)
        if constitution is not None:
            decision = constitution

        # 2. Default deny: No tool specified → BLOCK
        if decision is None and tool is None:
            decision = {"status": "BLOCK", "reason": "No tool specified."}

        # 3. Default deny: Unknown tool → BLOCK
        if decision is None and tool not in self.allowed_tools:
            decision = {"status": "BLOCK", "reason": f"Tool '{tool}' not authorized."}

        # 4. Workspace boundary: read_file must target within workspace
        if decision is None and tool == "read_file" and self.workspace:
            if not target.startswith(self.workspace):
                decision = {
                    "status": "BLOCK",
                    "reason": f"Target '{target}' is outside workspace '{self.workspace}'.",
                }

        if decision is None:
            decision = {
                "status": "ALLOW",
                "reason": f"Tool '{tool}' validated against active policy.",
            }

        # Record to audit log
        if self._audit is not None:
            self._audit.append(
                tool=tool,
                target=target,
                status=decision["status"],
                reason=decision["reason"],
            )

        return decision
