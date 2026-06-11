"""Gatekeeper v0.3: Constitution-driven policy with policy.json fallback.

Decision order:
1. Constitution rules (loaded from constitution.json) — first match wins
2. Policy config (loaded from policy.json) — whitelist + workspace boundary
3. Default deny — BLOCK
"""
import json
import os

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "policy.json")
DEFAULT_CONSTITUTION_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "constitution.json")


class GatekeeperPolicy:
    """Constitution-driven binary whitelist policy.

    Properties:
    - Constitution rules evaluated first (constitution.json)
    - Fallback to config-driven whitelist + workspace boundary (policy.json)
    - Unknown tool → BLOCK
    - Missing tool → BLOCK
    - Missing config file → failsafe BLOCK ALL
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH,
                 constitution_path: str | None = DEFAULT_CONSTITUTION_PATH):
        self.allowed_tools: set[str] = set()
        self.workspace: str = ""
        self.constitution_rules: list[dict] = []
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

    def _constitution_decision(self, tool: str | None, target: str) -> dict | None:
        """Evaluate constitution rules. Returns decision dict or None if no rule matches."""
        for rule in self.constitution_rules:
            rule_action = rule.get("action", "")
            # Match action (exact or wildcard *)
            if rule_action != "*" and rule_action != tool:
                continue

            condition = rule.get("condition", "")
            matched = False

            if "target starts with workspace" in condition:
                matched = bool(self.workspace and target.startswith(self.workspace))
            elif "target does not start with workspace" in condition:
                matched = bool(not self.workspace or not target.startswith(self.workspace))
            elif "tool not in allowed_tools" in condition:
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
        """
        tool = payload.get("tool")
        target = payload.get("target", "")

        # 1. Constitution rules (first match wins)
        constitution = self._constitution_decision(tool, target)
        if constitution is not None:
            return constitution

        # 2. Default deny: No tool specified → BLOCK
        if tool is None:
            return {"status": "BLOCK", "reason": "No tool specified."}

        # 3. Default deny: Unknown tool → BLOCK
        if tool not in self.allowed_tools:
            return {"status": "BLOCK", "reason": f"Tool '{tool}' not authorized."}

        # 4. Workspace boundary: read_file must target within workspace
        if tool == "read_file" and self.workspace:
            if not target.startswith(self.workspace):
                return {
                    "status": "BLOCK",
                    "reason": f"Target '{target}' is outside workspace '{self.workspace}'.",
                }

        return {
            "status": "ALLOW",
            "reason": f"Tool '{tool}' validated against active policy.",
        }
