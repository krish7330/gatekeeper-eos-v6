"""Gatekeeper v0.2: Config-driven policy with workspace boundary enforcement"""

import json
import os

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "policy.json")


class GatekeeperPolicy:
    """Config-driven binary whitelist policy with workspace boundary.

    Properties:
    - Config loaded from JSON file (tool whitelist + workspace path)
    - Unknown tool → BLOCK
    - Missing tool → BLOCK
    - read_file targeting outside workspace → BLOCK
    - Missing config file → failsafe BLOCK ALL
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.allowed_tools: set[str] = set()
        self.workspace: str = ""
        self._load_policy(config_path)

    def _load_policy(self, path: str) -> None:
        """Load configuration from JSON file. Failsafe: zero-trust if missing."""
        try:
            with open(path, "r") as f:
                config = json.load(f)
            self.allowed_tools = set(config.get("allowed_tools", []))
            self.workspace = config.get("workspace", "")
        except (FileNotFoundError, json.JSONDecodeError):
            # Failsafe: Default to absolute zero-trust
            self.allowed_tools = set()
            self.workspace = ""

    def evaluate_action(self, payload: dict) -> dict:
        """Evaluate an action payload against the active policy.

        Returns dict with 'status' (ALLOW/BLOCK) and 'reason'.
        """
        tool = payload.get("tool")
        target = payload.get("target", "")

        # Default deny: No tool specified → BLOCK
        if tool is None:
            return {"status": "BLOCK", "reason": "No tool specified."}

        # Default deny: Unknown tool → BLOCK
        if tool not in self.allowed_tools:
            return {"status": "BLOCK", "reason": f"Tool '{tool}' not authorized."}

        # Workspace boundary: read_file must target within workspace
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
