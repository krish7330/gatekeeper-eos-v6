"""Bounded agentic reasoning loop for multi-session orchestration.

Implements a bounded autonomous agent that selects next actions based on
evidence collected so far, while the orchestrator enforces absolute boundaries
from the signed test plan (scope, allowlist, expiry, drift sentinel).

Architecture (from the multi-session design):

    Signed Test Plan (scope + allowed tools + objective)
            │
            ▼
    Agent Core (reasoning loop) ── asks for next action ──► Action Selector
            │                                                        │
            │◄──────────── feedback (state update) ────────────────── ◄── Policy Gate
            │                                                              │
            └──────────► Drift Sentinel ──► State Updater ──────────────────┘

Safe rules:
  - All actions must come from allowed_tools in the signed plan.
  - All targets must be within authorized_assets.
  - Agent cannot exceed max_steps or max_time_seconds.
  - Agent state must not hallucinate findings (DRIFT-AGENT-STATE).
  - Everything is logged immutably in the evidence log.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AgenticError(Exception):
    """Base error for agentic operations."""


class AgentStateError(AgenticError):
    """Raised when the agent's world model is inconsistent or hallucinated."""


class AgentActionError(AgenticError):
    """Raised when an action violates bounds or is invalid."""


class AgentStopTriggered(AgenticError):
    """Raised when a stop condition is met (not an error — intentional stop)."""


# ---------------------------------------------------------------------------
# State machine — agent's world model
# ---------------------------------------------------------------------------


@dataclass
class WorldState:
    """Structured representation of the agent's knowledge about the target.

    This is the agent's world model — only confirmed evidence is stored here.
    The DRIFT-AGENT-STATE check verifies that no field has hallucinated data.
    """

    open_ports: list[int] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    injection_points: list[str] = field(default_factory=list)
    discovered_assets: list[str] = field(default_factory=list)
    tested_paths: list[str] = field(default_factory=list)
    findings_summary: list[dict[str, Any]] = field(default_factory=list)
    last_action_result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "open_ports": self.open_ports,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "injection_points": self.injection_points,
            "discovered_assets": self.discovered_assets,
            "tested_paths": self.tested_paths,
            "findings_summary": self.findings_summary,
            "last_action_result": self.last_action_result,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorldState:
        return cls(
            open_ports=data.get("open_ports", []),
            services=data.get("services", []),
            vulnerabilities=data.get("vulnerabilities", []),
            injection_points=data.get("injection_points", []),
            discovered_assets=data.get("discovered_assets", []),
            tested_paths=data.get("tested_paths", []),
            findings_summary=data.get("findings_summary", []),
            last_action_result=data.get("last_action_result", ""),
        )

    def update(self, action_output: dict[str, Any]) -> None:
        """Update the world model with confirmed evidence from an action output.

        All updates are additive — the state only grows. Hallucination checks
        compare the state against the evidence log to detect divergence.
        """
        if "open_ports" in action_output:
            for port in action_output["open_ports"]:
                if isinstance(port, int) and port not in self.open_ports:
                    self.open_ports.append(port)

        if "services" in action_output:
            for svc in action_output["services"]:
                if svc not in self.services:
                    self.services.append(svc)

        if "vulnerabilities" in action_output:
            for vuln in action_output["vulnerabilities"]:
                if vuln not in self.vulnerabilities:
                    self.vulnerabilities.append(vuln)

        if "injection_points" in action_output:
            for pt in action_output["injection_points"]:
                if pt not in self.injection_points:
                    self.injection_points.append(pt)

        if "discovered_assets" in action_output:
            for asset in action_output["discovered_assets"]:
                if asset not in self.discovered_assets:
                    self.discovered_assets.append(asset)

        if "tested_paths" in action_output:
            for path in action_output["tested_paths"]:
                if path not in self.tested_paths:
                    self.tested_paths.append(path)

        if "findings_summary" in action_output:
            for f in action_output["findings_summary"]:
                if f not in self.findings_summary:
                    self.findings_summary.append(f)

        if "last_action_result" in action_output:
            self.last_action_result = action_output["last_action_result"]


# ---------------------------------------------------------------------------
# Finding summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingSummary:
    """A single security finding discovered by the agent."""

    title: str
    severity: str = "info"
    confidence: float = 1.0
    cve: str | None = None
    remediation: str | None = None

    VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})

    def __post_init__(self) -> None:
        if self.severity not in self.VALID_SEVERITIES:
            raise AgentStateError(
                f"Invalid severity '{self.severity}'; must be one of {sorted(self.VALID_SEVERITIES)}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise AgentStateError(
                f"Confidence must be between 0 and 1, got {self.confidence}"
            )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
        }
        if self.cve:
            d["cve"] = self.cve
        if self.remediation:
            d["remediation"] = self.remediation
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FindingSummary:
        return cls(
            title=data["title"],
            severity=data.get("severity", "info"),
            confidence=data.get("confidence", 1.0),
            cve=data.get("cve"),
            remediation=data.get("remediation"),
        )


# ---------------------------------------------------------------------------
# ISO 8601 duration parser
# ---------------------------------------------------------------------------


_ISO_DURATION_RE = re.compile(
    r"^P"
    r"(?:([0-9]+)Y)?"   # years
    r"(?:([0-9]+)M)?"   # months
    r"(?:([0-9]+)D)?"   # days
    r"(?:T"
    r"(?:([0-9]+)H)?"   # hours
    r"(?:([0-9]+)M)?"   # minutes
    r"(?:([0-9]+(?:\.[0-9]+)?)S)?"  # seconds
    r")?$"
)


def parse_iso_duration(duration: str) -> int:
    """Parse an ISO 8601 duration string to total seconds.

    Args:
        duration: ISO 8601 duration string (e.g. 'PT1H', 'PT30M', 'P1DT2H').

    Returns:
        Total seconds as an integer.

    Raises:
        ValueError: If the duration string is malformed.
    """
    match = _ISO_DURATION_RE.match(duration.strip())
    if not match:
        raise ValueError(f"Invalid ISO 8601 duration string: '{duration}'")

    years, months, days, hours, minutes, seconds = match.groups()

    total = 0
    if years:
        total += int(years) * 365 * 24 * 3600  # approximate
    if months:
        total += int(months) * 30 * 24 * 3600   # approximate
    if days:
        total += int(days) * 24 * 3600
    if hours:
        total += int(hours) * 3600
    if minutes:
        total += int(minutes) * 60
    if seconds:
        total += int(float(seconds))

    return total


# ---------------------------------------------------------------------------
# Rule engine config
# ---------------------------------------------------------------------------


@dataclass
class RuleEngineConfig:
    """Optional configuration for the deterministic rule-based strategy."""

    phase_order: list[str] | None = None
    max_retries_per_phase: int = 3
    fallback_on_empty: str = "report"


# ---------------------------------------------------------------------------
# Stop conditions
# ---------------------------------------------------------------------------


class StopReason(Enum):
    MAX_STEPS = "max_steps_reached"
    MAX_TIME = "max_time_exceeded"
    CRITERIA_MET = "success_criteria_met"
    DRIFT_DETECTED = "drift_detected"
    USER_HALT = "user_halted"
    HUMAN_IN_THE_LOOP = "human_in_the_loop"
    NO_MORE_ACTIONS = "no_more_productive_actions"
    MAX_SEVERITY_FOUND = "max_severity_found"
    RULE_ENGINE_STALLED = "rule_engine_stalled"


class StopConditionType(Enum):
    """Types of stop conditions in the stop_conditions array."""
    FINDING_SEVERITY = "finding_severity"
    SUCCESS_CRITERION_MET = "success_criterion_met"
    MAX_STEPS = "max_steps"
    TIME_LIMIT = "time_limit"


@dataclass
class StopCondition:
    """Configuration for when the agent should stop its reasoning loop.

    Supports both flat configuration (max_steps, max_time_seconds, stop_on_finding,
    stop_on_criteria_met) and the array-based stop_conditions format.
    """

    max_steps: int = 100
    max_time_seconds: int = 3600
    stop_on_finding: str | list[str] = "none"
    stop_on_criteria_met: bool = True
    stop_conditions: list[dict[str, Any]] | None = None  # From new array-based schema

    SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]

    def should_stop(
        self,
        current_step: int,
        start_time: float,
        state: WorldState,
        success_criteria: list[str] | None = None,
    ) -> tuple[bool, StopReason]:
        """Check all stop conditions and return (should_stop, reason).

        Checks both flat config fields and array-based stop_conditions.

        Args:
            current_step: 1-based step counter.
            start_time: time.monotonic() when the agent started.
            state: Current world model state.
            success_criteria: List of criteria strings from the test plan.

        Returns:
            (True, reason) if a stop condition is met.
            (False, None) if the agent should continue.
        """
        # Check array-based stop_conditions first
        if self.stop_conditions:
            result = self._check_stop_conditions(
                current_step, start_time, state, success_criteria
            )
            if result:
                return result

        # Legacy flat field checks (used as fallback if stop_conditions is not set)
        # Max steps
        if current_step >= self.max_steps:
            return True, StopReason.MAX_STEPS

        # Max time
        elapsed = time.monotonic() - start_time
        if elapsed >= self.max_time_seconds:
            return True, StopReason.MAX_TIME

        # Max severity finding
        if self.stop_on_finding != "none":
            target_severities = (
                [self.stop_on_finding]
                if isinstance(self.stop_on_finding, str)
                else self.stop_on_finding
            )
            target_ranks = [
                self.SEVERITY_ORDER.index(s.lower())
                for s in target_severities
                if s.lower() in self.SEVERITY_ORDER
            ]
            if target_ranks:
                min_rank = min(target_ranks)
                for finding in state.findings_summary:
                    f_sev = finding.get("severity", "none").lower()
                    if f_sev in self.SEVERITY_ORDER:
                        f_rank = self.SEVERITY_ORDER.index(f_sev)
                        if f_rank >= min_rank:
                            return True, StopReason.MAX_SEVERITY_FOUND

        # Success criteria met
        if self.stop_on_criteria_met and success_criteria:
            if self._are_criteria_met(success_criteria, state):
                return True, StopReason.CRITERIA_MET

        return False, StopReason.NO_MORE_ACTIONS

    def _check_stop_conditions(
        self,
        current_step: int,
        start_time: float,
        state: WorldState,
        success_criteria: list[str] | None,
    ) -> tuple[bool, StopReason] | None:
        """Check the array-based stop_conditions from the new schema."""
        if not self.stop_conditions:
            return None

        for condition in self.stop_conditions:
            ctype = condition.get("type", "")
            cvalue = condition.get("value", "")

            if ctype == StopConditionType.MAX_STEPS.value:
                try:
                    limit = int(cvalue) if cvalue else self.max_steps
                except (ValueError, TypeError):
                    limit = self.max_steps
                if current_step >= limit:
                    return True, StopReason.MAX_STEPS

            elif ctype == StopConditionType.TIME_LIMIT.value:
                try:
                    limit = parse_iso_duration(cvalue) if cvalue else self.max_time_seconds
                except (ValueError, TypeError):
                    limit = self.max_time_seconds
                elapsed = time.monotonic() - start_time
                if elapsed >= limit:
                    return True, StopReason.MAX_TIME

            elif ctype == StopConditionType.FINDING_SEVERITY.value:
                target = cvalue.lower() if cvalue else "critical"
                if target in self.SEVERITY_ORDER:
                    target_rank = self.SEVERITY_ORDER.index(target)
                    for finding in state.findings_summary:
                        f_sev = finding.get("severity", "none").lower()
                        if f_sev in self.SEVERITY_ORDER:
                            f_rank = self.SEVERITY_ORDER.index(f_sev)
                            if f_rank >= target_rank:
                                return True, StopReason.MAX_SEVERITY_FOUND

            elif ctype == StopConditionType.SUCCESS_CRITERION_MET.value:
                if success_criteria and self._are_criteria_met(success_criteria, state):
                    return True, StopReason.CRITERIA_MET

        return None

    @staticmethod
    def _are_criteria_met(
        criteria: list[str],
        state: WorldState,
    ) -> bool:
        """Check if success criteria are satisfied by the current state.

        Uses simple keyword matching against the world model.
        A criterion is met if any of its keywords appear in the state.
        """
        if not criteria:
            return False

        # Build keyword sets from state
        state_text = json.dumps(state.to_dict()).lower()

        met_count = 0
        for criterion in criteria:
            keywords = criterion.lower().replace(":", "").split()
            meaningful = [k for k in keywords if len(k) > 3]
            if not meaningful:
                met_count += 1
                continue
            # Criterion is met if any meaningful keyword is in the state
            if any(k in state_text for k in meaningful):
                met_count += 1
                continue

        return met_count >= len(criteria)


# ---------------------------------------------------------------------------
# Action definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentAction:
    """A single atomic action proposed by the action selector.

    After the Policy Gate validates it, the Executor runs it.
    """

    tool: str
    command: str
    arguments: dict[str, Any] = field(default_factory=dict)
    target: str = ""
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "command": self.command,
            "arguments": self.arguments,
            "target": self.target,
            "reasoning": self.reasoning,
        }


# ---------------------------------------------------------------------------
# LLM provider — abstract interface for LLM-based action generation
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract interface for LLM-based action generation.

    Implementations handle the actual LLM API call (OpenAI, Anthropic, etc.)
    and return a raw response string that _select_with_llm parses into an
    AgentAction.
    """

    def __init__(self, model: str = "default") -> None:
        self.model = model

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send a prompt to the LLM and return the raw response text.

        The response is expected to contain valid JSON that can be parsed
        into an AgentAction dict (tool, command, arguments, target, reasoning).

        Args:
            prompt: The fully substituted prompt string with context.

        Returns:
            Raw response text from the LLM.
        """
        ...


class MockLLMProvider(LLMProvider):
    """Mock LLM provider for testing: returns a fixed AgentAction JSON.

    Useful for testing the LLM integration path without an actual API call.
    Tracks call_count and last_prompt for test assertions.
    """

    def __init__(self, model: str = "mock", default_action: dict[str, Any] | None = None) -> None:
        super().__init__(model)
        self.call_count = 0
        self.last_prompt = ""
        self._default_action = default_action or {
            "tool": "nmap",
            "command": "discover",
            "arguments": {"target": "target"},
            "target": "target",
            "reasoning": "Mock LLM: default action",
        }

    def generate(self, prompt: str) -> str:
        self.call_count += 1
        self.last_prompt = prompt
        return json.dumps(self._default_action)


class RuleFallbackLLMProvider(LLMProvider):
    """LLM provider that falls back to the deterministic rule engine.

    This is the default provider used when no real LLM is configured.
    It simulates the LLM by running the rule-based selector, which is useful
    for development and testing without an API key.
    """

    def __init__(self, model: str = "rule-fallback") -> None:
        super().__init__(model)
        self.call_count = 0
        self.last_prompt = ""
        self._fallback = ActionSelector(decision_strategy="rule")

    def generate(self, prompt: str) -> str:
        """Parse the prompt context and return a rule-based action as JSON."""
        self.call_count += 1
        self.last_prompt = prompt
        # The caller (_select_with_llm) handles the fallback to rules.
        # This provider just signals "use rules" by returning an empty str.
        return ""


# ---------------------------------------------------------------------------
# Action selector
# ---------------------------------------------------------------------------


class ActionSelector:
    """Selects the next action for the agent to take.

    In 'rule' mode, selects actions deterministically based on the world model.
    In 'llm' mode, constructs a prompt and calls an LLM (or simulates one).

    All selections are bounded by the allowed_tools and authorized_assets
    from the signed test plan.
    """

    def __init__(
        self,
        decision_strategy: str = "rule",
        llm_prompt: str | None = None,
        llm_provider: LLMProvider | None = None,
    ) -> None:
        self.strategy = decision_strategy
        self.llm_prompt = llm_prompt
        self.llm_provider = llm_provider
        self._last_rule_action: AgentAction | None = None
        self._stall_count: int = 0
        self._stall_threshold: int = 3  # consecutive identical actions before stall
        # State stagnation tracking
        self._state_snapshot: str = ""  # JSON fingerprint of last seen state
        self._stagnation_count: int = 0
        self._stagnation_threshold: int = 3
        # Multi-asset rotation
        self._asset_rotation_index: int = 0

    def _state_fingerprint(self, state: WorldState) -> str:
        """Produce a deterministic fingerprint of state progress fields."""
        return json.dumps({
            "n_ports": len(state.open_ports),
            "n_services": len(state.services),
            "n_vulns": len(state.vulnerabilities),
            "n_assets": len(state.discovered_assets),
        }, sort_keys=True)

    def select_action(
        self,
        state: WorldState,
        allowed_tools: list[dict[str, Any]],
        authorized_assets: list[str],
        objective: str,
        step: int,
        previous_actions: list[AgentAction],
    ) -> AgentAction:
        """Select the next action based on strategy.

        Args:
            state: Current world model.
            allowed_tools: From the signed plan — defines tool/command bindings.
            authorized_assets: Targets the agent is permitted to analyze.
            objective: The plan objective.
            step: Current step number (1-indexed).
            previous_actions: All actions taken so far.

        Returns:
            An AgentAction bounded by allowed_tools and authorized_assets.
        """
        if self.strategy == "hybrid":
            # Try rules first
            action = self._select_with_rules(state, allowed_tools, authorized_assets, step)

            # Detect stall: tool-loop, asset exhaustion, or state stagnation
            stall_reason = self._check_stalled(action, state, authorized_assets)
            if stall_reason:
                if self.llm_prompt:
                    # Fall back to LLM
                    llm_action = self._select_with_llm(
                        state, allowed_tools, authorized_assets, objective, step, previous_actions
                    )
                    # If LLM also produces the same stalled action, the agent is truly stuck
                    if (
                        llm_action.tool == action.tool
                        and llm_action.command == action.command
                    ):
                        self._reset_stall()
                        return AgentAction(
                            tool=action.tool,
                            command=action.command,
                            arguments=action.arguments,
                            target=action.target,
                            reasoning=(
                                f"RULE_ENGINE_STALLED: {stall_reason}. "
                                f"LLM fallback also returned the same action."
                            ),
                        )
                    # LLM produced a different action — reset stall tracking and return it
                    self._reset_stall()
                    return llm_action
                else:
                    # No LLM configured — mark the action as stalled
                    return AgentAction(
                        tool=action.tool,
                        command=action.command,
                        arguments=action.arguments,
                        target=action.target,
                        reasoning=(
                            f"RULE_ENGINE_STALLED: {stall_reason}. "
                            f"No LLM fallback configured."
                        ),
                    )

            return action

        if self.strategy == "llm":
            return self._select_with_llm(
                state, allowed_tools, authorized_assets, objective, step, previous_actions
            )

        return self._select_with_rules(
            state, allowed_tools, authorized_assets, step
        )

    def _reset_stall(self) -> None:
        """Reset all stall tracking counters."""
        self._stall_count = 0
        self._last_rule_action = None
        self._stagnation_count = 0
        self._state_snapshot = ""
        self._asset_rotation_index = 0

    def _select_with_rules(
        self,
        state: WorldState,
        allowed_tools: list[dict[str, Any]],
        authorized_assets: list[str],
        step: int,
    ) -> AgentAction:
        """Deterministic rule-based action selection.

        Phases based on the world model state:
          1. If no open ports discovered → run recon on next asset in rotation
          2. If open ports but no services → run service scan
          3. If services discovered → run vulnerability check
          4. If all done → report findings

        Rotates through authorized_assets on each call so multi-asset campaigns
        distribute work across all targets.
        """
        if not authorized_assets:
            target = "target"
        elif len(authorized_assets) == 1:
            target = authorized_assets[0]
        else:
            # Multi-asset rotation: cycle through authorized assets
            idx = self._asset_rotation_index % len(authorized_assets)
            target = authorized_assets[idx]
            self._asset_rotation_index = (self._asset_rotation_index + 1) % len(authorized_assets)

        # Choose tool based on what we know
        if not state.open_ports:
            tool = self._find_tool(allowed_tools, "nmap", "recon")
            command = tool["allowed_commands"][0] if tool else "discover"
            return AgentAction(
                tool=tool["name"] if tool else "recon",
                command=command if isinstance(command, str) else command[0],
                arguments={"target": target, "ports": "top-1000"},
                target=target,
                reasoning=f"Step {step}: Initial reconnaissance on {target}",
            )

        if not state.services:
            tool = self._find_tool(allowed_tools, "nmap", "scanner")
            command = tool["allowed_commands"][1] if tool and len(tool["allowed_commands"]) > 1 else (tool["allowed_commands"][0] if tool else "scan")
            return AgentAction(
                tool=tool["name"] if tool else "scanner",
                command=command if isinstance(command, str) else command[0],
                arguments={"target": target, "ports": state.open_ports[:10]},
                target=target,
                reasoning=f"Step {step}: Service fingerprinting on open ports {state.open_ports[:5]}",
            )

        # Vulnerabilities check
        if not state.vulnerabilities:
            tool = self._find_tool(allowed_tools, "grype", "trivy", "scanner")
            command = tool["allowed_commands"][0] if tool else "scan"
            return AgentAction(
                tool=tool["name"] if tool else "vulnerability-scanner",
                command=command if isinstance(command, str) else command[0],
                arguments={"target": target, "services": [s.get("name", "") for s in state.services[:5]]},
                target=target,
                reasoning=f"Step {step}: Vulnerability scan on discovered services",
            )

        # All done — report
        tool = self._find_tool(allowed_tools, "reporter")
        return AgentAction(
            tool=tool["name"] if tool else "reporter",
            command="summary",
            arguments={"findings": len(state.vulnerabilities), "ports": len(state.open_ports)},
            target=target,
            reasoning=f"Step {step}: All reconnaissance complete. Generating summary.",
        )

    def _select_with_llm(
        self,
        state: WorldState,
        allowed_tools: list[dict[str, Any]],
        authorized_assets: list[str],
        objective: str,
        step: int,
        previous_actions: list[AgentAction],
    ) -> AgentAction:
        """LLM-based action selection using the configured prompt template.

        If an LLMProvider is configured, sends the prompt to the provider and
        parses the JSON response into an AgentAction.

        Falls back to rule-based if:
          - No prompt is configured, OR
          - No provider is configured, OR
          - The provider returns empty/invalid JSON.
        """
        if not self.llm_prompt:
            return self._select_with_rules(state, allowed_tools, authorized_assets, step)

        # Build the prompt with context
        prompt = self.llm_prompt.replace("{{ allowed_tools }}", json.dumps(allowed_tools, indent=2))
        prompt = prompt.replace("{{ authorized_assets }}", json.dumps(authorized_assets))
        prompt = prompt.replace("{{ objective }}", objective)
        prompt = prompt.replace("{{ state }}", json.dumps(state.to_dict(), indent=2))
        prompt = prompt.replace("{{ step }}", str(step))

        # If we have an LLM provider, call it and parse the response
        if self.llm_provider is not None:
            response = self.llm_provider.generate(prompt)
            if response:
                try:
                    data = json.loads(response)
                    if isinstance(data, dict) and "tool" in data and "command" in data:
                        return AgentAction(
                            tool=data["tool"],
                            command=data["command"],
                            arguments=data.get("arguments", {}),
                            target=data.get("target", ""),
                            reasoning=data.get("reasoning", f"LLM decision (step {step})"),
                        )
                except (json.JSONDecodeError, TypeError):
                    pass

        # Fall back to rule-based selection
        return self._select_with_rules(state, allowed_tools, authorized_assets, step)

    def _check_stalled(
        self,
        action: AgentAction,
        state: WorldState,
        authorized_assets: list[str],
    ) -> str | None:
        """Check if the rule engine is stalling and return the stall reason.

        Three stall conditions are checked:
          1. Tool-loop stall: same tool+command for _stall_threshold consecutive calls.
          2. Asset-exhaustion stall: all authorized assets have been discovered but
             the selector keeps targeting the first one (no rotation).
          3. State-stagnation stall: no new state fields (ports, services, vulns,
             assets) have grown for _stagnation_threshold consecutive calls.

        Args:
            action: The action just produced by _select_with_rules.
            state: Current world model.
            authorized_assets: All assets the agent is permitted to analyze.

        Returns:
            Stall reason string if stalled, None if the engine is making progress.
        """
        # --- 1. Tool-loop stall ---
        tool_loop = self._check_tool_loop(action)
        if tool_loop:
            return tool_loop

        # --- 2. Asset-exhaustion stall ---
        asset_stall = self._check_asset_exhaustion(state, authorized_assets)
        if asset_stall:
            return asset_stall

        # --- 3. State-stagnation stall ---
        stagnation = self._check_state_stagnation(state)
        if stagnation:
            return stagnation

        return None

    def _check_tool_loop(self, action: AgentAction) -> str | None:
        """Detect tool-loop stall: same tool+command repeated."""
        if self._last_rule_action is None:
            self._last_rule_action = action
            self._stall_count = 0
            return None

        same = (
            action.tool == self._last_rule_action.tool
            and action.command == self._last_rule_action.command
        )

        if same:
            self._stall_count += 1
            if self._stall_count >= self._stall_threshold:
                return (
                    f"Rule engine produced {self._stall_threshold}+ consecutive "
                    f"identical actions ({action.tool}/{action.command}). "
                    f"Tool matching may be failing."
                )
        else:
            self._stall_count = 0

        self._last_rule_action = action
        return None

    def _check_asset_exhaustion(
        self,
        state: WorldState,
        authorized_assets: list[str],
    ) -> str | None:
        """Detect asset-exhaustion stall: all assets discovered but targeting same one.

        Only triggers when:
          - There is already evidence of a stall (stall_count > 0), so a clean
            phase transition to report mode doesn't get mislabeled as failure.
          - Multiple assets are authorized (>1)
          - All authorized assets appear in discovered_assets
        """
        if self._stall_count <= 0:
            return None

        if len(authorized_assets) <= 1:
            return None

        discovered_set = set(state.discovered_assets)
        authorized_set = set(authorized_assets)

        # Only trigger if ALL authorized assets have been discovered
        if discovered_set and discovered_set >= authorized_set:
            return (
                f"All {len(authorized_assets)} authorized assets have been discovered "
                f"but rule engine keeps targeting '{authorized_assets[0]}'. "
                f"No rotation logic available."
            )
        return None

    def _check_state_stagnation(self, state: WorldState) -> str | None:
        """Detect state-stagnation stall: no new state fields for threshold calls."""
        fingerprint = self._state_fingerprint(state)

        if not self._state_snapshot:
            self._state_snapshot = fingerprint
            self._stagnation_count = 0
            return None

        if fingerprint == self._state_snapshot:
            self._stagnation_count += 1
            if self._stagnation_count >= self._stagnation_threshold:
                return (
                    f"State has not progressed for {self._stagnation_threshold}+"
                    f" consecutive steps. Rule engine cannot advance without new evidence."
                )
        else:
            self._stagnation_count = 0

        self._state_snapshot = fingerprint
        return None

    @staticmethod
    def _find_tool(
        allowed_tools: list[dict[str, Any]],
        *names: str,
    ) -> dict[str, Any] | None:
        """Find a tool by any of the given names in the allowed tools list."""
        for tool in allowed_tools:
            tname = tool.get("name", "").lower()
            if any(n.lower() in tname for n in names):
                return tool
        return None


# ---------------------------------------------------------------------------
# Evidence log entry
# ---------------------------------------------------------------------------


@dataclass
class EvidenceEntry:
    """An immutable, timestamped record of an agent action and its result."""

    step: int
    action: AgentAction
    output: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "action": self.action.to_dict(),
            "output": self.output,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Drift sentinel — agent state hallucination check
# ---------------------------------------------------------------------------


def check_agent_state_drift(
    state: WorldState,
    evidence_log: list[EvidenceEntry],
) -> list[str]:
    """Check if the agent's world model has diverged from confirmed evidence.

    DRIFT-AGENT-STATE: Halt if the agent claims evidence that was never
    observed by any action.

    Args:
        state: Current world model state.
        evidence_log: All evidence entries from executed actions.

    Returns:
        List of drift violations (empty = no drift).
    """
    violations: list[str] = []

    # Collect all confirmed data points from the evidence log
    confirmed_ports: set[int] = set()
    confirmed_services: list[dict[str, Any]] = []
    confirmed_vulns: list[dict[str, Any]] = []
    confirmed_assets: set[str] = set()

    for entry in evidence_log:
        output = entry.output
        for port in output.get("open_ports", []):
            if isinstance(port, int):
                confirmed_ports.add(port)
        confirmed_services.extend(output.get("services", []))
        confirmed_vulns.extend(output.get("vulnerabilities", []))
        for asset in output.get("discovered_assets", []):
            if isinstance(asset, str):
                confirmed_assets.add(asset)

    # Check for hallucinated open ports
    for port in state.open_ports:
        if port not in confirmed_ports and confirmed_ports:
            violations.append(
                f"Hallucinated open port {port}: not found in any evidence log entry"
            )

    # Check for hallucinated assets
    for asset in state.discovered_assets:
        if asset not in confirmed_assets and confirmed_assets:
            violations.append(
                f"Hallucinated asset '{asset}': not found in any evidence log entry"
            )

    # Check for hallucinated services
    if confirmed_services:
        confirmed_svc_names = {s.get("name", "") for s in confirmed_services}
        for svc in state.services:
            svc_name = svc.get("name", "")
            if svc_name and svc_name not in confirmed_svc_names:
                violations.append(
                    f"Hallucinated service '{svc_name}': not found in evidence log"
                )

    # Check for hallucinated vulnerabilities
    if confirmed_vulns:
        confirmed_vuln_ids = {v.get("id", "") for v in confirmed_vulns}
        for vuln in state.vulnerabilities:
            vuln_id = vuln.get("id", "")
            if vuln_id and vuln_id not in confirmed_vuln_ids:
                violations.append(
                    f"Hallucinated vulnerability '{vuln_id}': not found in evidence log"
                )

    return violations


# ---------------------------------------------------------------------------
# Agent core — the main reasoning loop
# ---------------------------------------------------------------------------


@dataclass
class AgentCore:
    """The bounded autonomous reasoning loop for a single session.

    The agent:
      1. Starts with an empty world model.
      2. Asks the ActionSelector for the next action.
      3. The Policy Gate validates the action against the signed plan.
      4. The Executor runs the action and captures output.
      5. The Drift Sentinel checks for state hallucination.
      6. The State Updater updates the world model.
      7. Repeats until a StopCondition triggers or all actions are exhausted.
    """

    # Configuration
    allowed_tools: list[dict[str, Any]]
    authorized_assets: list[str]
    objective: str
    success_criteria: list[str] | None = None

    # Strategy
    decision_strategy: str = "rule"
    llm_prompt: str | None = None

    # Stop conditions
    max_steps: int = 100
    max_time_seconds: int = 3600
    stop_on_finding: str | list[str] = "none"
    stop_on_criteria_met: bool = True
    stop_conditions: list[dict[str, Any]] | None = None

    # State
    state: WorldState = field(default_factory=WorldState)
    evidence_log: list[EvidenceEntry] = field(default_factory=list)
    previous_actions: list[AgentAction] = field(default_factory=list)
    step: int = 0
    start_time: float = field(default_factory=time.monotonic)
    halted: bool = False
    stop_reason: StopReason | None = None

    # Human-in-the-loop
    allow_human_in_the_loop: bool = False
    human_approval_callback: Callable[[AgentAction], bool] | None = None

    # Rule engine config
    rule_engine_config: RuleEngineConfig | None = None

    # LLM provider (optional, for LLM-based strategies)
    llm_provider: LLMProvider | None = None

    # Optional: custom executor and drift checker (for testing)
    _action_selector: ActionSelector | None = None
    _drift_check_enabled: bool = True

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    @classmethod
    def from_agentic_config(
        cls,
        config: dict[str, Any],
        allowed_tools: list[dict[str, Any]],
        authorized_assets: list[str],
        objective: str,
        success_criteria: list[str] | None = None,
    ) -> AgentCore:
        """Build an AgentCore from an agentic_config block and plan data.

        Supports both legacy field names and the new schema:
          - llm_prompt / llm_prompt_template (alias)
          - max_time_seconds / max_duration (ISO 8601, alternative)
          - stop_conditions (array-based) supplements flat stop_on_finding
          - llm_provider_config (dict with provider type, model, etc.)
        """
        # Parse max_time_seconds: prefer explicit value, then parse max_duration
        max_time = config.get("max_time_seconds")
        if max_time is None:
            max_duration = config.get("max_duration")
            if max_duration:
                try:
                    max_time = parse_iso_duration(max_duration)
                except ValueError:
                    max_time = 3600
            else:
                max_time = 3600

        # Parse llm_prompt with alias support
        llm_prompt = config.get("llm_prompt") or config.get("llm_prompt_template")

        # Parse rule engine config
        rule_config_raw = config.get("rule_engine_config")
        rule_config = None
        if rule_config_raw:
            rule_config = RuleEngineConfig(
                phase_order=rule_config_raw.get("phase_order"),
                max_retries_per_phase=rule_config_raw.get("max_retries_per_phase", 3),
                fallback_on_empty=rule_config_raw.get("fallback_on_empty", "report"),
            )

        # Auto-create LLM provider from config if specified
        llm_provider = None
        llm_provider_config = config.get("llm_provider_config")
        if llm_provider_config:
            provider_type = llm_provider_config.get("type", "openai")

            # Common optional params forwarded to all production providers
            llm_kwargs: dict[str, Any] = {}
            for key in ("api_key", "base_url", "max_retries"):
                if key in llm_provider_config:
                    llm_kwargs[key] = llm_provider_config[key]

            if provider_type == "openai":
                # Lazy import to avoid circular dependency
                from gatekeeper_eos_v6.providers import OpenAIProvider

                llm_provider = OpenAIProvider(
                    model=llm_provider_config.get("model", "gpt-4o-mini"),
                    temperature=llm_provider_config.get("temperature", 0.2),
                    max_tokens=llm_provider_config.get("max_tokens", 1024),
                    **llm_kwargs,
                )
            elif provider_type == "anthropic":
                from gatekeeper_eos_v6.providers import AnthropicProvider

                llm_provider = AnthropicProvider(
                    model=llm_provider_config.get("model", "claude-sonnet-4-20250514"),
                    temperature=llm_provider_config.get("temperature", 0.2),
                    max_tokens=llm_provider_config.get("max_tokens", 1024),
                    **llm_kwargs,
                )
            elif provider_type in ("google", "gemini"):
                from gatekeeper_eos_v6.providers import GoogleProvider

                llm_provider = GoogleProvider(
                    model=llm_provider_config.get("model", "gemini-2.0-flash"),
                    temperature=llm_provider_config.get("temperature", 0.2),
                    max_tokens=llm_provider_config.get("max_tokens", 2048),
                    **llm_kwargs,
                )
            elif provider_type in ("mock", "test"):
                llm_provider = MockLLMProvider(
                    model=llm_provider_config.get("model", "mock"),
                )

        return cls(
            allowed_tools=allowed_tools,
            authorized_assets=authorized_assets,
            objective=objective,
            success_criteria=success_criteria,
            decision_strategy=config.get("decision_strategy", "rule"),
            llm_prompt=llm_prompt,
            llm_provider=llm_provider,
            max_steps=config.get("max_steps", 100),
            max_time_seconds=max_time,
            stop_on_finding=config.get("stop_on_finding", "none"),
            stop_on_criteria_met=config.get("stop_on_criteria_met", True),
            stop_conditions=config.get("stop_conditions"),
            _drift_check_enabled=config.get("agent_state_drift_check", True),
            allow_human_in_the_loop=config.get("allow_human_in_the_loop", False),
            rule_engine_config=rule_config,
        )

    def step_action(self, action: AgentAction, output: dict[str, Any]) -> None:
        """Advance the agent by one action: record evidence, update state, check drift.

        Args:
            action: The action that was executed.
            output: The output/evidence from the action execution.

        Raises:
            AgentStateError: If agent state drift is detected.
        """
        if self.halted:
            raise AgentStopTriggered("Agent is already halted")

        self.step += 1
        self.previous_actions.append(action)

        # Record evidence
        entry = EvidenceEntry(
            step=self.step,
            action=action,
            output=deepcopy(output),
        )
        self.evidence_log.append(entry)

        # Update world model
        self.state.update(output)

        # Check drift
        if self._drift_check_enabled:
            violations = check_agent_state_drift(self.state, self.evidence_log)
            if violations:
                self.halted = True
                self.stop_reason = StopReason.DRIFT_DETECTED
                raise AgentStateError(
                    f"Agent state drift detected ({len(violations)} violations): "
                    + "; ".join(violations)
                )

        # Human-in-the-loop check
        if self.allow_human_in_the_loop and self.human_approval_callback:
            # The callback determines if the action should proceed
            approved = self.human_approval_callback(action)
            if not approved:
                self.halted = True
                self.stop_reason = StopReason.HUMAN_IN_THE_LOOP
                raise AgentStopTriggered(
                    f"Stop condition met: human_in_the_loop (action '{action.tool}/{action.command}' rejected)"
                )

        # Check stop conditions (including stop_conditions array)
        stop_condition = StopCondition(
            max_steps=self.max_steps,
            max_time_seconds=self.max_time_seconds,
            stop_on_finding=self.stop_on_finding,
            stop_on_criteria_met=self.stop_on_criteria_met,
            stop_conditions=self.stop_conditions,
        )
        should_stop, reason = stop_condition.should_stop(
            self.step, self.start_time, self.state, self.success_criteria
        )
        if should_stop:
            self.halted = True
            self.stop_reason = reason
            raise AgentStopTriggered(f"Stop condition met: {reason.value}")

    def get_next_action(self) -> AgentAction:
        """Ask the action selector for the next action.

        Returns:
            The next AgentAction.

        Raises:
            AgentStopTriggered: If the agent is halted.
        """
        if self.halted:
            raise AgentStopTriggered(
                f"Agent is halted: {self.stop_reason.value if self.stop_reason else 'unknown'}"
            )

        # Persist the selector so stall tracking survives across calls
        if self._action_selector is None:
            self._action_selector = ActionSelector(
                decision_strategy=self.decision_strategy,
                llm_prompt=self.llm_prompt,
                llm_provider=self.llm_provider,
            )
        selector = self._action_selector

        action = selector.select_action(
            state=self.state,
            allowed_tools=self.allowed_tools,
            authorized_assets=self.authorized_assets,
            objective=self.objective,
            step=self.step + 1,  # Next step is current + 1
            previous_actions=self.previous_actions,
        )

        # Check for RULE_ENGINE_STALLED in the action's reasoning
        if "RULE_ENGINE_STALLED" in action.reasoning:
            self.halted = True
            self.stop_reason = StopReason.RULE_ENGINE_STALLED
            raise AgentStopTriggered(
                f"Stop condition met: {StopReason.RULE_ENGINE_STALLED.value}: {action.reasoning}"
            )

        return action

    def reset(self) -> None:
        """Reset the agent to initial state for a fresh run."""
        self.state = WorldState()
        self.evidence_log.clear()
        self.previous_actions.clear()
        self.step = 0
        self.start_time = time.monotonic()
        self.halted = False
        self.stop_reason = None
        self._action_selector = None  # Clear selector stall tracking
        # Note: llm_provider is NOT reset — it persists across runs


# ---------------------------------------------------------------------------
# Policy gate — validates actions against the signed plan
# ---------------------------------------------------------------------------


class PolicyGate:
    """Validates that an agent action is within the bounds of the signed plan.

    The Policy Gate is invoked twice per action cycle:
      1. Before execution: validate the proposed action.
      2. After execution: validate the output (target, scope, tool usage).
    """

    def __init__(
        self,
        allowed_tools: list[dict[str, Any]],
        authorized_assets: list[str],
    ) -> None:
        self._allowed_tools = allowed_tools
        self._authorized_assets = authorized_assets
        self._tool_names = {t["name"].lower() for t in allowed_tools}
        self._tool_commands: dict[str, set[str]] = {}
        for tool in allowed_tools:
            cmds = tool.get("allowed_commands", [])
            self._tool_commands[tool["name"].lower()] = {
                c.lower() if isinstance(c, str) else str(c) for c in cmds
            }

    def validate_action(self, action: AgentAction) -> list[str]:
        """Validate a proposed action against the signed plan.

        Returns:
            List of violation messages (empty = action is allowed).
        """
        violations: list[str] = []
        tool_name = action.tool.lower()

        # Tool must be in allowed_tools
        if tool_name not in self._tool_names:
            violations.append(
                f"Action uses unauthorized tool '{action.tool}'. "
                f"Allowed: {sorted(self._tool_names)}"
            )

        # Command must be in tool's allowed_commands
        if tool_name in self._tool_commands:
            allowed_cmds = self._tool_commands[tool_name]
            cmd = action.command.lower()
            if allowed_cmds and cmd not in allowed_cmds:
                violations.append(
                    f"Action uses command '{action.command}' which is not in "
                    f"allowed_commands for '{action.tool}'. Allowed: {sorted(allowed_cmds)}"
                )

        # Target must be in authorized_assets
        if action.target:
            if not self._is_target_in_scope(action.target):
                violations.append(
                    f"Action targets '{action.target}' which is not in authorized_assets. "
                    f"Authorized: {self._authorized_assets}"
                )

        return violations

    def _is_target_in_scope(self, target: str) -> bool:
        """Check if a target IP/hostname is within authorized assets.

        Supports:
          - Exact IP matching (10.0.0.10 == 10.0.0.10)
          - CIDR prefix matching (10.0.0.5 is within 10.0.0.0/24)
          - Hostname matching (target.example.com is in authorized list)
          - Mixed CIDR and hostname authorized assets

        Returns True if the target is within scope, False otherwise.
        """
        target_lower = target.lower().strip()
        target_lower = target_lower.rstrip("/")

        for authorized in self._authorized_assets:
            auth_lower = authorized.lower().strip()
            auth_lower = auth_lower.rstrip("/")

            # Exact match (IP or hostname)
            if target_lower == auth_lower:
                return True

            # Hostname suffix match (e.g., target is within *.example.com)
            if auth_lower.startswith("*.") and target_lower.endswith(auth_lower[1:]):
                return True

            # CIDR match — try to parse both as IP networks
            try:
                if "/" in auth_lower:
                    # Authorized is a subnet like 10.0.0.0/24
                    network = ipaddress.ip_network(auth_lower, strict=False)
                    # Check if target is an IP within this network
                    try:
                        target_ip = ipaddress.ip_address(target_lower)
                        if target_ip in network:
                            return True
                    except ValueError:
                        # Target is a hostname, not an IP — skip CIDR check
                        pass
                else:
                    # Authorized is a single IP — check if target matches
                    try:
                        auth_ip = ipaddress.ip_address(auth_lower)
                        target_ip = ipaddress.ip_address(target_lower)
                        if auth_ip == target_ip:
                            return True
                    except ValueError:
                        pass
            except ValueError:
                # Malformed CIDR or IP — skip this entry
                continue

        return False

    def validate_output(self, output: dict[str, Any]) -> list[str]:
        """Validate action output against the signed plan.

        Checks for scope expansion, unauthorized assets, and tool misuse.

        Returns:
            List of violation messages (empty = output is clean).
        """
        violations: list[str] = []

        # Any discovered assets must be within authorized scope
        discovered = output.get("discovered_assets", [])
        if discovered:
            for asset in discovered:
                if not self._is_target_in_scope(asset):
                    violations.append(
                        f"Discovered asset '{asset}' is outside authorized scope. "
                        f"Authorized: {self._authorized_assets}"
                    )

        return violations


# ---------------------------------------------------------------------------
# Convenience: run a full agent loop
# ---------------------------------------------------------------------------


def run_agent_loop(
    agent: AgentCore,
    execute_action: Callable[[AgentAction], dict[str, Any]],
    policy_gate: PolicyGate | None = None,
    snapshot_ledger: Any = None,
    session_id: str = "",
) -> tuple[WorldState, list[EvidenceEntry], StopReason | None]:
    """Run the full agent loop until a stop condition is met.

    Args:
        agent: The AgentCore instance to run.
        execute_action: A callable that takes an AgentAction and returns output dict.
        policy_gate: Optional PolicyGate to validate actions before execution.
        snapshot_ledger: Optional SnapshotLedger for auto-snapshot after each step.
        session_id: Session identifier for snapshot labels.

    Returns:
        (final_state, evidence_log, stop_reason)
    """
    # Lazy-import to avoid circular dependency at module level
    if snapshot_ledger is not None:
        from gatekeeper_eos_v6.snapshot import take_snapshot, context_revalidation as _restore

    while not agent.halted:
        try:
            # Get next action
            action = agent.get_next_action()

            # Validate through policy gate
            if policy_gate is not None:
                violations = policy_gate.validate_action(action)
                if violations:
                    # Log the violation and report it as output
                    agent.step_action(
                        action,
                        {
                            "last_action_result": f"POLICY_VIOLATION: {'; '.join(violations)}",
                            "violations": violations,
                        },
                    )
                    continue

            # Execute the action
            output = execute_action(action)

            # Validate output through policy gate
            if policy_gate is not None:
                output_violations = policy_gate.validate_output(output)
                if output_violations:
                    output["last_action_result"] = (
                        f"OUTPUT_VIOLATION: {'; '.join(output_violations)}"
                    )
                    output["violations"] = output_violations

            # Record the step
            agent.step_action(action, output)

            # Auto-snapshot after each successful step
            if snapshot_ledger is not None and session_id:
                take_snapshot(
                    agent=agent,
                    session_id=session_id,
                    checkpoint_id=f"CKPT-{agent.step:04d}-step",
                    ledger=snapshot_ledger,
                    drift_score=0,
                    invariants_satisfied=[f"STEP_{agent.step}"],
                    conversation_summary=(
                        f"Step {agent.step}: {action.tool}/{action.command} "
                        f"on {action.target}"
                    ),
                )

        except AgentStopTriggered:
            break
        except AgentStateError as e:
            # Attempt snapshot restore on drift
            if snapshot_ledger is not None and session_id:
                try:
                    entry, warnings = _restore(
                        agent=agent,
                        session_id=session_id,
                        ledger=snapshot_ledger,
                        max_drift_score=0,
                    )
                    # Restore succeeded — continue the loop with restored state
                    continue
                except Exception:
                    pass  # Restore failed, stop the loop
            break

    return agent.state, agent.evidence_log, agent.stop_reason
