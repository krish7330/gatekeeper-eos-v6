"""Multi-session campaign orchestration.

Reads a campaign YAML (multi-session orchestrator config) and provides
validation, dependency resolution, scheduling, drift rule enforcement,
and integration with the checkpoint and locks modules.

Top-level schema (campaign YAML):
  campaign_id: str (pattern ^CAMP-[a-zA-Z0-9]+$)
  sessions: list[SessionDef]
  global_drift_rules: list[DriftRule]

SessionDef:
  session_id: str (pattern ^SESS-[a-zA-Z0-9]+$)
  plan: str (ref) | dict (inline plan)
  schedule: Schedule
  dependencies: list[str]     (optional)
  max_parallel_actions: int   (optional, default 1)
  drift_rules_override: list[DriftRule] (optional)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import yaml

from gatekeeper_eos_v6.checkpoint import (
    write_checkpoint,
    load_checkpoint,
    get_resume_state,
    rollback_checkpoint,
    clear_checkpoints,
    CheckpointError,
)
from gatekeeper_eos_v6.locks import LockManager, Mutex, LockType, LockError


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DriftAction(Enum):
    HALT = "HALT"
    LOG_ONLY = "LOG_ONLY"


class SessionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    HALTED = "halted"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CampaignError(Exception):
    """Base error for campaign operations."""


class CampaignValidationError(CampaignError):
    """Raised when campaign YAML fails validation."""


class CampaignScheduleError(CampaignError):
    """Raised when scheduling a session fails."""


class CampaignDependencyError(CampaignError):
    """Raised when a dependency is unresolved or circular."""


class CampaignDriftError(CampaignError):
    """Raised when a drift rule is triggered."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftRule:
    """A single drift detection rule."""

    id: str
    description: str
    condition: str
    action: DriftAction = DriftAction.HALT

    VALID_IDS = frozenset({
        "DRIFT-TARGET", "DRIFT-TOOLS", "DRIFT-NET",
        "DRIFT-SCHEMA", "DRIFT-PLAN", "DRIFT-EXPIRY",
        "DRIFT-AGENT-STATE",
    })

    def __post_init__(self) -> None:
        if self.id not in self.VALID_IDS:
            raise CampaignValidationError(
                f"Invalid drift rule id '{self.id}'; must be one of {sorted(self.VALID_IDS)}"
            )


@dataclass(frozen=True)
class Schedule:
    """Time constraints for a session."""

    start_at: datetime
    deadline: datetime | None = None
    max_duration: str | None = None  # ISO 8601 duration string

    def is_ready(self, now: datetime | None = None) -> bool:
        """True if the session can start (current time >= start_at)."""
        now = now or datetime.now(timezone.utc)
        return now >= self.start_at

    def is_expired(self, now: datetime | None = None) -> bool:
        """True if the session has passed its deadline."""
        now = now or datetime.now(timezone.utc)
        if self.deadline is None:
            return False
        return now >= self.deadline


@dataclass(frozen=True)
class SessionDef:
    """Definition of a single session within a campaign."""

    session_id: str
    plan: str | dict  # plan reference (str) or inline plan (dict)
    schedule: Schedule
    dependencies: tuple[str, ...] = ()
    max_parallel_actions: int = 1
    drift_rules_override: tuple[DriftRule, ...] = ()

    SESSION_ID_PATTERN = re.compile(r"^SESS-[a-zA-Z0-9-]+$")

    def __post_init__(self) -> None:
        if not self.SESSION_ID_PATTERN.match(self.session_id):
            raise CampaignValidationError(
                f"Invalid session_id '{self.session_id}'; must match ^SESS-[a-zA-Z0-9-]+$"
            )
        if self.max_parallel_actions < 1:
            raise CampaignValidationError(
                f"max_parallel_actions must be >= 1, got {self.max_parallel_actions}"
            )


@dataclass(frozen=True)
class Campaign:
    """Top-level campaign definition."""

    campaign_id: str
    sessions: tuple[SessionDef, ...]
    global_drift_rules: tuple[DriftRule, ...] = ()

    CAMPAIGN_ID_PATTERN = re.compile(r"^CAMP-[a-zA-Z0-9-]+$")

    def __post_init__(self) -> None:
        if not self.CAMPAIGN_ID_PATTERN.match(self.campaign_id):
            raise CampaignValidationError(
                f"Invalid campaign_id '{self.campaign_id}'; must match ^CAMP-[a-zA-Z0-9-]+$"
            )
        if not self.sessions:
            raise CampaignValidationError("Campaign must have at least one session")


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------


def _parse_drift_rules(raw: list[dict[str, Any]]) -> tuple[DriftRule, ...]:
    """Parse a list of drift rule dicts into DriftRule objects."""
    rules: list[DriftRule] = []
    for r in raw:
        action = DriftAction(r.get("action", "HALT"))
        rules.append(DriftRule(
            id=r["id"],
            description=r.get("description", ""),
            condition=r.get("condition", ""),
            action=action,
        ))
    return tuple(rules)


def _parse_datetime(raw: str) -> datetime:
    """Parse an ISO 8601 datetime string."""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as e:
        raise CampaignValidationError(f"Invalid datetime string: '{raw}': {e}") from e


def _parse_session(raw: dict[str, Any]) -> SessionDef:
    """Parse a single session dict into a SessionDef."""
    schedule_raw = raw["schedule"]
    schedule = Schedule(
        start_at=_parse_datetime(schedule_raw["start_at"]),
        deadline=_parse_datetime(schedule_raw["deadline"]) if schedule_raw.get("deadline") else None,
        max_duration=schedule_raw.get("max_duration"),
    )

    plan = raw["plan"]
    # If plan is a dict (inline), store as-is; if string (ref), store the string
    if not isinstance(plan, (str, dict)):
        raise CampaignValidationError(
            f"plan for session '{raw.get('session_id', '?')}' must be a string or dict"
        )

    return SessionDef(
        session_id=raw["session_id"],
        plan=plan,
        schedule=schedule,
        dependencies=tuple(raw.get("dependencies", [])),
        max_parallel_actions=raw.get("max_parallel_actions", 1),
        drift_rules_override=_parse_drift_rules(raw.get("drift_rules_override", [])),
    )


def load_campaign(path: str | Path) -> Campaign:
    """Load a campaign from a YAML file.

    Args:
        path: Path to the campaign YAML file.

    Returns:
        Validated Campaign object.

    Raises:
        CampaignValidationError: If the YAML is malformed or fails validation.
        FileNotFoundError: If the file doesn't exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Campaign file not found: {path}")

    raw = path.read_text()
    try:
        data: dict[str, Any] = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise CampaignValidationError(f"Failed to parse campaign YAML: {e}") from e

    if not isinstance(data, dict):
        raise CampaignValidationError("Campaign YAML must be a mapping (dict)")

    return campaign_from_dict(data)


def campaign_from_dict(data: dict[str, Any]) -> Campaign:
    """Build a validated Campaign from a parsed dict.

    Args:
        data: Parsed YAML dict representing the campaign.

    Returns:
        Validated Campaign object.

    Raises:
        CampaignValidationError: On any validation failure.
    """
    errors: list[str] = []

    campaign_id = data.get("campaign_id", "")
    raw_sessions = data.get("sessions", [])
    raw_drift = data.get("global_drift_rules", [])

    # campaign_id
    if not campaign_id:
        errors.append("Missing required field: campaign_id")
    elif not Campaign.CAMPAIGN_ID_PATTERN.match(campaign_id):
        errors.append(
            f"Invalid campaign_id '{campaign_id}'; must match ^CAMP-[a-zA-Z0-9-]+$"
        )

    # sessions
    if not raw_sessions:
        errors.append("Missing required field: sessions (must have at least one)")

    # Parse sessions, collecting errors
    sessions: list[SessionDef] = []
    seen_ids: set[str] = set()
    for i, raw_s in enumerate(raw_sessions):
        try:
            session = _parse_session(raw_s)
        except CampaignValidationError as e:
            errors.append(f"sessions[{i}]: {e}")
            continue
        except KeyError as e:
            errors.append(f"sessions[{i}]: missing required field: {e}")
            continue

        sessions.append(session)

        # Check duplicate session IDs
        if session.session_id in seen_ids:
            errors.append(f"Duplicate session_id: {session.session_id}")
        seen_ids.add(session.session_id)

    # Parse drift rules
    try:
        global_drift = _parse_drift_rules(raw_drift)
    except CampaignValidationError as e:
        errors.append(f"global_drift_rules: {e}")

    session_id_set = {s.session_id for s in sessions}

    # Validate dependencies: all referenced sessions must exist
    for session in sessions:
        for dep_id in session.dependencies:
            if dep_id not in session_id_set:
                errors.append(
                    f"Session '{session.session_id}' depends on '{dep_id}' "
                    f"which is not defined in the campaign"
                )

    # Validate no circular dependencies
    dep_errors = _check_circular_dependencies(sessions)
    errors.extend(dep_errors)

    # Validate plan refs: if plan is a string, it should match PLAN-NNN pattern
    for session in sessions:
        if isinstance(session.plan, str):
            if not re.match(r"^PLAN-[a-zA-Z0-9-]+$", session.plan):
                errors.append(
                    f"Session '{session.session_id}': plan ref '{session.plan}' "
                    f"does not match pattern ^PLAN-[a-zA-Z0-9-]+$"
                )

    if errors:
        raise CampaignValidationError(
            f"Campaign validation failed ({len(errors)} errors):\n  "
            + "\n  ".join(errors)
        )

    return Campaign(
        campaign_id=campaign_id,
        sessions=tuple(sessions),
        global_drift_rules=global_drift,
    )


def _check_circular_dependencies(sessions: list[SessionDef]) -> list[str]:
    """Detect circular dependencies between sessions.

    Uses DFS to detect cycles in the dependency graph.
    Returns a list of error messages (empty = no cycles).
    """
    errors: list[str] = []
    session_map = {s.session_id: s for s in sessions}

    # Build adjacency list
    graph: dict[str, list[str]] = {}
    for s in sessions:
        graph[s.session_id] = list(s.dependencies)

    # DFS cycle detection
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {sid: WHITE for sid in graph}

    def dfs(node: str, path: list[str]) -> None:
        color[node] = GRAY
        path.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in color:
                errors.append(f"Session '{node}' depends on undefined session '{neighbor}'")
                continue
            if color[neighbor] == GRAY:
                # Cycle detected: find the cycle start in path
                cycle_start = path.index(neighbor)
                cycle = " -> ".join(path[cycle_start:] + [neighbor])
                errors.append(f"Circular dependency detected: {cycle}")
            elif color[neighbor] == WHITE:
                dfs(neighbor, path)
        path.pop()
        color[node] = BLACK

    for sid in graph:
        if color[sid] == WHITE:
            dfs(sid, [])

    return errors


# ---------------------------------------------------------------------------
# Campaign validation (non-throwing)
# ---------------------------------------------------------------------------


def validate_campaign(data: dict[str, Any]) -> list[str]:
    """Validate a campaign dict, returning a list of errors.

    Non-throwing version of campaign_from_dict for testing.
    Returns an empty list if the campaign is valid.
    """
    try:
        campaign_from_dict(data)
        return []
    except CampaignValidationError as e:
        msg = str(e)
        # Extract individual errors from the multi-line message
        lines = msg.split("\n  ")
        if len(lines) <= 1:
            return [msg]
        # First line is the summary, rest are individual errors
        return lines[1:] if lines[1:] else [msg]


# ---------------------------------------------------------------------------
# Dependency resolver
# ---------------------------------------------------------------------------


class DependencyResolver:
    """Resolves session execution order based on dependencies."""

    def __init__(self, campaign: Campaign) -> None:
        self._campaign = campaign
        self._session_map = {s.session_id: s for s in campaign.sessions}

    def get_ready_sessions(
        self,
        completed: set[str] | None = None,
        now: datetime | None = None,
    ) -> list[SessionDef]:
        """Return sessions that are ready to run.

        A session is ready if:
        - All its dependencies are completed
        - Its start_at time has passed
        - Its deadline has not passed
        - It is not already completed

        Args:
            completed: Set of completed session IDs.
            now: Current time (defaults to UTC now).

        Returns:
            List of ready SessionDef objects, ordered by start_at then dependencies.
        """
        completed = completed or set()
        now = now or datetime.now(timezone.utc)

        ready: list[SessionDef] = []
        for session in self._campaign.sessions:
            if session.session_id in completed:
                continue
            if session.schedule.is_expired(now):
                continue
            if not session.schedule.is_ready(now):
                continue
            if not all(dep in completed for dep in session.dependencies):
                continue
            ready.append(session)

        # Sort by start_at (earliest first), then by dependency depth
        ready.sort(key=lambda s: (s.schedule.start_at, len(s.dependencies)))
        return ready

    def get_execution_order(self) -> list[list[SessionDef]]:
        """Return a topological ordering of sessions as layers.

        Each layer is a list of sessions that can run in parallel.
        Layers are ordered: all sessions in layer N must complete before
        any session in layer N+1 can start.
        """
        # Build dependency graph
        graph: dict[str, set[str]] = {}
        for s in self._campaign.sessions:
            graph[s.session_id] = set(s.dependencies)

        layers: list[list[SessionDef]] = []
        remaining = set(graph.keys())
        session_map = {s.session_id: s for s in self._campaign.sessions}

        while remaining:
            # Find sessions whose dependencies are all satisfied
            current_layer: list[SessionDef] = []
            for sid in list(remaining):
                deps = graph[sid]
                if not deps & remaining:  # No remaining dependencies
                    current_layer.append(session_map[sid])

            if not current_layer:
                # Should not happen if validate_campaign passed
                break

            layers.append(current_layer)
            for s in current_layer:
                remaining.discard(s.session_id)

        return layers


# ---------------------------------------------------------------------------
# Drift rule enforcement
# ---------------------------------------------------------------------------


def check_drift_rules(
    session: SessionDef,
    global_rules: tuple[DriftRule, ...],
    trigger_state: dict[str, Any],
) -> list[DriftRule]:
    """Check drift rules against a trigger state.

    Args:
        session: The session being checked.
        global_rules: Global drift rules from the campaign.
        trigger_state: Dict of {rule_id: bool} indicating which rules triggered.

    Returns:
        List of drift rules that were triggered.
        Rules with action=HALT will halt the session.
        Rules with action=LOG_ONLY are informational.
    """
    # Build effective rules: overrides first, then global
    override_ids = {r.id for r in session.drift_rules_override}

    effective: dict[str, DriftRule] = {}
    for rule in global_rules:
        if rule.id not in override_ids:
            effective[rule.id] = rule
    for rule in session.drift_rules_override:
        effective[rule.id] = rule

    triggered: list[DriftRule] = []
    for rule_id, is_triggered in trigger_state.items():
        rule = effective.get(rule_id)
        if rule and is_triggered:
            triggered.append(rule)

    return triggered


# ---------------------------------------------------------------------------
# Campaign executor (high-level orchestration)
# ---------------------------------------------------------------------------


class CampaignExecutor:
    """Executes a campaign: session scheduling, checkpointing, drift enforcement."""

    def __init__(
        self,
        campaign: Campaign,
        checkpoint_dir: str | Path | None = None,
        lock_manager: LockManager | None = None,
        snapshot_dir: str | Path | None = None,
    ) -> None:
        self.campaign = campaign
        self.checkpoint_dir = Path(checkpoint_dir) if checkpoint_dir else Path("checkpoints")
        self.lock_manager = lock_manager or LockManager.default()
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else None
        self._resolver = DependencyResolver(campaign)

    def resolve_sessions(self) -> list[list[str]]:
        """Return a layered execution plan (list of session ID layers)."""
        layers = self._resolver.get_execution_order()
        return [[s.session_id for s in layer] for layer in layers]

    def check_session_drift(
        self,
        session: SessionDef,
        trigger_state: dict[str, bool],
    ) -> tuple[bool, list[DriftRule]]:
        """Check drift rules for a session.

        Returns:
            (halt, triggered_rules):
              halt=True if any rule has action HALT.
              triggered_rules is the full list of triggered rules.
        """
        triggered = check_drift_rules(
            session, self.campaign.global_drift_rules, trigger_state
        )
        halt = any(r.action == DriftAction.HALT for r in triggered)
        return halt, triggered

    def write_session_checkpoint(
        self,
        session: SessionDef,
        status: str,
        step_id: str = "init",
        output: dict[str, Any] | None = None,
    ) -> Path:
        """Write a checkpoint for a session.

        Integrates with the LockManager for checkpoint_mutex ordering.
        """
        plan_id = session.plan if isinstance(session.plan, str) else session.plan.get("plan_id", "inline")
        with self.lock_manager.acquire("checkpoint_mutex"):
            return write_checkpoint(
                session_id=session.session_id,
                plan_id=plan_id,
                step_id=step_id,
                status=status,
                output=output,
                checkpoint_dir=self.checkpoint_dir,
            )

    def rollback_session(
        self,
        session: SessionDef,
        reason: str,
    ) -> Path:
        """Roll back a session's checkpoint."""
        return rollback_checkpoint(
            session_id=session.session_id,
            reason=reason,
            checkpoint_dir=self.checkpoint_dir,
        )

    def run_agentic_session(
        self,
        session: SessionDef,
        execute_action: Callable[[Any], dict[str, Any]],
    ) -> tuple[Any, list[Any], Any | None]:
        """Run an agentic session: build AgentCore, wire PolicyGate, execute loop.

        Uses the session's inline plan (must contain agentic_config) to build an
        AgentCore, creates a PolicyGate from the plan's allowed_tools and
        authorized_assets, then runs the agent loop with checkpoint integration.

        If snapshot_dir is configured, auto-snapshots are taken:
          - Before each step (critical state mutation)
          - After restore (context_revalidation on drift halt)
          - After the loop ends

        Args:
            session: SessionDef with an inline plan containing agentic_config.
            execute_action: Callable that executes an AgentAction and returns output.

        Returns:
            (final_state, evidence_log, stop_reason)

        Raises:
            CampaignValidationError: If session does not have an inline plan with agentic_config.
        """
        from gatekeeper_eos_v6.agentic import AgentCore, PolicyGate, run_agent_loop

        if not isinstance(session.plan, dict):
            raise CampaignValidationError(
                f"Session '{session.session_id}' must have an inline plan (dict) to run agentic"
            )

        plan = session.plan
        config = plan.get("agentic_config")
        if not config:
            raise CampaignValidationError(
                f"Session '{session.session_id}' inline plan missing 'agentic_config'"
            )

        # Build AgentCore from config
        agent = AgentCore.from_agentic_config(
            config=config,
            allowed_tools=plan.get("allowed_tools", []),
            authorized_assets=plan.get("authorized_assets", []),
            objective=plan.get("objective", ""),
            success_criteria=plan.get("success_criteria"),
        )

        # Create PolicyGate
        gate = PolicyGate(
            allowed_tools=plan.get("allowed_tools", []),
            authorized_assets=plan.get("authorized_assets", []),
        )

        plan_id = plan.get("plan_id", "inline")

        # Write initial checkpoint
        with self.lock_manager.acquire("checkpoint_mutex"):
            write_checkpoint(
                session_id=session.session_id,
                plan_id=plan_id,
                step_id="agentic_start",
                status="running",
                output={
                    "decision_strategy": agent.decision_strategy,
                    "max_steps": agent.max_steps,
                    "session": session.session_id,
                },
                checkpoint_dir=self.checkpoint_dir,
            )

        # --- Auto-snapshot setup ---
        snapshot_ledger = None
        if self.snapshot_dir is not None:
            from gatekeeper_eos_v6.snapshot import SnapshotLedger, take_snapshot, context_revalidation

            ledger_path = self.snapshot_dir / f"{session.session_id}_snapshots.json"
            snapshot_ledger = SnapshotLedger(ledger_path)

            # Initial snapshot after checkpoint
            take_snapshot(
                agent=agent,
                session_id=session.session_id,
                checkpoint_id="CKPT-0000-init",
                ledger=snapshot_ledger,
                drift_score=0,
                invariants_satisfied=["INIT"],
                conversation_summary=f"Agent {agent.decision_strategy} session started. Objective: {agent.objective[:120]}",
            )

            # Wrap execute_action to snapshot before each critical state mutation
            _snap_counter = [1]  # mutable counter for closure
            _original_execute = execute_action

            def _snapshotting_execute(action: Any) -> dict[str, Any]:
                # Snapshot before the step (capture pre-mutation state)
                ckpt_id = f"CKPT-{_snap_counter[0]:04d}-pre"
                _snap_counter[0] += 1
                take_snapshot(
                    agent=agent,
                    session_id=session.session_id,
                    checkpoint_id=ckpt_id,
                    ledger=snapshot_ledger,
                    drift_score=0,
                    invariants_satisfied=["BEFORE_STEP"],
                    conversation_summary=f"Before action: {action.tool}/{action.command}",
                )
                return _original_execute(action)

            execute_action = _snapshotting_execute

        # Run the agent loop
        final_state, evidence_log, stop_reason = run_agent_loop(agent, execute_action, gate)

        # --- Auto-snapshot: post-loop recovery & final snapshot ---
        if snapshot_ledger is not None:
            from gatekeeper_eos_v6.snapshot import take_snapshot, context_revalidation as _do_restore
            import sys

            # If halted due to drift, attempt context_revalidation
            restored = False
            restore_warnings: list[str] = []
            if stop_reason and "drift" in str(stop_reason.value):
                try:
                    entry, warnings = _do_restore(
                        agent=agent,
                        session_id=session.session_id,
                        ledger=snapshot_ledger,
                        max_drift_score=0,
                    )
                    restored = True
                    restore_warnings.extend(warnings)
                    stop_reason = agent.stop_reason  # Updated by restore

                    # Snapshot after restore
                    take_snapshot(
                        agent=agent,
                        session_id=session.session_id,
                        checkpoint_id="CKPT-RESTORE",
                        ledger=snapshot_ledger,
                        drift_score=0,
                        invariants_satisfied=["RESTORED"],
                        conversation_summary=f"Restored from checkpoint {entry.checkpoint_id} ({len(warnings)} warnings)",
                    )
                except Exception as e:
                    restore_warnings.append(f"Restore failed: {e}")
                    print(f"[campaign] Session '{session.session_id}' restore failed: {e}", file=sys.stderr)

            # Determine final drift state for snapshot metadata
            final_drift_score = 1 if not restored and restore_warnings else 0

            # Final snapshot after loop
            take_snapshot(
                agent=agent,
                session_id=session.session_id,
                checkpoint_id="CKPT-FINAL",
                ledger=snapshot_ledger,
                drift_score=final_drift_score,
                invariants_satisfied=["FINAL"],
                conversation_summary=f"Session complete. Steps: {agent.step}, reason: {stop_reason.value if stop_reason else 'completed'}",
            )

            # Update final_state if restored
            if restored:
                final_state = agent.state
                evidence_log = agent.evidence_log

        # Write final checkpoint
        status = "completed"
        if stop_reason and "drift" in str(stop_reason.value):
            status = "halted"
        elif stop_reason and "human" in str(stop_reason.value):
            status = "halted"

        with self.lock_manager.acquire("checkpoint_mutex"):
            write_checkpoint(
                session_id=session.session_id,
                plan_id=plan_id,
                step_id="agentic_end",
                status=status,
                output={
                    "total_steps": agent.step,
                    "stop_reason": stop_reason.value if stop_reason else "completed",
                    "findings_count": len(final_state.findings_summary),
                    "vulnerabilities_count": len(final_state.vulnerabilities),
                    "open_ports_count": len(final_state.open_ports),
                    "evidence_count": len(evidence_log),
                },
                checkpoint_dir=self.checkpoint_dir,
            )

        return final_state, evidence_log, stop_reason
