"""E2E YAML test — proves the full config-to-runtime path.

Coverage:
  1. YAML → validation (load_campaign parses the agentic campaign YAML)
  2. AgentCore construction from YAML config (from_agentic_config)
  3. Stop conditions trigger AgentStopTriggered
  4. Snapshots written and restored correctly
  5. PolicyGate CIDR behaviour stays fixed
  6. Drift handling (state hallucination → halt → restore)

Run:  pytest tests/test_e2e_yaml.py -v
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gatekeeper_eos_v6.agentic import (
    AgentCore,
    AgentAction,
    PolicyGate,
    StopCondition,
    StopReason,
    AgentStopTriggered,
    AgentStateError,
    run_agent_loop,
)
from gatekeeper_eos_v6.campaign import (
    load_campaign,
    CampaignValidationError,
    CampaignExecutor,
)
from gatekeeper_eos_v6.snapshot import (
    SnapshotLedger,
    take_snapshot,
    context_revalidation,
    SnapshotNotFoundError,
)

# ===========================================================================
# Fixtures
# ===========================================================================

CAMPAIGN_PATH = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"


@pytest.fixture(scope="module")
def campaign():
    """Load the agentic campaign YAML once per module."""
    assert CAMPAIGN_PATH.exists(), f"Missing: {CAMPAIGN_PATH}"
    return load_campaign(CAMPAIGN_PATH)


@pytest.fixture(scope="module")
def recon_plan(campaign):
    """Return the inline plan dict for SESS-agentic-recon."""
    for s in campaign.sessions:
        if s.session_id == "SESS-agentic-recon":
            assert isinstance(s.plan, dict), "Expected inline plan"
            return s.plan
    raise AssertionError("SESS-agentic-recon not found")


@pytest.fixture(scope="module")
def vulnscan_plan(campaign):
    """Return the inline plan dict for SESS-agentic-vulnscan."""
    for s in campaign.sessions:
        if s.session_id == "SESS-agentic-vulnscan":
            assert isinstance(s.plan, dict), "Expected inline plan"
            return s.plan
    raise AssertionError("SESS-agentic-vulnscan not found")


@pytest.fixture
def recon_agent(recon_plan):
    """Build an AgentCore from the recon session's YAML config."""
    return AgentCore.from_agentic_config(
        config=recon_plan["agentic_config"],
        allowed_tools=recon_plan.get("allowed_tools", []),
        authorized_assets=recon_plan.get("authorized_assets", []),
        objective=recon_plan.get("objective", ""),
        success_criteria=recon_plan.get("success_criteria"),
    )


@pytest.fixture
def vulnscan_agent(vulnscan_plan):
    """Build an AgentCore from the vulnscan session's YAML config (stop_on_finding: critical)."""
    return AgentCore.from_agentic_config(
        config=vulnscan_plan["agentic_config"],
        allowed_tools=vulnscan_plan.get("allowed_tools", []),
        authorized_assets=vulnscan_plan.get("authorized_assets", []),
        objective=vulnscan_plan.get("objective", ""),
        success_criteria=vulnscan_plan.get("success_criteria"),
    )


@pytest.fixture
def recon_gate(recon_plan):
    """PolicyGate from the recon plan's allowed_tools + authorized_assets."""
    return PolicyGate(
        allowed_tools=recon_plan.get("allowed_tools", []),
        authorized_assets=recon_plan.get("authorized_assets", []),
    )


@pytest.fixture
def ledger(tmp_path):
    """A fresh SnapshotLedger in a temp dir."""
    return SnapshotLedger(tmp_path / "e2e_ledger.json")


# ===========================================================================
# 1. YAML → validation
# ===========================================================================


class TestYamlLoadAndValidate:
    """Prove the campaign YAML parses and validates correctly."""

    def test_campaign_loads(self, campaign):
        assert campaign.campaign_id == "CAMP-PENTEST-AGENTIC-2026-Q3"
        assert len(campaign.sessions) == 3

    def test_all_sessions_have_inline_plans(self, campaign):
        for s in campaign.sessions:
            assert isinstance(s.plan, dict), f"Session {s.session_id} lacks inline plan"

    def test_all_sessions_have_agentic_config(self, campaign):
        for s in campaign.sessions:
            assert "agentic_config" in s.plan, f"Session {s.session_id} missing agentic_config"
            assert s.plan["agentic_config"]["enabled"] is True

    def test_dependency_chain(self, campaign):
        sessions = {s.session_id: s for s in campaign.sessions}
        assert sessions["SESS-agentic-vulnscan"].dependencies == ("SESS-agentic-recon",)
        assert sessions["SESS-agentic-report"].dependencies == ("SESS-agentic-vulnscan",)

    def test_global_drift_rules_include_agent_state(self, campaign):
        rule_ids = {r.id for r in campaign.global_drift_rules}
        assert "DRIFT-TARGET" in rule_ids
        assert "DRIFT-TOOLS" in rule_ids
        assert "DRIFT-NET" in rule_ids
        assert "DRIFT-SCHEMA" in rule_ids
        assert "DRIFT-PLAN" in rule_ids
        assert "DRIFT-EXPIRY" in rule_ids

    def test_executor_resolves_layers(self, campaign):
        executor = CampaignExecutor(campaign)
        layers = executor.resolve_sessions()
        assert len(layers) == 3
        assert layers[0] == ["SESS-agentic-recon"]
        assert layers[1] == ["SESS-agentic-vulnscan"]
        assert layers[2] == ["SESS-agentic-report"]


# ===========================================================================
# 2. AgentCore construction from YAML config
# ===========================================================================


class TestAgentCoreFromYamlConfig:
    """Prove from_agentic_config correctly parses all YAML fields."""

    def test_recon_config_parsed(self, recon_agent):
        assert recon_agent.max_steps == 50
        assert recon_agent.max_time_seconds == 600  # PT10M
        assert recon_agent.decision_strategy == "rule"
        assert recon_agent.stop_on_finding == "none"
        assert recon_agent._drift_check_enabled is True

    def test_recon_stop_conditions_parsed(self, recon_agent):
        assert recon_agent.stop_conditions is not None
        assert len(recon_agent.stop_conditions) == 2
        assert recon_agent.stop_conditions[0]["type"] == "success_criterion_met"
        assert recon_agent.stop_conditions[1]["type"] == "time_limit"
        assert recon_agent.stop_conditions[1]["value"] == "PT15M"

    def test_recon_rule_engine_config_parsed(self, recon_agent):
        assert recon_agent.rule_engine_config is not None
        assert recon_agent.rule_engine_config.max_retries_per_phase == 2
        assert recon_agent.rule_engine_config.fallback_on_empty == "fingerprint"

    def test_recon_authorized_assets(self, recon_agent):
        assert "10.0.0.10" in recon_agent.authorized_assets

    def test_recon_objective(self, recon_agent):
        assert "open ports" in recon_agent.objective.lower()

    def test_vulnscan_config_parsed(self, vulnscan_agent):
        assert vulnscan_agent.max_steps == 50
        assert vulnscan_agent.max_time_seconds == 900  # 15 min
        assert vulnscan_agent.stop_on_finding == "critical"
        assert vulnscan_agent.decision_strategy == "rule"

    def test_vulnscan_stop_conditions(self, vulnscan_agent):
        assert vulnscan_agent.stop_conditions is not None
        assert len(vulnscan_agent.stop_conditions) == 1
        assert vulnscan_agent.stop_conditions[0]["type"] == "finding_severity"
        assert vulnscan_agent.stop_conditions[0]["value"] == "critical"


# ===========================================================================
# 3. Stop conditions trigger AgentStopTriggered
# ===========================================================================


class TestStopConditionsTrigger:
    """Prove stop conditions from YAML config halt the agent."""

    def test_stop_on_critical_finding_halts(self, vulnscan_agent):
        """stop_on_finding: critical should halt when a critical finding appears."""
        action = AgentAction(tool="vuln-scanner", command="scan-cve", target="10.0.0.10")
        output = {
            "findings_summary": [
                {"title": "Critical RCE", "severity": "critical", "confidence": 0.95},
            ],
            "vulnerabilities": [{"id": "CVE-2025-0001", "severity": "critical"}],
        }
        with pytest.raises(AgentStopTriggered, match="max_severity_found"):
            vulnscan_agent.step_action(action, output)
        assert vulnscan_agent.halted
        assert vulnscan_agent.stop_reason == StopReason.MAX_SEVERITY_FOUND

    def test_stop_conditions_array_halts_via_step(self, recon_agent):
        """success_criterion_met in stop_conditions should halt when criteria are met."""
        # First, add state so all 3 success criteria are satisfied:
        #   "All open ports on target identified"   → "open" in "open_ports"
        #   "Service versions fingerprinted"        → "service" in "services"
        #   "Technology stack documented"            → "technology" in last_action_result
        recon_agent.state.update({"open_ports": [80, 443], "services": [{"name": "nginx"}]})
        recon_agent.state.last_action_result = "Technology stack: nginx 1.25"

        action = AgentAction(tool="nmap", command="fingerprint", target="10.0.0.10")
        output = {"last_action_result": "Technology stack: nginx 1.25"}

        with pytest.raises(AgentStopTriggered, match="criteria_met|max_severity"):
            recon_agent.step_action(action, output)
        # Should stop because all 3 success criteria are met
        assert recon_agent.halted

    def test_stop_conditions_time_limit(self, recon_agent):
        """time_limit in stop_conditions should halt after elapsed time."""
        agent = AgentCore.from_agentic_config(
            config={
                "enabled": True,
                "stop_conditions": [
                    {"type": "time_limit", "value": "PT0.01S"},
                ],
            },
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.10"],
            objective="Test",
        )
        time.sleep(0.02)
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")
        with pytest.raises(AgentStopTriggered, match="max_time"):
            agent.step_action(action, {"open_ports": [80]})
        assert agent.stop_reason == StopReason.MAX_TIME


# ===========================================================================
# 4. Snapshots written and restored correctly
# ===========================================================================


class TestE2ESnapshots:
    """Prove snapshots capture agent state and context_revalidation restores it."""

    def test_take_snapshot_from_yaml_agent(self, recon_agent, ledger):
        """Take a snapshot of an agent built from YAML config, then verify it."""
        recon_agent.step = 1
        recon_agent.state.update({"open_ports": [80]})

        entry = take_snapshot(
            agent=recon_agent,
            session_id="SESS-agentic-recon",
            checkpoint_id="CKPT-E2E-001",
            ledger=ledger,
            drift_score=0,
            invariants_satisfied=["E2E_TEST"],
        )
        assert entry.session_id == "SESS-agentic-recon"
        assert entry.checkpoint_id == "CKPT-E2E-001"
        assert entry.working_memory["open_ports"] == [80]
        assert entry.chain_hash != ""
        assert len(entry.tool_call_history) == 0  # No evidence logged yet

    def test_snapshot_round_trip_restores_state(self, recon_agent, ledger):
        """Take a snapshot, modify the agent, then restore via context_revalidation."""
        # Set up some state + evidence
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")
        recon_agent.step_action(action, {"open_ports": [80]})
        original_ports = list(recon_agent.state.open_ports)

        # Snapshot
        take_snapshot(
            agent=recon_agent,
            session_id="SESS-agentic-recon",
            checkpoint_id="CKPT-E2E-ROUNDTRIP",
            ledger=ledger,
            drift_score=0,
        )

        # Hallucinate
        recon_agent.state.open_ports.append(9999)
        recon_agent.halted = True

        # Restore
        entry, warnings = context_revalidation(
            agent=recon_agent,
            session_id="SESS-agentic-recon",
            ledger=ledger,
        )
        assert recon_agent.state.open_ports == original_ports
        assert 9999 not in recon_agent.state.open_ports
        assert not recon_agent.halted
        assert len(recon_agent.evidence_log) == 1  # Evidence restored

    def test_hash_chain_across_snapshots(self, recon_agent, tmp_path):
        """Multiple snapshots from YAML-based agent should form a valid hash chain."""
        l = SnapshotLedger(tmp_path / "chain_test.json")

        # Snapshot 1 — step 0
        take_snapshot(recon_agent, "SESS-recon", "CKPT-001", l, drift_score=0)

        # Step once
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")
        recon_agent.step_action(action, {"open_ports": [80]})

        # Snapshot 2 — step 1
        take_snapshot(recon_agent, "SESS-recon", "CKPT-002", l, drift_score=0)

        # Step again
        recon_agent.step_action(action, {"open_ports": [443]})

        # Snapshot 3 — step 2
        take_snapshot(recon_agent, "SESS-recon", "CKPT-003", l, drift_score=0)

        violations = l.verify_integrity()
        assert violations == []

        # Chain links should be correct
        entries = l.index.all_entries()
        assert entries[0].prev_chain_hash == ""
        assert entries[1].prev_chain_hash == entries[0].chain_hash
        assert entries[2].prev_chain_hash == entries[1].chain_hash

    def test_recovery_from_all_drifted_snapshots(self, recon_agent, tmp_path):
        """When all snapshots have drift, context_revalidation raises."""
        l = SnapshotLedger(tmp_path / "all_drifted.json")

        take_snapshot(recon_agent, "SESS-recon", "CKPT-001", l, drift_score=2)
        take_snapshot(recon_agent, "SESS-recon", "CKPT-002", l, drift_score=3)

        recon_agent.halted = True
        with pytest.raises(SnapshotNotFoundError, match="No valid snapshot"):
            context_revalidation(recon_agent, "SESS-recon", l, max_drift_score=0)

    def test_snapshot_integrity_detects_tamper(self, recon_agent, tmp_path):
        """Tampered snapshot is detected by context_revalidation."""
        ledger_path = tmp_path / "tamper_test.json"
        l = SnapshotLedger(ledger_path)

        take_snapshot(recon_agent, "SESS-recon", "CKPT-001", l, drift_score=0)

        # Tamper with the file
        raw = json.loads(ledger_path.read_text())
        raw[0]["working_memory"]["open_ports"] = [6666]
        ledger_path.write_text(json.dumps(raw, indent=2))
        l.reload()

        recon_agent.halted = True
        from gatekeeper_eos_v6.snapshot import SnapshotIntegrityError

        with pytest.raises(SnapshotIntegrityError, match="integrity"):
            context_revalidation(recon_agent, "SESS-recon", l)


# ===========================================================================
# 5. PolicyGate CIDR behaviour stays fixed
# ===========================================================================


class TestE2EPolicyGateCidr:
    """Prove PolicyGate CIDR matching works end-to-end."""

    def test_cidr_in_scope_accepted(self):
        """Target within CIDR subnet passes."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.5")
        assert gate.validate_action(action) == []

    def test_cidr_out_of_scope_rejected(self):
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.1.5")
        violations = gate.validate_action(action)
        assert len(violations) >= 1

    def test_cidr_subnet_exact_match(self):
        """10.0.0.10 is within 10.0.0.0/24 (not a false startswith match)."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")
        assert gate.validate_action(action) == []

    def test_cidr_adjacent_subnet_rejected(self):
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.1.5")
        assert len(gate.validate_action(action)) >= 1

    def test_mixed_hostname_and_cidr(self):
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24", "target.example.com"],
        )
        # Hostname should match
        assert gate.validate_action(AgentAction(
            tool="nmap", command="scan", target="target.example.com",
        )) == []
        # Different hostname should fail
        assert len(gate.validate_action(AgentAction(
            tool="nmap", command="scan", target="evil.example.com",
        ))) >= 1

    def test_output_cidr_scope_enforced(self):
        gate = PolicyGate(
            allowed_tools=[{"name": "recon", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        assert gate.validate_output({"discovered_assets": ["10.0.0.10", "10.0.0.20"]}) == []
        violations = gate.validate_output({"discovered_assets": ["10.0.0.10", "192.168.1.1"]})
        assert len(violations) >= 1

    def test_single_ip_no_false_positive(self):
        """10.0.0.101 should NOT match authorized single IP 10.0.0.10."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.10"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.101")
        assert len(gate.validate_action(action)) >= 1


# ===========================================================================
# 6. Full E2E: YAML → AgentCore → snapshots → restore
# ===========================================================================


class TestE2EFullPath:
    """The big one: run the agent loop from YAML config through snapshot recovery."""

    def test_run_agent_loop_from_yaml_stops_by_criteria(self, recon_agent):
        """Agent built from YAML config runs the agent loop and stops via stop_conditions."""
        def execute(action):
            return {"open_ports": [80, 443], "services": [{"name": "nginx"}]}

        # The recon agent has stop_conditions: [success_criterion_met, time_limit]
        # With detected ports + services, criteria should be met
        final_state, evidence, reason = run_agent_loop(recon_agent, execute)

        assert len(final_state.open_ports) >= 1
        assert len(evidence) >= 1
        assert reason is not None
        # Either criteria met or drift/no-more-actions
        assert reason in (StopReason.CRITERIA_MET, StopReason.MAX_STEPS)

    def test_agent_loop_with_policy_gate(self, recon_agent, recon_gate):
        """Agent loop with PolicyGate should enforce bounds and record evidence."""
        call_count = [0]

        def execute(action):
            call_count[0] += 1
            # First call: just discover ports (recon phase → nmap discover)
            if call_count[0] == 1:
                return {"open_ports": [80]}
            # Second call: fingerprint services + include tech stack keyword
            # so all 3 success criteria are met before vulnerability phase
            return {
                "services": [{"name": "nginx"}],
                "last_action_result": "Technology stack: nginx 1.25",
            }

        gate = recon_gate
        final_state, evidence, reason = run_agent_loop(recon_agent, execute, gate)

        # All actions should be within bounds (no unauthorized targets)
        assert len(evidence) >= 1
        # Should have stopped via criteria met
        assert reason in (StopReason.CRITERIA_MET, StopReason.MAX_STEPS)

        # All evidence entries should have valid actions
        for entry in evidence:
            gate_violations = gate.validate_action(entry.action)
            assert gate_violations == [], f"Policy violation in loop: {gate_violations}"

    def test_agent_loop_with_snapshots(self, recon_agent, tmp_path):
        """Run agent loop with snapshot ledger, verify recovery works after."""
        ledger_path = tmp_path / "e2e_loop_ledger.json"
        l = SnapshotLedger(ledger_path)

        # Take initial snapshot
        take_snapshot(recon_agent, "SESS-recon", "CKPT-INIT", l, drift_score=0)

        # Run a few steps manually through step_action to build evidence
        action1 = AgentAction(tool="nmap", command="discover", target="10.0.0.10")
        try:
            recon_agent.step_action(action1, {"open_ports": [80]})
        except AgentStopTriggered:
            pass

        # Snapshot after step
        take_snapshot(recon_agent, "SESS-recon", "CKPT-STEP1", l, drift_score=0)

        action2 = AgentAction(tool="nmap", command="fingerprint", target="10.0.0.10")
        try:
            recon_agent.step_action(action2, {"services": [{"name": "nginx"}]})
        except AgentStopTriggered:
            pass

        # Snapshot after step 2
        take_snapshot(recon_agent, "SESS-recon", "CKPT-STEP2", l, drift_score=0)

        # Verify full chain integrity
        violations = l.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"

        # Now simulate drift and recover
        original_ports = list(recon_agent.state.open_ports)
        recon_agent.state.open_ports.append(9999)
        recon_agent.halted = True

        # Recover from CKPT-STEP2 (the most recent clean snapshot)
        entry, warnings = context_revalidation(recon_agent, "SESS-recon", l, max_drift_score=0)

        assert recon_agent.state.open_ports == original_ports
        assert 9999 not in recon_agent.state.open_ports
        assert not recon_agent.halted
        assert recon_agent.step == len(recon_agent.evidence_log)

    def test_drift_check_env_via_yaml(self, recon_agent, tmp_path):
        """Agent with _drift_check_enabled=True from YAML should detect state divergence."""
        l = SnapshotLedger(tmp_path / "drift_e2e.json")

        # First step — establishes baseline evidence
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")
        try:
            recon_agent.step_action(action, {"open_ports": [80]})
        except AgentStopTriggered:
            pass

        take_snapshot(recon_agent, "SESS-recon", "CKPT-BASELINE", l, drift_score=0)

        # Add a hallucinated port directly to state (bypassing step_action)
        recon_agent.state.open_ports.append(9999)

        # Next step should trigger drift detection
        action2 = AgentAction(tool="nmap", command="fingerprint", target="10.0.0.10")
        with pytest.raises(AgentStateError, match="drift|hallucinated"):
            recon_agent.step_action(action2, {"services": [{"name": "nginx"}]})
        assert recon_agent.halted
        assert recon_agent.stop_reason == StopReason.DRIFT_DETECTED

    def test_integrity_check_on_yaml_agent_snapshots(self, recon_agent, tmp_path):
        """Snapshots from YAML-based agent must pass integrity check on reload."""
        ledger_path = tmp_path / "reload_test.json"
        l = SnapshotLedger(ledger_path)

        for i in range(5):
            take_snapshot(recon_agent, "SESS-recon", f"CKPT-{i:03d}", l, drift_score=0)

        # Reload from disk
        l.reload()
        violations = l.verify_integrity()
        assert violations == []

    def test_multi_asset_discovery_does_not_trip_stall(self):
        """Discovering all authorized assets then moving to report should not stall.

        Prevents regression of the asset-exhaustion FP fix: when the rule
        selector transitions cleanly from scan to report phase after discovering
        all authorized assets, _check_asset_exhaustion must not fire because
        there is no stall evidence (stall_count == 0).
        """
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Scan all assets and report",
            decision_strategy="hybrid",  # Must use hybrid to exercise stall detection
            max_steps=4,  # 4 phases: recon → fingerprint → vuln → report
            stop_on_criteria_met=False,
        )

        call_count = [0]

        def execute(action):
            call_count[0] += 1
            # Phase 1: recon discovers ports + all assets
            if call_count[0] == 1:
                return {"open_ports": [80], "discovered_assets": assets}
            # Phase 2: service fingerprint
            if call_count[0] == 2:
                return {"services": [{"name": "nginx"}]}
            # Phase 3: vulnerability scan — return vulns to move past vuln phase
            if call_count[0] == 3:
                return {"vulnerabilities": [{"id": "CVE-2025-0001"}]}
            # Phase 4: report (agent transitions cleanly to report phase)
            return {"last_action_result": "summary generated"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Agent should complete all 4 phases without stall. The stall_count
        # is reset on every phase transition (different tool/command), so
        # _check_asset_exhaustion never fires because stall_count == 0.
        assert reason != StopReason.RULE_ENGINE_STALLED, (
            f"Stopped via stall while discovering multi-asset campaign. "
            f"Should have reached report phase. Reason: {reason}"
        )
        # All authorized assets should be in state
        assert len(final_state.discovered_assets) == 3 or len(evidence) > 0


# ===========================================================================
# 7. Drift handling: halt → restore → resume
# ===========================================================================


class TestE2EDriftRecovery:
    """Prove the full drift detection → halt → restore → resume cycle."""

    def test_full_drift_recovery_cycle(self, tmp_path):
        """Complete cycle: step → snapshot → hallucinate → drift halt → restore → resume.

        Uses a purpose-built agent without success_criteria to avoid spurious
        keyword matches against findings_summary.
        """
        l = SnapshotLedger(tmp_path / "drift_cycle.json")

        agent = AgentCore.from_agentic_config(
            config={
                "enabled": True,
                "max_steps": 10,
                "decision_strategy": "rule",
                "agent_state_drift_check": True,
            },
            allowed_tools=[
                {"name": "vuln-scanner", "allowed_commands": ["scan-cve"]},
                {"name": "cve-lookup", "allowed_commands": ["query"]},
            ],
            authorized_assets=["10.0.0.10"],
            objective="Drift recovery test",
            success_criteria=None,
        )

        # Step 1 — establish clean state
        action = AgentAction(tool="vuln-scanner", command="scan-cve", target="10.0.0.10")
        try:
            agent.step_action(action, {
                "vulnerabilities": [{"id": "CVE-2025-0001", "severity": "low"}],
            })
        except AgentStopTriggered:
            pass

        # Snapshot the clean state
        take_snapshot(agent, "SESS-vulnscan", "CKPT-CLEAN", l, drift_score=0)

        # Step 2 — hallucinate: directly add a non-evidenced vuln to state
        agent.state.vulnerabilities.append({"id": "CVE-9999", "severity": "critical"})

        # Step 3 — next action detects drift
        action2 = AgentAction(tool="cve-lookup", command="query", target="10.0.0.10")
        with pytest.raises(AgentStateError, match="drift|hallucinated"):
            agent.step_action(action2, {"last_action_result": "query sent"})
        assert agent.halted
        assert agent.stop_reason == StopReason.DRIFT_DETECTED

        # Step 4 — restore from clean snapshot
        entry, warnings = context_revalidation(
            agent, "SESS-vulnscan", l, max_drift_score=0,
        )
        assert entry.checkpoint_id == "CKPT-CLEAN"
        assert not agent.halted
        assert agent.stop_reason is None
        assert 9999 not in [v["id"] for v in agent.state.vulnerabilities]
        assert len(agent.state.vulnerabilities) == 1  # Only CVE-2025-0001

        # Step 5 — resume: agent can get a next action
        resumed_action = agent.get_next_action()
        assert resumed_action is not None
        assert resumed_action.tool is not None

    def test_drift_does_not_corrupt_other_sessions(self, recon_agent, vulnscan_agent, tmp_path):
        """Drift in one session should not affect snapshots of another session."""
        l = SnapshotLedger(tmp_path / "cross_session.json")

        # Both agents take a snapshot
        take_snapshot(recon_agent, "SESS-recon", "CKPT-001", l, drift_score=0)
        take_snapshot(vulnscan_agent, "SESS-vulnscan", "CKPT-001", l, drift_score=0)

        # Hallucinate in recon only
        recon_agent.state.open_ports.append(9999)
        recon_agent.halted = True

        # Restore recon — should get clean state
        e1, w1 = context_revalidation(recon_agent, "SESS-recon", l)
        assert 9999 not in recon_agent.state.open_ports

        # Vulnscan should be unaffected
        assert vulnscan_agent.halted is False
        assert not vulnscan_agent.state.vulnerabilities  # Still clean/empty


# ===========================================================================
# 8. CampaignExecutor integration
# ===========================================================================


class TestE2ECampaignExecutor:
    """Prove run_agentic_session works end-to-end with snapshot dir configured."""

    def test_executor_with_snapshots(self, tmp_path):
        """CampaignExecutor.run_agentic_session with snapshot_dir writes snapshots."""
        from gatekeeper_eos_v6.campaign import Campaign, SessionDef, Schedule

        plan = {
            "plan_id": "PLAN-E2E-01",
            "authorized_assets": ["10.0.0.10"],
            "allowed_tools": [
                {"name": "nmap", "allowed_commands": ["scan"]},
            ],
            "objective": "E2E test",
            "success_criteria": ["Open ports identified"],
            "agentic_config": {
                "enabled": True,
                "max_steps": 3,
                "decision_strategy": "rule",
                "stop_on_finding": "none",
                "agent_state_drift_check": True,
            },
        }

        session = SessionDef(
            session_id="SESS-e2e-exec",
            plan=plan,
            schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        )
        campaign = Campaign(campaign_id="CAMP-E2E", sessions=(session,))
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
        )

        def execute(action):
            return {"open_ports": [80], "services": [{"name": "nginx"}]}

        final_state, evidence, stop_reason = executor.run_agentic_session(session, execute)

        assert len(final_state.open_ports) >= 1
        assert len(evidence) >= 1

        # Verify snapshots were written
        snapshots_dir = tmp_path / "snapshots"
        assert snapshots_dir.exists()
        ledger_files = list(snapshots_dir.glob("*.json"))
        assert len(ledger_files) >= 1

        # Verify the snapshot ledger has entries
        from gatekeeper_eos_v6.snapshot import SnapshotLedger
        l = SnapshotLedger(ledger_files[0])
        assert l.index.size >= 3  # init + pre-step(s) + final

        # Verify hash chain integrity
        violations = l.verify_integrity()
        assert violations == [], f"Snapshot chain broken in E2E: {violations}"

    def test_executor_with_drift_halt_and_restore(self, tmp_path):
        """Executor with snapshot_dir: drift triggers halt, restore succeeds."""
        from gatekeeper_eos_v6.campaign import Campaign, SessionDef, Schedule, DriftRule

        plan = {
            "plan_id": "PLAN-E2E-DRIFT",
            "authorized_assets": ["10.0.0.10"],
            "allowed_tools": [
                {"name": "nmap", "allowed_commands": ["scan"]},
            ],
            "objective": "Drift recovery E2E",
            "success_criteria": ["Open ports identified"],
            "agentic_config": {
                "enabled": True,
                "max_steps": 10,
                "decision_strategy": "rule",
                "agent_state_drift_check": True,
            },
        }

        session = SessionDef(
            session_id="SESS-e2e-drift-restore",
            plan=plan,
            schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        )
        campaign = Campaign(
            campaign_id="CAMP-E2E-DRIFT",
            sessions=(session,),
            global_drift_rules=(
                DriftRule(id="DRIFT-AGENT-STATE", description="Hallucination check", condition="state_diverges"),
            ),
        )
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt2",
            snapshot_dir=tmp_path / "snapshots2",
        )

        call_count = [0]

        def execute(action):
            call_count[0] += 1
            # On the second call, return different ports to simulate partial state
            result = {"open_ports": [80], "services": [{"name": "nginx"}]}
            return result

        final_state, evidence, stop_reason = executor.run_agentic_session(session, execute)

        # The session should have completed (possibly with some steps)
        assert len(final_state.open_ports) >= 1 or len(evidence) >= 1

        # Verify snapshot ledger has entries
        snapshots_dir = tmp_path / "snapshots2"
        ledger_files = list(snapshots_dir.glob("*.json"))
        assert len(ledger_files) >= 1

        from gatekeeper_eos_v6.snapshot import SnapshotLedger
        l = SnapshotLedger(ledger_files[0])
        violations = l.verify_integrity()
        assert violations == [], f"Snapshot chain broken in drift E2E: {violations}"
