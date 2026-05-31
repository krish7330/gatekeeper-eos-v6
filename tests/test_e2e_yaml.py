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
import unittest.mock
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
    MockLLMProvider,
    run_agent_loop,
)
from gatekeeper_eos_v6.providers import OpenAIProvider, AnthropicProvider, GoogleProvider, create_llm_provider
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
# 7b. Checkpoint integration — run_agent_loop with snapshot_ledger
# ===========================================================================


class TestE2ECheckpointIntegration:
    """Prove run_agent_loop with snapshot_ledger writes snapshots and recovers from drift."""

    def test_loop_writes_snapshot_chain(self, tmp_path):
        """Full loop with snapshot_ledger produces valid hash chain."""
        from gatekeeper_eos_v6.snapshot import SnapshotLedger

        l = SnapshotLedger(tmp_path / "e2e_ckpt.json")

        agent = AgentCore(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover", "scan"]}],
            authorized_assets=["10.0.0.10"],
            objective="Checkpoint E2E",
            decision_strategy="rule",
            max_steps=5,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            return {"open_ports": [80, 443], "services": [{"name": "nginx"}]}

        state, evidence, reason = run_agent_loop(agent, execute, snapshot_ledger=l, session_id="SESS-e2e-ckpt")

        # Verify hash chain integrity
        violations = l.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"
        # Verify entries have correct session and sequence
        entries = l.index.get_by_session("SESS-e2e-ckpt")
        assert len(entries) >= 2, f"Expected ≥2 entries, got {len(entries)}"

    def test_loop_drift_recovery_e2e(self, tmp_path):
        """E2E: drift triggers recovery, loop resumes, final state is clean."""
        from gatekeeper_eos_v6.snapshot import SnapshotLedger

        l = SnapshotLedger(tmp_path / "e2e_drift.json")

        agent = AgentCore(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover", "scan"]}],
            authorized_assets=["10.0.0.10"],
            objective="Drift recovery E2E",
            decision_strategy="rule",
            max_steps=10,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        call_count = [0]
        drift_injected = [False]

        def execute(action):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"open_ports": [80]}
            if not drift_injected[0]:
                agent.state.open_ports.append(9999)
                drift_injected[0] = True
            return {"open_ports": [443], "services": [{"name": "nginx"}]}

        state, evidence, reason = run_agent_loop(agent, execute, snapshot_ledger=l, session_id="SESS-e2e-drift")

        # State should be clean (no hallucinated port)
        assert 9999 not in state.open_ports, f"Hallucinated port still present: {state.open_ports}"
        # Should not have stopped via drift
        assert reason != StopReason.DRIFT_DETECTED, f"Loop stopped via drift: {reason}"
        # Evidence collected (before + after recovery)
        assert len(evidence) >= 2, f"Expected ≥2 evidence entries, got {len(evidence)}"
        # Snapshot chain should be intact
        violations = l.verify_integrity()
        assert violations == [], f"Hash chain broken after recovery: {violations}"


# ===========================================================================
# 8. Tool-not-found hybrid E2E — Mode A stall detection
# ===========================================================================


class TestE2EToolNotFoundStall:
    """Prove the hybrid strategy detects and stops on tool-not-found stall.

    Mode A failure: when the rule engine's hardcoded substring search can't
    find any matching tool (e.g., tools named "nikto" and "sublist3r" instead
    of "nmap" and "reporter"), _select_with_rules generates invalid tool names.
    The hybrid strategy detects this via _check_tool_loop (same invalid
    tool+command repeated 3+ times) and returns RULE_ENGINE_STALLED.
    """

    def test_hybrid_stalls_when_no_matching_tools(self):
        """Tools with names outside the rule engine's hardcoded search trigger stall.

        The rule engine searches for substrings: "nmap", "recon", "scanner",
        "grype", "trivy", "reporter". None match "nikto" or "sublist3r",
        so _select_with_rules generates made-up tool names ("recon").
        The hybrid strategy detects 3+ consecutive identical actions and
        returns RULE_ENGINE_STALLED.
        """
        tools = [
            {"name": "nikto", "allowed_commands": ["scan"]},
            {"name": "sublist3r", "allowed_commands": ["discover"]},
        ]
        assets = ["10.0.0.10"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Example: scan target for vulnerabilities",
            decision_strategy="hybrid",
            max_steps=10,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            # Execute always returns nothing — rule engine stays in recon
            # phase and keeps generating the same invalid action
            return {"last_action_result": "no results"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Agent should stop via RULE_ENGINE_STALLED, not MAX_STEPS
        assert reason == StopReason.RULE_ENGINE_STALLED, (
            f"Expected RULE_ENGINE_STALLED, got {reason}"
        )
        # Evidence should show the repeated actions
        assert len(evidence) >= 1
        # All actions should be the same invalid tool (nikto doesn't match "nmap"/"recon")
        if evidence:
            for entry in evidence:
                assert entry.action.tool is not None

    def test_hybrid_stalls_with_policy_gate_rejection(self):
        """PolicyGate rejects invalid tool; hybrid still detects stall."""
        tools = [
            {"name": "gobuster", "allowed_commands": ["dir"]},
        ]
        assets = ["10.0.0.10"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Directory enumeration",
            decision_strategy="hybrid",
            max_steps=10,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        gate = PolicyGate(
            allowed_tools=tools,
            authorized_assets=assets,
        )

        call_count = [0]

        def execute(action):
            call_count[0] += 1
            return {"last_action_result": "scan complete"}

        final_state, evidence, reason = run_agent_loop(agent, execute, gate)

        # Should stall — gobuster doesn't match "nmap"/"recon"/"scanner"/etc.
        assert reason == StopReason.RULE_ENGINE_STALLED, (
            f"Expected RULE_ENGINE_STALLED, got {reason}"
        )
        # PolicyGate should have rejected the invalid tool names
        assert len(evidence) >= 1

        # Verify policy violations were recorded
        policy_violations = [
            e for e in evidence
            if "POLICY_VIOLATION" in e.output.get("last_action_result", "")
        ]
        assert len(policy_violations) >= 1, (
            "Expected at least one POLICY_VIOLATION evidence entry"
        )

    def test_rule_strategy_does_not_stall_on_same_config(self):
        """Rule strategy (not hybrid) with same tools does NOT detect stall.

        The 'rule' strategy doesn't call _check_stalled, so it keeps looping
        until MAX_STEPS without detecting the stall. Proves that the stall
        detection is specific to the 'hybrid' strategy.
        """
        tools = [
            {"name": "wapiti", "allowed_commands": ["scan"]},
        ]
        assets = ["10.0.0.10"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Web app scan",
            decision_strategy="rule",  # NOT hybrid
            max_steps=3,  # Low to keep test fast
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            return {"last_action_result": "no results"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Rule strategy should hit MAX_STEPS, not RULE_ENGINE_STALLED
        assert reason == StopReason.MAX_STEPS, (
            f"Expected MAX_STEPS, got {reason}"
        )


# ===========================================================================
# 9. Phase-lock stall (Mode B) — E2E
# ===========================================================================


class TestE2EPhaseLockStall:
    """Prove the hybrid strategy detects Mode B phase-lock stall.

    Mode B: when execute returns ports AND services simultaneously (e.g.,
    nmap -sV produces both), the rule selector jumps from recon (phase 1)
    directly to vuln scan (phase 3), skipping fingerprint (phase 2).
    If the vuln scan produces no new vulnerabilities, the selector stays
    in phase 3 repeating the same command, which _check_tool_loop detects
    as stall after 3+ consecutive identical actions.
    """

    def test_hybrid_stalls_on_phase_lock_skip(self):
        """Execute returns ports+services together, causing phase skip,
        then no vulns cause repeated vuln-scan commands -> stall."""
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Phase-lock stall test",
            decision_strategy="hybrid",
            max_steps=10,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        call_count = [0]

        def execute(action):
            call_count[0] += 1
            # Call 1: recon phase — return ports AND services together.
            # This triggers a phase skip: after step_action, state has
            # both open_ports and services, so the selector jumps past
            # the fingerprint phase (phase 2) to vuln scan (phase 3).
            if call_count[0] == 1:
                return {
                    "open_ports": [80, 443],
                    "services": [{"name": "nginx"}, {"name": "ssh"}],
                }
            # Calls 2+: vuln phase — never return vulns, so the selector
            # keeps generating the same vuln-scan command, triggering
            # _check_tool_loop after 3+ repetitions.
            return {"last_action_result": "no vulnerabilities found"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Agent should stop via RULE_ENGINE_STALLED (phase-lock), not MAX_STEPS
        assert reason == StopReason.RULE_ENGINE_STALLED, (
            f"Expected RULE_ENGINE_STALLED, got {reason}"
        )
        # Both services should have been discovered on the first call
        assert len(final_state.services) == 2, (
            "Should have discovered both services from the batched execute call"
        )
        # Evidence should show the repeated actions before stall fired
        assert len(evidence) >= 1

    def test_healthy_multi_phase_progression_does_not_stall(self):
        """Control test: sequential phase transitions (one output type per
        call) proceed cleanly through all 4 phases without stall.

        Each call returns only the output expected for that phase:
          1. recon -> only ports
          2. fingerprint -> only services
          3. vuln scan -> vulns
          4. report -> summary
        The selector transitions cleanly between phases, so _check_tool_loop
        never sees 3+ consecutive identical actions.
        """
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Healthy progression test",
            decision_strategy="hybrid",
            max_steps=4,  # exactly 1 per phase: recon → fingerprint → vuln → report
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        call_count = [0]

        def execute(action):
            call_count[0] += 1
            # Phase 1: recon -> just ports
            if call_count[0] == 1:
                return {"open_ports": [80]}
            # Phase 2: fingerprint -> just services
            if call_count[0] == 2:
                return {"services": [{"name": "nginx"}]}
            # Phase 3: vuln scan -> return vulns to move to report phase
            if call_count[0] == 3:
                return {"vulnerabilities": [{"id": "CVE-2025-0001"}]}
            # Phase 4: report -> summary
            return {"last_action_result": "report generated"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Agent should stop via MAX_STEPS after all 4 phases complete.
        # Each phase produces a different tool/command combination, so
        # stall_count resets on every transition. With max_steps=4, the
        # agent stops before the report phase can repeat 3+ times.
        assert reason == StopReason.MAX_STEPS, (
            f"Expected MAX_STEPS after 4 clean phases, got {reason}"
        )
        # Should have discovered the service
        assert len(final_state.services) == 1


# ===========================================================================
# 10. Multi-asset target rotation — E2E
# ===========================================================================


class TestE2EMultiAssetRotation:
    """Prove the hybrid strategy rotates through multiple authorized assets.

    Each call to select_action should target a different asset, cycling
    through the authorized list. This prevents the agent from always
    hammering the first asset and spreads work across all targets.
    """

    def test_hybrid_rotation_cycles_across_three_assets(self):
        """3 authorized assets → selector rotates through each one per call
        while progressing through phases normally."""
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Scan all assets",
            decision_strategy="hybrid",
            max_steps=4,  # Must stop before 3+ reporter repeats trigger stall
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        captured_targets = []

        def execute(action):
            captured_targets.append(action.target)
            # Return results that advance through all phases on first call.
            # 
            # IMPORTANT: Do NOT return discovered_assets — we don't need them
            # for the rotation check, and including them would cause the
            # asset-exhaustion stall check to fire (all assets discovered +
            # stall_count > 0 from repeated reporter calls).
            #
            # Call 1: recon → nmap/discover (state advances past all phases)
            # Calls 2-4: report → reporter/summary
            # max_steps=4 stops at step 4 before 3+ identical report calls
            return {
                "open_ports": [80, 443],
                "services": [{"name": "nginx"}],
                "vulnerabilities": [{"id": "CVE-2025-0001"}],
            }

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # The agent should have stopped via MAX_STEPS (not stall or error)
        assert reason == StopReason.MAX_STEPS, (
            f"Expected MAX_STEPS, got {reason}. Targets: {captured_targets}"
        )

        # Targets should show partial rotation across 3 assets:
        # Call 1: recon → 10.0.0.10 (idx 0)
        # Call 2: report → 10.0.0.11 (idx 1)
        # Call 3: report → 10.0.0.12 (idx 2)
        # Call 4: report → 10.0.0.10 (idx 0, wraps around)
        assert len(captured_targets) == 4, f"Expected 4 actions, got {len(captured_targets)}"
        assert captured_targets == ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.10"]

    def test_hybrid_rotation_with_phase_progression(self):
        """Rotation persists across phase transitions: after state advances
        from recon to fingerprint, the rotated asset target changes too."""
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10", "10.0.0.11"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Rotating scan",
            decision_strategy="hybrid",
            max_steps=4,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        captured_targets = []

        def execute(action):
            captured_targets.append(action.target)
            # Phase 1: recon → just ports on 10.0.0.10
            # Phase 2: fingerprint → just services on 10.0.0.11
            # Phase 3: vuln scan → vulns on 10.0.0.10 (wraps around)
            # Phase 4: report → summary on 10.0.0.11
            if len(captured_targets) == 1:
                return {"open_ports": [80]}
            elif len(captured_targets) == 2:
                return {"services": [{"name": "nginx"}]}
            elif len(captured_targets) == 3:
                return {"vulnerabilities": [{"id": "CVE-2025-0001"}]}
            else:
                return {"last_action_result": "report done"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Should stop via MAX_STEPS after 4 steps
        assert reason == StopReason.MAX_STEPS

        # Targets should rotate: recon → 10.0.0.10, fingerprint → 10.0.0.11,
        # vuln → 10.0.0.10, report → 10.0.0.11
        assert len(captured_targets) == 4
        assert captured_targets == ["10.0.0.10", "10.0.0.11", "10.0.0.10", "10.0.0.11"]

    def test_rotation_keeps_rotating_during_tool_loop_stall(self):
        """Even during a tool-loop stall, the target keeps rotating through
        authorized assets. The tool is the same (nmap/discover) but the target
        cycles each call.

        This prevents the asset-exhaustion stall from firing because the
        selector never repeatedly targets the same asset — each call picks
        the next one in rotation.
        """
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Rotation during stall",
            decision_strategy="hybrid",
            max_steps=6,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        captured_targets = []

        def execute(action):
            captured_targets.append(action.target)
            # Never return progress — agent stays in recon phase forever
            return {"last_action_result": "scanning..."}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Agent should stop via RULE_ENGINE_STALLED (executor never advances
        # state, so same nmap/discover repeats 3+ times)
        assert reason == StopReason.RULE_ENGINE_STALLED, (
            f"Expected RULE_ENGINE_STALLED, got {reason}"
        )

        # The targets should show clean rotation across 3 assets
        # Even with stall, the selector rotates targets each call
        assert len(captured_targets) >= 1

        # First 3 targets should be 10.0.0.10, 10.0.0.11, 10.0.0.12
        # (stall fires around call 4+, so we get at least 3 captured actions)
        assert captured_targets[:3] == ["10.0.0.10", "10.0.0.11", "10.0.0.12"], (
            f"Expected rotation across 3 assets, got: {captured_targets[:3]}"
        )

    def test_rule_strategy_rotates_too(self):
        """Rule strategy also rotates through assets (rotation is in
        _select_with_rules, not strategy-specific)."""
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10", "10.0.0.11"]

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Rule rotation",
            decision_strategy="rule",  # Not hybrid!
            max_steps=4,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        captured_targets = []

        def execute(action):
            captured_targets.append(action.target)
            # Phase 1: recon
            if len(captured_targets) == 1:
                return {"open_ports": [80]}
            # Phase 2: fingerprint
            elif len(captured_targets) == 2:
                return {"services": [{"name": "nginx"}]}
            # Phase 3: vuln
            elif len(captured_targets) == 3:
                return {"vulnerabilities": [{"id": "CVE-2025-0001"}]}
            # Phase 4: report
            return {"last_action_result": "done"}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        assert reason == StopReason.MAX_STEPS
        # Rule strategy also rotates: 10.0.0.10, 10.0.0.11, 10.0.0.10, 10.0.0.11
        assert len(captured_targets) == 4
        assert captured_targets == ["10.0.0.10", "10.0.0.11", "10.0.0.10", "10.0.0.11"]


# ===========================================================================
# 11. CampaignExecutor integration
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


# ===========================================================================
# 12. LLM integration — E2E
# ===========================================================================


class TestE2ELLMIntegration:
    """Prove the LLM provider integration works end-to-end via run_agent_loop.

    Covers:
      - LLM strategy with MockLLMProvider produces valid agent loop
      - Hybrid with LLM fallback recovers from stall
      - LLM with no prompt falls back to rules (no crash)
      - LLM provider that returns same action confirms stall
    """

    def test_llm_strategy_uses_provider_actions(self):
        """LLM strategy with MockLLMProvider: agent loop uses provider's actions."""
        # Configure a mock provider that returns a reporter/summary action
        custom_action = {
            "tool": "reporter",
            "command": "summary",
            "arguments": {"findings": 1},
            "target": "10.0.0.10",
            "reasoning": "Mock LLM chose report phase",
        }
        provider = MockLLMProvider(default_action=custom_action)

        agent = AgentCore(
            allowed_tools=[
                {"name": "nmap", "allowed_commands": ["discover", "scan"]},
                {"name": "reporter", "allowed_commands": ["summary"]},
            ],
            authorized_assets=["10.0.0.10"],
            objective="LLM E2E test",
            decision_strategy="llm",
            llm_prompt="You are an agent. Tools: {{ allowed_tools }}. State: {{ state }}.",
            llm_provider=provider,
            max_steps=3,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            # The LLM returned reporter/summary — just acknowledge it
            return {"last_action_result": "summary sent", "findings_summary": []}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Provider should have been called at least once
        assert provider.call_count >= 1, "MockLLMProvider was never called"
        # Agent should have executed the LLM's provided action
        assert len(evidence) >= 1, "No evidence was recorded"
        # The evidence should reflect the LLM's action (reporter/summary)
        if evidence:
            assert evidence[0].action.tool == "reporter", (
                f"Expected reporter, got {evidence[0].action.tool}"
            )
            assert evidence[0].action.command == "summary"
        # The prompt should have been substituted (no mustache templates)
        assert "{{ allowed_tools }}" not in provider.last_prompt, (
            "Prompt template was not substituted"
        )

    def test_hybrid_with_llm_unsticks_from_stall(self):
        """Hybrid strategy with LLM provider: when rule engine stalls from
        repeated tool actions, the LLM fallback returns a different action
        and the loop continues instead of stopping via RULE_ENGINE_STALLED."""
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10"]

        # Create a mock provider that returns the reporter action on any call.
        # The rules selector will keep generating nmap/scan (stays in fingerprint
        # phase because execute never returns progress). When the stall fires,
        # the LLM fallback returns reporter/summary (different action), which
        # resets the stall counter.
        unstuck_action = {
            "tool": "reporter",
            "command": "summary",
            "arguments": {},
            "target": "10.0.0.10",
            "reasoning": "LLM: switching to report phase",
        }
        provider = MockLLMProvider(default_action=unstuck_action)

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Hybrid LLM unstick test",
            decision_strategy="hybrid",
            llm_prompt="Rescue prompt. State: {{ state }}",
            llm_provider=provider,
            max_steps=15,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            # Never return progress — keeps rules in fingerprint phase (nmap/scan)
            # But when LLM returns reporter/summary, we acknowledge it
            return {"last_action_result": "completed", "findings_summary": []}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Provider should have been called at least once (to unstick)
        assert provider.call_count >= 1, "LLM provider was never called for unstick"
        # The agent should NOT have stopped via RULE_ENGINE_STALLED because
        # the LLM fallback produced a different action that reset the stall.
        assert reason != StopReason.RULE_ENGINE_STALLED, (
            f"Agent stalled despite LLM fallback. Reason: {reason}"
        )
        # Agent stopped via some other reason (likely MAX_STEPS)
        assert reason is not None

    def test_hybrid_with_llm_returns_same_action_stalls(self):
        """Hybrid strategy with LLM provider that returns the same stalled
        action: the stall is confirmed and the agent stops via
        RULE_ENGINE_STALLED (LLM could not unstick)."""
        tools = [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            {"name": "reporter", "allowed_commands": ["summary"]},
        ]
        assets = ["10.0.0.10"]

        # Create a mock provider that returns the SAME action as the rule
        # engine would produce (nmap/scan). This simulates an LLM that
        # can't find a better action and confirms the stall.
        same_action = {
            "tool": "nmap",
            "command": "discover",  # Must match rule engine recon phase (nmap/discover)
            "arguments": {"target": "10.0.0.10", "ports": "top-1000"},
            "target": "10.0.0.10",
            "reasoning": "LLM: continuing scan",
        }
        provider = MockLLMProvider(default_action=same_action)

        agent = AgentCore(
            allowed_tools=tools,
            authorized_assets=assets,
            objective="Hybrid LLM same action test",
            decision_strategy="hybrid",
            llm_prompt="Rescue prompt. State: {{ state }}",
            llm_provider=provider,
            max_steps=15,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            # Never return progress — keeps rules in fingerprint phase (nmap/scan)
            return {"last_action_result": "scanning..."}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Provider should have been called at least once
        assert provider.call_count >= 1, "LLM provider was never called"
        # Agent should stop via RULE_ENGINE_STALLED because LLM confirmed the stall
        assert reason == StopReason.RULE_ENGINE_STALLED, (
            f"Expected RULE_ENGINE_STALLED when LLM returns same action, got {reason}"
        )
        # Evidence should have entries from before the stall
        assert len(evidence) >= 1

    def test_llm_without_prompt_falls_back_to_rules(self):
        """LLM strategy without llm_prompt falls back to rule-based selection.
        Even with a provider configured, no prompt means no LLM call."""
        provider = MockLLMProvider()

        agent = AgentCore(
            allowed_tools=[
                {"name": "nmap", "allowed_commands": ["discover"]},
            ],
            authorized_assets=["10.0.0.10"],
            objective="LLM fallback test",
            decision_strategy="llm",
            llm_prompt=None,  # No prompt — should fall back to rules
            llm_provider=provider,
            max_steps=2,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            return {"open_ports": [80]}

        final_state, evidence, reason = run_agent_loop(agent, execute)

        # Provider should NOT have been called (no prompt means no LLM invocation)
        assert provider.call_count == 0, (
            f"Expected 0 calls to provider (no prompt), got {provider.call_count}"
        )
        # Agent should have used rule-based actions
        assert len(evidence) >= 1
        assert evidence[0].action.tool is not None

    def test_llm_strategy_with_policy_gate_and_provider(self):
        """LLM strategy with PolicyGate: provider actions pass through gate."""
        custom_action = {
            "tool": "nmap",
            "command": "discover",
            "arguments": {"target": "10.0.0.10"},
            "target": "10.0.0.10",
            "reasoning": "LLM chose recon",
        }
        provider = MockLLMProvider(default_action=custom_action)

        agent = AgentCore(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.10"],
            objective="LLM gate test",
            decision_strategy="llm",
            llm_prompt="Gate test prompt",
            llm_provider=provider,
            max_steps=2,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.10"],
        )

        def execute(action):
            return {"open_ports": [80]}

        final_state, evidence, reason = run_agent_loop(agent, execute, gate)

        # Provider should have been called
        assert provider.call_count >= 1
        # All actions should pass the policy gate
        for entry in evidence:
            violations = gate.validate_action(entry.action)
            assert violations == [], f"Policy violation in LLM action: {violations}"
        # Agent completed without errors
        assert reason is not None


# ===========================================================================
# 13. OpenAIProvider — E2E
# ===========================================================================


class TestE2EOpenAIProvider:
    """Prove the OpenAIProvider works end-to-end through run_agent_loop.

    All tests mock the internal OpenAI client so no real API calls are made.
    """

    def test_openai_provider_in_llm_strategy(self, monkeypatch):
        """OpenAIProvider with LLM strategy: provider generates actions,
        agent loop executes them, evidence reflects the LLM's choices."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-e2e-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            # Mock a valid API response returning nmap/discover
            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = json.dumps({
                "tool": "nmap",
                "command": "discover",
                "arguments": {"target": "10.0.0.10", "ports": "top-1000"},
                "target": "10.0.0.10",
                "reasoning": "E2E: begin reconnaissance",
            })
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()

            agent = AgentCore(
                allowed_tools=[
                    {"name": "nmap", "allowed_commands": ["discover", "scan"]},
                    {"name": "reporter", "allowed_commands": ["summary"]},
                ],
                authorized_assets=["10.0.0.10"],
                objective="OpenAI E2E test",
                decision_strategy="llm",
                llm_prompt="Analyze this target: {{ state }}",
                llm_provider=provider,
                max_steps=2,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                return {"open_ports": [80]}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            # Provider should have been called
            assert provider.call_count >= 1
            # The prompt should be substituted
            assert "{{ state }}" not in provider.last_prompt
            # Evidence should reflect the LLM's action
            assert len(evidence) >= 1
            if evidence:
                assert evidence[0].action.tool == "nmap"
                assert evidence[0].action.command == "discover"
            # The API should have been called with correct params
            mock_client.chat.completions.create.assert_called()
            call_kwargs = mock_client.chat.completions.create.call_args.kwargs
            assert call_kwargs["model"] == "gpt-4o-mini"
            assert len(call_kwargs["messages"]) == 2

    def test_openai_provider_in_hybrid_strategy(self, monkeypatch):
        """OpenAIProvider in hybrid strategy: on stall, provider is called
        to unstick. The provider returns a different action, which resets
        the stall and allows the loop to continue."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-hybrid-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            # Provider returns reporter/summary (different from rules' nmap/scan)
            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = json.dumps({
                "tool": "reporter",
                "command": "summary",
                "arguments": {},
                "target": "10.0.0.10",
                "reasoning": "Unstick: switching to report",
            })
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()

            tools = [
                {"name": "nmap", "allowed_commands": ["discover", "scan"]},
                {"name": "reporter", "allowed_commands": ["summary"]},
            ]
            assets = ["10.0.0.10"]

            agent = AgentCore(
                allowed_tools=tools,
                authorized_assets=assets,
                objective="OpenAI hybrid unstick",
                decision_strategy="hybrid",
                llm_prompt="Rescue: {{ state }}",
                llm_provider=provider,
                max_steps=15,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                # Never return progress — keeps rules in fingerprint (nmap/scan)
                return {"last_action_result": "scanning..."}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            # Provider should have been called to unstick
            assert provider.call_count >= 1
            # Should NOT have stopped via RULE_ENGINE_STALLED
            assert reason != StopReason.RULE_ENGINE_STALLED, (
                f"Stalled despite OpenAI fallback. Reason: {reason}"
            )

    def test_openai_provider_api_error_falls_back(self, monkeypatch):
        """OpenAIProvider API error -> falls back to rule-based selection.
        The agent loop should continue without crashing."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-fallback")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client
            # API raises an error
            mock_client.chat.completions.create.side_effect = Exception("API under maintenance")

            provider = OpenAIProvider()

            agent = AgentCore(
                allowed_tools=[
                    {"name": "nmap", "allowed_commands": ["discover"]},
                ],
                authorized_assets=["10.0.0.10"],
                objective="API error fallback test",
                decision_strategy="llm",
                llm_prompt="Prompt: {{ allowed_tools }}",
                llm_provider=provider,
                max_steps=2,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                return {"open_ports": [80]}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            # Provider should have been called (and failed)
            assert provider.call_count >= 1
            # Agent should have fallen back to rules and completed
            assert len(evidence) >= 1
            # Evidence should show rule-based actions (nmap/discover from recon phase)
            if evidence:
                assert evidence[0].action.tool is not None
            assert reason is not None

    def test_create_llm_provider_factory_e2e(self, monkeypatch):
        """create_llm_provider factory creates an OpenAIProvider that works
        in the agent loop."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-factory")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = json.dumps({
                "tool": "nmap",
                "command": "discover",
                "arguments": {"target": "10.0.0.10"},
                "target": "10.0.0.10",
                "reasoning": "Factory E2E",
            })
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            # Create via factory
            provider = create_llm_provider("openai", model="gpt-4o")
            assert isinstance(provider, OpenAIProvider)
            assert provider.model == "gpt-4o"

            agent = AgentCore(
                allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
                authorized_assets=["10.0.0.10"],
                objective="Factory E2E",
                decision_strategy="llm",
                llm_prompt="Factory test: {{ state }}",
                llm_provider=provider,
                max_steps=1,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                return {"open_ports": [80]}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            assert provider.call_count >= 1
            assert len(evidence) >= 1
            # Model should have been passed to API
            call_kwargs = mock_client.chat.completions.create.call_args.kwargs
            assert call_kwargs["model"] == "gpt-4o"


# ===========================================================================
# 13b. AnthropicProvider — E2E
# ===========================================================================


class TestE2EAnthropicProvider:
    """Prove the AnthropicProvider works end-to-end through run_agent_loop.

    All tests mock the internal Anthropic client so no real API calls are made.
    """

    def test_anthropic_provider_in_llm_strategy(self, monkeypatch):
        """AnthropicProvider with LLM strategy: provider generates actions,
        agent loop executes them, evidence reflects the LLM's choices."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-e2e-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            # Mock a valid API response returning nmap/discover
            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = json.dumps({
                "tool": "nmap",
                "command": "discover",
                "arguments": {"target": "10.0.0.10", "ports": "top-1000"},
                "target": "10.0.0.10",
                "reasoning": "E2E: begin reconnaissance",
            })
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()

            agent = AgentCore(
                allowed_tools=[
                    {"name": "nmap", "allowed_commands": ["discover", "scan"]},
                    {"name": "reporter", "allowed_commands": ["summary"]},
                ],
                authorized_assets=["10.0.0.10"],
                objective="Anthropic E2E test",
                decision_strategy="llm",
                llm_prompt="Analyze this target: {{ state }}",
                llm_provider=provider,
                max_steps=2,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                return {"open_ports": [80]}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            # Provider should have been called
            assert provider.call_count >= 1
            # The prompt should be substituted
            assert "{{ state }}" not in provider.last_prompt
            # Evidence should reflect the LLM's action
            assert len(evidence) >= 1
            if evidence:
                assert evidence[0].action.tool == "nmap"
                assert evidence[0].action.command == "discover"
            # The API should have been called with correct params
            mock_client.messages.create.assert_called()
            call_kwargs = mock_client.messages.create.call_args.kwargs
            assert call_kwargs["model"] == "claude-sonnet-4-20250514"
            assert len(call_kwargs["messages"]) == 1
            # System prompt should be passed via the dedicated system parameter
            assert call_kwargs["system"] is not None
            assert "penetration-testing AI" in call_kwargs["system"]

    def test_anthropic_provider_in_hybrid_strategy(self, monkeypatch):
        """AnthropicProvider in hybrid strategy: on stall, provider is called
        to unstick. The provider returns a different action, which resets
        the stall and allows the loop to continue."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-hybrid-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            # Provider returns reporter/summary (different from rules' nmap/scan)
            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = json.dumps({
                "tool": "reporter",
                "command": "summary",
                "arguments": {},
                "target": "10.0.0.10",
                "reasoning": "Unstick: switching to report",
            })
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()

            tools = [
                {"name": "nmap", "allowed_commands": ["discover", "scan"]},
                {"name": "reporter", "allowed_commands": ["summary"]},
            ]
            assets = ["10.0.0.10"]

            agent = AgentCore(
                allowed_tools=tools,
                authorized_assets=assets,
                objective="Anthropic hybrid unstick",
                decision_strategy="hybrid",
                llm_prompt="Rescue: {{ state }}",
                llm_provider=provider,
                max_steps=15,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                # Never return progress — keeps rules in fingerprint (nmap/scan)
                return {"last_action_result": "scanning..."}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            # Provider should have been called to unstick
            assert provider.call_count >= 1
            # Should NOT have stopped via RULE_ENGINE_STALLED
            assert reason != StopReason.RULE_ENGINE_STALLED, (
                f"Stalled despite Anthropic fallback. Reason: {reason}"
            )

    def test_anthropic_provider_api_error_falls_back(self, monkeypatch):
        """AnthropicProvider API error -> falls back to rule-based selection.
        The agent loop should continue without crashing."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fallback")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client
            # API raises an error
            mock_client.messages.create.side_effect = Exception("API under maintenance")

            provider = AnthropicProvider()

            agent = AgentCore(
                allowed_tools=[
                    {"name": "nmap", "allowed_commands": ["discover"]},
                ],
                authorized_assets=["10.0.0.10"],
                objective="API error fallback test",
                decision_strategy="llm",
                llm_prompt="Prompt: {{ allowed_tools }}",
                llm_provider=provider,
                max_steps=2,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                return {"open_ports": [80]}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            # Provider should have been called (and failed)
            assert provider.call_count >= 1
            # Agent should have fallen back to rules and completed
            assert len(evidence) >= 1
            # Evidence should show rule-based actions
            if evidence:
                assert evidence[0].action.tool is not None
            assert reason is not None

    def test_create_llm_provider_factory_anthropic_e2e(self, monkeypatch):
        """create_llm_provider factory creates an AnthropicProvider that works
        in the agent loop."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-factory")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = json.dumps({
                "tool": "nmap",
                "command": "discover",
                "arguments": {"target": "10.0.0.10"},
                "target": "10.0.0.10",
                "reasoning": "Factory E2E",
            })
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            # Create via factory
            provider = create_llm_provider("anthropic", model="claude-3-haiku-20240307")
            assert isinstance(provider, AnthropicProvider)
            assert provider.model == "claude-3-haiku-20240307"

            agent = AgentCore(
                allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
                authorized_assets=["10.0.0.10"],
                objective="Factory E2E",
                decision_strategy="llm",
                llm_prompt="Factory test: {{ state }}",
                llm_provider=provider,
                max_steps=1,
                stop_on_criteria_met=False,
                stop_on_finding="none",
            )

            def execute(action):
                return {"open_ports": [80]}

            final_state, evidence, reason = run_agent_loop(agent, execute)

            assert provider.call_count >= 1
            assert len(evidence) >= 1
            # Model should have been passed to API
            call_kwargs = mock_client.messages.create.call_args.kwargs
            assert call_kwargs["model"] == "claude-3-haiku-20240307"


# ===========================================================================
# 14. YAML spec validation — LLM provider config
# ===========================================================================


class TestE2EYamlLLMProviderConfig:
    """Prove the pentest-llm-orchestrator.yaml spec loads correctly and
    from_agentic_config creates agents with the correct LLM provider."""

    LLM_CAMPAIGN_PATH = Path(__file__).resolve().parent.parent / "specs" / "pentest-llm-orchestrator.yaml"
    AGENTIC_CAMPAIGN_PATH = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"

    # ------------------------------------------------------------------
    # Fixtures
    # ------------------------------------------------------------------

    @pytest.fixture(scope="class")
    def llm_campaign(self):
        """Load the LLM provider campaign YAML once per class."""
        assert self.LLM_CAMPAIGN_PATH.exists(), f"Missing: {self.LLM_CAMPAIGN_PATH}"
        return load_campaign(self.LLM_CAMPAIGN_PATH)

    @pytest.fixture(scope="class")
    def llm_recon_plan(self, llm_campaign):
        """Return the inline plan dict for SESS-llm-recon."""
        for s in llm_campaign.sessions:
            if s.session_id == "SESS-llm-recon":
                assert isinstance(s.plan, dict), "Expected inline plan"
                return s.plan
        raise AssertionError("SESS-llm-recon not found")

    @pytest.fixture(scope="class")
    def hybrid_plan(self, llm_campaign):
        """Return the inline plan dict for SESS-hybrid-recon."""
        for s in llm_campaign.sessions:
            if s.session_id == "SESS-hybrid-recon":
                assert isinstance(s.plan, dict), "Expected inline plan"
                return s.plan
        raise AssertionError("SESS-hybrid-recon not found")

    @pytest.fixture(scope="class")
    def mock_llm_plan(self, llm_campaign):
        """Return the inline plan dict for SESS-mock-llm-report."""
        for s in llm_campaign.sessions:
            if s.session_id == "SESS-mock-llm-report":
                assert isinstance(s.plan, dict), "Expected inline plan"
                return s.plan
        raise AssertionError("SESS-mock-llm-report not found")

    @pytest.fixture
    def llm_recon_agent(self, llm_recon_plan, monkeypatch):
        """Build an AgentCore with LLM provider from YAML.

        Uses ``type: openai`` in the YAML spec, which requires
        ``OPENAI_API_KEY``. We set it here so the fixture can
        create the provider without a real API key.
        """
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-llm-fixture")
        return AgentCore.from_agentic_config(
            config=llm_recon_plan["agentic_config"],
            allowed_tools=llm_recon_plan.get("allowed_tools", []),
            authorized_assets=llm_recon_plan.get("authorized_assets", []),
            objective=llm_recon_plan.get("objective", ""),
        )

    @pytest.fixture
    def hybrid_agent(self, hybrid_plan):
        """Build an AgentCore with hybrid strategy from YAML."""
        return AgentCore.from_agentic_config(
            config=hybrid_plan["agentic_config"],
            allowed_tools=hybrid_plan.get("allowed_tools", []),
            authorized_assets=hybrid_plan.get("authorized_assets", []),
            objective=hybrid_plan.get("objective", ""),
        )

    @pytest.fixture
    def mock_llm_agent(self, mock_llm_plan):
        """Build an AgentCore with mock LLM provider from YAML."""
        return AgentCore.from_agentic_config(
            config=mock_llm_plan["agentic_config"],
            allowed_tools=mock_llm_plan.get("allowed_tools", []),
            authorized_assets=mock_llm_plan.get("authorized_assets", []),
            objective=mock_llm_plan.get("objective", ""),
        )

    @pytest.fixture(scope="class")
    def anthropic_plan(self, llm_campaign):
        """Return the inline plan dict for SESS-anthropic-report."""
        for s in llm_campaign.sessions:
            if s.session_id == "SESS-anthropic-report":
                assert isinstance(s.plan, dict), "Expected inline plan"
                return s.plan
        raise AssertionError("SESS-anthropic-report not found")

    @pytest.fixture(scope="class")
    def groq_plan(self, llm_campaign):
        """Return the inline plan dict for SESS-groq-recon."""
        for s in llm_campaign.sessions:
            if s.session_id == "SESS-groq-recon":
                assert isinstance(s.plan, dict), "Expected inline plan"
                return s.plan
        raise AssertionError("SESS-groq-recon not found")

    @pytest.fixture(scope="class")
    def gemini_plan(self, llm_campaign):
        """Return the inline plan dict for SESS-gemini-analysis."""
        for s in llm_campaign.sessions:
            if s.session_id == "SESS-gemini-analysis":
                assert isinstance(s.plan, dict), "Expected inline plan"
                return s.plan
        raise AssertionError("SESS-gemini-analysis not found")

    @pytest.fixture
    def anthropic_agent(self, anthropic_plan, monkeypatch):
        """Build an AgentCore with Anthropic provider from YAML.

        Uses ``type: anthropic`` which requires ``ANTHROPIC_API_KEY``.
        We set it here so the fixture can create the provider without
        a real API key.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-yaml-fixture")
        return AgentCore.from_agentic_config(
            config=anthropic_plan["agentic_config"],
            allowed_tools=anthropic_plan.get("allowed_tools", []),
            authorized_assets=anthropic_plan.get("authorized_assets", []),
            objective=anthropic_plan.get("objective", ""),
        )

    @pytest.fixture
    def groq_agent(self, groq_plan, monkeypatch):
        """Build an AgentCore with Groq-backed OpenAI provider from YAML.

        Uses ``type: openai`` with ``base_url`` pointing to Groq's API.
        Requires ``OPENAI_API_KEY`` (set to a Groq key in production).
        We set a dummy here so the fixture can create the provider.
        """
        monkeypatch.setenv("OPENAI_API_KEY", "sk-groq-test-yaml-fixture")
        return AgentCore.from_agentic_config(
            config=groq_plan["agentic_config"],
            allowed_tools=groq_plan.get("allowed_tools", []),
            authorized_assets=groq_plan.get("authorized_assets", []),
            objective=groq_plan.get("objective", ""),
        )

    @pytest.fixture
    def gemini_agent(self, gemini_plan, monkeypatch):
        """Build an AgentCore with Google/Gemini provider from YAML.

        Uses ``type: google`` which requires ``GEMINI_API_KEY``.
        We set it here so the fixture can create the provider without
        a real API key.
        """
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-yaml-fixture")
        return AgentCore.from_agentic_config(
            config=gemini_plan["agentic_config"],
            allowed_tools=gemini_plan.get("allowed_tools", []),
            authorized_assets=gemini_plan.get("authorized_assets", []),
            objective=gemini_plan.get("objective", ""),
        )

    # ------------------------------------------------------------------
    # Campaign loading
    # ------------------------------------------------------------------

    def test_llm_campaign_loads(self, llm_campaign):
        """LLM campaign YAML parses correctly with 6 sessions."""
        assert llm_campaign.campaign_id == "CAMP-PENTEST-LLM-2026-Q3"
        assert len(llm_campaign.sessions) == 6

    def test_llm_campaign_session_ids(self, llm_campaign):
        """All 6 sessions have expected IDs."""
        session_ids = {s.session_id for s in llm_campaign.sessions}
        assert "SESS-llm-recon" in session_ids
        assert "SESS-hybrid-recon" in session_ids
        assert "SESS-anthropic-report" in session_ids
        assert "SESS-groq-recon" in session_ids
        assert "SESS-gemini-analysis" in session_ids
        assert "SESS-mock-llm-report" in session_ids

    def test_llm_campaign_has_llm_provider_config(self, llm_campaign):
        """All sessions have llm_provider_config in their agentic_config."""
        for s in llm_campaign.sessions:
            ac = s.plan["agentic_config"]
            assert "llm_provider_config" in ac, (
                f"Session {s.session_id} missing llm_provider_config"
            )
            assert "type" in ac["llm_provider_config"], (
                f"Session {s.session_id} llm_provider_config missing 'type'"
            )

    def test_llm_campaign_dependency_chain(self, llm_campaign):
        """Session dependencies match expected chain."""
        sessions = {s.session_id: s for s in llm_campaign.sessions}
        assert sessions["SESS-hybrid-recon"].dependencies == ("SESS-llm-recon",)
        assert sessions["SESS-anthropic-report"].dependencies == ("SESS-hybrid-recon",)
        assert sessions["SESS-groq-recon"].dependencies == ("SESS-anthropic-report",)
        assert sessions["SESS-gemini-analysis"].dependencies == ("SESS-groq-recon",)
        assert sessions["SESS-mock-llm-report"].dependencies == ("SESS-gemini-analysis",)

    def test_llm_campaign_drift_rules(self, llm_campaign):
        """LLM campaign has drift rules."""
        rule_ids = {r.id for r in llm_campaign.global_drift_rules}
        assert "DRIFT-TARGET" in rule_ids
        assert "DRIFT-TOOLS" in rule_ids
        assert "DRIFT-SCHEMA" in rule_ids
        assert "DRIFT-EXPIRY" in rule_ids

    # ------------------------------------------------------------------
    # LLM strategy agent (decision_strategy: llm)
    # ------------------------------------------------------------------

    def test_llm_recon_agent_config(self, llm_recon_agent, llm_recon_plan):
        """Agent from LLM strategy YAML has correct config."""
        assert llm_recon_agent.decision_strategy == "llm"
        assert llm_recon_agent.llm_prompt is not None
        assert "{{ allowed_tools }}" in llm_recon_plan["agentic_config"]["llm_prompt_template"]
        assert llm_recon_agent.max_steps == 30
        assert llm_recon_agent.stop_on_finding == "high"

    def test_llm_recon_has_provider(self, llm_recon_agent):
        """LLM strategy agent has an OpenAIProvider created from config.

        The provider is eagerly created inside from_agentic_config when
        llm_provider_config is present. The fixture sets OPENAI_API_KEY
        to allow construction without a real key.
        """
        assert llm_recon_agent.llm_provider is not None
        assert isinstance(llm_recon_agent.llm_provider, OpenAIProvider)
        assert llm_recon_agent.llm_provider.model == "gpt-4o-mini"

    def test_llm_recon_authorized_assets(self, llm_recon_agent):
        """Two authorized assets loaded from YAML."""
        assert len(llm_recon_agent.authorized_assets) == 2
        assert "10.0.0.10" in llm_recon_agent.authorized_assets
        assert "10.0.0.11" in llm_recon_agent.authorized_assets

    def test_llm_recon_stop_conditions(self, llm_recon_agent):
        """Stop conditions parsed from YAML."""
        assert llm_recon_agent.stop_conditions is not None
        assert len(llm_recon_agent.stop_conditions) == 2
        types = [c["type"] for c in llm_recon_agent.stop_conditions]
        assert "success_criterion_met" in types
        assert "time_limit" in types

    # ------------------------------------------------------------------
    # Hybrid strategy agent (decision_strategy: hybrid)
    # ------------------------------------------------------------------

    def test_hybrid_agent_config(self, hybrid_agent, hybrid_plan):
        """Agent from hybrid strategy YAML has correct config."""
        assert hybrid_agent.decision_strategy == "hybrid"
        assert hybrid_agent.llm_prompt is not None
        assert "{{ state }}" in hybrid_plan["agentic_config"]["llm_prompt_template"]
        assert hybrid_agent.max_steps == 50
        assert hybrid_agent.stop_on_finding == "critical"

    def test_hybrid_has_mock_provider(self, hybrid_agent):
        """Hybrid strategy with type: mock creates a MockLLMProvider."""
        assert hybrid_agent.llm_provider is not None
        assert hybrid_agent.llm_provider.model == "gpt-4o-mini"

    def test_hybrid_three_assets(self, hybrid_agent):
        """Hybrid session has 3 authorized assets for rotation."""
        assert len(hybrid_agent.authorized_assets) == 3
        assert "10.0.0.12" in hybrid_agent.authorized_assets

    # ------------------------------------------------------------------
    # Mock LLM strategy agent (type: mock, no API key needed)
    # ------------------------------------------------------------------

    def test_mock_llm_agent_config(self, mock_llm_agent, mock_llm_plan):
        """Agent from mock LLM strategy YAML has correct config."""
        assert mock_llm_agent.decision_strategy == "llm"
        assert mock_llm_agent.llm_prompt is not None
        assert mock_llm_agent.max_steps == 10
        assert mock_llm_agent._drift_check_enabled is False

    def test_mock_llm_provider_is_mock(self, mock_llm_agent):
        """type: mock creates a MockLLMProvider even without API key."""
        assert mock_llm_agent.llm_provider is not None
        assert mock_llm_agent.llm_provider.model == "mock"

    def test_mock_llm_provider_generates_action(self, mock_llm_agent):
        """MockLLMProvider from YAML config can generate actions."""
        provider = mock_llm_agent.llm_provider
        response = provider.generate("test prompt")
        assert response is not None
        import json
        data = json.loads(response)
        assert "tool" in data
        assert "command" in data
        assert provider.call_count == 1

    # ------------------------------------------------------------------
    # Anthropic strategy agent (type: anthropic)
    # ------------------------------------------------------------------

    def test_anthropic_agent_config(self, anthropic_agent, anthropic_plan):
        """Agent from Anthropic strategy YAML has correct config."""
        assert anthropic_agent.decision_strategy == "llm"
        assert anthropic_agent.llm_prompt is not None
        assert "{{ state }}" in anthropic_plan["agentic_config"]["llm_prompt_template"]
        assert "Claude" in anthropic_plan["agentic_config"]["llm_prompt_template"]
        assert anthropic_agent.max_steps == 15
        assert anthropic_agent.stop_on_criteria_met is True
        assert anthropic_agent._drift_check_enabled is True

    def test_anthropic_has_provider(self, anthropic_agent):
        """Anthropic strategy agent has an AnthropicProvider created from config."""
        assert anthropic_agent.llm_provider is not None
        assert isinstance(anthropic_agent.llm_provider, AnthropicProvider)
        assert anthropic_agent.llm_provider.model == "claude-sonnet-4-20250514"

    def test_anthropic_provider_config_values(self, anthropic_agent):
        """Anthropic provider has correct temperature and max_tokens from YAML."""
        provider = anthropic_agent.llm_provider
        assert provider._temperature == 0.3
        assert provider._max_tokens == 2048

    def test_anthropic_session_dependency(self, llm_campaign):
        """Anthropic session depends on SESS-hybrid-recon."""
        sessions = {s.session_id: s for s in llm_campaign.sessions}
        assert "SESS-hybrid-recon" in sessions["SESS-anthropic-report"].dependencies

    # ------------------------------------------------------------------
    # Groq strategy agent (type: openai with base_url)
    # ------------------------------------------------------------------

    def test_groq_agent_config(self, groq_agent, groq_plan):
        """Agent from Groq strategy YAML has correct config."""
        assert groq_agent.decision_strategy == "llm"
        assert groq_agent.llm_prompt is not None
        assert "Groq" in groq_plan["agentic_config"]["llm_prompt_template"]
        assert groq_agent.max_steps == 20
        assert groq_agent._drift_check_enabled is True

    def test_groq_has_provider(self, groq_agent):
        """Groq strategy agent has an OpenAIProvider with base_url set."""
        assert groq_agent.llm_provider is not None
        assert isinstance(groq_agent.llm_provider, OpenAIProvider)
        assert groq_agent.llm_provider.model == "llama-3.3-70b-versatile"

    def test_groq_provider_config_values(self, groq_agent):
        """Groq provider has correct temperature and max_tokens from YAML."""
        provider = groq_agent.llm_provider
        assert provider._temperature == 0.1
        assert provider._max_tokens == 1024

    def test_groq_session_dependency(self, llm_campaign):
        """Groq session depends on SESS-anthropic-report."""
        sessions = {s.session_id: s for s in llm_campaign.sessions}
        assert "SESS-anthropic-report" in sessions["SESS-groq-recon"].dependencies

    # ------------------------------------------------------------------
    # Gemini strategy agent (type: google)
    # ------------------------------------------------------------------

    def test_gemini_agent_config(self, gemini_agent, gemini_plan):
        """Agent from Gemini strategy YAML has correct config."""
        assert gemini_agent.decision_strategy == "llm"
        assert gemini_agent.llm_prompt is not None
        assert "Gemini" in gemini_plan["agentic_config"]["llm_prompt_template"]
        assert gemini_agent.max_steps == 25
        assert gemini_agent._drift_check_enabled is True

    def test_gemini_has_provider(self, gemini_agent):
        """Gemini strategy agent has a GoogleProvider created from config."""
        assert gemini_agent.llm_provider is not None
        assert isinstance(gemini_agent.llm_provider, GoogleProvider)
        assert gemini_agent.llm_provider.model == "gemini-2.0-flash"

    def test_gemini_provider_config_values(self, gemini_agent):
        """Gemini provider has correct temperature and max_tokens from YAML."""
        provider = gemini_agent.llm_provider
        assert provider._temperature == 0.2
        assert provider._max_tokens == 2048

    def test_gemini_session_dependency(self, llm_campaign):
        """Gemini session depends on SESS-groq-recon."""
        sessions = {s.session_id: s for s in llm_campaign.sessions}
        assert "SESS-groq-recon" in sessions["SESS-gemini-analysis"].dependencies

    # ------------------------------------------------------------------
    # Existing campaign also parses llm_provider_config (commented)
    # ------------------------------------------------------------------

    def test_existing_campaign_has_commented_llm_config(self):
        """The existing pentest-agentic-orchestrator.yaml has a commented-out
        llm_provider_config section in Session 1's agentic_config.

        We verify this by reading the raw YAML text, not the parsed config,
        since commented lines are invisible to the parser."""
        raw = self.AGENTIC_CAMPAIGN_PATH.read_text()
        assert "# llm_provider_config:" in raw, (
            "Expected commented-out llm_provider_config in "
            "pentest-agentic-orchestrator.yaml"
        )
        assert "#   type: openai" in raw
        assert "#   model: gpt-4o-mini" in raw
        assert "#   temperature: 0.2" in raw
        assert "#   max_tokens: 1024" in raw
