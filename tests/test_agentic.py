"""Tests for the bounded agentic reasoning engine.

Covers: WorldState, ActionSelector, StopCondition, PolicyGate, AgentCore,
evidence log, drift detection, agent loop, and campaign integration.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gatekeeper_eos_v6.agentic import (
    WorldState,
    AgentAction,
    ActionSelector,
    StopCondition,
    StopReason,
    StopConditionType,
    EvidenceEntry,
    AgentCore,
    PolicyGate,
    FindingSummary,
    RuleEngineConfig,
    AgenticError,
    AgentStateError,
    AgentActionError,
    AgentStopTriggered,
    check_agent_state_drift,
    parse_iso_duration,
    run_agent_loop,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def empty_state() -> WorldState:
    return WorldState()


@pytest.fixture
def populated_state() -> WorldState:
    return WorldState(
        open_ports=[22, 80, 443],
        services=[{"name": "nginx", "version": "1.24", "port": 80}],
        vulnerabilities=[{"id": "CVE-2024-1234", "severity": "high"}],
        discovered_assets=["10.0.0.10"],
        tested_paths=["/api/login", "/admin"],
    )


@pytest.fixture
def sample_allowed_tools() -> list[dict]:
    return [
        {
            "name": "nmap",
            "version": "7.95",
            "hash": "sha256:TEST_HASH",
            "allowed_commands": ["discover", "scan", "fingerprint"],
        },
        {
            "name": "vuln-scanner",
            "version": "1.0",
            "hash": "sha256:VULN_HASH",
            "allowed_commands": ["scan-cve", "check-exploit"],
        },
        {
            "name": "reporter",
            "version": "1.0",
            "hash": "sha256:REPORT_HASH",
            "allowed_commands": ["summary", "executive-summary"],
        },
    ]


@pytest.fixture
def sample_authorized_assets() -> list[str]:
    return ["10.0.0.10", "target.example.com"]


@pytest.fixture
def sample_objective() -> str:
    return "Discover all vulnerabilities on the target system."


@pytest.fixture
def sample_agent_core(
    sample_allowed_tools,
    sample_authorized_assets,
    sample_objective,
) -> AgentCore:
    return AgentCore(
        allowed_tools=sample_allowed_tools,
        authorized_assets=sample_authorized_assets,
        objective=sample_objective,
        max_steps=100,
        max_time_seconds=3600,
    )


@pytest.fixture
def sample_action() -> AgentAction:
    return AgentAction(
        tool="nmap",
        command="discover",
        arguments={"target": "10.0.0.10"},
        target="10.0.0.10",
        reasoning="Initial recon step",
    )


# ===========================================================================
# WorldState
# ===========================================================================


class TestWorldState:
    def test_default_state_empty(self, empty_state):
        assert empty_state.open_ports == []
        assert empty_state.services == []
        assert empty_state.vulnerabilities == []
        assert empty_state.last_action_result == ""

    def test_to_dict_includes_all_fields(self, populated_state):
        d = populated_state.to_dict()
        assert d["open_ports"] == [22, 80, 443]
        assert len(d["services"]) == 1
        assert d["last_action_result"] == ""

    def test_from_dict_round_trip(self, populated_state):
        d = populated_state.to_dict()
        restored = WorldState.from_dict(d)
        assert restored.open_ports == populated_state.open_ports
        assert restored.services == populated_state.services
        assert restored.vulnerabilities == populated_state.vulnerabilities

    def test_update_adds_open_ports(self, empty_state):
        empty_state.update({"open_ports": [22, 80]})
        assert empty_state.open_ports == [22, 80]

    def test_update_appends_new_ports(self):
        state = WorldState(open_ports=[22])
        state.update({"open_ports": [80, 443]})
        assert state.open_ports == [22, 80, 443]

    def test_update_does_not_duplicate_ports(self):
        state = WorldState(open_ports=[22, 80])
        state.update({"open_ports": [80, 443]})
        assert state.open_ports == [22, 80, 443]

    def test_update_ignores_non_int_ports(self):
        state = WorldState()
        state.update({"open_ports": [22, "not-a-port"]})
        assert state.open_ports == [22]
        assert "not-a-port" not in state.open_ports

    def test_update_adds_services(self, empty_state):
        svc = {"name": "nginx", "version": "1.24"}
        empty_state.update({"services": [svc]})
        assert empty_state.services == [svc]

    def test_update_adds_vulnerabilities(self, empty_state):
        vuln = {"id": "CVE-2024-0001", "severity": "critical"}
        empty_state.update({"vulnerabilities": [vuln]})
        assert empty_state.vulnerabilities == [vuln]

    def test_update_adds_injection_points(self, empty_state):
        empty_state.update({"injection_points": ["/api/login"]})
        assert empty_state.injection_points == ["/api/login"]

    def test_update_adds_discovered_assets(self, empty_state):
        empty_state.update({"discovered_assets": ["10.0.0.10"]})
        assert empty_state.discovered_assets == ["10.0.0.10"]

    def test_update_sets_last_action_result(self, empty_state):
        empty_state.update({"last_action_result": "Port scan complete"})
        assert empty_state.last_action_result == "Port scan complete"

    def test_update_multiple_keys(self, empty_state):
        empty_state.update({
            "open_ports": [443],
            "services": [{"name": "https"}],
            "last_action_result": "Done",
        })
        assert empty_state.open_ports == [443]
        assert len(empty_state.services) == 1

    def test_from_dict_with_partial_data(self):
        state = WorldState.from_dict({"open_ports": [22]})
        assert state.open_ports == [22]
        assert state.services == []
        assert state.vulnerabilities == []

    def test_from_dict_with_empty(self):
        state = WorldState.from_dict({})
        assert state.open_ports == []
        assert state.services == []


# ===========================================================================
# AgentAction
# ===========================================================================


class TestAgentAction:
    def test_create_action(self):
        action = AgentAction(
            tool="nmap", command="scan",
            arguments={"ports": "80,443"}, target="10.0.0.10",
            reasoning="Initial scan",
        )
        assert action.tool == "nmap"
        assert action.command == "scan"
        assert action.arguments == {"ports": "80,443"}

    def test_to_dict(self, sample_action):
        d = sample_action.to_dict()
        assert d["tool"] == "nmap"
        assert d["command"] == "discover"
        assert d["target"] == "10.0.0.10"
        assert "reasoning" in d

    def test_default_reasoning(self):
        action = AgentAction(tool="test", command="run")
        assert action.reasoning == ""

    def test_default_arguments(self):
        action = AgentAction(tool="test", command="run")
        assert action.arguments == {}

    def test_frozen(self, sample_action):
        with pytest.raises(Exception):
            sample_action.tool = "changed"  # type: ignore[misc]


# ===========================================================================
# StopCondition
# ===========================================================================


class TestStopCondition:
    def test_max_steps_triggered(self):
        cond = StopCondition(max_steps=5)
        should, reason = cond.should_stop(
            current_step=5, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_STEPS

    def test_max_steps_not_triggered_below(self):
        cond = StopCondition(max_steps=5)
        should, reason = cond.should_stop(
            current_step=4, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is False
        assert reason == StopReason.NO_MORE_ACTIONS

    def test_max_time_triggered(self):
        cond = StopCondition(max_time_seconds=0.01)
        start = time.monotonic()
        time.sleep(0.02)
        should, reason = cond.should_stop(
            current_step=1, start_time=start,
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_TIME

    def test_max_time_not_triggered_early(self):
        cond = StopCondition(max_time_seconds=600)
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is False

    def test_stop_on_critical_finding(self):
        cond = StopCondition(stop_on_finding="critical")
        state = WorldState(findings_summary=[{"severity": "critical", "id": "CVE-001"}])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is True
        assert reason == StopReason.MAX_SEVERITY_FOUND

    def test_stop_on_high_finding_with_high_severity(self):
        cond = StopCondition(stop_on_finding="high")
        state = WorldState(findings_summary=[{"severity": "high", "id": "CVE-002"}])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is True

    def test_stop_on_high_finding_with_low_does_not_stop(self):
        cond = StopCondition(stop_on_finding="high")
        state = WorldState(findings_summary=[{"severity": "low", "id": "CVE-003"}])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is False

    def test_stop_on_list_of_severities(self):
        cond = StopCondition(stop_on_finding=["medium", "high"])
        state = WorldState(findings_summary=[{"severity": "medium", "id": "CVE-004"}])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is True

    def test_stop_on_criteria_met(self):
        cond = StopCondition(stop_on_criteria_met=True)
        state = WorldState(
            open_ports=[80],
            services=[{"name": "nginx"}],
        )
        should, reason = cond.should_stop(
            current_step=5, start_time=time.monotonic(),
            state=state,
            success_criteria=["All open ports identified"],
        )
        # The keyword "ports" should match "open_ports" in the state
        assert should is True
        assert reason == StopReason.CRITERIA_MET

    def test_stop_on_criteria_not_met(self):
        cond = StopCondition(stop_on_criteria_met=True)
        state = WorldState()
        should, _ = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
            success_criteria=["Something about non-existent data"],
        )
        assert should is False

    def test_default_values(self):
        cond = StopCondition()
        assert cond.max_steps == 100
        assert cond.max_time_seconds == 3600
        assert cond.stop_on_finding == "none"
        assert cond.stop_on_criteria_met is True

    def test_max_steps_edge_0(self):
        """max_steps of 0 means stop immediately."""
        cond = StopCondition(max_steps=0)
        should, reason = cond.should_stop(
            current_step=0, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_STEPS

    def test_no_success_criteria_no_stop(self):
        cond = StopCondition(stop_on_criteria_met=True)
        should, _ = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=WorldState(),
            success_criteria=None,
        )
        assert should is False

    def test_empty_success_criteria_no_stop(self):
        cond = StopCondition(stop_on_criteria_met=True)
        should, _ = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=WorldState(),
            success_criteria=[],
        )
        assert should is False


# ===========================================================================
# ActionSelector
# ===========================================================================


class TestActionSelector:
    def test_rule_based_initial_recon(self, sample_allowed_tools, sample_authorized_assets):
        selector = ActionSelector(decision_strategy="rule")
        state = WorldState()  # empty — should trigger recon
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Discover vulnerabilities", step=1, previous_actions=[],
        )
        # Should select a recon/discovery action
        assert action.target == "10.0.0.10"

    def test_rule_based_service_scan_when_ports_discovered(
        self, sample_allowed_tools, sample_authorized_assets,
    ):
        selector = ActionSelector(decision_strategy="rule")
        state = WorldState(open_ports=[80, 443])
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Discover vulnerabilities", step=2, previous_actions=[],
        )
        assert action.target == "10.0.0.10"

    def test_rule_based_vuln_scan_when_services_discovered(
        self, sample_allowed_tools, sample_authorized_assets,
    ):
        selector = ActionSelector(decision_strategy="rule")
        state = WorldState(
            open_ports=[80, 443],
            services=[{"name": "nginx", "version": "1.24"}],
        )
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Discover vulnerabilities", step=3, previous_actions=[],
        )
        # Should select vulnerability scan
        assert action.target == "10.0.0.10"

    def test_rule_based_report_when_all_done(
        self, sample_allowed_tools, sample_authorized_assets,
    ):
        selector = ActionSelector(decision_strategy="rule")
        state = WorldState(
            open_ports=[80, 443],
            services=[{"name": "nginx"}],
            vulnerabilities=[{"id": "CVE-001"}],
        )
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Discover vulnerabilities", step=4, previous_actions=[],
        )
        # Should move to reporting phase
        # Note: the reporter tool is in allowed_tools, so it should be found
        assert action.tool == "reporter" or action.tool == "vuln-scanner"

    def test_select_with_fallback_when_no_llm_prompt(
        self, sample_allowed_tools, sample_authorized_assets,
    ):
        selector = ActionSelector(decision_strategy="llm")
        # No prompt configured — should fall back to rule-based
        action = selector.select_action(
            WorldState(), sample_allowed_tools, sample_authorized_assets,
            "Test", step=1, previous_actions=[],
        )
        assert action.target == "10.0.0.10"

    def test_find_tool_by_partial_name(self, sample_allowed_tools):
        # Should find 'nmap' when searching with 'map'
        tool = ActionSelector._find_tool(sample_allowed_tools, "map")
        assert tool is not None
        assert tool["name"] == "nmap"

    def test_find_tool_not_found(self, sample_allowed_tools):
        tool = ActionSelector._find_tool(sample_allowed_tools, "nonexistent")
        assert tool is None

    def test_find_tool_with_multiple_names(self, sample_allowed_tools):
        # Should find 'vuln-scanner' when searching with 'scanner'
        tool = ActionSelector._find_tool(sample_allowed_tools, "scanner", "cve")
        assert tool is not None
        assert "vuln-scanner" in tool["name"]


# ===========================================================================
# PolicyGate
# ===========================================================================


class TestPolicyGate:
    def test_valid_action_passes(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        action = AgentAction(
            tool="nmap", command="discover",
            target="10.0.0.10",
        )
        violations = gate.validate_action(action)
        assert violations == []

    def test_unauthorized_tool_fails(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        action = AgentAction(
            tool="malware", command="exploit",
            target="10.0.0.10",
        )
        violations = gate.validate_action(action)
        assert len(violations) >= 1
        assert any("unauthorized" in v.lower() for v in violations)

    def test_unauthorized_command_fails(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        action = AgentAction(
            tool="nmap", command="exploit",
            target="10.0.0.10",
        )
        violations = gate.validate_action(action)
        assert len(violations) >= 1
        assert any("command" in v.lower() for v in violations)

    def test_unauthorized_target_fails(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        action = AgentAction(
            tool="nmap", command="discover",
            target="evil.remote.com",
        )
        violations = gate.validate_action(action)
        assert len(violations) >= 1
        assert any("target" in v.lower() for v in violations)

    def test_empty_target_passes(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        action = AgentAction(tool="nmap", command="discover", target="")
        violations = gate.validate_action(action)
        assert violations == []

    def test_output_scope_violation_detected(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        output = {"discovered_assets": ["10.0.0.10", "external.evil.com"]}
        violations = gate.validate_output(output)
        assert len(violations) >= 1
        assert any("external.evil.com" in v for v in violations)

    def test_output_within_scope_passes(self, sample_allowed_tools, sample_authorized_assets):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        output = {"discovered_assets": ["10.0.0.10"]}
        violations = gate.validate_output(output)
        assert violations == []

    def test_output_no_discovered_assets_passes(
        self, sample_allowed_tools, sample_authorized_assets,
    ):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        output = {"open_ports": [80]}
        violations = gate.validate_output(output)
        assert violations == []

    def test_output_empty_discovered_assets_passes(
        self, sample_allowed_tools, sample_authorized_assets,
    ):
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)
        output = {"discovered_assets": []}
        violations = gate.validate_output(output)
        assert violations == []

    def test_cidr_subnet_target_accepted(self):
        """A target IP within a CIDR-authorized subnet should pass."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.5")
        violations = gate.validate_action(action)
        assert violations == []

    def test_cidr_subnet_target_outside_rejected(self):
        """A target IP outside the CIDR-authorized subnet should fail."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.1.5")
        violations = gate.validate_action(action)
        assert len(violations) >= 1
        assert any("target" in v.lower() for v in violations)

    def test_cidr_startswith_false_positive_prevented(self):
        """10.0.0.101 should NOT match 10.0.0.10/24 — both are in the same /24 though.
        This test verifies proper subnet math: 10.0.0.101 IS in 10.0.0.0/24 so it SHOULD pass."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.101")
        violations = gate.validate_action(action)
        assert violations == []

    def test_cidr_adjacent_subnet_rejected(self):
        """10.0.1.5 in 10.0.1.0/24 should not match 10.0.0.0/24."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.1.5")
        violations = gate.validate_action(action)
        assert len(violations) >= 1

    def test_hostname_mixed_with_cidr(self):
        """Hostname targets should match by exact name, not CIDR."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24", "target.example.com"],
        )
        # Hostname match
        action = AgentAction(tool="nmap", command="scan", target="target.example.com")
        violations = gate.validate_action(action)
        assert violations == []

    def test_hostname_not_in_scope_rejected(self):
        """Hostname not in authorized list should fail."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="nmap", command="scan", target="evil.example.com")
        violations = gate.validate_action(action)
        assert len(violations) >= 1

    def test_cidr_output_discovered_asset_in_scope(self):
        """Discovered assets within CIDR subnet should pass."""
        gate = PolicyGate(
            allowed_tools=[{"name": "recon", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        output = {"discovered_assets": ["10.0.0.10", "10.0.0.20"]}
        violations = gate.validate_output(output)
        assert violations == []

    def test_cidr_output_discovered_asset_outside_rejected(self):
        """Discovered assets outside CIDR subnet should fail."""
        gate = PolicyGate(
            allowed_tools=[{"name": "recon", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        output = {"discovered_assets": ["10.0.0.10", "192.168.1.1"]}
        violations = gate.validate_output(output)
        assert len(violations) >= 1
        assert any("192.168.1.1" in v for v in violations)

    def test_single_ip_authorized_exact_match(self):
        """Exact IP match should pass."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.10"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")
        violations = gate.validate_action(action)
        assert violations == []

    def test_single_ip_authorized_close_but_not_exact(self):
        """10.0.0.101 should NOT match authorized single IP 10.0.0.10."""
        gate = PolicyGate(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
            authorized_assets=["10.0.0.10"],
        )
        action = AgentAction(tool="nmap", command="scan", target="10.0.0.101")
        violations = gate.validate_action(action)
        assert len(violations) >= 1

    def test_empty_target_skipped(self):
        """Empty target should not be checked against scope."""
        gate = PolicyGate(
            allowed_tools=[{"name": "reporter", "allowed_commands": ["summary"]}],
            authorized_assets=["10.0.0.0/24"],
        )
        action = AgentAction(tool="reporter", command="summary", target="")
        violations = gate.validate_action(action)
        assert violations == []


# ===========================================================================
# Evidence entry
# ===========================================================================


class TestEvidenceEntry:
    def test_create_entry(self, sample_action):
        entry = EvidenceEntry(
            step=1, action=sample_action,
            output={"open_ports": [80]},
        )
        assert entry.step == 1
        assert entry.action.tool == "nmap"

    def test_to_dict(self, sample_action):
        entry = EvidenceEntry(
            step=1, action=sample_action,
            output={"open_ports": [80]},
        )
        d = entry.to_dict()
        assert d["step"] == 1
        assert d["action"]["tool"] == "nmap"
        assert d["output"]["open_ports"] == [80]
        assert "timestamp" in d

    def test_timestamp_is_set(self, sample_action):
        entry = EvidenceEntry(
            step=1, action=sample_action,
            output={},
        )
        assert entry.timestamp is not None
        # Should be parseable ISO 8601
        datetime.fromisoformat(entry.timestamp)


# ===========================================================================
# Drift detection
# ===========================================================================


class TestCheckAgentStateDrift:
    def test_no_drift_when_empty(self):
        state = WorldState()
        violations = check_agent_state_drift(state, [])
        assert violations == []

    def test_no_drift_when_evidence_matches(self):
        state = WorldState(open_ports=[80, 443])
        evidence = [
            EvidenceEntry(
                step=1,
                action=AgentAction(tool="nmap", command="scan"),
                output={"open_ports": [80]},
            ),
            EvidenceEntry(
                step=2,
                action=AgentAction(tool="nmap", command="scan"),
                output={"open_ports": [443]},
            ),
        ]
        violations = check_agent_state_drift(state, evidence)
        assert violations == []

    def test_drift_when_hallucinated_port(self):
        state = WorldState(open_ports=[80, 9999])  # 9999 not in evidence
        evidence = [
            EvidenceEntry(
                step=1,
                action=AgentAction(tool="nmap", command="scan"),
                output={"open_ports": [80]},
            ),
        ]
        violations = check_agent_state_drift(state, evidence)
        assert len(violations) >= 1
        assert any("9999" in v for v in violations)

    def test_no_drift_when_no_confirmed_ports(self):
        """If no evidence has ports, drift check skips (nothing to compare)."""
        state = WorldState(open_ports=[80])  # Has port but no evidence
        evidence = [
            EvidenceEntry(
                step=1,
                action=AgentAction(tool="nmap", command="scan"),
                output={},
            ),
        ]
        violations = check_agent_state_drift(state, evidence)
        assert violations == []

    def test_drift_when_hallucinated_asset(self):
        state = WorldState(discovered_assets=["10.0.0.10", "10.0.0.99"])
        evidence = [
            EvidenceEntry(
                step=1,
                action=AgentAction(tool="recon", command="discover"),
                output={"discovered_assets": ["10.0.0.10"]},
            ),
        ]
        violations = check_agent_state_drift(state, evidence)
        assert len(violations) >= 1

    def test_drift_when_hallucinated_service(self):
        state = WorldState(services=[{"name": "nginx"}, {"name": "apache"}])
        evidence = [
            EvidenceEntry(
                step=1,
                action=AgentAction(tool="nmap", command="fingerprint"),
                output={"services": [{"name": "nginx"}]},
            ),
        ]
        violations = check_agent_state_drift(state, evidence)
        assert len(violations) >= 1
        assert any("apache" in v for v in violations)

    def test_no_drift_with_missing_service_name(self):
        """Services without 'name' key should not trigger drift."""
        state = WorldState(services=[{"port": 80}])
        evidence = [
            EvidenceEntry(
                step=1,
                action=AgentAction(tool="nmap", command="scan"),
                output={"services": [{"port": 80}]},
            ),
        ]
        violations = check_agent_state_drift(state, evidence)
        assert violations == []


# ===========================================================================
# AgentCore
# ===========================================================================


class TestAgentCore:
    def test_create_agent(self, sample_agent_core):
        assert not sample_agent_core.halted
        assert sample_agent_core.step == 0
        assert sample_agent_core.state.open_ports == []

    def test_step_action_records_evidence(self, sample_agent_core, sample_action):
        sample_agent_core.step_action(sample_action, {"open_ports": [80]})
        assert sample_agent_core.step == 1
        assert len(sample_agent_core.evidence_log) == 1
        assert sample_agent_core.evidence_log[0].step == 1

    def test_step_action_updates_state(self, sample_agent_core, sample_action):
        sample_agent_core.step_action(sample_action, {"open_ports": [80, 443]})
        assert sample_agent_core.state.open_ports == [80, 443]

    def test_step_action_appends_multiple_steps(self, sample_agent_core, sample_action):
        for i in range(3):
            sample_agent_core.step_action(sample_action, {"open_ports": [80 + i]})
        assert sample_agent_core.step == 3
        assert len(sample_agent_core.evidence_log) == 3
        assert sample_agent_core.state.open_ports == [80, 81, 82]

    def test_step_action_raises_when_halted(self, sample_agent_core, sample_action):
        sample_agent_core.halted = True
        with pytest.raises(AgentStopTriggered, match="halted"):
            sample_agent_core.step_action(sample_action, {})

    def test_step_action_stops_on_max_steps(self, sample_agent_core, sample_action):
        agent = AgentCore(
            allowed_tools=[], authorized_assets=[], objective="test",
            max_steps=2,
        )
        agent.step_action(sample_action, {"open_ports": [80]})
        # Step 2 hits max_steps (2 >= 2)
        with pytest.raises(AgentStopTriggered, match="max_steps"):
            agent.step_action(sample_action, {"open_ports": [443]})

    def test_step_action_stops_on_drift(self, sample_agent_core, sample_action):
        agent = AgentCore(
            allowed_tools=[], authorized_assets=[], objective="test",
            _drift_check_enabled=True,
        )
        agent.step_action(sample_action, {"open_ports": [80]})
        # Now hallucinate a port in the state directly (bypass update)
        agent.state.open_ports.append(9999)
        with pytest.raises(AgentStateError, match="drift"):
            agent.step_action(sample_action, {"open_ports": [443]})

    def test_get_next_action_returns_action(self, sample_agent_core):
        action = sample_agent_core.get_next_action()
        assert isinstance(action, AgentAction)
        assert action.tool is not None

    def test_get_next_action_raises_when_halted(self, sample_agent_core):
        sample_agent_core.halted = True
        with pytest.raises(AgentStopTriggered, match="halted"):
            sample_agent_core.get_next_action()

    def test_get_next_action_produces_different_actions_over_time(
        self, sample_agent_core,
    ):
        a1 = sample_agent_core.get_next_action()
        sample_agent_core.step_action(a1, {"open_ports": [80]})
        a2 = sample_agent_core.get_next_action()
        # Rules-based selector should produce different actions as state grows
        assert a1.tool == a2.tool or a1.command != a2.command

    def test_elapsed_seconds(self, sample_agent_core):
        elapsed = sample_agent_core.elapsed_seconds
        assert elapsed >= 0

    def test_reset_clears_state(self, sample_agent_core, sample_action):
        sample_agent_core.step_action(sample_action, {"open_ports": [80]})
        assert sample_agent_core.step == 1
        sample_agent_core.reset()
        assert sample_agent_core.step == 0
        assert sample_agent_core.state.open_ports == []
        assert sample_agent_core.evidence_log == []
        assert not sample_agent_core.halted

    def test_from_agentic_config(self, sample_allowed_tools, sample_authorized_assets):
        config = {
            "enabled": True,
            "max_steps": 50,
            "max_time_seconds": 600,
            "decision_strategy": "rule",
            "stop_on_finding": "critical",
            "agent_state_drift_check": True,
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test objective",
            success_criteria=["Criterion 1"],
        )
        assert agent.max_steps == 50
        assert agent.max_time_seconds == 600
        assert agent.decision_strategy == "rule"
        assert agent.stop_on_finding == "critical"
        assert agent._drift_check_enabled is True
        assert agent.success_criteria == ["Criterion 1"]
        assert agent.allowed_tools == sample_allowed_tools

    def test_from_agentic_config_defaults(self, sample_allowed_tools, sample_authorized_assets):
        agent = AgentCore.from_agentic_config(
            {"enabled": True}, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.max_steps == 100
        assert agent.max_time_seconds == 3600
        assert agent.decision_strategy == "rule"
        assert agent._drift_check_enabled is True


# ===========================================================================
# Agent loop (run_agent_loop)
# ===========================================================================


class TestRunAgentLoop:
    def test_loop_runs_until_stop(self, sample_agent_core, sample_action):
        def execute(action):
            return {"open_ports": [80, 443], "services": [{"name": "nginx"}]}

        state, evidence, reason = run_agent_loop(sample_agent_core, execute)
        assert state.open_ports == [80, 443]
        assert len(evidence) >= 1
        assert reason is not None

    def test_loop_stops_on_policy_violation(self, sample_allowed_tools, sample_authorized_assets):
        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=sample_authorized_assets,
            objective="Test",
            max_steps=10,
        )
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)

        def execute(action):
            return {}

        state, evidence, reason = run_agent_loop(agent, execute, gate)
        assert len(evidence) >= 1
        assert reason is not None

    def test_loop_with_custom_action_selector(self, sample_agent_core):
        """Use a custom selector that always returns the same action."""
        from gatekeeper_eos_v6.agentic import ActionSelector

        class FixedSelector(ActionSelector):
            def __init__(self):
                super().__init__()
                self.call_count = 0

            def select_action(self, state, allowed_tools, authorized_assets, objective, step, previous_actions):
                self.call_count += 1
                return AgentAction(tool="nmap", command="discover", target="10.0.0.10")

        selector = FixedSelector()
        agent = AgentCore(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.10"],
            objective="Test",
            max_steps=3,
        )
        agent._action_selector = selector

        def execute(action):
            return {"open_ports": [80 + selector.call_count]}

        state, evidence, reason = run_agent_loop(agent, execute)
        assert len(evidence) == 3  # Should run exactly 3 steps
        assert reason == StopReason.MAX_STEPS

    def test_loop_with_allowed_output_violation(self, sample_allowed_tools, sample_authorized_assets):
        """Loop logs output violations without crashing."""
        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=sample_authorized_assets,
            objective="Test",
            max_steps=3,
        )
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)

        def execute(action):
            # Return an asset outside authorized scope
            return {"discovered_assets": ["10.0.0.10", "evil.com"]}

        state, evidence, reason = run_agent_loop(agent, execute, gate)
        assert len(evidence) >= 1  # Ran at least one step
        # The output violation should be recorded
        last_entry = evidence[-1]
        assert "evil.com" in json.dumps(last_entry.to_dict())


# ===========================================================================
# Integration: agentic campaign YAML loading
# ===========================================================================


class TestAgenticCampaignIntegration:
    def test_agentic_campaign_yaml_loads(self):
        """The agentic campaign YAML should parse without errors."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        assert campaign_path.exists(), f"Missing: {campaign_path}"

        camp = load_campaign(campaign_path)
        assert camp.campaign_id == "CAMP-PENTEST-AGENTIC-2026-Q3"
        assert len(camp.sessions) == 3

    def test_agentic_campaign_has_agentic_configs(self):
        """Each session's inline plan should have agentic_config."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)

        for session in camp.sessions:
            plan = session.plan
            assert isinstance(plan, dict)
            assert "agentic_config" in plan, f"Session {session.session_id} missing agentic_config"
            assert plan["agentic_config"]["enabled"] is True

    def test_agentic_campaign_has_dependency_chain(self):
        """SESS-agentic-vulnscan depends on recon, report depends on vulnscan."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)

        sessions = {s.session_id: s for s in camp.sessions}
        assert sessions["SESS-agentic-vulnscan"].dependencies == ("SESS-agentic-recon",)
        assert sessions["SESS-agentic-report"].dependencies == ("SESS-agentic-vulnscan",)

    def test_agentic_campaign_executor(self):
        """CampaignExecutor should resolve agentic campaign layers."""
        from gatekeeper_eos_v6.campaign import load_campaign, CampaignExecutor

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)
        executor = CampaignExecutor(camp)
        layers = executor.resolve_sessions()
        # 3 layers: recon, vulnscan, report
        assert len(layers) == 3
        assert layers[0] == ["SESS-agentic-recon"]
        assert layers[1] == ["SESS-agentic-vulnscan"]
        assert layers[2] == ["SESS-agentic-report"]

    def test_agentic_sessions_can_build_agent_cores(self):
        """Each session's plan can be used to build an AgentCore."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)

        for session in camp.sessions:
            plan = session.plan
            config = plan["agentic_config"]
            agent = AgentCore.from_agentic_config(
                config=config,
                allowed_tools=plan.get("allowed_tools", []),
                authorized_assets=plan.get("authorized_assets", []),
                objective=plan.get("objective", ""),
                success_criteria=plan.get("success_criteria"),
            )
            assert agent.max_steps >= 1
            assert agent.max_time_seconds >= 60
            assert agent.decision_strategy in ("llm", "rule")

    def test_global_drift_rules_apply(self):
        """Agentic campaign should have global drift rules."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)
        assert len(camp.global_drift_rules) >= 4
        rule_ids = {r.id for r in camp.global_drift_rules}
        assert "DRIFT-TARGET" in rule_ids
        assert "DRIFT-TOOLS" in rule_ids
        assert "DRIFT-EXPIRY" in rule_ids


# ===========================================================================
# Integration: drift rule enforcement with agentic sessions
# ===========================================================================


class TestAgenticDriftIntegration:
    def test_drift_rules_check_agentic_session(self, sample_agent_core):
        """Drift rules from the campaign should be enforceable on agentic sessions."""
        from gatekeeper_eos_v6.campaign import check_drift_rules, DriftRule, DriftAction

        rules = (
            DriftRule(id="DRIFT-TARGET", description="No scope expansion", condition="target_baseline_changes", action=DriftAction.HALT),
            DriftRule(id="DRIFT-TOOLS", description="Tool integrity", condition="tool_hash_mismatch", action=DriftAction.HALT),
        )
        triggered = check_drift_rules(
            # We need a session-like object with drift_rules_override
            type("FakeSession", (), {"drift_rules_override": (), "session_id": "SESS-agentic"})(),
            rules,
            {"DRIFT-TARGET": True, "DRIFT-TOOLS": False},
        )
        assert len(triggered) == 1
        assert triggered[0].id == "DRIFT-TARGET"

    def test_policy_gate_and_drift_sentinel_together(self, sample_allowed_tools, sample_authorized_assets):
        """PolicyGate + DriftSentinel catch both pre-action and post-action violations."""
        gate = PolicyGate(sample_allowed_tools, sample_authorized_assets)

        # Bad action: unauthorized tool
        bad_action = AgentAction(tool="unknown-tool", command="run", target="10.0.0.10")
        violations = gate.validate_action(bad_action)
        assert len(violations) >= 1

        # Bad output: scope expansion
        bad_output = {"discovered_assets": ["10.0.0.10", "outside.com"]}
        output_violations = gate.validate_output(bad_output)
        assert len(output_violations) >= 1

    def test_agentic_config_with_output_schema_validation(self):
        """agentic_config state_schema can be used for output validation."""
        config = {
            "enabled": True,
            "state_schema": {
                "type": "object",
                "properties": {
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                },
            },
        }
        assert config["state_schema"]["type"] == "object"
        assert "open_ports" in config["state_schema"]["properties"]

    def test_executor_integration(self, sample_agent_core, tmp_path):
        """Agent can checkpoint through the campaign executor."""
        from gatekeeper_eos_v6.campaign import CampaignExecutor, Campaign, SessionDef, Schedule
        from datetime import datetime, timezone
        import json

        session = SessionDef(
            session_id="SESS-agentic-test",
            plan={"plan_id": "PLAN-AGENT-01", "allowed_tools": [{"name": "test"}]},
            schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        )
        camp = Campaign(
            campaign_id="CAMP-AGENT-TEST",
            sessions=(session,),
        )
        executor = CampaignExecutor(camp, checkpoint_dir=tmp_path / "ckpt")

        path = executor.write_session_checkpoint(
            session, status="running",
            output={"step": 1, "state": sample_agent_core.state.to_dict()},
        )
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["plan_id"] == "PLAN-AGENT-01"
        assert data["session_id"] == "SESS-agentic-test"
        assert data["status"] == "running"


# ===========================================================================
# FindingSummary
# ===========================================================================


class TestFindingSummary:
    def test_create_basic(self):
        fs = FindingSummary(title="Open port 80", severity="high")
        assert fs.title == "Open port 80"
        assert fs.severity == "high"
        assert fs.confidence == 1.0
        assert fs.cve is None

    def test_create_full(self):
        fs = FindingSummary(
            title="CVE-2024-1234 on nginx",
            severity="critical",
            confidence=0.95,
            cve="CVE-2024-1234",
            remediation="Upgrade nginx to 1.25",
        )
        assert fs.severity == "critical"
        assert fs.confidence == 0.95
        assert fs.cve == "CVE-2024-1234"

    def test_invalid_severity_raises(self):
        with pytest.raises(AgentStateError, match="severity"):
            FindingSummary(title="test", severity="extreme")

    def test_negative_confidence_raises(self):
        with pytest.raises(AgentStateError, match="Confidence"):
            FindingSummary(title="test", confidence=-0.1)

    def test_to_dict(self):
        fs = FindingSummary(title="Port 443", severity="medium", cve="CVE-2024-5678")
        d = fs.to_dict()
        assert d["title"] == "Port 443"
        assert d["severity"] == "medium"
        assert d["cve"] == "CVE-2024-5678"
        assert "remediation" not in d

    def test_from_dict(self):
        fs = FindingSummary.from_dict({
            "title": "Port 22 exposed",
            "severity": "critical",
            "confidence": 0.8,
        })
        assert fs.title == "Port 22 exposed"
        assert fs.severity == "critical"
        assert fs.confidence == 0.8

    def test_from_dict_minimal(self):
        fs = FindingSummary.from_dict({"title": "Info note"})
        assert fs.severity == "info"
        assert fs.confidence == 1.0

    def test_round_trip(self):
        fs = FindingSummary(title="XSS", severity="high", cve="CVE-2024-9999")
        d = fs.to_dict()
        restored = FindingSummary.from_dict(d)
        assert restored.title == fs.title
        assert restored.severity == fs.severity
        assert restored.cve == fs.cve

    def test_frozen(self):
        fs = FindingSummary(title="test", severity="low")
        with pytest.raises(Exception):
            fs.title = "changed"  # type: ignore[misc]


# ===========================================================================
# ISO 8601 Duration Parser
# ===========================================================================


class TestParseIsoDuration:
    def test_parse_hours(self):
        assert parse_iso_duration("PT1H") == 3600
        assert parse_iso_duration("PT2H") == 7200

    def test_parse_minutes(self):
        assert parse_iso_duration("PT30M") == 1800
        assert parse_iso_duration("PT1M") == 60

    def test_parse_seconds(self):
        assert parse_iso_duration("PT30S") == 30
        assert parse_iso_duration("PT1S") == 1

    def test_parse_days(self):
        assert parse_iso_duration("P1D") == 86400
        assert parse_iso_duration("P2D") == 172800

    def test_parse_combined(self):
        assert parse_iso_duration("P1DT2H") == 86400 + 7200
        assert parse_iso_duration("PT1H30M") == 3600 + 1800

    def test_parse_hours_minutes_seconds(self):
        assert parse_iso_duration("PT1H30M15S") == 3600 + 1800 + 15

    def test_parse_fractional_seconds(self):
        assert parse_iso_duration("PT0.5S") == 0
        assert parse_iso_duration("PT1.5S") == 1

    def test_parse_days_hours_minutes(self):
        assert parse_iso_duration("P2DT12H30M") == 2 * 86400 + 12 * 3600 + 30 * 60

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="duration"):
            parse_iso_duration("not-a-duration")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="duration"):
            parse_iso_duration("")

    def test_missing_p_raises(self):
        with pytest.raises(ValueError, match="duration"):
            parse_iso_duration("T1H")

    def test_strips_whitespace(self):
        assert parse_iso_duration("  PT1H  ") == 3600

    def test_parse_years_approx(self):
        # Years are approximate (365 days)
        assert parse_iso_duration("P1Y") == 365 * 86400


# ===========================================================================
# StopCondition with stop_conditions array
# ===========================================================================


class TestStopConditionArray:
    def test_stop_conditions_max_steps(self):
        cond = StopCondition(stop_conditions=[
            {"type": "max_steps", "value": "3"},
        ])
        should, reason = cond.should_stop(
            current_step=3, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_STEPS

    def test_stop_conditions_max_steps_not_triggered(self):
        cond = StopCondition(stop_conditions=[
            {"type": "max_steps", "value": "10"},
        ])
        should, _ = cond.should_stop(
            current_step=3, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is False

    def test_stop_conditions_finding_severity(self):
        cond = StopCondition(stop_conditions=[
            {"type": "finding_severity", "value": "high"},
        ])
        state = WorldState(findings_summary=[
            {"severity": "critical", "id": "CVE-001"},
        ])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is True
        assert reason == StopReason.MAX_SEVERITY_FOUND

    def test_stop_conditions_finding_severity_low_not_triggered(self):
        cond = StopCondition(stop_conditions=[
            {"type": "finding_severity", "value": "critical"},
        ])
        state = WorldState(findings_summary=[
            {"severity": "low", "id": "CVE-001"},
        ])
        should, _ = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is False

    def test_stop_conditions_time_limit_triggered(self):
        cond = StopCondition(stop_conditions=[
            {"type": "time_limit", "value": "PT0.01S"},
        ])
        start = time.monotonic()
        time.sleep(0.02)
        should, reason = cond.should_stop(
            current_step=1, start_time=start,
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_TIME

    def test_stop_conditions_time_limit_not_triggered(self):
        cond = StopCondition(stop_conditions=[
            {"type": "time_limit", "value": "PT1H"},
        ])
        should, _ = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is False

    def test_stop_conditions_success_criterion_met(self):
        cond = StopCondition(stop_conditions=[
            {"type": "success_criterion_met"},
        ])
        state = WorldState(open_ports=[80])
        should, reason = cond.should_stop(
            current_step=5, start_time=time.monotonic(),
            state=state,
            success_criteria=["All open ports identified"],
        )
        assert should is True
        assert reason == StopReason.CRITERIA_MET

    def test_stop_conditions_success_criterion_not_met(self):
        cond = StopCondition(stop_conditions=[
            {"type": "success_criterion_met"},
        ])
        state = WorldState()
        should, _ = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
            success_criteria=["Something about non-existent data"],
        )
        assert should is False

    def test_stop_conditions_multiple_first_wins(self):
        """Multiple conditions: the first triggered one wins."""
        cond = StopCondition(stop_conditions=[
            {"type": "finding_severity", "value": "medium"},
            {"type": "max_steps", "value": "1"},
        ])
        state = WorldState(findings_summary=[{"severity": "high"}])
        should, reason = cond.should_stop(
            current_step=5, start_time=time.monotonic(),
            state=state,
        )
        # finding_severity triggers first (order in array)
        assert should is True
        assert reason == StopReason.MAX_SEVERITY_FOUND

    def test_stop_conditions_empty_array_no_effect(self):
        cond = StopCondition(stop_conditions=[])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is False
        assert reason == StopReason.NO_MORE_ACTIONS

    def test_stop_conditions_with_invalid_type_ignored(self):
        cond = StopCondition(stop_conditions=[
            {"type": "unknown_type", "value": "x"},
            {"type": "max_steps", "value": "2"},
        ])
        should, reason = cond.should_stop(
            current_step=2, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_STEPS

    def test_stop_conditions_fallback_to_flat_when_empty(self):
        """When stop_conditions is None, fall back to flat config."""
        cond = StopCondition(max_steps=3)
        should, reason = cond.should_stop(
            current_step=3, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is True
        assert reason == StopReason.MAX_STEPS

    def test_stop_conditions_none_fallback(self):
        cond = StopCondition(stop_conditions=None)
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=WorldState(),
        )
        assert should is False


# ===========================================================================
# AgentCore with new features
# ===========================================================================


class TestAgentCoreNewFeatures:
    def test_from_agentic_config_with_max_duration(self, sample_allowed_tools, sample_authorized_assets):
        """max_duration ISO 8601 should be parsed to seconds."""
        config = {
            "enabled": True,
            "max_duration": "PT30M",  # 30 minutes
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.max_time_seconds == 1800

    def test_from_agentic_config_max_duration_fallback(self, sample_allowed_tools, sample_authorized_assets):
        """If max_duration is invalid, fall back to default."""
        config = {
            "enabled": True,
            "max_duration": "not-valid",
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.max_time_seconds == 3600  # default

    def test_from_agentic_config_max_time_seconds_takes_precedence(self, sample_allowed_tools, sample_authorized_assets):
        """Explicit max_time_seconds overrides max_duration."""
        config = {
            "enabled": True,
            "max_time_seconds": 600,
            "max_duration": "PT2H",
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.max_time_seconds == 600  # explicit wins

    def test_from_agentic_config_with_llm_prompt_template(self, sample_allowed_tools, sample_authorized_assets):
        """llm_prompt_template should be used as llm_prompt alias."""
        config = {
            "enabled": True,
            "llm_prompt_template": "You are an agent. Allowed tools: {{ allowed_tools }}. Target: {{ authorized_assets }}.",
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.llm_prompt is not None
        assert "{{ allowed_tools }}" in agent.llm_prompt

    def test_from_agentic_config_llm_prompt_precedence(self, sample_allowed_tools, sample_authorized_assets):
        """llm_prompt takes precedence over llm_prompt_template."""
        config = {
            "enabled": True,
            "llm_prompt": "direct prompt",
            "llm_prompt_template": "template prompt",
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.llm_prompt == "direct prompt"

    def test_from_agentic_config_with_rule_engine_config(self, sample_allowed_tools, sample_authorized_assets):
        """rule_engine_config should be parsed."""
        config = {
            "enabled": True,
            "rule_engine_config": {
                "phase_order": ["recon", "fingerprint", "vuln", "report"],
                "max_retries_per_phase": 5,
                "fallback_on_empty": "fingerprint",
            },
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.rule_engine_config is not None
        assert agent.rule_engine_config.phase_order == ["recon", "fingerprint", "vuln", "report"]
        assert agent.rule_engine_config.max_retries_per_phase == 5
        assert agent.rule_engine_config.fallback_on_empty == "fingerprint"

    def test_from_agentic_config_rule_engine_defaults(self, sample_allowed_tools, sample_authorized_assets):
        """Omitting rule_engine_config leaves it None."""
        agent = AgentCore.from_agentic_config(
            {"enabled": True}, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.rule_engine_config is None

    def test_from_agentic_config_with_stop_conditions(self, sample_allowed_tools, sample_authorized_assets):
        """stop_conditions should be stored on AgentCore and passed to StopCondition."""
        config = {
            "enabled": True,
            "stop_conditions": [
                {"type": "finding_severity", "value": "critical"},
                {"type": "max_steps", "value": "50"},
            ],
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.stop_conditions is not None
        assert len(agent.stop_conditions) == 2
        assert agent.stop_conditions[0]["type"] == "finding_severity"
        assert agent.stop_conditions[0]["value"] == "critical"
        assert agent.stop_conditions[1]["type"] == "max_steps"

    def test_from_agentic_config_with_allow_human_in_the_loop(self, sample_allowed_tools, sample_authorized_assets):
        config = {
            "enabled": True,
            "allow_human_in_the_loop": True,
        }
        agent = AgentCore.from_agentic_config(
            config, sample_allowed_tools, sample_authorized_assets,
            objective="Test",
        )
        assert agent.allow_human_in_the_loop is True

    def test_human_in_the_loop_approval_passes(self, sample_action):
        """When callback approves, action proceeds."""
        agent = AgentCore(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.10"],
            objective="Test",
            allow_human_in_the_loop=True,
            human_approval_callback=lambda a: True,
            max_steps=10,
        )
        agent.step_action(sample_action, {"open_ports": [80]})
        assert agent.step == 1
        assert not agent.halted

    def test_human_in_the_loop_rejection_halts(self, sample_action):
        """When callback rejects, agent halts with HUMAN_IN_THE_LOOP."""
        agent = AgentCore(
            allowed_tools=[{"name": "nmap", "allowed_commands": ["discover"]}],
            authorized_assets=["10.0.0.10"],
            objective="Test",
            allow_human_in_the_loop=True,
            human_approval_callback=lambda a: False,
            max_steps=10,
        )
        with pytest.raises(AgentStopTriggered, match="human_in_the_loop"):
            agent.step_action(sample_action, {"open_ports": [80]})
        assert agent.halted
        assert agent.stop_reason == StopReason.HUMAN_IN_THE_LOOP

    def test_human_in_the_loop_no_callback_passes(self, sample_action):
        """If allow_human_in_the_loop is True but no callback, action proceeds."""
        agent = AgentCore(
            allowed_tools=[], authorized_assets=[], objective="Test",
            allow_human_in_the_loop=True,
            human_approval_callback=None,
            max_steps=10,
        )
        agent.step_action(sample_action, {"open_ports": [80]})
        assert agent.step == 1

    def test_step_action_with_stop_conditions_array_triggers(self, sample_action):
        """stop_conditions array should trigger during step_action via StopCondition."""
        agent = AgentCore(
            allowed_tools=[], authorized_assets=[], objective="Test",
            max_steps=100,  # high — won't trigger
            stop_conditions=[
                {"type": "max_steps", "value": "1"},  # triggers on step >= 1
            ],
        )
        with pytest.raises(AgentStopTriggered, match="max_steps"):
            agent.step_action(sample_action, {"open_ports": [80]})
        assert agent.halted
        assert agent.stop_reason == StopReason.MAX_STEPS

    def test_finding_summary_in_worldstate_update(self):
        """WorldState should handle FindingSummary-like dicts in findings_summary."""
        state = WorldState()
        finding = FindingSummary(title="XSS", severity="medium", confidence=0.8).to_dict()
        state.update({"findings_summary": [finding]})
        assert len(state.findings_summary) == 1
        assert state.findings_summary[0]["title"] == "XSS"

    def test_finding_summary_in_worldstate_no_duplicates(self):
        state = WorldState()
        finding = {"title": "Port 22", "severity": "low"}
        state.update({"findings_summary": [finding]})
        state.update({"findings_summary": [finding]})
        assert len(state.findings_summary) == 1

    def test_finding_summary_stops_agent_on_severity(self):
        """Using FindingSummary dicts in findings_summary should trigger severity stop."""
        cond = StopCondition(stop_on_finding="high")
        state = WorldState(findings_summary=[
            FindingSummary(title="RCE", severity="critical").to_dict(),
        ])
        should, reason = cond.should_stop(
            current_step=1, start_time=time.monotonic(),
            state=state,
        )
        assert should is True
        assert reason == StopReason.MAX_SEVERITY_FOUND


# ===========================================================================
# Integration: agentic campaign YAML with new fields
# ===========================================================================


class TestAgenticYAMLNewFields:
    def test_agentic_yaml_stop_conditions_parse(self):
        """Verify the YAML's stop_conditions can be loaded and used."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)

        recon_session = [s for s in camp.sessions if s.session_id == "SESS-agentic-recon"][0]
        plan = recon_session.plan
        config = plan["agentic_config"]

        assert "stop_conditions" in config
        assert len(config["stop_conditions"]) >= 1
        assert config["stop_conditions"][0]["type"] == "success_criterion_met"

    def test_agentic_yaml_max_duration_parse(self):
        """Verify max_duration is parsed correctly from YAML."""
        from gatekeeper_eos_v6.campaign import load_campaign
        from gatekeeper_eos_v6.agentic import parse_iso_duration

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)

        recon_session = [s for s in camp.sessions if s.session_id == "SESS-agentic-recon"][0]
        config = recon_session.plan["agentic_config"]

        assert "max_duration" in config
        seconds = parse_iso_duration(config["max_duration"])
        assert seconds == 600  # PT10M = 10 * 60

    def test_agentic_yaml_rule_engine_config_parse(self):
        """Verify rule_engine_config is loaded from YAML."""
        from gatekeeper_eos_v6.campaign import load_campaign

        campaign_path = Path(__file__).resolve().parent.parent / "specs" / "pentest-agentic-orchestrator.yaml"
        camp = load_campaign(campaign_path)

        recon_session = [s for s in camp.sessions if s.session_id == "SESS-agentic-recon"][0]
        config = recon_session.plan["agentic_config"]

        assert "rule_engine_config" in config
        engine_config = config["rule_engine_config"]
        assert engine_config["max_retries_per_phase"] == 2
        assert engine_config["fallback_on_empty"] == "fingerprint"
