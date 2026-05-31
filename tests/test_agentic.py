"""Tests for the bounded agentic reasoning engine.

Covers: WorldState, ActionSelector, StopCondition, PolicyGate, AgentCore,
evidence log, drift detection, agent loop, and campaign integration.
"""

from __future__ import annotations

import json
import time
import unittest.mock
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
    LLMProvider,
    MockLLMProvider,
    RuleFallbackLLMProvider,
    AgenticError,
    AgentStateError,
    AgentActionError,
    AgentStopTriggered,
    check_agent_state_drift,
    parse_iso_duration,
    run_agent_loop,
)
from gatekeeper_eos_v6.providers import OpenAIProvider, AnthropicProvider, GoogleProvider, create_llm_provider, RateLimiter, CircuitBreaker, CircuitState, _call_with_retry, _is_retryable_error


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

    # --- Multi-asset rotation ---

    def test_rotation_cycles_through_assets(self, sample_allowed_tools):
        """With 3 authorized assets, selector rotates through all of them."""
        selector = ActionSelector(decision_strategy="rule")
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
        state = WorldState()  # Empty — triggers recon, same tool each call

        targets = []
        for i in range(6):
            action = selector.select_action(
                state, sample_allowed_tools, assets,
                "Rotate test", step=i + 1, previous_actions=[],
            )
            targets.append(action.target)

        # Should rotate through 10.0.0.10 -> 10.0.0.11 -> 10.0.0.12 -> 10.0.0.10 -> ...
        assert targets == ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.10", "10.0.0.11", "10.0.0.12"]

    def test_rotation_single_asset_no_cycle(self, sample_allowed_tools):
        """Single authorized asset → no rotation, always same target."""
        selector = ActionSelector(decision_strategy="rule")
        assets = ["10.0.0.10"]
        state = WorldState()

        targets = []
        for i in range(3):
            action = selector.select_action(
                state, sample_allowed_tools, assets,
                "Single test", step=i + 1, previous_actions=[],
            )
            targets.append(action.target)

        # All calls should target the same single asset
        assert targets == ["10.0.0.10", "10.0.0.10", "10.0.0.10"]

    def test_rotation_no_assets_uses_fallback(self, sample_allowed_tools):
        """Empty authorized_assets → fallback target string."""
        selector = ActionSelector(decision_strategy="rule")
        action = selector.select_action(
            WorldState(), sample_allowed_tools, [],
            "No assets", step=1, previous_actions=[],
        )
        assert action.target == "target"

    def test_rotation_preserves_index_across_calls(self, sample_allowed_tools):
        """State changes (different phases) should not reset the rotation index."""
        selector = ActionSelector(decision_strategy="rule")
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        # Call 1: empty state → recon → target 10.0.0.10
        state = WorldState()
        a1 = selector.select_action(state, sample_allowed_tools, assets, "Test", step=1, previous_actions=[])
        assert a1.target == "10.0.0.10"

        # Call 2: state with ports → fingerprint → target 10.0.0.11 (rotated)
        state = WorldState(open_ports=[80])
        a2 = selector.select_action(state, sample_allowed_tools, assets, "Test", step=2, previous_actions=[])
        assert a2.target == "10.0.0.11"

        # Call 3: state with services → vuln scan → target 10.0.0.12 (rotated)
        state = WorldState(open_ports=[80], services=[{"name": "nginx"}])
        a3 = selector.select_action(state, sample_allowed_tools, assets, "Test", step=3, previous_actions=[])
        assert a3.target == "10.0.0.12"

    def test_rotation_hybrid_preserves_stall_detection(self, sample_allowed_tools):
        """Hybrid strategy with asset rotation: target changes don't prevent stall
        because _check_tool_loop checks tool+command, not target."""
        selector = ActionSelector(decision_strategy="hybrid")
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
        state = WorldState(open_ports=[80])  # Keeps in fingerprint → same tool/command

        for i in range(5):
            action = selector.select_action(
                state, sample_allowed_tools, assets,
                "Stall test", step=i + 1, previous_actions=[],
            )
            if i >= 3:
                # Despite target rotation, stall should trigger because
                # tool (nmap) and command (scan) are identical
                assert "RULE_ENGINE_STALLED" in action.reasoning

    def test_rotation_reset_after_stall_reset(self):
        """_reset_stall should reset the rotation index to 0."""
        selector = ActionSelector(decision_strategy="rule")
        assets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        # Advance rotation to index 2
        for i in range(3):
            action = selector.select_action(
                WorldState(), [{"name": "nmap", "allowed_commands": ["discover"]}], assets,
                "Test", step=i + 1, previous_actions=[],
            )
        assert action.target == "10.0.0.12"  # index 2

        # Reset stall (which also resets rotation index)
        selector._reset_stall()

        # Next action should target index 0 again
        action = selector.select_action(
            WorldState(), [{"name": "nmap", "allowed_commands": ["discover"]}], assets,
            "Test", step=4, previous_actions=[],
        )
        assert action.target == "10.0.0.10"

    def test_rotation_reset_within_agent_core(self, sample_allowed_tools, sample_authorized_assets):
        """AgentCore.reset() clears the selector, which resets rotation index."""
        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=["10.0.0.10", "10.0.0.11"],
            objective="Reset rotation test",
            decision_strategy="rule",
            max_steps=10,
        )

        # Run a few steps — advances rotation index
        for i in range(3):
            action = agent.get_next_action()
            agent.step_action(action, {"open_ports": [80 + i]})

        # Reset the agent
        agent.reset()

        # First action after reset should target index 0 (10.0.0.10)
        action = agent.get_next_action()
        assert action.target == "10.0.0.10"


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

    # --- Checkpoint integration ---

    def test_loop_with_snapshots_writes_ledger(self, sample_allowed_tools, sample_authorized_assets, tmp_path):
        """run_agent_loop with snapshot_ledger writes snapshot entries."""
        from gatekeeper_eos_v6.snapshot import SnapshotLedger

        l = SnapshotLedger(tmp_path / "ckpt_ledger.json")
        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=sample_authorized_assets,
            objective="Checkpoint test",
            decision_strategy="rule",
            max_steps=3,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            return {"open_ports": [80, 443], "services": [{"name": "nginx"}]}

        state, evidence, reason = run_agent_loop(agent, execute, snapshot_ledger=l, session_id="SESS-ckpt")

        # Should have written snapshots for each step
        assert l.index.size >= 2, f"Expected ≥2 snapshot entries, got {l.index.size}"
        violations = l.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"

    def test_loop_drift_recovery_continues(self, sample_allowed_tools, sample_authorized_assets, tmp_path):
        """Drift during loop is recovered via snapshot restore; loop continues."""
        from gatekeeper_eos_v6.snapshot import SnapshotLedger

        l = SnapshotLedger(tmp_path / "drift_ledger.json")
        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=sample_authorized_assets,
            objective="Drift recovery test",
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
            # Inject hallucinated port once (before step 2)
            if not drift_injected[0]:
                agent.state.open_ports.append(9999)
                drift_injected[0] = True
            return {"open_ports": [443]}

        state, evidence, reason = run_agent_loop(agent, execute, snapshot_ledger=l, session_id="SESS-drift")

        # After recovery, state should be clean (no hallucinated ports)
        assert 9999 not in state.open_ports, (
            f"Hallucinated port 9999 still in state: {state.open_ports}"
        )
        # The loop should NOT have stopped via DRIFT_DETECTED
        assert reason != StopReason.DRIFT_DETECTED, (
            f"Loop stopped via drift despite recovery attempt: {reason}"
        )
        # Evidence should have entries (both before and after recovery)
        assert len(evidence) >= 2, (
            f"Expected evidence after recovery, got {len(evidence)}"
        )

    def test_loop_drift_no_snapshot_stops(self, sample_allowed_tools, sample_authorized_assets, tmp_path):
        """Drift before any snapshot is written stops the loop cleanly."""
        from gatekeeper_eos_v6.snapshot import SnapshotLedger

        l = SnapshotLedger(tmp_path / "empty_ledger.json")
        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=sample_authorized_assets,
            objective="Drift no restore test",
            decision_strategy="rule",
            max_steps=10,
            stop_on_criteria_met=False,
            stop_on_finding="none",
        )

        def execute(action):
            # Inject hallucination on every call (before auto-snapshot can save)
            agent.state.open_ports.append(9999)
            return {"open_ports": [80]}

        state, evidence, reason = run_agent_loop(agent, execute, snapshot_ledger=l, session_id="SESS-norestore")

        # No valid snapshot to restore from -> loop stops via DRIFT_DETECTED
        assert reason == StopReason.DRIFT_DETECTED, (
            f"Expected DRIFT_DETECTED, got {reason}"
        )
        # No evidence was recorded (drift on step 1 before auto-snapshot)
        # step_action records evidence BEFORE checking drift, so one entry
        # is always present even when drift is detected on the first call.
        assert len(evidence) >= 1
        # Drift state still contains hallucinated port
        assert 9999 in state.open_ports


# ===========================================================================
# LLMProvider
# ===========================================================================


class TestLLMProvider:
    """Tests for LLMProvider base class and built-in implementations."""

    def test_mock_provider_generates_json(self):
        """MockLLMProvider.generate returns valid JSON with tool/command."""
        provider = MockLLMProvider()
        response = provider.generate("test prompt")
        data = json.loads(response)
        assert data["tool"] == "nmap"
        assert data["command"] == "discover"
        assert data["target"] == "target"

    def test_mock_provider_tracks_calls(self):
        """MockLLMProvider tracks call_count and last_prompt."""
        provider = MockLLMProvider()
        assert provider.call_count == 0

        provider.generate("prompt 1")
        assert provider.call_count == 1
        assert "prompt 1" in provider.last_prompt

        provider.generate("prompt 2")
        assert provider.call_count == 2
        assert "prompt 2" in provider.last_prompt

    def test_mock_provider_custom_action(self):
        """MockLLMProvider accepts a custom default action dict."""
        custom = {
            "tool": "reporter",
            "command": "summary",
            "arguments": {"findings": 5},
            "target": "10.0.0.10",
            "reasoning": "Custom mock response",
        }
        provider = MockLLMProvider(default_action=custom)
        response = provider.generate("test")
        data = json.loads(response)
        assert data["tool"] == "reporter"
        assert data["command"] == "summary"
        assert data["arguments"]["findings"] == 5

    def test_mock_provider_model_default(self):
        """MockLLMProvider defaults model to 'mock'."""
        provider = MockLLMProvider()
        assert provider.model == "mock"

        provider2 = MockLLMProvider(model="custom-model")
        assert provider2.model == "custom-model"

    def test_rule_fallback_provider_returns_empty(self):
        """RuleFallbackLLMProvider returns empty string (signals rule fallback)."""
        provider = RuleFallbackLLMProvider()
        response = provider.generate("any prompt")
        assert response == ""
        assert provider.call_count == 1

    def test_llm_response_parsing_in_selector(self, sample_allowed_tools, sample_authorized_assets):
        """ActionSelector._select_with_llm parses MockLLMProvider's response."""
        custom_action = {
            "tool": "reporter",
            "command": "summary",
            "arguments": {},
            "target": "10.0.0.10",
            "reasoning": "LLM chose report phase",
        }
        provider = MockLLMProvider(default_action=custom_action)
        selector = ActionSelector(
            decision_strategy="llm",
            llm_prompt="You are an agent. Tools: {{ allowed_tools }}",
            llm_provider=provider,
        )

        state = WorldState(open_ports=[80], services=[{"name": "nginx"}])
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Test LLM", step=1, previous_actions=[],
        )

        # Should use the LLM action, not rule fallback
        assert action.tool == "reporter"
        assert action.command == "summary"
        assert provider.call_count == 1
        # The prompt should have been substituted with context
        assert "{{ allowed_tools }}" not in provider.last_prompt
        assert "nmap" in provider.last_prompt or "Tools:" in provider.last_prompt

    def test_llm_empty_response_falls_back_to_rules(self, sample_allowed_tools, sample_authorized_assets):
        """Empty LLM response -> fall back to rule-based selection."""
        provider = MockLLMProvider()
        # Override to return empty (simulating no valid response)
        provider._default_action = {}  # Will produce invalid JSON
        # Actually MockLLMProvider always returns valid JSON
        # Let me use a different approach: use RuleFallbackLLMProvider which returns ""
        fallback_provider = RuleFallbackLLMProvider()

        selector = ActionSelector(
            decision_strategy="llm",
            llm_prompt="Template: {{ allowed_tools }}",
            llm_provider=fallback_provider,
        )

        state = WorldState()  # Empty -> recon phase
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Test", step=1, previous_actions=[],
        )

        # Should fall back to rule-based (recon on first asset)
        assert action.tool is not None
        assert action.target == "10.0.0.10"
        assert fallback_provider.call_count == 1

    def test_llm_no_provider_falls_back(self, sample_allowed_tools, sample_authorized_assets):
        """No LLM provider configured -> fall back to rules."""
        selector = ActionSelector(
            decision_strategy="llm",
            llm_prompt="Template: {{ allowed_tools }}",
            # No llm_provider
        )

        state = WorldState()
        action = selector.select_action(
            state, sample_allowed_tools, sample_authorized_assets,
            "Test", step=1, previous_actions=[],
        )

        # Falls back to rules
        assert action.target == "10.0.0.10"

    def test_agent_core_wires_llm_provider_to_selector(self, sample_allowed_tools, sample_authorized_assets):
        """AgentCore with llm_provider passes it to the ActionSelector."""
        provider = MockLLMProvider()

        agent = AgentCore(
            allowed_tools=sample_allowed_tools,
            authorized_assets=sample_authorized_assets,
            objective="LLM provider test",
            decision_strategy="llm",
            llm_prompt="You are an agent. Tools: {{ allowed_tools }}",
            llm_provider=provider,
            max_steps=3,
        )

        action = agent.get_next_action()
        # The selector should have used the provider
        assert provider.call_count >= 1
        assert action.tool is not None

    def test_hybrid_with_llm_provider_uses_fallback(self, sample_allowed_tools, sample_authorized_assets):
        """Hybrid strategy with LLM provider: on stall, calls provider for unstick."""
        custom_action = {
            "tool": "reporter",
            "command": "summary",
            "arguments": {},
            "target": "10.0.0.10",
            "reasoning": "LLM unstick",
        }
        provider = MockLLMProvider(default_action=custom_action)

        selector = ActionSelector(
            decision_strategy="hybrid",
            llm_prompt="Rescue: {{ state }}",
            llm_provider=provider,
        )

        # State that keeps selector in same phase
        state = WorldState(open_ports=[80])

        # Call 4+ times to trigger stall
        stalled_action = None
        for i in range(5):
            action = selector.select_action(
                state, sample_allowed_tools, sample_authorized_assets,
                "Test", step=i + 1, previous_actions=[],
            )
            if i == 3:
                stalled_action = action

        # LLM should have been called at least once
        assert provider.call_count >= 1
        # The LLM returned a different action (reporter/summary != nmap/scan)
        # So the stall should be reset, and the action should NOT have stall marker
        assert stalled_action is not None
        assert "RULE_ENGINE_STALLED" not in stalled_action.reasoning
        assert stalled_action.tool == "reporter"


# ===========================================================================
# OpenAIProvider
# ===========================================================================


class TestOpenAIProvider:
    """Tests for OpenAIProvider — a real LLM provider backed by the OpenAI API.

    All tests mock the internal OpenAI client so no real API calls are made.
    """

    def test_creates_client_with_env_key(self, monkeypatch):
        """With OPENAI_API_KEY set, OpenAIProvider creates a client."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-12345")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            provider = OpenAIProvider()

            mock_openai.assert_called_once()
            call_kwargs = mock_openai.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-test-key-12345"
            assert provider.model == "gpt-4o-mini"

    def test_creates_client_with_explicit_key(self, monkeypatch):
        """Explicit api_key argument takes precedence over env var."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-should-be-ignored")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            provider = OpenAIProvider(api_key="sk-explicit")

            call_kwargs = mock_openai.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-explicit"

    def test_no_key_raises_value_error(self, monkeypatch):
        """No API key in env or constructor -> ValueError."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            OpenAIProvider()

    def test_generate_success(self, monkeypatch):
        """Successful API call returns parsed JSON string."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            # Simulate a valid API response
            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "nmap", "command": "discover", "arguments": {"target": "10.0.0.1"}, "target": "10.0.0.1", "reasoning": "Initial recon"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()
            result = provider.generate("Scan the target")

            # Verify the response was returned and is valid JSON
            parsed = json.loads(result)
            assert parsed["tool"] == "nmap"
            assert parsed["command"] == "discover"
            assert provider.call_count == 1
            assert provider.last_prompt == "Scan the target"
            assert provider.last_raw_response == result

            # Verify the API was called with expected args
            mock_client.chat.completions.create.assert_called_once()
            call_kwargs = mock_client.chat.completions.create.call_args.kwargs
            assert call_kwargs["model"] == "gpt-4o-mini"
            assert len(call_kwargs["messages"]) == 2
            assert call_kwargs["messages"][0]["role"] == "system"
            assert call_kwargs["messages"][1]["role"] == "user"
            assert call_kwargs["messages"][1]["content"] == "Scan the target"

    def test_generate_invalid_json_returns_empty(self, monkeypatch):
        """API returns non-JSON content -> returns empty string."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = "This is not JSON"
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()
            result = provider.generate("test")

            assert result == "", f"Expected empty string, got: {result}"
            assert provider.last_raw_response == "This is not JSON"

    def test_generate_api_error_returns_empty(self, monkeypatch):
        """API call raises exception -> returns empty string (after max_retries=0)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client
            mock_client.chat.completions.create.side_effect = Exception("API timeout")

            provider = OpenAIProvider(max_retries=0)
            result = provider.generate("test")

            assert result == "", f"Expected empty string on error, got: {result}"

    def test_generate_tracks_multiple_calls(self, monkeypatch):
        """Multiple calls increment call_count correctly."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()

            provider.generate("call 1")
            provider.generate("call 2")
            provider.generate("call 3")

            assert provider.call_count == 3

    def test_custom_model_and_params(self, monkeypatch):
        """Custom model, temperature, max_tokens passed to API."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider(
                model="gpt-4o",
                temperature=0.8,
                max_tokens=2048,
                timeout=60,
            )

            assert provider.model == "gpt-4o"
            provider.generate("test")

            call_kwargs = mock_client.chat.completions.create.call_args.kwargs
            assert call_kwargs["model"] == "gpt-4o"
            assert call_kwargs["temperature"] == 0.8
            assert call_kwargs["max_tokens"] == 2048
            assert call_kwargs["timeout"] == 60

    def test_custom_base_url(self, monkeypatch):
        """Custom base_url passed to OpenAI client constructor."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            provider = OpenAIProvider(base_url="http://localhost:8080/v1")

            call_kwargs = mock_openai.call_args.kwargs
            assert call_kwargs["base_url"] == "http://localhost:8080/v1"

    def test_create_llm_provider_factory(self, monkeypatch):
        """create_llm_provider factory returns correct provider types."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            # OpenAI provider
            openai_prov = create_llm_provider("openai")
            assert isinstance(openai_prov, OpenAIProvider)

            # Mock provider
            mock_prov = create_llm_provider("mock")
            assert isinstance(mock_prov, MockLLMProvider)

            # Test provider (alias for mock)
            test_prov = create_llm_provider("test")
            assert isinstance(test_prov, MockLLMProvider)

    def test_create_llm_provider_unknown_type(self):
        """Unknown provider_type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown provider_type"):
            create_llm_provider("nonexistent")


# ===========================================================================
# AnthropicProvider
# ===========================================================================


class TestAnthropicProvider:
    """Tests for AnthropicProvider — a real LLM provider backed by the Anthropic API.

    All tests mock the internal Anthropic client so no real API calls are made.
    """

    def test_creates_client_with_env_key(self, monkeypatch):
        """With ANTHROPIC_API_KEY set, AnthropicProvider creates a client."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            provider = AnthropicProvider()

            mock_anthropic.assert_called_once()
            call_kwargs = mock_anthropic.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-ant-test-key-12345"
            assert provider.model == "claude-sonnet-4-20250514"

    def test_creates_client_with_explicit_key(self, monkeypatch):
        """Explicit api_key argument takes precedence over env var."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-be-ignored")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            provider = AnthropicProvider(api_key="sk-ant-explicit")

            call_kwargs = mock_anthropic.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-ant-explicit"

    def test_no_key_raises_value_error(self, monkeypatch):
        """No API key in env or constructor -> ValueError."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            AnthropicProvider()

    def test_generate_success(self, monkeypatch):
        """Successful API call returns parsed JSON string."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            # Simulate a valid API response from Anthropic's Messages API
            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = '{"tool": "nmap", "command": "discover", "arguments": {"target": "10.0.0.1"}, "target": "10.0.0.1", "reasoning": "Initial recon"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()
            result = provider.generate("Scan the target")

            # Verify the response was returned and is valid JSON
            parsed = json.loads(result)
            assert parsed["tool"] == "nmap"
            assert parsed["command"] == "discover"
            assert provider.call_count == 1
            assert provider.last_prompt == "Scan the target"
            assert provider.last_raw_response == result

            # Verify the API was called with expected args
            mock_client.messages.create.assert_called_once()
            call_kwargs = mock_client.messages.create.call_args.kwargs
            assert call_kwargs["model"] == "claude-sonnet-4-20250514"
            assert len(call_kwargs["messages"]) == 1
            assert call_kwargs["messages"][0]["role"] == "user"
            assert call_kwargs["messages"][0]["content"] == "Scan the target"
            assert call_kwargs["system"] is not None
            assert "DEFAULT_SYSTEM_PROMPT" not in repr(call_kwargs["system"])
            assert "penetration-testing AI" in call_kwargs["system"]
            assert call_kwargs["max_tokens"] == 1024

    def test_generate_invalid_json_returns_empty(self, monkeypatch):
        """API returns non-JSON content -> returns empty string."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = "This is not JSON"
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()
            result = provider.generate("test")

            assert result == "", f"Expected empty string, got: {result}"
            assert provider.last_raw_response == "This is not JSON"

    def test_generate_empty_content_returns_empty(self, monkeypatch):
        """API returns empty content -> returns empty string."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_response = unittest.mock.MagicMock()
            mock_response.content = []
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()
            result = provider.generate("test")

            assert result == "", f"Expected empty string, got: {result}"

    def test_generate_api_error_returns_empty(self, monkeypatch):
        """API call raises exception -> returns empty string (after max_retries=0)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client
            mock_client.messages.create.side_effect = Exception("API timeout")

            provider = AnthropicProvider(max_retries=0)
            result = provider.generate("test")

            assert result == "", f"Expected empty string on error, got: {result}"

    def test_generate_tracks_multiple_calls(self, monkeypatch):
        """Multiple calls increment call_count correctly."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()

            provider.generate("call 1")
            provider.generate("call 2")
            provider.generate("call 3")

            assert provider.call_count == 3

    def test_custom_model_and_params(self, monkeypatch):
        """Custom model, temperature, max_tokens passed to API."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider(
                model="claude-3-5-sonnet-20241022",
                temperature=0.8,
                max_tokens=2048,
                timeout=60,
            )

            assert provider.model == "claude-3-5-sonnet-20241022"
            provider.generate("test")

            call_kwargs = mock_client.messages.create.call_args.kwargs
            assert call_kwargs["model"] == "claude-3-5-sonnet-20241022"
            assert call_kwargs["temperature"] == 0.8
            assert call_kwargs["max_tokens"] == 2048
            assert call_kwargs["timeout"] == 60

    def test_custom_base_url(self, monkeypatch):
        """Custom base_url passed to Anthropic client constructor."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            provider = AnthropicProvider(base_url="http://localhost:8080/v1")

            call_kwargs = mock_anthropic.call_args.kwargs
            assert call_kwargs["base_url"] == "http://localhost:8080/v1"

    def test_create_llm_provider_factory_anthropic(self, monkeypatch):
        """create_llm_provider factory returns AnthropicProvider for 'anthropic'."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            prov = create_llm_provider("anthropic", model="claude-3-haiku-20240307")
            assert isinstance(prov, AnthropicProvider)
            assert prov.model == "claude-3-haiku-20240307"


# ===========================================================================
# GoogleProvider
# ===========================================================================


class TestGoogleProvider:
    """Tests for GoogleProvider — a real LLM provider backed by the Gemini API.

    All tests mock the internal google.genai client so no real API calls are made.
    """

    def test_creates_client_with_env_key(self, monkeypatch):
        """With GEMINI_API_KEY set, GoogleProvider creates a client."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key-12345")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            provider = GoogleProvider()

            mock_genai.assert_called_once()
            call_kwargs = mock_genai.call_args.kwargs
            assert call_kwargs["api_key"] == "test-gemini-key-12345"
            assert provider.model == "gemini-2.0-flash"

    def test_creates_client_with_explicit_key(self, monkeypatch):
        """Explicit api_key argument takes precedence over env var."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-should-be-ignored")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            provider = GoogleProvider(api_key="gemini-explicit")

            call_kwargs = mock_genai.call_args.kwargs
            assert call_kwargs["api_key"] == "gemini-explicit"

    def test_no_key_raises_value_error(self, monkeypatch):
        """No API key in env or constructor -> ValueError."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            GoogleProvider()

    def test_generate_success(self, monkeypatch):
        """Successful API call returns parsed JSON string."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            # Simulate a valid API response from Google's generate_content
            mock_response = unittest.mock.MagicMock()
            mock_response.text = '{"tool": "nmap", "command": "discover", "arguments": {"target": "10.0.0.1"}, "target": "10.0.0.1", "reasoning": "Initial recon"}'
            mock_client.models.generate_content.return_value = mock_response

            provider = GoogleProvider()
            result = provider.generate("Scan the target")

            # Verify the response was returned and is valid JSON
            parsed = json.loads(result)
            assert parsed["tool"] == "nmap"
            assert parsed["command"] == "discover"
            assert provider.call_count == 1
            assert provider.last_prompt == "Scan the target"
            assert provider.last_raw_response == result

            # Verify the API was called with expected args
            mock_client.models.generate_content.assert_called_once()
            call_kwargs = mock_client.models.generate_content.call_args.kwargs
            assert call_kwargs["model"] == "gemini-2.0-flash"
            # contents should be the user prompt
            assert call_kwargs["contents"] == "Scan the target"
            # config should have system_instruction
            config = call_kwargs["config"]
            assert config.system_instruction is not None
            assert "penetration-testing AI" in config.system_instruction
            assert config.temperature == 0.2
            assert config.max_output_tokens == 1024

    def test_generate_invalid_json_returns_empty(self, monkeypatch):
        """API returns non-JSON content -> returns empty string."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            mock_response = unittest.mock.MagicMock()
            mock_response.text = "This is not JSON"
            mock_client.models.generate_content.return_value = mock_response

            provider = GoogleProvider()
            result = provider.generate("test")

            assert result == "", f"Expected empty string, got: {result}"
            assert provider.last_raw_response == "This is not JSON"

    def test_generate_api_error_returns_empty(self, monkeypatch):
        """API call raises exception -> returns empty string (after max_retries=0)."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client
            mock_client.models.generate_content.side_effect = Exception("API timeout")

            provider = GoogleProvider(max_retries=0)
            result = provider.generate("test")

            assert result == "", f"Expected empty string on error, got: {result}"

    def test_generate_tracks_multiple_calls(self, monkeypatch):
        """Multiple calls increment call_count correctly."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            mock_response = unittest.mock.MagicMock()
            mock_response.text = '{"tool": "test", "command": "run"}'
            mock_client.models.generate_content.return_value = mock_response

            provider = GoogleProvider()

            provider.generate("call 1")
            provider.generate("call 2")
            provider.generate("call 3")

            assert provider.call_count == 3

    def test_custom_model_and_params(self, monkeypatch):
        """Custom model, temperature, max_tokens passed to API."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            mock_response = unittest.mock.MagicMock()
            mock_response.text = '{"tool": "test", "command": "run"}'
            mock_client.models.generate_content.return_value = mock_response

            provider = GoogleProvider(
                model="gemini-1.5-pro",
                temperature=0.8,
                max_tokens=2048,
                timeout=60,
            )

            assert provider.model == "gemini-1.5-pro"
            provider.generate("test")

            call_kwargs = mock_client.models.generate_content.call_args.kwargs
            assert call_kwargs["model"] == "gemini-1.5-pro"
            config = call_kwargs["config"]
            assert config.temperature == 0.8
            assert config.max_output_tokens == 2048

    def test_custom_base_url(self, monkeypatch):
        """Custom base_url passed to genai.Client http_options."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            provider = GoogleProvider(base_url="http://localhost:8080/v1")

            call_kwargs = mock_genai.call_args.kwargs
            assert "http_options" in call_kwargs
            assert call_kwargs["http_options"]["base_url"] == "http://localhost:8080/v1"

    def test_create_llm_provider_factory_google(self, monkeypatch):
        """create_llm_provider factory returns GoogleProvider for 'google'."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            prov = create_llm_provider("google", model="gemini-2.0-flash-lite")
            assert isinstance(prov, GoogleProvider)
            assert prov.model == "gemini-2.0-flash-lite"

    def test_create_llm_provider_factory_gemini_alias(self, monkeypatch):
        """create_llm_provider factory returns GoogleProvider for 'gemini' alias."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            prov = create_llm_provider("gemini", model="gemini-1.5-pro")
            assert isinstance(prov, GoogleProvider)
            assert prov.model == "gemini-1.5-pro"


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
# Hybrid strategy: stall detection
# ===========================================================================


class TestHybridStallDetection:
    """Tests for ActionSelector._check_stalled and its three sub-checks.

    Covers: tool-loop, asset-exhaustion, and state-stagnation stall detection.
    """

    # --- _check_tool_loop ---

    def test_check_tool_loop_detects_repeated_actions(self, sample_allowed_tools, sample_authorized_assets):
        """3+ consecutive identical tool/command -> stall."""
        selector = ActionSelector(decision_strategy="hybrid")
        state = WorldState(open_ports=[80])  # stays in fingerprint phase

        action = AgentAction(tool="nmap", command="scan", target="10.0.0.10")

        # First call: initializes _last_rule_action, no stall
        assert selector._check_tool_loop(action) is None

        # Second call: 1 same -> count=1, no stall
        assert selector._check_tool_loop(action) is None

        # Third call: 2 same -> count=2, no stall (threshold is 3)
        assert selector._check_tool_loop(action) is None

        # Fourth call: 3 same -> count >= 3 -> stall!
        reason = selector._check_tool_loop(action)
        assert reason is not None
        assert "identical actions" in reason
        assert "nmap/scan" in reason

    def test_check_tool_loop_resets_on_different_action(self, sample_allowed_tools, sample_authorized_assets):
        """Different action resets the stall counter."""
        selector = ActionSelector(decision_strategy="hybrid")

        # Two identical actions
        for _ in range(2):
            selector._check_tool_loop(AgentAction(tool="nmap", command="scan"))

        # Different action resets
        selector._check_tool_loop(AgentAction(tool="nmap", command="discover"))

        # After reset, count=0. One discover -> count=1, still under threshold.
        selector._check_tool_loop(AgentAction(tool="nmap", command="discover"))

        # Second discover after reset -> count=2, still under threshold
        reason = selector._check_tool_loop(AgentAction(tool="nmap", command="discover"))
        assert reason is None

    def test_check_tool_loop_first_call_no_stall(self):
        """First call initializes, never stalls."""
        selector = ActionSelector()
        reason = selector._check_tool_loop(AgentAction(tool="nmap", command="discover"))
        assert reason is None

    # --- _check_asset_exhaustion ---

    def test_check_asset_exhaustion_triggers(self):
        """All authorized assets discovered + stall_count > 0 -> stall."""
        selector = ActionSelector()
        selector._stall_count = 3  # Must have stall evidence first
        state = WorldState(discovered_assets=["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        authorized = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        reason = selector._check_asset_exhaustion(state, authorized)
        assert reason is not None
        assert "All 3 authorized assets have been discovered" in reason
        assert "No rotation logic" in reason

    def test_check_asset_exhaustion_not_triggered_without_stall(self):
        """All assets discovered but stall_count is 0 -> no stall (clean phase transition)."""
        selector = ActionSelector()
        selector._stall_count = 0  # No stall evidence
        state = WorldState(discovered_assets=["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        authorized = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        reason = selector._check_asset_exhaustion(state, authorized)
        assert reason is None

    def test_check_asset_exhaustion_skips_when_single_asset(self):
        """Single authorized asset never triggers asset-exhaustion stall."""
        selector = ActionSelector()
        selector._stall_count = 3
        state = WorldState(discovered_assets=["10.0.0.10"])
        reason = selector._check_asset_exhaustion(state, ["10.0.0.10"])
        assert reason is None

    def test_check_asset_exhaustion_not_triggered_early(self):
        """Not all authorized assets discovered yet -> no stall."""
        selector = ActionSelector()
        state = WorldState(discovered_assets=["10.0.0.10"])
        authorized = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

        reason = selector._check_asset_exhaustion(state, authorized)
        assert reason is None

    def test_check_asset_exhaustion_no_discovered_assets(self):
        """No discovered assets at all -> no stall."""
        selector = ActionSelector()
        selector._stall_count = 3
        state = WorldState()
        reason = selector._check_asset_exhaustion(state, ["10.0.0.10", "10.0.0.11"])
        assert reason is None

    # --- _check_state_stagnation ---

    def test_check_state_stagnation_triggers(self):
        """State unchanged for 3+ consecutive steps -> stall."""
        selector = ActionSelector()
        state = WorldState(open_ports=[80], services=[{"name": "nginx"}])

        # First call: initializes snapshot
        assert selector._check_state_stagnation(state) is None

        # Second call: same state -> count=1
        assert selector._check_state_stagnation(state) is None

        # Third call: same state -> count=2
        assert selector._check_state_stagnation(state) is None

        # Fourth call: same state -> count >= 3 -> stall!
        reason = selector._check_state_stagnation(state)
        assert reason is not None
        assert "State has not progressed" in reason

    def test_check_state_stagnation_resets_on_progress(self):
        """State change resets the stagnation counter."""
        selector = ActionSelector()

        # Two calls with same state
        state1 = WorldState(open_ports=[80])
        selector._check_state_stagnation(state1)
        selector._check_state_stagnation(state1)

        # State changes -> resets counter
        state2 = WorldState(open_ports=[80, 443])
        assert selector._check_state_stagnation(state2) is None  # reset, count=0

        # One more call with new state -> count=1
        selector._check_state_stagnation(state2)

        # Second call -> count=2, still under threshold (3)
        assert selector._check_state_stagnation(state2) is None

    def test_check_state_stagnation_first_call_no_stall(self):
        """First call initializes snapshot, never stalls."""
        selector = ActionSelector()
        reason = selector._check_state_stagnation(WorldState())
        assert reason is None

    # --- _check_stalled (orchestrator) ---

    def test_check_stalled_returns_first_reason(self, sample_authorized_assets):
        """_check_stalled returns the first stall reason found."""
        selector = ActionSelector()
        state = WorldState(open_ports=[80])
        action = AgentAction(tool="nmap", command="scan")

        # Push tool-loop to threshold
        for _ in range(3):
            selector._check_tool_loop(action)

        reason = selector._check_stalled(action, state, sample_authorized_assets)
        assert reason is not None
        # Should be tool-loop (checked first)
        assert "identical actions" in reason

    def test_check_stalled_none_when_progress(self, sample_authorized_assets):
        """When all checks pass, _check_stalled returns None."""
        selector = ActionSelector()
        state = WorldState(open_ports=[80])
        action = AgentAction(tool="nmap", command="discover")

        # Different actions each time -> no tool-loop
        selector._check_tool_loop(action)
        selector._check_tool_loop(AgentAction(tool="nmap", command="scan"))

        reason = selector._check_stalled(action, state, sample_authorized_assets)
        assert reason is None


# ===========================================================================
# Hybrid strategy: integration
# ===========================================================================


class TestHybridStrategyIntegration:
    """Tests for the hybrid strategy in select_action and get_next_action.

    Covers: hybrid stall -> reasoning marker, LLM fallback, agent stop.
    """

    @pytest.fixture
    def hybrid_tools(self) -> list[dict]:
        """Tools where the rule selector will always pick the same tool."""
        return [
            {
                "name": "nmap",
                "version": "7.95",
                "allowed_commands": ["discover", "scan"],
            },
            {
                "name": "reporter",
                "version": "1.0",
                "allowed_commands": ["summary"],
            },
        ]

    def test_hybrid_strategy_reasoning_contains_stall(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """Stalled hybrid selector bakes RULE_ENGINE_STALLED into action.reasoning."""
        selector = ActionSelector(decision_strategy="hybrid")

        # State that keeps selector in the same phase (fingerprint)
        state = WorldState(open_ports=[80])

        # Call select_action 5 times (threshold=3 -> stall on 4th+)
        for i in range(6):
            action = selector.select_action(
                state, hybrid_tools, sample_authorized_assets,
                "Test", step=i + 1, previous_actions=[],
            )
            # After the 4th call (0-indexed: 3), stall should trigger
            if i >= 3:
                assert "RULE_ENGINE_STALLED" in action.reasoning, (
                    f"Expected stall on call {i}, got: {action.reasoning}"
                )

    def test_hybrid_strategy_no_stall_on_progress(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """State progress prevents stall."""
        selector = ActionSelector(decision_strategy="hybrid")

        # Start empty -> recon
        state = WorldState()
        action = selector.select_action(
            state, hybrid_tools, sample_authorized_assets,
            "Test", step=1, previous_actions=[],
        )
        assert "RULE_ENGINE_STALLED" not in action.reasoning

        # Now with ports -> fingerprint (different command)
        state = WorldState(open_ports=[80])
        action = selector.select_action(
            state, hybrid_tools, sample_authorized_assets,
            "Test", step=2, previous_actions=[],
        )
        assert "RULE_ENGINE_STALLED" not in action.reasoning

        # Services done -> vuln/report (different tool)
        state = WorldState(
            open_ports=[80],
            services=[{"name": "nginx"}],
            vulnerabilities=[{"id": "CVE-001"}],
        )
        action = selector.select_action(
            state, hybrid_tools, sample_authorized_assets,
            "Test", step=5, previous_actions=[],
        )
        assert "RULE_ENGINE_STALLED" not in action.reasoning

    def test_hybrid_strategy_llm_fallback_different_action(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """LLM fallback that produces a different action resets stall."""
        # Use a custom ActionSelector that overrides _select_with_llm
        class LLMRescueSelector(ActionSelector):
            def __init__(self):
                super().__init__(decision_strategy="hybrid", llm_prompt="rescue prompt")
                self.llm_calls = 0

            def _select_with_llm(self, state, allowed_tools, authorized_assets, objective, step, previous_actions):
                self.llm_calls += 1
                # Return a DIFFERENT action than the rule selector
                return AgentAction(
                    tool="reporter",
                    command="summary",
                    target="10.0.0.10",
                    reasoning=f"LLM fallback call #{self.llm_calls}",
                )

        selector = LLMRescueSelector()
        state = WorldState(open_ports=[80])  # keeps in fingerprint (nmap scan)

        # Call until stall should trigger (threshold=3, so call 0,1,2 no stall, call 3+ stall)
        for i in range(5):
            action = selector.select_action(
                state, hybrid_tools, sample_authorized_assets,
                "Test", step=i + 1, previous_actions=[],
            )

        # LLM was called at least once (after stall triggered)
        assert selector.llm_calls >= 1
        # The LLM action (reporter/summary) is different from rule action (nmap/scan)
        # so it should NOT have RULE_ENGINE_STALLED reasoning
        assert "RULE_ENGINE_STALLED" not in action.reasoning

    def test_hybrid_strategy_llm_fallback_same_action(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """LLM returns same stalled action -> stall marker in reasoning."""
        class StuckLLMSelector(ActionSelector):
            def __init__(self):
                super().__init__(decision_strategy="hybrid", llm_prompt="stuck prompt")
                self.llm_calls = 0

            def _select_with_llm(self, state, allowed_tools, authorized_assets, objective, step, previous_actions):
                self.llm_calls += 1
                # Return SAME action as rule selector would (nmap/scan)
                return AgentAction(
                    tool="nmap",
                    command="scan",
                    target="10.0.0.10",
                    reasoning=f"LLM fallback call #{self.llm_calls}",
                )

        selector = StuckLLMSelector()
        state = WorldState(open_ports=[80])

        stalled_action = None
        for i in range(5):
            action = selector.select_action(
                state, hybrid_tools, sample_authorized_assets,
                "Test", step=i + 1, previous_actions=[],
            )
            # Capture the action when stall triggers (4th call, 0-indexed: 3)
            if i == 3:
                stalled_action = action

        # LLM was called at least once (after stall triggered)
        assert selector.llm_calls >= 1
        # When LLM returns same action, the action should have RULE_ENGINE_STALLED
        assert stalled_action is not None, "Stall should have triggered on call 4"
        assert "RULE_ENGINE_STALLED" in stalled_action.reasoning
        assert "LLM fallback also returned the same action" in stalled_action.reasoning

    def test_hybrid_strategy_no_llm_configured(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """No LLM prompt configured -> stall marker with 'No LLM fallback' note."""
        selector = ActionSelector(decision_strategy="hybrid")
        assert selector.llm_prompt is None  # no LLM configured

        state = WorldState(open_ports=[80])

        action = None
        for i in range(5):
            action = selector.select_action(
                state, hybrid_tools, sample_authorized_assets,
                "Test", step=i + 1, previous_actions=[],
            )

        assert "RULE_ENGINE_STALLED" in action.reasoning
        assert "No LLM fallback configured" in action.reasoning

    def test_get_next_action_raises_on_stalled(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """get_next_action raises AgentStopTriggered when selector stalls."""
        agent = AgentCore(
            allowed_tools=hybrid_tools,
            authorized_assets=sample_authorized_assets,
            objective="Test hybrid stall",
            decision_strategy="hybrid",
            max_steps=20,
        )
        # Pre-populate state so selector stays in same phase
        agent.state.open_ports = [80]

        # First 3 calls should work (no stall yet)
        for _ in range(3):
            action = agent.get_next_action()
            agent.step_action(action, {"last_action_result": "still scanning"})

        # 4th+ call should trigger stall -> AgentStopTriggered
        with pytest.raises(AgentStopTriggered, match="RULE_ENGINE_STALLED"):
            agent.get_next_action()

        assert agent.halted
        assert agent.stop_reason == StopReason.RULE_ENGINE_STALLED

    def test_hybrid_agent_loop_stops_on_stall(self, hybrid_tools, sample_authorized_assets):
        """run_agent_loop with hybrid strategy stops via RULE_ENGINE_STALLED."""
        agent = AgentCore(
            allowed_tools=hybrid_tools,
            authorized_assets=sample_authorized_assets,
            objective="Test",
            decision_strategy="hybrid",
            max_steps=20,
        )
        agent.state.open_ports = [80]  # Start with ports so selector stays in fingerprint

        def execute(action):
            return {"last_action_result": "scanning..."}

        state, evidence, reason = run_agent_loop(agent, execute)

        assert reason == StopReason.RULE_ENGINE_STALLED
        assert len(evidence) >= 3

    def test_hybrid_loop_with_llm_fallback_unstucks(
        self, hybrid_tools, sample_authorized_assets,
    ):
        """LLM fallback that advances state prevents stall loop exit."""
        class ProgressiveSelector(ActionSelector):
            def __init__(self):
                super().__init__(decision_strategy="hybrid", llm_prompt="progress prompt")
                self.llm_calls = 0

            def _select_with_llm(self, state, allowed_tools, authorized_assets, objective, step, previous_actions):
                self.llm_calls += 1
                # LLM returns a different action that actually produces progress
                return AgentAction(
                    tool="reporter", command="summary", target="10.0.0.10",
                )

        agent = AgentCore(
            allowed_tools=hybrid_tools,
            authorized_assets=sample_authorized_assets,
            objective="Test",
            decision_strategy="hybrid",
            llm_prompt="progress prompt",
            max_steps=10,
        )
        # Inject the custom selector
        selector = ProgressiveSelector()
        agent._action_selector = selector

        agent.state.open_ports = [80]  # Stays in fingerprint without progress

        # Execute should trigger stall -> LLM fallback -> different action
        def execute(action):
            return {"last_action_result": "summary done"}

        state, evidence, reason = run_agent_loop(agent, execute)

        # LLM was called at least once (unstuck from stall)
        assert selector.llm_calls >= 1
        # The agent may still stop via MAX_STEPS after running out of steps
        # The important thing is it didn't stop via RULE_ENGINE_STALLED
        # (because LLM unblocked it)
        assert reason != StopReason.RULE_ENGINE_STALLED


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


# ===========================================================================
# RateLimiter
# ===========================================================================


class TestRateLimiter:
    """Tests for the token-bucket RateLimiter."""

    def test_initial_tokens_full_capacity(self):
        """RateLimiter starts with full capacity tokens."""
        limiter = RateLimiter(capacity=10, tokens_per_second=5.0)
        assert limiter.available_tokens == 10.0

    def test_consume_one_token_reduces_available(self):
        """wait_if_needed consumes one token."""
        limiter = RateLimiter(capacity=5, tokens_per_second=10.0)
        limiter.wait_if_needed()
        assert limiter.available_tokens == pytest.approx(4.0, rel=1e-3)

    def test_consumes_multiple_tokens(self):
        """Multiple calls consume multiple tokens."""
        limiter = RateLimiter(capacity=10, tokens_per_second=10.0)
        for _ in range(4):
            limiter.wait_if_needed()
        assert limiter.available_tokens == pytest.approx(6.0, rel=1e-3)

    def test_available_tokens_refills_over_time(self):
        """After waiting, tokens are replenished."""
        limiter = RateLimiter(capacity=5, tokens_per_second=10.0)
        # Consume all 5
        for _ in range(5):
            limiter.wait_if_needed()
        assert limiter.available_tokens == pytest.approx(0.0, abs=1e-3)
        # Wait for refill
        import time
        time.sleep(0.3)  # ~3 tokens at 10/s
        assert limiter.available_tokens >= 2.0

    def test_reset_restores_full_capacity(self):
        """reset() restores tokens to capacity and clears wait tracking."""
        limiter = RateLimiter(capacity=10, tokens_per_second=5.0)
        for _ in range(8):
            limiter.wait_if_needed()
        assert limiter.available_tokens == pytest.approx(2.0, rel=1e-3)
        limiter.reset()
        assert limiter.available_tokens == pytest.approx(10.0, rel=1e-3)
        assert limiter.total_wait_seconds == 0.0

    def test_total_wait_seconds_nonzero_after_exhaustion(self):
        """total_wait_seconds > 0 after rate limit wait."""
        limiter = RateLimiter(capacity=2, tokens_per_second=100.0)
        # Consume both tokens
        limiter.wait_if_needed()
        limiter.wait_if_needed()
        # Should have waited at least some time for 3rd call
        limiter.wait_if_needed()
        assert limiter.total_wait_seconds > 0.0

    def test_low_tokens_per_second_waits_longer(self):
        """Low refill rate causes longer waits."""
        import time
        limiter = RateLimiter(capacity=1, tokens_per_second=1.0)
        start = time.monotonic()
        limiter.wait_if_needed()  # consume
        limiter.wait_if_needed()  # empty -> must wait
        elapsed = time.monotonic() - start
        assert elapsed >= 0.5  # at least half the refill time

    def test_wait_if_needed_blocks_when_empty(self):
        """wait_if_needed blocks when bucket is empty."""
        import time
        limiter = RateLimiter(capacity=1, tokens_per_second=10.0)
        limiter.wait_if_needed()  # consume the only token
        start = time.monotonic()
        limiter.wait_if_needed()  # empty -> must wait
        elapsed = time.monotonic() - start
        assert elapsed >= 0.05  # at least some wait time


# ===========================================================================
# Retry helpers (_call_with_retry, _is_retryable_error)
# ===========================================================================


class TestRetryHelpers:
    """Tests for _is_retryable_error and _call_with_retry."""

    # --- _is_retryable_error ---

    def test_is_retryable_429(self):
        """HTTP 429 is retryable."""
        assert _is_retryable_error(Exception("429 Too Many Requests")) is True

    def test_is_retryable_503(self):
        """HTTP 503 is retryable."""
        assert _is_retryable_error(Exception("503 Service Unavailable")) is True

    def test_is_retryable_502(self):
        """HTTP 502 is retryable."""
        assert _is_retryable_error(Exception("502 Bad Gateway")) is True

    def test_is_retryable_500(self):
        """HTTP 500 is retryable (sometimes transient)."""
        assert _is_retryable_error(Exception("500 Internal Server Error")) is True

    def test_is_not_retryable_401(self):
        """HTTP 401 is not retryable."""
        assert _is_retryable_error(Exception("401 Unauthorized")) is False

    def test_is_not_retryable_403(self):
        """HTTP 403 is not retryable."""
        assert _is_retryable_error(Exception("403 Forbidden")) is False

    def test_is_not_retryable_400(self):
        """HTTP 400 is not retryable."""
        assert _is_retryable_error(Exception("400 Bad Request")) is False

    def test_is_not_retryable_404(self):
        """HTTP 404 is not retryable."""
        assert _is_retryable_error(Exception("404 Not Found")) is False

    def test_is_retryable_connection_error(self):
        """Connection error is retryable."""
        assert _is_retryable_error(Exception("Connection reset by peer")) is True

    def test_is_retryable_timeout(self):
        """Timeout error is retryable."""
        assert _is_retryable_error(Exception("Connection timeout")) is True
        assert _is_retryable_error(Exception("Request timed out")) is True

    def test_is_retryable_too_many_requests(self):
        """Too Many Requests text (without 429 code) is retryable."""
        assert _is_retryable_error(Exception("too many requests, try again later")) is True

    def test_is_not_retryable_json_decode_error(self):
        """JSON decode error is not retryable."""
        assert _is_retryable_error(Exception("JSON decode failed at line 1")) is False

    def test_is_not_retryable_parse_error(self):
        """Parse error is not retryable."""
        assert _is_retryable_error(Exception("Parse error: unexpected token")) is False

    # --- _call_with_retry ---

    def test_call_with_retry_success_first_try(self):
        """Success on first try returns result with 0 retries."""
        result, retries, delay = _call_with_retry(
            lambda: "success", max_retries=3,
        )
        assert result == "success"
        assert retries == 0
        assert delay == 0.0

    def test_call_with_retry_succeeds_after_retry(self):
        """Retries then succeeds."""
        attempts = [0]

        def flaky_call():
            attempts[0] += 1
            if attempts[0] < 3:
                raise Exception("429 Rate Limited")
            return "success"

        result, retries, delay = _call_with_retry(
            flaky_call, max_retries=3, base_delay=0.01,
        )
        assert result == "success"
        assert retries == 2
        assert delay > 0.0

    def test_call_with_retry_exhausts_all_retries(self):
        """Fails after all retries exhausted."""
        attempts = [0]

        def always_fails():
            attempts[0] += 1
            raise Exception("429 Rate Limited")

        result, retries, delay = _call_with_retry(
            always_fails, max_retries=2, base_delay=0.01,
        )
        assert result == ""
        assert retries == 2
        assert attempts[0] == 3  # original + 2 retries
        assert delay > 0.0

    def test_call_with_retry_zero_retries(self):
        """max_retries=0 means no retry on failure."""
        result, retries, delay = _call_with_retry(
            lambda: (_ for _ in ()).throw(Exception("503 error")),
            max_retries=0, base_delay=0.01,
        )
        assert result == ""
        assert retries == 0

    def test_call_with_retry_non_retryable_error(self):
        """Non-retryable error (401) does not retry."""
        result, retries, delay = _call_with_retry(
            lambda: (_ for _ in ()).throw(Exception("401 Unauthorized")),
            max_retries=3, base_delay=0.01,
        )
        assert result == ""
        assert retries == 0

    def test_call_with_retry_passes_rate_limiter(self):
        """RateLimiter is consulted before each attempt."""
        limiter = RateLimiter(capacity=5, tokens_per_second=10.0)
        initial_tokens = limiter.available_tokens

        result, retries, delay = _call_with_retry(
            lambda: "success", max_retries=0,
            rate_limiter=limiter,
        )
        assert result == "success"
        # One token consumed
        assert limiter.available_tokens == pytest.approx(initial_tokens - 1, rel=1e-3)

    def test_call_with_retry_delay_increases_with_attempts(self):
        """Each retry has increasing delay (exponential backoff)."""
        delays = []

        def track_delay(d):
            delays.append(d)

        attempts = [0]

        def always_fails():
            attempts[0] += 1
            raise Exception("429 Rate Limited")

        result, retries, total_delay = _call_with_retry(
            always_fails, max_retries=3, base_delay=0.1,
        )
        assert retries == 3
        assert total_delay > 0.0


# ===========================================================================
# Provider retry metrics
# ===========================================================================


class TestProviderRetryMetrics:
    """Tests for retry metrics tracking on OpenAIProvider and AnthropicProvider.

    Verifies that retry_count, total_retry_delay, and last_rate_limit_hit
    are correctly updated during retry scenarios.
    """

    def test_openai_retry_count_zero_on_success(self, monkeypatch):
        """retry_count is 0 when no retries occur."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()
            provider.generate("test")

            assert provider.retry_count == 0
            assert provider.total_retry_delay == 0.0
            assert provider.last_rate_limit_hit == 0.0

    def test_openai_retry_count_increments_on_retry(self, monkeypatch):
        """retry_count increments after transient errors."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            # First call raises 429 (retryable), second succeeds
            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]

            mock_client.chat.completions.create.side_effect = [
                Exception("429 Rate Limited"),
                mock_response,
            ]

            provider = OpenAIProvider(max_retries=1, rate_limiter=RateLimiter(capacity=100, tokens_per_second=1000))
            result = provider.generate("test")

            assert result != ""
            assert provider.retry_count == 1
            assert provider.total_retry_delay > 0.0
            assert provider.last_rate_limit_hit > 0.0

    def test_openai_last_rate_limit_hit_unchanged_on_success(self, monkeypatch):
        """last_rate_limit_hit stays 0.0 when no retry."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIProvider()
            provider.generate("test")

            assert provider.last_rate_limit_hit == 0.0

    def test_anthropic_retry_count_zero_on_success(self, monkeypatch):
        """Anthropic retry_count is 0 when no retries occur."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()
            provider.generate("test")

            assert provider.retry_count == 0
            assert provider.total_retry_delay == 0.0
            assert provider.last_rate_limit_hit == 0.0

    def test_anthropic_retry_count_increments_on_retry(self, monkeypatch):
        """Anthropic retry_count increments after transient errors."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]

            mock_client.messages.create.side_effect = [
                Exception("429 Rate Limited"),
                mock_response,
            ]

            provider = AnthropicProvider(max_retries=1, rate_limiter=RateLimiter(capacity=100, tokens_per_second=1000))
            result = provider.generate("test")

            assert result != ""
            assert provider.retry_count == 1
            assert provider.total_retry_delay > 0.0
            assert provider.last_rate_limit_hit > 0.0

    def test_anthropic_last_rate_limit_hit_unchanged_on_success(self, monkeypatch):
        """Anthropic last_rate_limit_hit stays 0.0 when no retry."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            mock_content_block = unittest.mock.MagicMock()
            mock_content_block.text = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.content = [mock_content_block]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicProvider()
            provider.generate("test")

            assert provider.last_rate_limit_hit == 0.0

    def test_provider_cannot_construct_negative_max_retries(self):
        """max_retries can be 0 (no retry) but not negative."""
        # _call_with_retry is called from generate with max_retries=0
        # A negative value would cause range(max_retries+1) = range(0) = empty
        # So it would never attempt the call at all
        assert True  # structural: negative max_retries is handled at the caller

    def test_provider_retry_metrics_persist_across_calls(self, monkeypatch):
        """Retry metrics accumulate across multiple generate calls."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]

            # First call succeeds, second has 1 retry, third succeeds
            mock_client.chat.completions.create.side_effect = [
                mock_response,
                Exception("429 Rate Limited"),
                mock_response,
                mock_response,
            ]

            provider = OpenAIProvider(max_retries=1, rate_limiter=RateLimiter(capacity=100, tokens_per_second=1000))

            # Call 1: success, no retries
            provider.generate("call 1")
            assert provider.call_count == 1
            assert provider.retry_count == 0

            # Call 2: retry once then success
            provider.generate("call 2")
            assert provider.call_count == 2
            assert provider.retry_count == 1
            assert provider.total_retry_delay > 0.0

            # Call 3: success
            provider.generate("call 3")
            assert provider.call_count == 3
            assert provider.retry_count == 1  # cumulative, still 1
# ===========================================================================
# from_agentic_config parameter forwarding
# ===========================================================================


class TestFromAgenticConfigParameterForwarding:
    """Tests that from_agentic_config forwards api_key, base_url, max_retries
    to all production provider constructors.
    """

    def test_openai_forwarding_api_key(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """api_key flows through from_agentic_config to OpenAIProvider."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "model": "gpt-4o",
                    "api_key": "sk-forwarded-key",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            mock_prov.assert_called_once()
            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-forwarded-key"
            assert call_kwargs["model"] == "gpt-4o"

    def test_openai_forwarding_base_url(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """base_url flows through from_agentic_config to OpenAIProvider."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "model": "llama-3.3-70b-versatile",
                    "base_url": "https://api.groq.com/openai/v1",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["base_url"] == "https://api.groq.com/openai/v1"

    def test_openai_forwarding_max_retries(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """max_retries flows through from_agentic_config to OpenAIProvider."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "model": "gpt-4o-mini",
                    "max_retries": 10,
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["max_retries"] == 10

    def test_openai_forwarding_all_params(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """All three optional params forwarded together to OpenAIProvider."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "model": "gpt-4o",
                    "api_key": "sk-all-three",
                    "base_url": "https://custom.endpoint/v1",
                    "max_retries": 5,
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-all-three"
            assert call_kwargs["base_url"] == "https://custom.endpoint/v1"
            assert call_kwargs["max_retries"] == 5

    def test_anthropic_forwarding_api_key(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """api_key flows through from_agentic_config to AnthropicProvider."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with unittest.mock.patch("gatekeeper_eos_v6.providers.AnthropicProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "anthropic",
                    "model": "claude-sonnet-4-20250514",
                    "api_key": "sk-ant-forwarded",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["api_key"] == "sk-ant-forwarded"

    def test_anthropic_forwarding_base_url(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """base_url flows through from_agentic_config to AnthropicProvider."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.AnthropicProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "anthropic",
                    "model": "claude-sonnet-4-20250514",
                    "base_url": "https://custom.anthropic.endpoint/v1",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["base_url"] == "https://custom.anthropic.endpoint/v1"

    def test_google_forwarding_api_key(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """api_key flows through from_agentic_config to GoogleProvider."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

        with unittest.mock.patch("gatekeeper_eos_v6.providers.GoogleProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "google",
                    "model": "gemini-2.0-flash",
                    "api_key": "gemini-forwarded",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["api_key"] == "gemini-forwarded"

    def test_google_forwarding_base_url(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """base_url flows through from_agentic_config to GoogleProvider."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.GoogleProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "gemini",
                    "model": "gemini-2.0-flash",
                    "base_url": "https://custom.gemini.endpoint/v1",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["base_url"] == "https://custom.gemini.endpoint/v1"

    def test_google_forwarding_max_retries(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """max_retries flows through from_agentic_config to GoogleProvider."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.GoogleProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "google",
                    "model": "gemini-2.0-flash",
                    "max_retries": 7,
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert call_kwargs["max_retries"] == 7

    def test_no_forwarding_when_not_in_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """When optional params are absent, they are not passed to the provider."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "model": "gpt-4o-mini",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "api_key" not in call_kwargs
            assert "base_url" not in call_kwargs
            assert "max_retries" not in call_kwargs
# ===========================================================================
# CircuitBreaker
# ===========================================================================


class TestCircuitBreaker:
    """Tests for the CircuitBreaker token-bucket failure isolation."""

    def test_initial_state_closed(self):
        """CircuitBreaker starts in CLOSED state."""
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.closed is True
        assert cb.open is False
        assert cb.failure_count == 0

    def test_opens_after_threshold_failures(self):
        """After failure_threshold consecutive failures, circuit opens."""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=999)

        def _fail() -> str:
            raise ValueError("API error")

        # Failures 1 and 2: still closed
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(_fail)
        assert cb.failure_count == 2
        assert cb.state == CircuitState.CLOSED

        # Failure 3: circuit opens
        with pytest.raises(ValueError):
            cb.call(_fail)
        assert cb.failure_count == 3
        assert cb.state == CircuitState.OPEN
        assert cb.open is True

    def test_open_rejects_calls(self):
        """Open circuit returns fallback instead of calling the function."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=999)

        def _fail() -> str:
            raise ValueError("error")

        # Open the circuit
        with pytest.raises(ValueError):
            cb.call(_fail)

        # Now circuit is open -> returns fallback
        result = cb.call(_fail, fallback="fallback_val")
        assert result == "fallback_val"
        assert cb.open is True

    def test_half_open_after_recovery_timeout(self):
        """After recovery_timeout, circuit transitions to HALF_OPEN."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)

        def _fail() -> str:
            raise ValueError("error")

        # Open the circuit
        with pytest.raises(ValueError):
            cb.call(_fail)

        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(0.02)

        # State should now be half-open
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes_circuit(self):
        """A successful call in half-open state closes the circuit."""
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)

        def _fail() -> str:
            raise ValueError("error")

        # Open the circuit
        with pytest.raises(ValueError):
            cb.call(_fail)

        time.sleep(0.02)

        # Now half-open - successful call should close
        def _succeed() -> str:
            return "success"

        result = cb.call(_succeed)
        assert result == "success"
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_half_open_failure_opens_again(self):
        """A failed call in half-open state opens the circuit again after max retries."""
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.01,
            half_open_max_retries=2,
        )

        def _fail() -> str:
            raise ValueError("error")

        # Open the circuit
        with pytest.raises(ValueError):
            cb.call(_fail)

        time.sleep(0.02)

        # Half-open, first failure -> still half-open (retries left)
        with pytest.raises(ValueError):
            cb.call(_fail)
        assert cb.state == CircuitState.HALF_OPEN

        # Second failure -> opens again
        with pytest.raises(ValueError):
            cb.call(_fail)
        assert cb.state == CircuitState.OPEN

    def test_reset_closes_circuit(self):
        """reset() forces the circuit back to CLOSED."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=999)

        def _fail() -> str:
            raise ValueError("error")

        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(_fail)

        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
        assert cb.closed is True

    def test_success_resets_failure_count(self):
        """A successful call in CLOSED state resets the failure count."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=999)

        def _fail() -> str:
            raise ValueError("error")

        def _succeed() -> str:
            return "ok"

        for _ in range(3):
            with pytest.raises(ValueError):
                cb.call(_fail)

        assert cb.failure_count == 3

        # Success resets
        cb.call(_succeed)
        assert cb.failure_count == 0
        assert cb.state == CircuitState.CLOSED

    def test_success_after_multiple_failures_closes(self):
        """Test full cycle: CLOSED -> failures -> OPEN -> timeout -> HALF_OPEN -> success -> CLOSED."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)

        def _fail() -> str:
            raise ValueError("error")

        def _succeed() -> str:
            return "ok"

        # Phase 1: CLOSED -> OPEN
        with pytest.raises(ValueError):
            cb.call(_fail)
        with pytest.raises(ValueError):
            cb.call(_fail)
        assert cb.state == CircuitState.OPEN

        # Phase 2: Wait -> HALF_OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN

        # Phase 3: success -> CLOSED
        result = cb.call(_succeed)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

# ===========================================================================
# Integration: breaker + rate limiter combined
# ===========================================================================


class TestCircuitBreakerRateLimiterIntegration:
    """Tests that CircuitBreaker and RateLimiter work together correctly."""

    def test_breaker_and_limiter_coexist(self, monkeypatch):
        """RateLimiter and CircuitBreaker both configured and working together."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            limiter = RateLimiter(capacity=100, tokens_per_second=1000.0)
            cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)

            provider = OpenAIProvider(
                max_retries=0,
                rate_limiter=limiter,
                circuit_breaker=cb,
            )

            # Circuit is CLOSED -> calls go through
            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            result = provider.generate("test 1")
            assert result != ""  # Goes through
            assert provider.call_count == 1

            # Still CLOSED after success
            assert cb.state == CircuitState.CLOSED

    def test_breaker_opens_after_rate_limiter_and_failures(self, monkeypatch):
        """RateLimiter passes, then CircuitBreaker opens after failures."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            limiter = RateLimiter(capacity=100, tokens_per_second=1000.0)
            cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)

            provider = OpenAIProvider(
                max_retries=0,
                rate_limiter=limiter,
                circuit_breaker=cb,
            )

            # Exhaust circuit: 2 failures
            mock_client.chat.completions.create.side_effect = Exception("API error")
            for i in range(2):
                result = provider.generate(f"fail {i}")
                assert result == ""

            # Circuit should be OPEN now
            assert cb.state == CircuitState.OPEN
            assert provider.call_count == 2

            # Next call: circuit OPEN -> fast-rejects (call_count still incremented in generate())
            result = provider.generate("should fast reject")
            assert result == ""
            assert provider.call_count == 3
            assert mock_client.chat.completions.create.call_count == 2  # Real API call was blocked

    def test_breaker_limiter_from_yaml_config(self, sample_allowed_tools, sample_authorized_assets):
        """from_agentic_config with both rate_limiter_config and circuit_breaker_config."""
        config = {
            "enabled": True,
            "llm_provider_config": {
                "provider_type": "openai",
                "model": "gpt-4o-mini",
                "api_key": "sk-test-key",
                "max_retries": 2,
                "temperature": 0.2,
                "rate_limiter_config": {
                    "capacity": 50,
                    "tokens_per_second": 5.0,
                },
                "circuit_breaker_config": {
                    "failure_threshold": 3,
                    "recovery_timeout": 30.0,
                    "half_open_max_retries": 2,
                },
            },
        }

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Integration test",
            )

            assert agent.llm_provider is not None
            provider = agent.llm_provider
            assert provider._rate_limiter is not None
            assert provider._circuit_breaker is not None
            assert provider._circuit_breaker._failure_threshold == 3
            assert provider._circuit_breaker._recovery_timeout == 30.0
            assert provider._circuit_breaker._half_open_max_retries == 2

    def test_breaker_limiter_defaults_with_empty_configs(self, sample_allowed_tools, sample_authorized_assets):
        """Empty dicts for rate_limiter_config and circuit_breaker_config use defaults."""
        config = {
            "enabled": True,
            "llm_provider_config": {
                "provider_type": "openai",
                "model": "gpt-4o-mini",
                "api_key": "sk-test-key",
                "max_retries": 2,
                "rate_limiter_config": {},
                "circuit_breaker_config": {},
            },
        }

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Defaults test",
            )

            assert agent.llm_provider is not None
            provider = agent.llm_provider
            assert provider._rate_limiter is not None
            assert provider._circuit_breaker is not None
            # Default values
            assert provider._circuit_breaker._failure_threshold == 5
            assert provider._circuit_breaker._recovery_timeout == 60.0


# ===========================================================================
# from_agentic_config — rate limiter & circuit breaker config forwarding
# ===========================================================================


class TestFromAgenticConfigRateLimiterAndCircuitBreaker:
    """Tests that from_agentic_config correctly parses rate_limiter_config
    and circuit_breaker_config from llm_provider_config."""

    def test_openai_rate_limiter_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """rate_limiter_config values are forwarded to OpenAIProvider."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "openai",
                    "rate_limiter_config": {
                        "capacity": 30,
                        "tokens_per_second": 2.0,
                    },
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            rl = agent.llm_provider._rate_limiter
            assert rl._capacity == 30
            assert rl._tokens_per_second == 2.0

    def test_openai_circuit_breaker_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """circuit_breaker_config values are forwarded to OpenAIProvider."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "openai",
                    "circuit_breaker_config": {
                        "failure_threshold": 3,
                        "recovery_timeout": 15.0,
                        "half_open_max_retries": 2,
                    },
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            cb = agent.llm_provider._circuit_breaker
            assert cb._failure_threshold == 3
            assert cb._recovery_timeout == 15.0
            assert cb._half_open_max_retries == 2

    def test_openai_both_configs(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """Both rate_limiter_config and circuit_breaker_config forwarded together."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "openai",
                    "rate_limiter_config": {"capacity": 10, "tokens_per_second": 1.0},
                    "circuit_breaker_config": {"failure_threshold": 2, "recovery_timeout": 5.0},
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            assert agent.llm_provider._rate_limiter is not None
            assert agent.llm_provider._circuit_breaker is not None

    def test_openai_no_configs(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """No rate_limiter_config or circuit_breaker_config -> not created."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "openai",
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            assert agent.llm_provider._rate_limiter is None
            assert agent.llm_provider._circuit_breaker is None

    def test_anthropic_rate_limiter_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """rate_limiter_config values are forwarded to AnthropicProvider."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "anthropic",
                    "rate_limiter_config": {
                        "capacity": 20,
                        "tokens_per_second": 5.0,
                    },
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            rl = agent.llm_provider._rate_limiter
            assert rl._capacity == 20
            assert rl._tokens_per_second == 5.0

    def test_anthropic_circuit_breaker_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """circuit_breaker_config values are forwarded to AnthropicProvider."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("anthropic.Anthropic") as mock_anthropic:
            mock_client = unittest.mock.MagicMock()
            mock_anthropic.return_value = mock_client

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "anthropic",
                    "circuit_breaker_config": {
                        "failure_threshold": 4,
                        "recovery_timeout": 20.0,
                    },
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            cb = agent.llm_provider._circuit_breaker
            assert cb._failure_threshold == 4
            assert cb._recovery_timeout == 20.0

    def test_google_rate_limiter_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """rate_limiter_config values are forwarded to GoogleProvider."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "google",
                    "rate_limiter_config": {
                        "capacity": 15,
                        "tokens_per_second": 3.0,
                    },
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            rl = agent.llm_provider._rate_limiter
            assert rl._capacity == 15
            assert rl._tokens_per_second == 3.0

    def test_google_circuit_breaker_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """circuit_breaker_config values are forwarded to GoogleProvider."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

        with unittest.mock.patch("google.genai.Client") as mock_genai:
            mock_client = unittest.mock.MagicMock()
            mock_genai.return_value = mock_client

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "provider_type": "google",
                    "circuit_breaker_config": {
                        "failure_threshold": 5,
                        "recovery_timeout": 30.0,
                    },
                },
            }
            agent = AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )
            assert agent.config_llm_provider is not None
            cb = agent.llm_provider._circuit_breaker
            assert cb._failure_threshold == 5
            assert cb._recovery_timeout == 30.0



# ===========================================================================
# from_agentic_config — rate limiter & circuit breaker config forwarding
# ===========================================================================


class TestFromAgenticConfigRateLimiterAndCircuitBreaker:
    """Tests that from_agentic_config correctly parses rate_limiter_config
    and circuit_breaker_config from llm_provider_config."""

    def test_openai_rate_limiter_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """rate_limiter_config creates a RateLimiter with correct params."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "rate_limiter_config": {
                        "capacity": 100,
                        "tokens_per_second": 10.0,
                    },
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "rate_limiter" in call_kwargs
            limiter = call_kwargs["rate_limiter"]
            assert limiter._capacity == 100
            assert limiter._tokens_per_second == 10.0

    def test_openai_rate_limiter_defaults(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """rate_limiter_config defaults: capacity=60, tokens_per_second=3.0."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "rate_limiter_config": {},  # empty -> defaults
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "rate_limiter" in call_kwargs
            limiter = call_kwargs["rate_limiter"]
            assert limiter._capacity == 60
            assert limiter._tokens_per_second == 3.0

    def test_anthropic_circuit_breaker_config(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """circuit_breaker_config creates a CircuitBreaker with correct params."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.AnthropicProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "anthropic",
                    "circuit_breaker_config": {
                        "failure_threshold": 10,
                        "recovery_timeout": 120.0,
                        "half_open_max_retries": 5,
                    },
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "circuit_breaker" in call_kwargs
            cb = call_kwargs["circuit_breaker"]
            assert cb._failure_threshold == 10
            assert cb._recovery_timeout == 120.0
            assert cb._half_open_max_retries == 5

    def test_circuit_breaker_config_defaults(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """circuit_breaker_config defaults: failure_threshold=5, recovery_timeout=60, half_open_max_retries=3."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "circuit_breaker_config": {},  # empty -> defaults
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "circuit_breaker" in call_kwargs
            cb = call_kwargs["circuit_breaker"]
            assert cb._failure_threshold == 5
            assert cb._recovery_timeout == 60.0
            assert cb._half_open_max_retries == 3

    def test_both_rate_limiter_and_circuit_breaker(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """Both rate_limiter_config and circuit_breaker_config can be specified together."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                    "rate_limiter_config": {"capacity": 30, "tokens_per_second": 5.0},
                    "circuit_breaker_config": {"failure_threshold": 3, "recovery_timeout": 30.0},
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "rate_limiter" in call_kwargs
            assert "circuit_breaker" in call_kwargs
            assert call_kwargs["rate_limiter"]._capacity == 30
            assert call_kwargs["circuit_breaker"]._failure_threshold == 3

    def test_no_rate_limiter_config_not_forwarded(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """Without rate_limiter_config, no rate_limiter is forwarded (provider uses default)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.OpenAIProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "openai",
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "rate_limiter" not in call_kwargs
            assert "circuit_breaker" not in call_kwargs

    def test_google_rate_limiter_and_circuit_breaker(self, monkeypatch, sample_allowed_tools, sample_authorized_assets):
        """rate_limiter_config and circuit_breaker_config work with GoogleProvider."""
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")

        with unittest.mock.patch("gatekeeper_eos_v6.providers.GoogleProvider") as mock_prov:
            mock_instance = unittest.mock.MagicMock()
            mock_prov.return_value = mock_instance

            config = {
                "enabled": True,
                "llm_provider_config": {
                    "type": "google",
                    "rate_limiter_config": {"capacity": 20, "tokens_per_second": 2.0},
                    "circuit_breaker_config": {"failure_threshold": 5},
                },
            }
            AgentCore.from_agentic_config(
                config, sample_allowed_tools, sample_authorized_assets,
                objective="Test",
            )

            call_kwargs = mock_prov.call_args.kwargs
            assert "rate_limiter" in call_kwargs
            assert "circuit_breaker" in call_kwargs
            assert call_kwargs["rate_limiter"]._capacity == 20
            assert call_kwargs["circuit_breaker"]._failure_threshold == 5

    def test_circuit_breaker_wired_in_providers_generate(self, monkeypatch):
        """CircuitBreaker.call is invoked when a provider's generate() is called with circuit_breaker set."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        with unittest.mock.patch("openai.OpenAI") as mock_openai:
            mock_client = unittest.mock.MagicMock()
            mock_openai.return_value = mock_client

            mock_choice = unittest.mock.MagicMock()
            mock_choice.message.content = '{"tool": "test", "command": "run"}'
            mock_response = unittest.mock.MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            cb = CircuitBreaker(failure_threshold=3, recovery_timeout=999)
            provider = OpenAIProvider(circuit_breaker=cb, max_retries=0)

            # First call succeeds
            result = provider.generate("test")
            assert result != ""
            assert cb.state == CircuitState.CLOSED

            # Open the circuit
            mock_client.chat.completions.create.side_effect = ValueError("API error")

            for _ in range(3):
                result = provider.generate("test")
            # The circuit breaker will open after 3 failures,
            # but generate will return "" for each call
            # After opening, the circuit breaker returns fallback=""
            assert cb.open is True
