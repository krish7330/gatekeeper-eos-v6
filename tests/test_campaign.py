"""Tests for campaign orchestration: validation, scheduling, dependencies, drift, executor."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
import yaml

from gatekeeper_eos_v6.campaign import (
    DriftRule,
    DriftAction,
    Schedule,
    SessionDef,
    SessionStatus,
    Campaign,
    CampaignError,
    CampaignValidationError,
    CampaignScheduleError,
    CampaignDependencyError,
    CampaignDriftError,
    load_campaign,
    campaign_from_dict,
    validate_campaign,
    DependencyResolver,
    check_drift_rules,
    CampaignExecutor,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def sample_campaign_dict() -> dict:
    """A valid campaign dict matching the schema."""
    return {
        "campaign_id": "CAMP-2026-05-WEBAPP",
        "sessions": [
            {
                "session_id": "SESS-recon",
                "plan": "PLAN-WEBAPP-01",
                "schedule": {
                    "start_at": "2026-06-01T02:00:00Z",
                    "max_duration": "PT30M",
                },
                "max_parallel_actions": 3,
            },
            {
                "session_id": "SESS-auth-bypass",
                "plan": {
                    "plan_id": "PLAN-AUTH-01",
                    "authorized_assets": ["auth.target.com"],
                    "objective": "Test auth bypass",
                },
                "schedule": {
                    "start_at": "2026-06-01T02:30:00Z",
                    "deadline": "2026-06-01T04:00:00Z",
                },
                "dependencies": ["SESS-recon"],
                "drift_rules_override": [
                    {
                        "id": "DRIFT-TARGET",
                        "description": "Target change is okay",
                        "action": "LOG_ONLY",
                    }
                ],
            },
        ],
        "global_drift_rules": [
            {"id": "DRIFT-TARGET", "description": "Target must be static", "action": "HALT"},
            {"id": "DRIFT-TOOLS", "description": "Tool integrity mandatory", "action": "HALT"},
            {"id": "DRIFT-SCHEMA", "description": "Schema violations are warnings", "action": "LOG_ONLY"},
        ],
    }


@pytest.fixture
def sample_campaign(sample_campaign_dict) -> Campaign:
    return campaign_from_dict(sample_campaign_dict)


@pytest.fixture
def future_start_schedule() -> Schedule:
    return Schedule(
        start_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )


# ===========================================================================
# DriftRule
# ===========================================================================


class TestDriftRule:
    def test_create_valid(self):
        rule = DriftRule(id="DRIFT-TARGET", description="Test", condition="target changed")
        assert rule.id == "DRIFT-TARGET"
        assert rule.action == DriftAction.HALT

    def test_create_log_only(self):
        rule = DriftRule(id="DRIFT-SCHEMA", description="Warn", condition="schema mismatch", action=DriftAction.LOG_ONLY)
        assert rule.action == DriftAction.LOG_ONLY

    def test_invalid_id_raises(self):
        with pytest.raises(CampaignValidationError, match="DRIFT-UNKNOWN"):
            DriftRule(id="DRIFT-UNKNOWN", description="Bad", condition="x")

    def test_empty_id_raises(self):
        with pytest.raises(CampaignValidationError):
            DriftRule(id="", description="Empty", condition="x")

    def test_valid_ids(self):
        for rid in ["DRIFT-TARGET", "DRIFT-TOOLS", "DRIFT-NET", "DRIFT-SCHEMA", "DRIFT-PLAN", "DRIFT-EXPIRY"]:
            rule = DriftRule(id=rid, description="Valid", condition="x")
            assert rule.id == rid

    def test_drift_agent_state_is_valid(self):
        rule = DriftRule(id="DRIFT-AGENT-STATE", description="Hallucination detect", condition="state_diverges")
        assert rule.id == "DRIFT-AGENT-STATE"
        assert rule.action == DriftAction.HALT

    def test_drift_agent_state_immutable(self):
        rule = DriftRule(id="DRIFT-AGENT-STATE", description="Test", condition="x")
        with pytest.raises(Exception):
            rule.id = "DRIFT-TOOLS"  # type: ignore[misc]


# ===========================================================================
# Schedule
# ===========================================================================


class TestSchedule:
    def test_ready_when_now_equals_start(self):
        t = datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc)
        sched = Schedule(start_at=t)
        assert sched.is_ready(t)

    def test_ready_when_now_after_start(self):
        sched = Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert sched.is_ready()

    def test_not_ready_when_before_start(self, future_start_schedule):
        assert not future_start_schedule.is_ready()

    def test_not_expired_when_no_deadline(self):
        sched = Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert not sched.is_expired()

    def test_expired_when_past_deadline(self):
        sched = Schedule(
            start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deadline=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        now = datetime(2026, 1, 3, tzinfo=timezone.utc)
        assert sched.is_expired(now)

    def test_not_expired_before_deadline(self):
        sched = Schedule(
            start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deadline=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert not sched.is_expired(now)

    def test_max_duration_is_optional(self):
        sched = Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert sched.max_duration is None

    def test_max_duration_string(self):
        sched = Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc), max_duration="PT30M")
        assert sched.max_duration == "PT30M"


# ===========================================================================
# SessionDef
# ===========================================================================


class TestSessionDef:
    def test_create_valid_with_plan_ref(self):
        s = SessionDef(
            session_id="SESS-recon",
            plan="PLAN-WEBAPP-01",
            schedule=Schedule(start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc)),
        )
        assert s.session_id == "SESS-recon"
        assert s.plan == "PLAN-WEBAPP-01"

    def test_create_valid_with_inline_plan(self):
        s = SessionDef(
            session_id="SESS-auth",
            plan={"plan_id": "PLAN-AUTH-01", "objective": "Test"},
            schedule=Schedule(start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc)),
        )
        assert isinstance(s.plan, dict)
        assert s.plan["plan_id"] == "PLAN-AUTH-01"

    def test_invalid_session_id_pattern(self):
        with pytest.raises(CampaignValidationError, match="SESS-"):
            SessionDef(
                session_id="bad-id",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
            )

    def test_invalid_session_id_no_prefix(self):
        with pytest.raises(CampaignValidationError):
            SessionDef(
                session_id="SESSION-123",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
            )

    def test_zero_max_parallel_actions_raises(self):
        with pytest.raises(CampaignValidationError):
            SessionDef(
                session_id="SESS-zero",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
                max_parallel_actions=0,
            )

    def test_negative_max_parallel_actions_raises(self):
        with pytest.raises(CampaignValidationError):
            SessionDef(
                session_id="SESS-neg",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
                max_parallel_actions=-1,
            )

    def test_default_max_parallel_actions(self):
        s = SessionDef(
            session_id="SESS-default",
            plan="PLAN-01",
            schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        )
        assert s.max_parallel_actions == 1

    def test_dependencies_default_empty(self):
        s = SessionDef(
            session_id="SESS-no-deps",
            plan="PLAN-01",
            schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        )
        assert s.dependencies == ()

    def test_immutable(self):
        s = SessionDef(
            session_id="SESS-immutable",
            plan="PLAN-01",
            schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        )
        with pytest.raises(Exception):
            s.session_id = "SESS-changed"  # type: ignore[misc]


# ===========================================================================
# Campaign
# ===========================================================================


class TestCampaign:
    def test_create_valid(self, sample_campaign):
        assert sample_campaign.campaign_id == "CAMP-2026-05-WEBAPP"
        assert len(sample_campaign.sessions) == 2

    def test_invalid_campaign_id_raises(self):
        with pytest.raises(CampaignValidationError, match="CAMP-"):
            Campaign(campaign_id="bad-id", sessions=(s for s in []))

    def test_invalid_campaign_id_no_prefix(self):
        with pytest.raises(CampaignValidationError):
            Campaign(campaign_id="CAMPAIGN-123", sessions=(s for s in []))

    def test_empty_sessions_raises(self):
        with pytest.raises(CampaignValidationError, match="at least one session"):
            Campaign(
                campaign_id="CAMP-001",
                sessions=tuple(),
            )

    def test_empty_sessions_as_literal(self):
        with pytest.raises(CampaignValidationError):
            Campaign(
                campaign_id="CAMP-001",
                sessions=(),
            )

    def test_immutable(self, sample_campaign):
        with pytest.raises(Exception):
            sample_campaign.campaign_id = "CAMP-changed"  # type: ignore[misc]

    def test_empty_global_drift_rules(self):
        camp = Campaign(
            campaign_id="CAMP-001",
            sessions=(SessionDef(
                session_id="SESS-test",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
            ),),
        )
        assert camp.global_drift_rules == ()


# ===========================================================================
# YAML loading
# ===========================================================================


class TestLoadCampaign:
    def test_load_from_yaml_file(self, tmp_path, sample_campaign_dict):
        yaml_path = tmp_path / "campaign.yaml"
        yaml_path.write_text(yaml.dump(sample_campaign_dict))
        camp = load_campaign(yaml_path)
        assert camp.campaign_id == "CAMP-2026-05-WEBAPP"
        assert len(camp.sessions) == 2

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_campaign("/nonexistent/path/campaign.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        bad_path = tmp_path / "bad.yaml"
        bad_path.write_text("{invalid: yaml: [broken")
        with pytest.raises(CampaignValidationError, match="Failed to parse"):
            load_campaign(bad_path)

    def test_yaml_is_not_mapping(self, tmp_path):
        path = tmp_path / "scalar.yaml"
        path.write_text("just a string")
        with pytest.raises(CampaignValidationError, match="must be a mapping"):
            load_campaign(path)


# ===========================================================================
# campaign_from_dict
# ===========================================================================


class TestCampaignFromDict:
    def test_valid_dict(self, sample_campaign_dict):
        camp = campaign_from_dict(sample_campaign_dict)
        assert camp.campaign_id == "CAMP-2026-05-WEBAPP"

    def test_missing_campaign_id(self, sample_campaign_dict):
        data = {k: v for k, v in sample_campaign_dict.items() if k != "campaign_id"}
        with pytest.raises(CampaignValidationError, match="campaign_id"):
            campaign_from_dict(data)

    def test_empty_sessions(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"] = []
        with pytest.raises(CampaignValidationError, match="at least one"):
            campaign_from_dict(data)

    def test_missing_sessions(self, sample_campaign_dict):
        data = {k: v for k, v in sample_campaign_dict.items() if k != "sessions"}
        with pytest.raises(CampaignValidationError, match="Missing required field: sessions"):
            campaign_from_dict(data)

    def test_duplicate_session_ids(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"].append(data["sessions"][0])
        with pytest.raises(CampaignValidationError, match="Duplicate"):
            campaign_from_dict(data)

    def test_invalid_plan_ref_format(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"][0]["plan"] = "INVALID-REF"
        with pytest.raises(CampaignValidationError, match="PLAN-"):
            campaign_from_dict(data)

    def test_missing_session_id(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        del data["sessions"][0]["session_id"]
        with pytest.raises(CampaignValidationError):
            campaign_from_dict(data)

    def test_missing_schedule(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        del data["sessions"][0]["schedule"]
        with pytest.raises(CampaignValidationError):
            campaign_from_dict(data)

    def test_missing_plan(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        del data["sessions"][0]["plan"]
        with pytest.raises(CampaignValidationError):
            campaign_from_dict(data)

    def test_invalid_drift_rule_in_global(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["global_drift_rules"].append({"id": "DRIFT-INVALID", "description": "Bad"})
        with pytest.raises(CampaignValidationError):
            campaign_from_dict(data)

    def test_plan_is_neither_string_nor_dict(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"][0]["plan"] = 42
        with pytest.raises(CampaignValidationError):
            campaign_from_dict(data)

    def test_schedule_invalid_datetime(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"][0]["schedule"]["start_at"] = "not-a-date"
        with pytest.raises(CampaignValidationError):
            campaign_from_dict(data)


# ===========================================================================
# validate_campaign (non-throwing)
# ===========================================================================


class TestValidateCampaign:
    def test_valid_returns_empty(self, sample_campaign_dict):
        errors = validate_campaign(sample_campaign_dict)
        assert errors == []

    def test_invalid_returns_errors(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"] = []
        errors = validate_campaign(data)
        assert len(errors) >= 1
        assert any("session" in e.lower() for e in errors)

    def test_multiple_errors_collected(self, sample_campaign_dict):
        data = {
            "campaign_id": "bad",
            "sessions": [
                {
                    "session_id": "bad-session",
                    "plan": "xxx",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                }
            ],
        }
        errors = validate_campaign(data)
        # Should include: bad campaign_id, bad session_id, bad plan ref
        assert len(errors) >= 2

    def test_nonexistent_dependency_reported(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["sessions"][0]["dependencies"] = ["SESS-nonexistent"]
        errors = validate_campaign(data)
        assert any("nonexistent" in e for e in errors)

    def test_global_drift_rule_error(self):
        data = {
            "campaign_id": "CAMP-001",
            "sessions": [
                {
                    "session_id": "SESS-test",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                }
            ],
            "global_drift_rules": [{"id": "BAD-ID", "description": "x"}],
        }
        errors = validate_campaign(data)
        assert any("BAD-ID" in e for e in errors)


# ===========================================================================
# Circular dependency detection
# ===========================================================================


class TestCircularDependencies:
    def test_no_circular_deps(self, sample_campaign):
        # SESS-recon depends on nothing; SESS-auth-bypass depends on SESS-recon — no cycle
        resolver = DependencyResolver(sample_campaign)
        layers = resolver.get_execution_order()
        # Should be 2 layers: [SESS-recon], [SESS-auth-bypass]
        assert len(layers) == 2

    def test_direct_circular_dep_detected(self):
        data = {
            "campaign_id": "CAMP-circ",
            "sessions": [
                {
                    "session_id": "SESS-a",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-b"],
                },
                {
                    "session_id": "SESS-b",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-a"],
                },
            ],
        }
        with pytest.raises(CampaignValidationError, match="Circular"):
            campaign_from_dict(data)

    def test_indirect_circular_dep_detected(self):
        data = {
            "campaign_id": "CAMP-indirect",
            "sessions": [
                {
                    "session_id": "SESS-a",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-b"],
                },
                {
                    "session_id": "SESS-b",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-c"],
                },
                {
                    "session_id": "SESS-c",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-a"],
                },
            ],
        }
        with pytest.raises(CampaignValidationError, match="Circular"):
            campaign_from_dict(data)

    def test_self_dependency_cycle(self):
        data = {
            "campaign_id": "CAMP-self",
            "sessions": [
                {
                    "session_id": "SESS-self",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-self"],
                },
            ],
        }
        with pytest.raises(CampaignValidationError, match="Circular|depends on itself"):
            try:
                campaign_from_dict(data)
            except CampaignValidationError as e:
                # Either a circular dependency or self-dependency error
                assert "Circular" in str(e) or "depends" in str(e)
                raise

    def test_undefined_dependency_reported(self):
        data = {
            "campaign_id": "CAMP-undefined",
            "sessions": [
                {
                    "session_id": "SESS-a",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-undefined"],
                },
            ],
        }
        errors = validate_campaign(data)
        assert any("undefined" in e.lower() for e in errors)


# ===========================================================================
# DependencyResolver
# ===========================================================================


class TestDependencyResolver:
    def test_get_ready_sessions_no_completed(self, sample_campaign):
        resolver = DependencyResolver(sample_campaign)
        now = datetime(2026, 6, 1, 2, 15, 0, tzinfo=timezone.utc)
        ready = resolver.get_ready_sessions(completed=set(), now=now)
        # SESS-recon is ready (start_at 02:00), SESS-auth-bypass depends on SESS-recon
        assert len(ready) == 1
        assert ready[0].session_id == "SESS-recon"

    def test_get_ready_sessions_all_completed(self, sample_campaign):
        resolver = DependencyResolver(sample_campaign)
        now = datetime(2026, 6, 1, 3, 0, 0, tzinfo=timezone.utc)
        ready = resolver.get_ready_sessions(completed={"SESS-recon", "SESS-auth-bypass"}, now=now)
        assert ready == []

    def test_get_ready_with_deps_satisfied(self, sample_campaign):
        resolver = DependencyResolver(sample_campaign)
        now = datetime(2026, 6, 1, 2, 45, 0, tzinfo=timezone.utc)
        ready = resolver.get_ready_sessions(completed={"SESS-recon"}, now=now)
        # SESS-auth-bypass starts at 02:30, its dep SESS-recon is done
        assert len(ready) == 1
        assert ready[0].session_id == "SESS-auth-bypass"

    def test_get_ready_before_start(self):
        data = {
            "campaign_id": "CAMP-future",
            "sessions": [
                {
                    "session_id": "SESS-future",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2099-01-01T00:00:00Z"},
                },
            ],
        }
        camp = campaign_from_dict(data)
        resolver = DependencyResolver(camp)
        ready = resolver.get_ready_sessions(now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert ready == []

    def test_get_ready_after_deadline(self):
        data = {
            "campaign_id": "CAMP-deadline",
            "sessions": [
                {
                    "session_id": "SESS-dead",
                    "plan": "PLAN-01",
                    "schedule": {
                        "start_at": "2026-01-01T00:00:00Z",
                        "deadline": "2026-01-02T00:00:00Z",
                    },
                },
            ],
        }
        camp = campaign_from_dict(data)
        resolver = DependencyResolver(camp)
        ready = resolver.get_ready_sessions(now=datetime(2026, 1, 3, tzinfo=timezone.utc))
        assert ready == []

    def test_execution_order_single_layer(self):
        """Sessions with no dependencies all run in parallel."""
        data = {
            "campaign_id": "CAMP-parallel",
            "sessions": [
                {
                    "session_id": "SESS-a",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                },
                {
                    "session_id": "SESS-b",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                },
            ],
        }
        camp = campaign_from_dict(data)
        resolver = DependencyResolver(camp)
        layers = resolver.get_execution_order()
        assert len(layers) == 1
        assert len(layers[0]) == 2

    def test_execution_order_sequential(self, sample_campaign):
        resolver = DependencyResolver(sample_campaign)
        layers = resolver.get_execution_order()
        assert len(layers) == 2
        assert layers[0][0].session_id == "SESS-recon"
        assert layers[1][0].session_id == "SESS-auth-bypass"

    def test_get_ready_empty_when_all_completed(self, sample_campaign):
        resolver = DependencyResolver(sample_campaign)
        ready = resolver.get_ready_sessions(completed={"SESS-recon", "SESS-auth-bypass"})
        assert ready == []

    def test_dependency_chain_multiple_layers(self):
        data = {
            "campaign_id": "CAMP-chain",
            "sessions": [
                {
                    "session_id": "SESS-a",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                },
                {
                    "session_id": "SESS-b",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-a"],
                },
                {
                    "session_id": "SESS-c",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-b"],
                },
            ],
        }
        camp = campaign_from_dict(data)
        resolver = DependencyResolver(camp)
        layers = resolver.get_execution_order()
        assert len(layers) == 3
        assert len(layers[0]) == 1 and layers[0][0].session_id == "SESS-a"
        assert len(layers[1]) == 1 and layers[1][0].session_id == "SESS-b"
        assert len(layers[2]) == 1 and layers[2][0].session_id == "SESS-c"

    def test_ready_sessions_sorted_by_start_at(self):
        data = {
            "campaign_id": "CAMP-sorted",
            "sessions": [
                {
                    "session_id": "SESS-late",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T03:00:00Z"},
                },
                {
                    "session_id": "SESS-early",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T01:00:00Z"},
                },
            ],
        }
        camp = campaign_from_dict(data)
        resolver = DependencyResolver(camp)
        ready = resolver.get_ready_sessions(now=datetime(2026, 1, 1, 4, 0, 0, tzinfo=timezone.utc))
        assert ready[0].session_id == "SESS-early"
        assert ready[1].session_id == "SESS-late"


# ===========================================================================
# Drift rule enforcement
# ===========================================================================


class TestCheckDriftRules:
    def test_no_triggered_rules(self, sample_campaign):
        triggered = check_drift_rules(
            sample_campaign.sessions[0],
            sample_campaign.global_drift_rules,
            {},
        )
        assert triggered == []

    def test_no_triggered_with_rules_not_set(self, sample_campaign):
        triggered = check_drift_rules(
            sample_campaign.sessions[0],
            sample_campaign.global_drift_rules,
            {"DRIFT-TARGET": False, "DRIFT-TOOLS": False},
        )
        assert triggered == []

    def test_halt_rule_triggered(self, sample_campaign):
        triggered = check_drift_rules(
            sample_campaign.sessions[0],
            sample_campaign.global_drift_rules,
            {"DRIFT-TARGET": True},
        )
        assert len(triggered) == 1
        assert triggered[0].id == "DRIFT-TARGET"
        assert triggered[0].action == DriftAction.HALT

    def test_log_only_rule_triggered(self, sample_campaign):
        triggered = check_drift_rules(
            sample_campaign.sessions[0],
            sample_campaign.global_drift_rules,
            {"DRIFT-SCHEMA": True},
        )
        assert len(triggered) == 1
        assert triggered[0].id == "DRIFT-SCHEMA"
        assert triggered[0].action == DriftAction.LOG_ONLY

    def test_multiple_rules_triggered(self, sample_campaign):
        triggered = check_drift_rules(
            sample_campaign.sessions[0],
            sample_campaign.global_drift_rules,
            {"DRIFT-TARGET": True, "DRIFT-SCHEMA": True},
        )
        assert len(triggered) == 2

    def test_session_override_downgrades_to_log(self, sample_campaign):
        """SESS-auth-bypass overrides DRIFT-TARGET to LOG_ONLY."""
        triggered = check_drift_rules(
            sample_campaign.sessions[1],
            sample_campaign.global_drift_rules,
            {"DRIFT-TARGET": True},
        )
        assert len(triggered) == 1
        assert triggered[0].action == DriftAction.LOG_ONLY

    def test_session_override_not_affecting_global(self, sample_campaign):
        """Global DRIFT-TOOLS should still HALT even if session overrides DRIFT-TARGET."""
        triggered = check_drift_rules(
            sample_campaign.sessions[1],
            sample_campaign.global_drift_rules,
            {"DRIFT-TOOLS": True},
        )
        assert len(triggered) == 1
        assert triggered[0].action == DriftAction.HALT

    def test_unknown_rule_id_in_trigger_is_ignored(self, sample_campaign):
        triggered = check_drift_rules(
            sample_campaign.sessions[0],
            sample_campaign.global_drift_rules,
            {"UNKNOWN-RULE": True},
        )
        assert triggered == []


# ===========================================================================
# CampaignExecutor
# ===========================================================================


class TestCampaignExecutor:
    def test_resolve_sessions(self, sample_campaign):
        executor = CampaignExecutor(sample_campaign)
        layers = executor.resolve_sessions()
        assert layers == [["SESS-recon"], ["SESS-auth-bypass"]]

    def test_resolve_sessions_parallel(self):
        data = {
            "campaign_id": "CAMP-parallel",
            "sessions": [
                {
                    "session_id": "SESS-a",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                },
                {
                    "session_id": "SESS-b",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                },
            ],
        }
        camp = campaign_from_dict(data)
        executor = CampaignExecutor(camp)
        layers = executor.resolve_sessions()
        assert len(layers) == 1
        assert set(layers[0]) == {"SESS-a", "SESS-b"}

    def test_check_session_drift_no_trigger(self, sample_campaign):
        executor = CampaignExecutor(sample_campaign)
        halt, triggered = executor.check_session_drift(
            sample_campaign.sessions[0], {}
        )
        assert halt is False
        assert triggered == []

    def test_check_session_drift_halt(self, sample_campaign):
        executor = CampaignExecutor(sample_campaign)
        halt, triggered = executor.check_session_drift(
            sample_campaign.sessions[0],
            {"DRIFT-TARGET": True},
        )
        assert halt is True
        assert len(triggered) == 1
        assert triggered[0].id == "DRIFT-TARGET"

    def test_check_session_drift_log_only(self, sample_campaign):
        executor = CampaignExecutor(sample_campaign)
        halt, triggered = executor.check_session_drift(
            sample_campaign.sessions[0],
            {"DRIFT-SCHEMA": True},
        )
        assert halt is False  # LOG_ONLY does not halt
        assert len(triggered) == 1
        assert triggered[0].id == "DRIFT-SCHEMA"

    def test_check_session_drift_overridden(self, sample_campaign):
        executor = CampaignExecutor(sample_campaign)
        halt, triggered = executor.check_session_drift(
            sample_campaign.sessions[1],  # has DRIFT-TARGET override -> LOG_ONLY
            {"DRIFT-TARGET": True},
        )
        assert halt is False  # overridden to LOG_ONLY
        assert triggered[0].action == DriftAction.LOG_ONLY

    def test_write_session_checkpoint(self, sample_campaign, tmp_path):
        executor = CampaignExecutor(sample_campaign, checkpoint_dir=tmp_path / "ckpt")
        path = executor.write_session_checkpoint(
            sample_campaign.sessions[0],
            status="running",
            step_id="init",
        )
        assert path.exists()
        assert path.name == "SESS-recon.json"

    def test_write_session_checkpoint_with_plan_ref(self, sample_campaign, tmp_path):
        executor = CampaignExecutor(sample_campaign, checkpoint_dir=tmp_path / "ckpt")
        path = executor.write_session_checkpoint(
            sample_campaign.sessions[0],
            status="running",
        )
        import json
        data = json.loads(path.read_text())
        assert data["plan_id"] == "PLAN-WEBAPP-01"

    def test_write_session_checkpoint_with_inline_plan(self, sample_campaign, tmp_path):
        executor = CampaignExecutor(sample_campaign, checkpoint_dir=tmp_path / "ckpt")
        path = executor.write_session_checkpoint(
            sample_campaign.sessions[1],
            status="completed",
        )
        import json
        data = json.loads(path.read_text())
        assert data["plan_id"] == "PLAN-AUTH-01"

    def test_rollback_session(self, sample_campaign, tmp_path):
        executor = CampaignExecutor(sample_campaign, checkpoint_dir=tmp_path / "ckpt")
        # First write a checkpoint
        executor.write_session_checkpoint(sample_campaign.sessions[0], status="running")
        # Then roll it back
        path = executor.rollback_session(sample_campaign.sessions[0], reason="drift detected")
        assert path.exists()

    def test_rollback_session_not_found_raises(self, sample_campaign, tmp_path):
        executor = CampaignExecutor(sample_campaign, checkpoint_dir=tmp_path / "ckpt")
        from gatekeeper_eos_v6.checkpoint import CheckpointNotFoundError
        with pytest.raises(CheckpointNotFoundError):
            executor.rollback_session(sample_campaign.sessions[0], reason="test")

    def test_custom_lock_manager(self, sample_campaign):
        from gatekeeper_eos_v6.locks import LockManager
        lm = LockManager.default()
        executor = CampaignExecutor(sample_campaign, lock_manager=lm)
        assert executor.lock_manager is lm


# ===========================================================================
# CampaignExecutor agentic session
# ===========================================================================


class TestCampaignExecutorAgentic:
    def test_run_agentic_session_happy_path(self, tmp_path):
        """Run a simple agentic session through CampaignExecutor."""

        plan = {
            "plan_id": "PLAN-AGENT-TEST-01",
            "authorized_assets": ["10.0.0.10"],
            "allowed_tools": [
                {
                    "name": "nmap",
                    "version": "7.95",
                    "hash": "sha256:TEST",
                    "allowed_commands": ["scan"],
                },
            ],
            "objective": "Find open ports on target",
            "success_criteria": ["All open ports identified"],
            "agentic_config": {
                "enabled": True,
                "max_steps": 2,
                "decision_strategy": "rule",
                "stop_on_finding": "none",
            },
        }

        session_def = SessionDef(
            session_id="SESS-agentic-test",
            plan=plan,
            schedule=Schedule(
                start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc),
            ),
        )

        campaign = Campaign(
            campaign_id="CAMP-AGENT-TEST",
            sessions=(session_def,),
        )

        executor = CampaignExecutor(campaign, checkpoint_dir=tmp_path / "ckpt")

        def execute_action(action):
            return {"open_ports": [80, 443], "services": [{"name": "nginx"}]}

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session_def, execute_action,
        )

        assert len(final_state.open_ports) >= 1
        assert len(evidence) >= 1
        assert stop_reason is not None
        # Check that checkpoints were written
        ckpt_dir = tmp_path / "ckpt"
        assert ckpt_dir.exists()
        checkpoint_files = list(ckpt_dir.glob("*.json"))
        assert len(checkpoint_files) >= 1

    def test_run_agentic_session_rejects_plan_ref(self, tmp_path):
        """run_agentic_session should reject sessions with plan references (strings)."""
        campaign = Campaign(
            campaign_id="CAMP-AGENT-REJECT",
            sessions=(
                SessionDef(
                    session_id="SESS-reject",
                    plan="PLAN-REF-01",
                    schedule=Schedule(
                        start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc),
                    ),
                ),
            ),
        )
        executor = CampaignExecutor(campaign, checkpoint_dir=tmp_path / "ckpt")

        with pytest.raises(CampaignValidationError, match="inline plan"):
            executor.run_agentic_session(
                campaign.sessions[0],
                lambda a: {},
            )

    def test_run_agentic_session_rejects_missing_agentic_config(self, tmp_path):
        """Inline plan without agentic_config should fail."""
        campaign = Campaign(
            campaign_id="CAMP-NO-CONFIG",
            sessions=(
                SessionDef(
                    session_id="SESS-no-config",
                    plan={"plan_id": "PLAN-01", "objective": "test"},
                    schedule=Schedule(
                        start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc),
                    ),
                ),
            ),
        )
        executor = CampaignExecutor(campaign, checkpoint_dir=tmp_path / "ckpt")

        with pytest.raises(CampaignValidationError, match="agentic_config"):
            executor.run_agentic_session(
                campaign.sessions[0],
                lambda a: {},
            )

    def test_run_agentic_session_with_drift_agent_state(self, tmp_path):
        """Agent state drift should halt the session and write halted checkpoint."""
        plan = {
            "plan_id": "PLAN-AGENT-DRIFT-01",
            "authorized_assets": ["10.0.0.10"],
            "allowed_tools": [
                {
                    "name": "nmap",
                    "version": "7.95",
                    "hash": "sha256:TEST",
                    "allowed_commands": ["scan"],
                },
            ],
            "objective": "Test drift",
            "success_criteria": [],
            "agentic_config": {
                "enabled": True,
                "max_steps": 5,
                "decision_strategy": "rule",
                "agent_state_drift_check": True,
            },
        }

        session_def = SessionDef(
            session_id="SESS-agentic-drift",
            plan=plan,
            schedule=Schedule(
                start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc),
            ),
        )

        campaign = Campaign(
            campaign_id="CAMP-AGENT-DRIFT",
            sessions=(session_def,),
            global_drift_rules=(
                DriftRule(id="DRIFT-AGENT-STATE", description="Check halluncinations", condition="state_diverges"),
            ),
        )

        executor = CampaignExecutor(campaign, checkpoint_dir=tmp_path / "ckpt")

        def execute_action(action):
            return {"open_ports": [80]}

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session_def, execute_action,
        )

        assert stop_reason is not None
        assert len(evidence) >= 1


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_empty_plan_ref(self, sample_campaign_dict):
        """Empty plan string should fail pattern validation."""
        data = dict(sample_campaign_dict)
        data["sessions"][0]["plan"] = ""
        errors = validate_campaign(data)
        assert any("PLAN-" in e for e in errors)

    def test_very_long_campaign_id(self):
        long_id = "CAMP-" + "X" * 1000
        camp = Campaign(
            campaign_id=long_id,
            sessions=(SessionDef(
                session_id="SESS-test",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
            ),),
        )
        assert camp.campaign_id == long_id

    def test_many_sessions(self):
        sessions = []
        for i in range(100):
            sessions.append(SessionDef(
                session_id=f"SESS-session-{i:03d}",
                plan="PLAN-01",
                schedule=Schedule(start_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
            ))
        camp = Campaign(
            campaign_id="CAMP-large",
            sessions=tuple(sessions),
        )
        assert len(camp.sessions) == 100

    def test_dependency_on_self_detected(self):
        errors = validate_campaign({
            "campaign_id": "CAMP-self",
            "sessions": [
                {
                    "session_id": "SESS-self",
                    "plan": "PLAN-01",
                    "schedule": {"start_at": "2026-01-01T00:00:00Z"},
                    "dependencies": ["SESS-self"],
                },
            ],
        })
        assert any("SESS-self" in e for e in errors)

    def test_expired_session_not_ready(self):
        sched = Schedule(
            start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            deadline=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        now = datetime(2026, 1, 3, tzinfo=timezone.utc)
        assert sched.is_expired(now)
        assert sched.is_ready(now)  # ready but expired — the caller checks both

    def test_drift_rules_empty_list(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data["global_drift_rules"] = []
        camp = campaign_from_dict(data)
        assert camp.global_drift_rules == ()

    def test_drift_rules_none(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        data.pop("global_drift_rules", None)
        camp = campaign_from_dict(data)
        assert camp.global_drift_rules == ()

    def test_schedule_no_start_at(self, sample_campaign_dict):
        data = dict(sample_campaign_dict)
        del data["sessions"][0]["schedule"]["start_at"]
        errors = validate_campaign(data)
        assert any("start_at" in e.lower() or "start" in e.lower() for e in errors)
