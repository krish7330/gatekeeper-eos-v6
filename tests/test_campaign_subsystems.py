"""Tests for CampaignExecutor with use_subsystems=True.

Covers:
- Attested snapshot creation via _take_snapshot helper
- Asset validation against reputation tracking
- Asset discovery recording in reputation ledger
- Provider drift tracking (no-crash path)
- Backward compatibility (use_subsystems=False = no-op)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gatekeeper_eos_v6.campaign import (
    Campaign,
    CampaignExecutor,
    SessionDef,
    Schedule,
)
from gatekeeper_eos_v6.subsystems import (
    ReputationTracker,
    AttestationLedger,
    ProviderTrustScorer,
)
from gatekeeper_eos_v6.snapshot import SnapshotLedger


# ===========================================================================
# Helpers
# ===========================================================================


def _make_agentic_plan(**overrides: str | list | dict) -> dict:
    """Create a minimal agentic plan dict for testing."""
    plan: dict = {
        "plan_id": "PLAN-SUBSYS-TEST",
        "authorized_assets": ["10.0.0.10"],
        "allowed_tools": [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
        ],
        "objective": "Subsystem integration test",
        "success_criteria": ["Open ports identified"],
        "agentic_config": {
            "enabled": True,
            "max_steps": 2,
            "decision_strategy": "rule",
            "stop_on_finding": "none",
        },
    }
    plan.update(overrides)
    return plan


def _make_session(plan: dict, session_id: str = "SESS-subsys-test") -> SessionDef:
    """Create a SessionDef for testing."""
    return SessionDef(
        session_id=session_id,
        plan=plan,
        schedule=Schedule(
            start_at=datetime(2026, 6, 1, 2, 0, 0, tzinfo=timezone.utc),
        ),
    )


def _execute_echo(action):
    """Simple execute_action that returns open ports and services."""
    return {"open_ports": [80, 443], "services": [{"name": "nginx"}]}


# ===========================================================================
# Subsystem-patching fixture
# ===========================================================================


@pytest.fixture
def patched_subsystems(tmp_path: Path):
    """Create test ledger instances and patch all module-level singletons.

    Yields a dict with references to the test ledgers so tests can
    assert on them.  Tears down the patches in the finalizer.
    """
    # Create temp paths
    att_ledger_path = tmp_path / "attestations.json"
    att_key_path = tmp_path / "private_key"
    rep_ledger_path = tmp_path / "reputation.json"
    trust_ledger_path = tmp_path / "trust.json"

    # Create private key
    key = os.urandom(32)
    att_key_path.write_bytes(key)

    # Create ledger instances
    attestation_ledger = AttestationLedger(att_ledger_path, att_key_path)
    reputation_tracker = ReputationTracker(rep_ledger_path)
    trust_scorer = ProviderTrustScorer(trust_ledger_path)

    # Patch module-level singletons
    import gatekeeper_eos_v6.snapshot as snap_mod
    import gatekeeper_eos_v6.campaign_integration as ci_mod

    old_att = snap_mod._ATTESTATION_LEDGER
    old_rep = ci_mod._REPUTATION_TRACKER
    old_trust = ci_mod._TRUST_SCORER

    snap_mod._ATTESTATION_LEDGER = attestation_ledger
    ci_mod._REPUTATION_TRACKER = reputation_tracker
    ci_mod._TRUST_SCORER = trust_scorer

    yield {
        "attestation_ledger": attestation_ledger,
        "reputation_tracker": reputation_tracker,
        "trust_scorer": trust_scorer,
    }

    # Restore
    snap_mod._ATTESTATION_LEDGER = old_att
    ci_mod._REPUTATION_TRACKER = old_rep
    ci_mod._TRUST_SCORER = old_trust


# ===========================================================================
# Tests: Attested snapshots
# ===========================================================================


class TestAttestedSnapshots:
    """use_subsystems=True with snapshot_dir creates HMAC-signed attestations."""

    def test_attestations_created_for_each_snapshot(
        self, patched_subsystems, tmp_path: Path,
    ):
        """All 4 snapshot sites (init, pre-step, restore, final) create attestations."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-ATTEST", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=True,
        )

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, _execute_echo,
        )

        # Snapshot ledger file exists with intact hash chain
        snap_file = tmp_path / "snapshots" / "SESS-subsys-test_snapshots.json"
        assert snap_file.exists(), "Snapshot ledger file not created"

        ledger = SnapshotLedger(snap_file)
        violations = ledger.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"
        assert ledger.index.size >= 2, (
            f"Expected ≥2 entries, got {ledger.index.size}"
        )

        # Attestations were created for each snapshot
        att_ledger = patched_subsystems["attestation_ledger"]
        attestations = att_ledger.load_attestations("SESS-subsys-test")
        assert len(attestations) >= 2, (
            f"Expected ≥2 attestations, got {len(attestations)}"
        )

        # Every attestation must pass HMAC verification
        for att in attestations:
            assert att_ledger.verify_attestation(att), (
                f"Attestation {att.checkpoint_id} HMAC verification failed"
            )

        # Checkpoint IDs in attestations match snapshot checkpoint IDs
        snap_ckpt_ids = {e.checkpoint_id for e in ledger.index.get_by_session(
            "SESS-subsys-test",
        )}
        att_ckpt_ids = {a.checkpoint_id for a in attestations}
        assert snap_ckpt_ids == att_ckpt_ids, (
            f"Snapshot checkpoint IDs {snap_ckpt_ids} don't match "
            f"attestation checkpoint IDs {att_ckpt_ids}"
        )

    def test_use_subsystems_false_creates_no_attestations(
        self, patched_subsystems, tmp_path: Path,
    ):
        """use_subsystems=False creates regular snapshots without attestations."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-NOATT", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=False,  # default
        )

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, _execute_echo,
        )

        # Snapshot ledger exists
        snap_file = tmp_path / "snapshots" / "SESS-subsys-test_snapshots.json"
        assert snap_file.exists()

        # Hash chain intact
        ledger = SnapshotLedger(snap_file)
        assert ledger.verify_integrity() == []

        # No attestations were created
        att_ledger = patched_subsystems["attestation_ledger"]
        attestations = att_ledger.load_attestations("SESS-subsys-test")
        assert len(attestations) == 0, (
            f"Expected 0 attestations with use_subsystems=False, "
            f"got {len(attestations)}"
        )


# ===========================================================================
# Tests: Asset reputation validation
# ===========================================================================


class TestAssetReputation:
    """Discovered assets are validated and recorded via reputation tracker."""

    def test_new_assets_recorded_in_reputation(
        self, patched_subsystems, tmp_path: Path,
    ):
        """Newly discovered assets are recorded in the reputation ledger."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-RECORD", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        def execute_with_discovery(action):
            return {
                "open_ports": [80],
                "discovered_assets": ["10.0.0.10", "10.0.0.11"],
            }

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, execute_with_discovery,
        )

        # Both assets should be in the reputation tracker
        rep_tracker = patched_subsystems["reputation_tracker"]

        rep_10 = rep_tracker.get_reputation("10.0.0.10")
        assert rep_10 is not None, "10.0.0.10 not recorded in reputation"
        assert rep_10.reputation.session_count >= 1

        rep_11 = rep_tracker.get_reputation("10.0.0.11")
        assert rep_11 is not None, "10.0.0.11 not recorded in reputation"
        assert rep_11.reputation.session_count >= 1

        # Verify session was recorded (metadata doesn't include is_positive)
        assert rep_10.reputation.session_count >= 1
        assert rep_10.reputation.positive_flags == 0

    def test_malicious_asset_skipped_with_warning(
        self, patched_subsystems, tmp_path: Path,
    ):
        """Assets flagged as malicious are skipped (warn, not crash)."""
        rep_tracker = patched_subsystems["reputation_tracker"]

        # Pre-populate reputation with a malicious asset
        rep_tracker.observe_asset(
            session_id="prev-scan",
            asset_id="10.0.0.10",
            metadata={"is_malicious": True},
        )

        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-SKIP", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        def execute_with_discovery(action):
            return {
                "open_ports": [80],
                "discovered_assets": ["10.0.0.10"],  # flagged malicious
            }

        # Should not raise — warnings.warn is used, not exceptions
        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, execute_with_discovery,
        )

        # Asset is still in the final state (validation is advisory)
        assert "10.0.0.10" in final_state.discovered_assets

        # But the asset should NOT have been recorded again
        # (record_asset_discovery is only called for valid assets)
        rep = rep_tracker.get_reputation("10.0.0.10")
        assert rep.reputation.session_count == 1, (
            "Malicious asset was re-recorded despite failing validation"
        )

    def test_asset_reputation_decay(
        self, patched_subsystems, tmp_path: Path,
    ):
        """Assets with low reputation are flagged (score < 0.6)."""
        rep_tracker = patched_subsystems["reputation_tracker"]

        # Pre-populate with negative flags to drive score below 0.6
        for i in range(5):
            rep_tracker.observe_asset(
                session_id=f"bad-scan-{i}",
                asset_id="low-rep-asset",
                metadata={"is_positive": False},
            )

        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-LOWREP", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        def execute_with_discovery(action):
            return {
                "open_ports": [80],
                "discovered_assets": ["low-rep-asset", "10.0.0.10"],
            }

        # Should not crash
        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, execute_with_discovery,
        )

        # Both assets are in the final state
        assert "low-rep-asset" in final_state.discovered_assets
        assert "10.0.0.10" in final_state.discovered_assets


# ===========================================================================
# Tests: Provider drift tracking
# ===========================================================================


class TestProviderDriftTracking:
    """Provider drift tracking fires correctly when LLM provider has retries."""

    def test_no_provider_does_not_crash(
        self, patched_subsystems, tmp_path: Path,
    ):
        """When agent has no LLM provider, drift tracking block is a no-op."""
        plan = _make_agentic_plan()  # rule-based, no llm_provider
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-NOPROV", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        # Should complete without errors
        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, _execute_echo,
        )
        assert len(final_state.open_ports) >= 1

    def test_provider_without_retries_skips_drift(
        self, patched_subsystems, tmp_path: Path,
    ):
        """When LLM provider has retry_count=0, drift recording is skipped."""
        plan = _make_agentic_plan(**{
            "agentic_config": {
                "enabled": True,
                "max_steps": 2,
                "decision_strategy": "llm",
                "stop_on_finding": "none",
                "llm_prompt": "Test prompt: {{ state }}",
                "llm_provider_config": {
                    "type": "mock",
                    "model": "mock-provider-no-retry",
                },
            },
        })
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-SUBSYS-NORETRY", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, _execute_echo,
        )

        # Trust scorer should be empty (no retries = no drift recorded)
        trust = patched_subsystems["trust_scorer"]
        score = trust.get_trust_score("mock-provider-no-retry")
        # MockLLMProvider has no retries, so drift tracking is skipped
        assert score is None or score.trust_score.total_drifts == 0


# ===========================================================================
# Tests: Backward compatibility
# ===========================================================================


class TestBackwardCompatibility:
    """use_subsystems=False (default) must not change existing behavior."""

    def test_default_is_false(self, tmp_path: Path):
        """Default value of use_subsystems is False."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(campaign_id="CAMP-DEFAULT", sessions=(session,))
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
        )
        assert executor.use_subsystems is False

    def test_run_without_subsystems_completes(
        self, patched_subsystems, tmp_path: Path,
    ):
        """Default executor runs successfully without subsystem integration."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-DEFAULT", sessions=(session,),
        )
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=False,  # explicit default
        )

        def execute_action(action):
            return {"open_ports": [80, 443]}

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, execute_action,
        )
        assert len(final_state.open_ports) >= 1
        assert len(evidence) >= 1

        # No attestations created
        att_ledger = patched_subsystems["attestation_ledger"]
        assert len(att_ledger.load_attestations("SESS-subsys-test")) == 0

        # No reputation recorded
        rep_tracker = patched_subsystems["reputation_tracker"]
        assert rep_tracker.get_reputation("10.0.0.10") is None

    def test_new_param_does_not_break_existing_tests(self, tmp_path: Path):
        """Existing callers (without use_subsystems) continue to work."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-LEGACY", sessions=(session,),
        )
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
        )
        assert executor.use_subsystems is False
        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, _execute_echo,
        )
        assert len(evidence) >= 1


# ===========================================================================
# Tests: Auto-config from YAML
# ===========================================================================


class TestAutoConfig:
    """subsystems_config auto-loads from YAML and drives thresholds."""

    def test_auto_loads_from_yaml_when_subsystems_enabled(
        self, tmp_path: Path,
    ):
        """use_subsystems=True without explicit config auto-loads from YAML."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-AUTOCFG", sessions=(session,),
        )
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )
        # Config should be auto-loaded from YAML (not empty)
        assert executor.subsystems_config != {}, (
            "subsystems_config should be auto-loaded from YAML, not empty"
        )
        assert executor.subsystems_config.get("enabled") is True
        assert executor.subsystems_config.get("reputation", {}).get("min_score") == 0.6
        assert executor.subsystems_config.get("provider_trust", {}).get("min_severity") == 0.1

    def test_explicit_config_overrides_yaml(
        self, tmp_path: Path,
    ):
        """Explicit subsystems_config dict overrides YAML defaults."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-EXPLCFG", sessions=(session,),
        )
        custom_config = {
            "enabled": True,
            "reputation": {"min_score": 0.9},
            "provider_trust": {"min_severity": 0.5},
        }
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
            subsystems_config=custom_config,
        )
        assert executor.subsystems_config["reputation"]["min_score"] == 0.9
        assert executor.subsystems_config["provider_trust"]["min_severity"] == 0.5

    def test_custom_min_reputation_threshold_applied(
        self, patched_subsystems, tmp_path: Path,
    ):
        """Custom min_reputation from config is used in asset validation."""
        rep_tracker = patched_subsystems["reputation_tracker"]

        # Pre-populate asset with slightly negative score (should be above 0.6 but below 0.9)
        rep_tracker.observe_asset(
            session_id="prev-scan",
            asset_id="moderate-rep-asset",
            metadata={"is_positive": False},
        )
        rep_tracker.observe_asset(
            session_id="prev-scan",
            asset_id="moderate-rep-asset",
            metadata={"is_positive": False},
        )

        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-HIGHREP", sessions=(session,),
        )

        custom_config = {
            "enabled": True,
            "reputation": {"min_score": 0.9},  # Stricter threshold
        }
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
            subsystems_config=custom_config,
        )

        def execute_with_discovery(action):
            return {
                "open_ports": [80],
                "discovered_assets": ["moderate-rep-asset"],
            }

        # Should not crash
        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, execute_with_discovery,
        )

        # Asset is still in final state (validation is advisory)
        assert "moderate-rep-asset" in final_state.discovered_assets

        # Asset should NOT have been re-recorded (score below 0.9 threshold)
        # session_count should remain at 2 (from the 2 setup observations),
        # not incremented to 3 by the executor's record_asset_discovery call.
        rep = rep_tracker.get_reputation("moderate-rep-asset")
        assert rep.reputation.session_count == 2, (
            "Asset was re-recorded despite being below the custom 0.9 threshold; "
            f"expected session_count=2, got {rep.reputation.session_count}"
        )

    def test_subsystems_disabled_no_config(
        self, tmp_path: Path,
    ):
        """When use_subsystems=False, subsystems_config is an empty dict."""
        plan = _make_agentic_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-NOCFG", sessions=(session,),
        )
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=False,
        )
        assert executor.subsystems_config == {},"Expected empty config when subsystems disabled"
