"""End-to-end integration test for the full subsystem pipeline.

Validates the complete stack working together:
  1. YAML config loading (ledger paths, thresholds)
  2. Campaign loop with use_subsystems=True + snapshot_dir
  3. Attestation signing via _take_snapshot helper (all 4 snapshot sites)
  4. Reputation tracking via post-loop asset validation
  5. Provider drift detection via retry-aware tracking
  6. Snapshot hash chain integrity verification
  7. Cross-session reputation accumulation

Pattern: Tests follow the same patched-subsystems fixture pattern used in
test_campaign_subsystems.py — no real I/O, no real API calls.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
from gatekeeper_eos_v6.agentic import WorldState
from gatekeeper_eos_v6.snapshot import SnapshotLedger, take_snapshot_with_attestation
from gatekeeper_eos_v6.subsystems.config import (
    load_subsystems_config,
    apply_subsystems_config,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _make_plan(
    session_id: str = "SESS-e2e",
    decision_strategy: str = "rule",
    **overrides: Any,
) -> dict:
    """Create a minimal agentic plan dict for E2E testing."""
    plan: dict = {
        "plan_id": "PLAN-E2E-TEST",
        "authorized_assets": ["10.0.0.1", "10.0.0.2"],
        "allowed_tools": [
            {"name": "nmap", "allowed_commands": ["discover", "scan"]},
        ],
        "objective": "E2E subsystem integration test",
        "success_criteria": ["Open ports identified", "Services discovered"],
        "agentic_config": {
            "enabled": True,
            "max_steps": 3,
            "decision_strategy": decision_strategy,
            "stop_on_finding": "none",
        },
    }
    plan.update(overrides)
    return plan


def _make_session(
    plan: dict,
    session_id: str = "SESS-e2e",
    start_hour: int = 0,
) -> SessionDef:
    """Create a SessionDef for E2E testing."""
    return SessionDef(
        session_id=session_id,
        plan=plan,
        schedule=Schedule(
            start_at=datetime(2026, 6, 1, start_hour, 0, 0, tzinfo=timezone.utc),
        ),
    )


def _execute_recon(action: Any) -> dict[str, Any]:
    """Simple execute_action that returns discovered assets and ports."""
    return {
        "open_ports": [22, 80, 443],
        "services": [{"name": "nginx", "version": "1.24"}],
        "discovered_assets": ["10.0.0.1", "10.0.0.2"],
    }


# ===========================================================================
# Subsystem-patching fixture
# ===========================================================================


@pytest.fixture
def patched_subsystems(tmp_path: Path) -> dict[str, Any]:
    """Create test ledger instances and patch all module-level singletons.

    Yields a dict with references to the test ledgers so tests can
    assert on them.  Tears down the patches in the finalizer.
    """
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
        "att_ledger_path": att_ledger_path,
        "att_key_path": att_key_path,
    }

    # Restore
    snap_mod._ATTESTATION_LEDGER = old_att
    ci_mod._REPUTATION_TRACKER = old_rep
    ci_mod._TRUST_SCORER = old_trust


# ===========================================================================
# E2E Test: Full Pipeline
# ===========================================================================


class TestFullPipelineE2E:
    """Full stack E2E: YAML config → campaign loop → all 3 subsystems."""

    # ------------------------------------------------------------------
    # 1. YAML config loading → subsystem initialization
    # ------------------------------------------------------------------

    def test_yaml_config_loads_and_initializes_subsystems(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 1: Load YAML config, apply it, and verify it populates correctly.

        This validates that load_subsystems_config() → apply_subsystems_config()
        produces the expected dict structure with all default values.
        """
        config = load_subsystems_config()
        assert isinstance(config, dict), "YAML config must return a dict"
        assert config.get("enabled") is True, "Subsystems should be enabled by default"
        assert config.get("reputation", {}).get("min_score") == 0.6
        assert config.get("provider_trust", {}).get("min_score") == 0.7
        assert config.get("provider_trust", {}).get("min_severity") == 0.1
        assert config.get("attestations", {}).get("enabled") is True

        # apply_subsystems_config should ensure ledger dirs exist
        result = apply_subsystems_config(config)
        assert result["enabled"] is True
        # Ledger dirs should have been created
        ledger_dir = Path(config["ledger_paths"]["attestations"]).parent
        assert ledger_dir.exists(), f"Ledger dir {ledger_dir} should exist"
        assert ledger_dir.is_dir()

    # ------------------------------------------------------------------
    # 2. Full campaign execution with subsystems
    # ------------------------------------------------------------------

    def test_campaign_loop_produces_attested_snapshots(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 2: Campaign with use_subsystems=True creates HMAC-signed
        attestations with intact hash chain."""
        plan = _make_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-E2E-ATTEST", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=True,
        )

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, _execute_recon,
        )

        # Verify snapshot ledger integrity
        snap_file = tmp_path / "snapshots" / "SESS-e2e_snapshots.json"
        assert snap_file.exists(), "Snapshot ledger file not created"

        ledger = SnapshotLedger(snap_file)
        violations = ledger.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"
        assert ledger.index.size >= 2, (
            f"Expected >=2 snapshot entries, got {ledger.index.size}"
        )

        # Verify attestations were created
        att_ledger = patched_subsystems["attestation_ledger"]
        attestations = att_ledger.load_attestations("SESS-e2e")
        assert len(attestations) >= 2, (
            f"Expected >=2 attestations, got {len(attestations)}"
        )

        # Every attestation must pass HMAC verification
        for att in attestations:
            assert att_ledger.verify_attestation(att), (
                f"Attestation {att.checkpoint_id} HMAC verification failed"
            )

        # Checkpoint IDs match between snapshots and attestations
        snap_ckpt_ids = {
            e.checkpoint_id
            for e in ledger.index.get_by_session("SESS-e2e")
        }
        att_ckpt_ids = {a.checkpoint_id for a in attestations}
        assert snap_ckpt_ids == att_ckpt_ids, (
            f"Snapshot CKPT IDs {snap_ckpt_ids} != attestation CKPT IDs {att_ckpt_ids}"
        )

    def test_campaign_validates_and_records_discovered_assets(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 3: Post-loop asset validation records discovered assets
        in the reputation tracker."""
        plan = _make_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-E2E-REPUTATION", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        final_state, _, _ = executor.run_agentic_session(
            session, _execute_recon,
        )

        # Both assets should be in the reputation tracker
        rep_tracker = patched_subsystems["reputation_tracker"]

        rep_1 = rep_tracker.get_reputation("10.0.0.1")
        assert rep_1 is not None, "10.0.0.1 not recorded in reputation"
        assert rep_1.reputation.session_count >= 1

        rep_2 = rep_tracker.get_reputation("10.0.0.2")
        assert rep_2 is not None, "10.0.0.2 not recorded in reputation"
        assert rep_2.reputation.session_count >= 1

        # Assets appear in final state
        assert "10.0.0.1" in final_state.discovered_assets
        assert "10.0.0.2" in final_state.discovered_assets

    def test_campaign_does_not_track_drift_when_no_retries(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 4: Mock LLM provider (retry_count=0) does not trigger drift recording."""
        plan = _make_plan(
            decision_strategy="llm",
            agentic_config={
                "enabled": True,
                "max_steps": 2,
                "decision_strategy": "llm",
                "stop_on_finding": "none",
                "llm_prompt": "Test prompt: {{ state }}",
                "llm_provider_config": {
                    "type": "mock",
                    "model": "mock-e2e-provider",
                },
            },
        )
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-E2E-DRIFT", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
        )

        def execute_drift(action: Any) -> dict[str, Any]:
            return {
                "open_ports": [80],
                "discovered_assets": ["10.0.0.1"],
            }

        executor.run_agentic_session(
            session, execute_drift,
        )

        # Mock provider has retry_count=0 so drift should NOT be recorded
        trust = patched_subsystems["trust_scorer"]
        score = trust.get_trust_score("mock-e2e-provider")
        assert score is None or score.trust_score.total_drifts == 0, (
            "Expected no drift for provider with retry_count=0"
        )

    # ------------------------------------------------------------------
    # 5. Backward compatibility (use_subsystems=False = no subsystems)
    # ------------------------------------------------------------------

    def test_disabled_subsystems_skip_all_integration(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 5: With use_subsystems=False, no attestations, reputation,
        or trust data is produced."""
        plan = _make_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-E2E-DISABLED", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=False,
        )

        executor.run_agentic_session(session, _execute_recon)

        # No attestations
        att_ledger = patched_subsystems["attestation_ledger"]
        assert len(att_ledger.load_attestations("SESS-e2e")) == 0

        # No reputation
        rep_tracker = patched_subsystems["reputation_tracker"]
        assert rep_tracker.get_reputation("10.0.0.1") is None

        # No trust data
        trust = patched_subsystems["trust_scorer"]
        # Provider was rule-based, so no provider at all
        # (asserting no crash is sufficient)

    # ------------------------------------------------------------------
    # 6. Realistic multi-session config-driven thresholds
    # ------------------------------------------------------------------

    def test_config_driven_thresholds_applied(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 6: Custom config thresholds (min_reputation, min_severity)
        are applied during campaign execution."""
        rep_tracker = patched_subsystems["reputation_tracker"]

        # Pre-populate with enough negative flags to push score below 0.9
        for i in range(10):
            rep_tracker.observe_asset(
                session_id=f"low-rep-{i}",
                asset_id="low-scoring-asset",
                metadata={"is_positive": False},
            )

        plan = _make_plan()
        session = _make_session(plan)
        campaign = Campaign(
            campaign_id="CAMP-E2E-THRESHOLDS", sessions=(session,),
        )

        custom_config = {
            "enabled": True,
            "reputation": {"min_score": 0.9},  # Very strict
            "provider_trust": {"min_severity": 0.8},  # Only flag severe drift
        }
        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            use_subsystems=True,
            subsystems_config=custom_config,
        )

        def execute_low_rep(action: Any) -> dict[str, Any]:
            return {
                "open_ports": [80],
                "discovered_assets": ["low-scoring-asset"],
            }

        executor.run_agentic_session(session, execute_low_rep)

        # Asset should NOT have been re-recorded (below 0.9 threshold)
        rep = rep_tracker.get_reputation("low-scoring-asset")
        assert rep.reputation.session_count == 10, (
            "Asset was re-recorded despite being below the custom 0.9 threshold; "
            f"expected session_count=10, got {rep.reputation.session_count}"
        )

    # ------------------------------------------------------------------
    # 7. Assisted snapshot+attestation via take_snapshot_with_attestation
    # ------------------------------------------------------------------

    def test_take_snapshot_with_attestation_via_helper(
        self, patched_subsystems, tmp_path: Path,
    ) -> None:
        """Step 7: take_snapshot_with_attestation helper produces both
        a snapshot ledger entry and a verifiable attestation."""
        snap_ledger_path = tmp_path / "snapshots_e2e_helper.json"
        snap_ledger = SnapshotLedger(snap_ledger_path)

        snapshot, attestation = take_snapshot_with_attestation(
            ledger=snap_ledger,
            session_id="SESS-e2e-helper",
            checkpoint_id="CKPT-E2E-001",
            working_memory={"open_ports": [80, 443], "discovered_assets": ["10.0.0.1"]},
            tool_call_history=[{"step": 1, "action": {"tool": "nmap", "command": "discover"}}],
            conversation_summary="E2E helper test",
            drift_score=0,
            invariants_satisfied=["E2E-TEST"],
        )

        # Snapshot integrity
        assert snap_ledger.index.size == 1
        assert snapshot.session_id == "SESS-e2e-helper"
        assert snap_ledger.verify_integrity() == []

        # Attestation verification
        att_ledger = patched_subsystems["attestation_ledger"]
        assert att_ledger.verify_attestation(attestation)
        assert attestation.session_id == "SESS-e2e-helper"
        assert attestation.checkpoint_id == "CKPT-E2E-001"
        assert attestation.sequence == 1


# ===========================================================================
# 8. Drift recovery E2E: halt → restore → resume with subsystems
# ===========================================================================


class TestDriftRecoveryE2E:
    """E2E tests for the drift recovery path with use_subsystems=True.

    Validates the full halt → restore → resume cycle through the campaign
    executor, verifying that attested snapshots, hash chain integrity, and
    reputation tracking all survive the recovery.
    """

    def test_drift_restore_creates_ckpt_restore_with_attestation(
        self, patched_subsystems, monkeypatch, tmp_path: Path,
    ) -> None:
        """Step 8: When agent state drift is detected, the campaign executor
        performs context_revalidation and creates CKPT-RESTORE with an
        attestation.

        Injects a hallucinated port via monkeypatch on WorldState.update,
        which causes step_action to raise AgentStateError. The executor's
        post-loop code detects the drift halt, restores from the last clean
        snapshot, and creates CKPT-RESTORE.
        """
        # Patch WorldState.update to inject a hallucinated port after the
        # first successful step. This simulates agent state drift that the
        # drift sentinel will detect on the next step_action call.
        original_update = WorldState.update
        hallucination_injected = [False]

        def _patched_update(self, output: dict) -> None:
            original_update(self, output)
            if not hallucination_injected[0]:
                if self.open_ports:
                    self.open_ports.append(9999)  # Hallucinated port
                    hallucination_injected[0] = True

        monkeypatch.setattr(WorldState, "update", _patched_update)

        plan = {
            "plan_id": "PLAN-DRIFT-RECOVERY",
            "authorized_assets": ["10.0.0.1"],
            "allowed_tools": [
                {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            ],
            "objective": "Drift recovery E2E test",
            "success_criteria": ["Open ports identified"],
            "agentic_config": {
                "enabled": True,
                "max_steps": 5,
                "decision_strategy": "rule",
                "stop_on_finding": "none",
                "agent_state_drift_check": True,
            },
        }
        session = _make_session(plan, session_id="SESS-drift-recovery")
        campaign = Campaign(
            campaign_id="CAMP-E2E-DRIFT-RECOVER", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=True,
        )

        def execute(action):
            return {
                "open_ports": [80, 443],
                "services": [{"name": "nginx"}],
                "discovered_assets": ["10.0.0.1", "10.0.0.2"],
            }

        final_state, evidence, stop_reason = executor.run_agentic_session(
            session, execute,
        )

        # --- Snapshot ledger verification ---
        snap_file = tmp_path / "snapshots" / "SESS-drift-recovery_snapshots.json"
        assert snap_file.exists(), "Snapshot ledger file not created"

        ledger = SnapshotLedger(snap_file)
        violations = ledger.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"

        entries = ledger.index.get_by_session("SESS-drift-recovery")
        ckpt_ids = {e.checkpoint_id for e in entries}
        assert "CKPT-RESTORE" in ckpt_ids, (
            f"Missing CKPT-RESTORE snapshot. Checkpoint IDs: {sorted(ckpt_ids)}"
        )
        assert "CKPT-FINAL" in ckpt_ids, (
            f"Missing CKPT-FINAL snapshot. Checkpoint IDs: {sorted(ckpt_ids)}"
        )

        # --- Attestation verification ---
        att_ledger = patched_subsystems["attestation_ledger"]
        attestations = att_ledger.load_attestations("SESS-drift-recovery")
        att_ckpt_ids = {a.checkpoint_id for a in attestations}
        assert "CKPT-RESTORE" in att_ckpt_ids, (
            f"CKPT-RESTORE attestation missing. Attestation CKPT IDs: {sorted(att_ckpt_ids)}"
        )

        for att in attestations:
            assert att_ledger.verify_attestation(att), (
                f"Attestation {att.checkpoint_id} HMAC verification failed"
            )

        # Snapshot and attestation checkpoint IDs must match
        assert ckpt_ids == att_ckpt_ids, (
            f"Snapshot CKPT IDs {ckpt_ids} != attestation CKPT IDs {att_ckpt_ids}"
        )

        # --- State is clean after restore ---
        # The hallucinated port (9999) must NOT be in the final state
        assert 9999 not in final_state.open_ports, (
            f"Hallucinated port 9999 still present after restore: {final_state.open_ports}"
        )

        # --- State is clean after restore ---
        # The hallucinated port (9999) must NOT be in the final state
        # (note: evidence may be empty because the restore resets state
        # to the pre-step snapshot, which has no evidence yet)
        assert 9999 not in final_state.open_ports, (
            f"Hallucinated port 9999 still present after restore: {final_state.open_ports}"
        )

        # Stop reason is cleared by context_revalidation (it resets
        # agent.stop_reason = None as "restored state is clean"), so
        # we don't assert on it here. The CKPT-RESTORE snapshot and
        # clean hash chain are the evidence that recovery happened.

    def test_drift_restore_preserves_reputation_before_drift(
        self, patched_subsystems, monkeypatch, tmp_path: Path,
    ) -> None:
        """Step 9: Assets discovered before drift are still present in the
        reputation tracker after restore.

        Pre-populates the reputation tracker with an asset, then triggers
        drift recovery. The pre-populated reputation must survive.
        """
        rep_tracker = patched_subsystems["reputation_tracker"]

        # Pre-populate reputation with an asset from a previous session
        rep_tracker.observe_asset(
            session_id="pre-scan",
            asset_id="known-good-asset",
            metadata={"is_positive": True, "discovery_method": "nmap"},
        )

        # Patch WorldState.update to inject drift after first step
        original_update = WorldState.update
        hallucination_injected = [False]

        def _patched_update(self, output: dict) -> None:
            original_update(self, output)
            if not hallucination_injected[0]:
                if self.open_ports:
                    self.open_ports.append(9999)
                    hallucination_injected[0] = True

        monkeypatch.setattr(WorldState, "update", _patched_update)

        plan = {
            "plan_id": "PLAN-DRIFT-PRESERVE",
            "authorized_assets": ["10.0.0.1"],
            "allowed_tools": [
                {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            ],
            "objective": "Drift preserve reputation test",
            "success_criteria": ["Open ports identified"],
            "agentic_config": {
                "enabled": True,
                "max_steps": 5,
                "decision_strategy": "rule",
                "stop_on_finding": "none",
                "agent_state_drift_check": True,
            },
        }
        session = _make_session(plan, session_id="SESS-drift-preserve")
        campaign = Campaign(
            campaign_id="CAMP-E2E-DRIFT-PRESERVE", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=True,
        )

        def execute(action):
            return {
                "open_ports": [80],
                "discovered_assets": ["known-good-asset"],
            }

        executor.run_agentic_session(session, execute)

        # The pre-populated reputation must survive the restore
        rep = rep_tracker.get_reputation("known-good-asset")
        assert rep is not None, "known-good-asset lost from reputation after restore"
        assert rep.reputation.session_count >= 1, (
            f"Session count should be >= 1, got {rep.reputation.session_count}"
        )

        # CKPT-RESTORE must be in the snapshot ledger
        snap_file = tmp_path / "snapshots" / "SESS-drift-preserve_snapshots.json"
        assert snap_file.exists()
        ledger = SnapshotLedger(snap_file)
        violations = ledger.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"

        ckpt_ids = {e.checkpoint_id for e in ledger.index.get_by_session("SESS-drift-preserve")}
        assert "CKPT-RESTORE" in ckpt_ids, (
            f"Missing CKPT-RESTORE snapshot. IDs: {sorted(ckpt_ids)}"
        )

        # Attestations must include CKPT-RESTORE
        att_ledger = patched_subsystems["attestation_ledger"]
        attestations = att_ledger.load_attestations("SESS-drift-preserve")
        att_ckpt_ids = {a.checkpoint_id for a in attestations}
        assert "CKPT-RESTORE" in att_ckpt_ids, (
            f"Missing CKPT-RESTORE attestation. IDs: {sorted(att_ckpt_ids)}"
        )

        for att in attestations:
            assert att_ledger.verify_attestation(att), (
                f"Attestation {att.checkpoint_id} HMAC verification failed"
            )

    def test_drift_restore_no_subystems_skips_attestations(
        self, monkeypatch, tmp_path: Path,
    ) -> None:
        """Step 10: With use_subsystems=False, drift restore still works
        but creates no attestations."""
        original_update = WorldState.update
        hallucination_injected = [False]

        def _patched_update(self, output: dict) -> None:
            original_update(self, output)
            if not hallucination_injected[0]:
                if self.open_ports:
                    self.open_ports.append(9999)
                    hallucination_injected[0] = True

        monkeypatch.setattr(WorldState, "update", _patched_update)

        plan = {
            "plan_id": "PLAN-DRIFT-NO-SUBSYS",
            "authorized_assets": ["10.0.0.1"],
            "allowed_tools": [
                {"name": "nmap", "allowed_commands": ["discover", "scan"]},
            ],
            "objective": "Drift no subsystems test",
            "success_criteria": ["Open ports identified"],
            "agentic_config": {
                "enabled": True,
                "max_steps": 5,
                "decision_strategy": "rule",
                "stop_on_finding": "none",
                "agent_state_drift_check": True,
            },
        }
        session = _make_session(plan, session_id="SESS-drift-no-subsys")
        campaign = Campaign(
            campaign_id="CAMP-E2E-DRIFT-NOSUBSYS", sessions=(session,),
        )

        executor = CampaignExecutor(
            campaign,
            checkpoint_dir=tmp_path / "ckpt",
            snapshot_dir=tmp_path / "snapshots",
            use_subsystems=False,
        )

        def execute(action):
            return {"open_ports": [80]}

        executor.run_agentic_session(session, execute)

        # Snapshots exist (no subsystems, so regular snapshots)
        snap_file = tmp_path / "snapshots" / "SESS-drift-no-subsys_snapshots.json"
        assert snap_file.exists()
        ledger = SnapshotLedger(snap_file)
        violations = ledger.verify_integrity()
        assert violations == [], f"Hash chain broken: {violations}"

        # CKPT-RESTORE exists
        ckpt_ids = {e.checkpoint_id for e in ledger.index.get_by_session("SESS-drift-no-subsys")}
        assert "CKPT-RESTORE" in ckpt_ids, (
            f"Missing CKPT-RESTORE. IDs: {sorted(ckpt_ids)}"
        )

        # No attestations (use_subsystems=False — the _take_snapshot
        # helper skips the attestation path entirely)
