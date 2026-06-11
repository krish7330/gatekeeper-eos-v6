"""Integration tests for subsystems — cross-subsystem workflows.

Tests cover:
- Snapshot + signed attestations working together
- Reputation + provider trust working together
- Full three-subsystem workflow
"""

import os
from pathlib import Path

import pytest

from gatekeeper_eos_v6.subsystems import (
    ReputationTracker,
    AttestationLedger,
    ProviderTrustScorer,
)


# ============================================================================
# Integration: Snapshot + Attestations
# ============================================================================


class TestSnapshotAttestationIntegration:
    """Test snapshot ledger with signed attestations."""

    @pytest.fixture
    def setup_ledgers(self, tmp_path: Path):
        """Create both ledger instances."""
        snapshot_ledger_path = tmp_path / "snapshots.json"
        attestation_ledger_path = tmp_path / "attestations.json"
        private_key_path = tmp_path / "private_key"

        # Create private key
        private_key = os.urandom(32)
        private_key_path.write_bytes(private_key)

        from gatekeeper_eos_v6.snapshot import SnapshotLedger

        snapshot_ledger = SnapshotLedger(snapshot_ledger_path)
        attestation_ledger = AttestationLedger(
            attestation_ledger_path, private_key_path
        )

        return {
            "snapshot": snapshot_ledger,
            "attestation": attestation_ledger,
            "private_key": private_key,
        }

    def test_create_snapshot_with_attestation(self, setup_ledgers):
        """Create snapshot and verify both ledgers are updated."""
        snapshot_ledger = setup_ledgers["snapshot"]
        attestation_ledger = setup_ledgers["attestation"]

        snapshot = snapshot_ledger.append(
            session_id="sess-1",
            checkpoint_id="ckpt-1",
            working_memory={"key": "value"},
            tool_call_history=[{"action": "test"}],
            conversation_summary="Test conversation",
            drift_score=0,
        )

        attestation = attestation_ledger.create_attestation(
            session_id="sess-1",
            checkpoint_id="ckpt-1",
            state={
                "working_memory": {"key": "value"},
                "snapshot_sequence": snapshot.sequence,
            },
            metadata={"checkpoint_id": "ckpt-1"},
        )

        assert snapshot_ledger.index.size == 1
        assert snapshot.sequence == 0
        assert attestation_ledger.verify_attestation(attestation)

        attestations = attestation_ledger.load_attestations("sess-1")
        assert len(attestations) == 1
        assert attestations[0].checkpoint_id == "ckpt-1"

    def test_independent_integrity_across_ledgers(self, setup_ledgers):
        """Snapshot and attestation integrity are independent — tampering
        snapshot does not break the attestation (they cover different state)."""
        snapshot_ledger = setup_ledgers["snapshot"]
        attestation_ledger = setup_ledgers["attestation"]

        snapshot = snapshot_ledger.append(
            session_id="sess-1",
            checkpoint_id="ckpt-1",
            working_memory={"original": "data"},
        )

        attestation = attestation_ledger.create_attestation(
            session_id="sess-1",
            checkpoint_id="ckpt-1",
            state={"working_memory": {"original": "data"}},
        )

        assert snapshot_ledger.verify_integrity() == []
        assert attestation_ledger.verify_attestation(attestation)

        # Tamper with snapshot state — snapshot integrity breaks
        snapshot.working_memory["original"] = "tampered"
        assert len(snapshot_ledger.verify_integrity()) > 0

        # The attestation was created over an independent state dict,
        # so tampering the snapshot does NOT affect the attestation.
        assert attestation_ledger.verify_attestation(attestation) is True

        # Tampering the attestation's own state DOES break verification
        attestation.state["working_memory"]["original"] = "tampered"
        assert attestation_ledger.verify_attestation(attestation) is False

    def test_take_snapshot_with_attestation_helper(self, setup_ledgers):
        """Take snapshot with attestation using the helper function."""
        snapshot_ledger = setup_ledgers["snapshot"]
        attestation_ledger = setup_ledgers["attestation"]

        from gatekeeper_eos_v6.snapshot import take_snapshot_with_attestation

        # Patch the module-level ledger for testing
        import gatekeeper_eos_v6.snapshot as snap_mod
        snap_mod._ATTESTATION_LEDGER = attestation_ledger

        try:
            snapshot, attestation = take_snapshot_with_attestation(
                ledger=snapshot_ledger,
                session_id="sess-1",
                checkpoint_id="ckpt-1",
                working_memory={"ports": [80, 443]},
                tool_call_history=[{"action": "nmap", "args": "-sV"}],
                conversation_summary="Initial scan",
                drift_score=0,
                invariants_satisfied=["INV-NO-DRIFT"],
            )

            assert snapshot_ledger.index.size == 1
            assert snapshot.session_id == "sess-1"
            assert attestation_ledger.verify_attestation(attestation)
            assert attestation.session_id == "sess-1"
            assert attestation.checkpoint_id == "ckpt-1"
        finally:
            snap_mod._ATTESTATION_LEDGER = None


# ============================================================================
# Integration: Reputation + Provider Trust
# ============================================================================


class TestReputationTrustIntegration:
    """Test reputation tracker with provider trust scoring."""

    @pytest.fixture
    def setup_trackers(self, tmp_path: Path):
        rep_ledger_path = tmp_path / "reputation.json"
        trust_ledger_path = tmp_path / "trust.json"

        rep_tracker = ReputationTracker(rep_ledger_path)
        trust_scorer = ProviderTrustScorer(trust_ledger_path)

        return {
            "reputation": rep_tracker,
            "trust": trust_scorer,
        }

    def test_asset_reputation_with_provider_drift(self, setup_trackers):
        """Track asset reputation and provider drift together."""
        rep = setup_trackers["reputation"]
        trust = setup_trackers["trust"]

        rep_record = rep.observe_asset(
            session_id="sess-1",
            asset_id="192.168.1.1:8080",
            metadata={"is_positive": True, "provider": "openai-gpt-4o-mini"},
        )

        trust_metrics = trust.record_drift(
            provider_id="openai-gpt-4o-mini",
            drift_type="false_positive",
            severity=0.7,
            metadata={"asset_id": "192.168.1.1:8080"},
        )

        assert rep_record.reputation.session_count == 1
        assert rep_record.reputation.positive_flags == 1
        assert trust_metrics.trust_score.total_drifts == 1
        assert trust_metrics.trust_score.false_positives == 1

    def test_cross_reference_with_trust(self, setup_trackers):
        """Cross-reference assets and verify trust scores are independent."""
        rep = setup_trackers["reputation"]
        trust = setup_trackers["trust"]

        rep.observe_asset("sess-1", "asset-1", {
            "is_positive": True,
        })
        rep.observe_asset("sess-2", "asset-1", {
            "is_malicious": True,
        })

        trust.record_drift("prov-a", "false_positive", 0.8)
        trust.record_drift("prov-b", "hallucinated_finding", 0.9)

        rep_record = rep.get_reputation("asset-1")
        assert rep_record.is_flagged_malicious is True
        assert rep_record.reputation.negative_flags >= 1

        prov_a = trust.get_trust_score("prov-a")
        prov_b = trust.get_trust_score("prov-b")
        assert prov_a is not None
        assert prov_b is not None


# ============================================================================
# Integration: All Three Subsystems
# ============================================================================


class TestFullStackIntegration:
    """Test all three subsystems working together."""

    @pytest.fixture
    def setup_full_stack(self, tmp_path: Path):
        rep_path = tmp_path / "reputation.json"
        att_path = tmp_path / "attestations.json"
        trust_path = tmp_path / "trust.json"
        key_path = tmp_path / "private_key"

        key = os.urandom(32)
        key_path.write_bytes(key)

        return {
            "reputation": ReputationTracker(rep_path),
            "attestations": AttestationLedger(att_path, key_path),
            "trust": ProviderTrustScorer(trust_path),
        }

    def test_full_workflow(self, setup_full_stack):
        """Complete workflow: discover asset → create snapshot → track drift."""
        rep = setup_full_stack["reputation"]
        att = setup_full_stack["attestations"]
        trust = setup_full_stack["trust"]

        # Step 1: Discover asset
        asset_id = "192.168.1.1:8080"
        rep_record = rep.observe_asset(
            session_id="scan-session-1",
            asset_id=asset_id,
            metadata={"is_positive": True, "discovery_method": "nmap"},
        )

        # Step 2: Create snapshot with attestation
        attestation = att.create_attestation(
            session_id="scan-session-1",
            checkpoint_id="checkpoint-1",
            state={
                "discovered_assets": [asset_id],
                "scan_results": {"ports": [8080]},
            },
            metadata={"reputation_score": rep_record.reputation.score},
        )

        # Step 3: Track provider drift
        trust.record_drift(
            provider_id="openai-gpt-4o-mini",
            drift_type="false_positive",
            severity=0.6,
            metadata={"asset_id": asset_id},
        )

        # Verify all three
        assert rep.get_reputation(asset_id).reputation.session_count == 1
        assert att.verify_attestation(attestation)
        assert (
            trust.get_trust_score("openai-gpt-4o-mini").trust_score.total_drifts == 1
        )
