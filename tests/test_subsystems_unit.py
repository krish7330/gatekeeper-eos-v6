"""Unit tests for gatekeeper-eos-v6 security subsystems.

Expanded coverage beyond the smoke test — tests for all major code paths,
edge cases, and the HMAC sign/verify cycle.
"""

import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from gatekeeper_eos_v6.subsystems import (
    ReputationTracker,
    ReputationScore,
    AssetReputation,
    AttestationLedger,
    SignedAttestation,
    AttestationError,
    ProviderTrustScorer,
    TrustScore,
    ProviderMetrics,
)


# ============================================================================
# Reputation Tracker Tests
# ============================================================================


class TestReputationScore:
    """Tests for the ReputationScore static compute method."""

    def test_fresh_asset_returns_bayesian_prior(self):
        """A never-seen asset gets 0.5 from Beta(1,1) prior."""
        score = ReputationScore.compute_score(0, 0, 0, "2026-06-08T00:00:00Z")
        assert 0.49 < score < 0.51

    def test_perfect_asset_approaches_one(self):
        """Many positive, zero negative → score near 1.0."""
        score = ReputationScore.compute_score(100, 100, 0, "2026-06-08T00:00:00Z")
        assert score > 0.98

    def test_flagged_asset_approaches_zero(self):
        """Many malicious flags → score near 0.0."""
        score = ReputationScore.compute_score(10, 0, 10, "2026-06-08T00:00:00Z")
        assert score < 0.15

    def test_score_clamped(self):
        """compute_score never returns outside [0, 1]."""
        for _ in range(100):
            s = ReputationScore.compute_score(50, 50, 50, "2026-06-08T00:00:00Z")
            assert 0.0 <= s <= 1.0

    def test_decay_reduces_score(self):
        """Same asset, older last_seen → lower score."""
        now = ReputationScore.compute_score(5, 4, 1, "2026-06-08T00:00:00Z")
        old = ReputationScore.compute_score(5, 4, 1, "2025-06-08T00:00:00Z")  # 365 days ago
        assert old < now


class TestReputationTracker:
    """Tests for ReputationTracker (integration with ledger)."""

    @pytest.fixture
    def tracker(self, tmp_path: Path):
        ledger_path = tmp_path / "reputation_ledger.json"
        return ReputationTracker(ledger_path)

    def test_observe_asset_first_time(self, tracker):
        """First observation creates a new record with session_count=1."""
        record = tracker.observe_asset(
            session_id="sess-1",
            asset_id="10.0.0.1:22",
            metadata={"is_positive": True},
        )
        assert record.asset_id == "10.0.0.1:22"
        assert record.reputation.session_count == 1
        assert record.reputation.positive_flags == 1
        assert record.is_flagged_malicious is False

    def test_observe_asset_multiple_sessions(self, tracker):
        """Multiple observations increment counters correctly."""
        for i in range(5):
            tracker.observe_asset(
                session_id=f"sess-{i}",
                asset_id="asset-1",
                metadata={"is_positive": True},
            )
        record = tracker.get_reputation("asset-1")
        assert record is not None
        assert record.reputation.session_count == 5
        assert record.reputation.positive_flags == 5

    def test_observe_asset_malicious_flag(self, tracker):
        """A malicious flag sets is_flagged_malicious and increments negative_flags."""
        tracker.observe_asset("sess-1", "bad-host", {"is_malicious": True, "reason": "known C2"})
        record = tracker.get_reputation("bad-host")
        assert record is not None
        assert record.is_flagged_malicious is True
        assert record.reputation.negative_flags == 1

    def test_get_reputation_nonexistent_returns_none(self, tracker):
        """Getting reputation for an unseen asset returns None."""
        assert tracker.get_reputation("never-seen") is None

    def test_cross_reference_returns_attestations(self, tracker):
        """cross_reference returns all attestations for an asset."""
        tracker.observe_asset("sess-1", "target", {"is_positive": True})
        tracker.observe_asset("sess-2", "target", {"is_positive": True})
        attestations = tracker.cross_reference("target")
        assert len(attestations) == 2

    def test_cross_reference_nonexistent_returns_empty(self, tracker):
        """cross_reference for unseen asset returns empty list."""
        assert tracker.cross_reference("ghost") == []

    def test_reputation_persists_across_instances(self, tmp_path):
        """Loading from same ledger file recovers reputation."""
        p = tmp_path / "rep.json"
        t1 = ReputationTracker(p)
        t1.observe_asset("sess-1", "persist-test", {"is_positive": True})
        t2 = ReputationTracker(p)
        record = t2.get_reputation("persist-test")
        assert record is not None
        assert record.reputation.session_count >= 1

    def test_ledger_file_created(self, tmp_path):
        """Ledger file is created on first observation."""
        p = tmp_path / "new_rep.json"
        t = ReputationTracker(p)
        t.observe_asset("sess-1", "a", {"is_positive": True})
        assert p.exists()
        data = json.loads(p.read_text())
        assert len(data) == 1


# ============================================================================
# Signed Attestations Tests
# ============================================================================


class TestSignedAttestation:
    """Tests for the SignedAttestation data class (unit-level)."""

    def test_compute_state_hash_is_deterministic(self):
        """Same state produces the same hash."""
        state = {"ports": [80, 443], "tags": ["web"]}
        h1 = SignedAttestation._compute_state_hash(state)
        h2 = SignedAttestation._compute_state_hash(state)
        assert h1 == h2

    def test_compute_state_hash_changes_with_data(self):
        """Different states produce different hashes."""
        h1 = SignedAttestation._compute_state_hash({"a": 1})
        h2 = SignedAttestation._compute_state_hash({"a": 2})
        assert h1 != h2

    def test_chain_hash_links_entries(self):
        """chain_hash depends on prev_chain_hash."""
        state_hash = "abcd" * 16  # 64 hex chars
        ch1 = SignedAttestation._compute_chain_hash("", state_hash)
        ch2 = SignedAttestation._compute_chain_hash("different_prev", state_hash)
        assert ch1 != ch2


class TestAttestationLedger:
    """Tests for AttestationLedger (integration with ledger + keys)."""

    @pytest.fixture
    def ledger(self, tmp_path: Path):
        ledger_path = tmp_path / "attestations.json"
        key_path = tmp_path / "private_key"
        key = os.urandom(32)
        key_path.write_bytes(key)
        return AttestationLedger(ledger_path, key_path)

    def test_create_and_verify(self, ledger):
        """A freshly created attestation verifies successfully."""
        att = ledger.create_attestation(
            session_id="SESS-001",
            checkpoint_id="CKPT-0001-init",
            state={"working_memory": {"step": 0}},
        )
        assert ledger.verify_attestation(att) is True
        assert len(att.signature) == 64  # hex-encoded SHA-256 HMAC

    def test_tampered_state_fails_verification(self, ledger):
        """Modifying the state after creation invalidates the signature."""
        att = ledger.create_attestation("SESS-001", "CKPT-0002", {"original": "data"})
        assert ledger.verify_attestation(att) is True
        att.state["original"] = "tampered"
        assert ledger.verify_attestation(att) is False

    def test_tampered_chain_hash_fails_verification(self, ledger):
        """Modifying chain_hash directly should fail."""
        att = ledger.create_attestation("SESS-001", "CKPT-0003", {"seq": 1})
        orig_sig = att.signature
        att.chain_hash = "0" * 64
        assert ledger.verify_attestation(att) is False

    def test_chain_hash_linking(self, ledger):
        """Subsequent entries chain to previous ones."""
        a1 = ledger.create_attestation("S", "C1", {"n": 1})
        a2 = ledger.create_attestation("S", "C2", {"n": 2})
        assert a2.prev_chain_hash == a1.chain_hash
        assert a1.prev_chain_hash == ""  # genesis

    def test_load_attestations_by_session(self, ledger):
        """load_attestations filters by session_id."""
        ledger.create_attestation("SESS-A", "C1", {})
        ledger.create_attestation("SESS-A", "C2", {})
        ledger.create_attestation("SESS-B", "C1", {})
        a = ledger.load_attestations("SESS-A")
        b = ledger.load_attestations("SESS-B")
        assert len(a) == 2
        assert len(b) == 1

    def test_no_private_key_raises(self):
        """Creating an attestation without a key raises AttestationLedgerError."""
        # No key_path and no env var
        if "ATTESTATION_PRIVATE_KEY" in os.environ:
            old = os.environ.pop("ATTESTATION_PRIVATE_KEY")
        else:
            old = None
        try:
            bad = AttestationLedger(Path("/tmp/nonexistent/no_key_ledger.json"))
            with pytest.raises(AttestationError):
                bad.create_attestation("S", "C", {})
        finally:
            if old is not None:
                os.environ["ATTESTATION_PRIVATE_KEY"] = old

    def test_ledger_file_created_on_init(self, tmp_path):
        """Ledger file is written on first __init__ if missing."""
        p = tmp_path / "fresh_ledger.json"
        assert not p.exists()
        _ = AttestationLedger(p, private_key_path=tmp_path / "key")
        assert p.exists()

    def test_env_var_key_fallback(self, tmp_path, monkeypatch):
        """Private key can come from ATTESTATION_PRIVATE_KEY env var.

        _init_keys() should check the env var before generating a random key.
        """
        key = os.urandom(32)
        monkeypatch.setenv("ATTESTATION_PRIVATE_KEY", key.hex())
        ledger = AttestationLedger(
            ledger_path=tmp_path / "env_key_ledger.json",
            private_key_path=None,
        )
        # _init_keys() should use the env var key instead of generating new one
        att = ledger.create_attestation("S", "C", {"test": True})
        assert ledger.verify_attestation(att) is True


# ============================================================================
# Provider Trust Scorer Tests
# ============================================================================


class TestTrustScore:
    """Tests for the TrustScore static compute method."""

    def test_no_drift_is_perfect(self):
        """A provider with zero drift events has score 1.0."""
        assert TrustScore.compute_score(0, 0, 0, "2026-06-08T00:00:00Z") == 1.0

    def test_hallucination_weighs_more_than_false_positive(self):
        """Hallucinated findings incur a higher penalty than false positives."""
        # 3 false positives vs 3 hallucinations
        fp_score = TrustScore.compute_score(3, 0, 3, "2026-06-08T00:00:00Z")
        hall_score = TrustScore.compute_score(0, 3, 3, "2026-06-08T00:00:00Z")
        assert hall_score < fp_score

    def test_score_decays_with_age(self):
        """Older drift events result in lower score."""
        recent = TrustScore.compute_score(1, 1, 2, "2026-06-08T00:00:00Z")
        old = TrustScore.compute_score(1, 1, 2, "2025-06-08T00:00:00Z")
        assert old < recent

    def test_no_negative_score(self):
        """Compute_score never returns below 0."""
        score = TrustScore.compute_score(100, 100, 200, "2026-06-08T00:00:00Z")
        assert score >= 0.0


class TestProviderTrustScorer:
    """Tests for ProviderTrustScorer (integration with ledger)."""

    @pytest.fixture
    def scorer(self, tmp_path: Path):
        ledger_path = tmp_path / "provider_ledger.json"
        return ProviderTrustScorer(ledger_path)

    def test_record_false_positive(self, scorer):
        """Recording a false positive increments that counter."""
        m = scorer.record_drift("p1", "false_positive", 0.5)
        assert m.trust_score.false_positives == 1
        assert m.trust_score.hallucinated_findings == 0
        assert m.trust_score.total_drifts == 1

    def test_record_hallucination(self, scorer):
        """Recording a hallucination increments that counter."""
        m = scorer.record_drift("p1", "hallucinated_finding", 0.9)
        assert m.trust_score.hallucinated_findings == 1

    def test_get_trust_score_nonexistent_returns_none(self, scorer):
        """Querying for an unknown provider returns None."""
        assert scorer.get_trust_score("no-such-provider") is None

    def test_get_provider_for_action_returns_best(self, scorer):
        """get_provider_for_action returns the highest-trust provider above threshold."""
        scorer.record_drift("low", "hallucinated_finding", 0.9)
        scorer.record_drift("low", "hallucinated_finding", 0.9)
        scorer.record_drift("high", "false_positive", 0.2)

        best = scorer.get_provider_for_action("scan", min_trust_score=0.5)
        assert best == "high"

    def test_get_provider_for_action_returns_none_when_below_threshold(self, scorer):
        """When all providers are below threshold, returns None."""
        scorer.record_drift("bad", "hallucinated_finding", 0.9)
        scorer.record_drift("bad", "hallucinated_finding", 0.9)
        scorer.record_drift("bad", "hallucinated_finding", 0.9)
        assert scorer.get_provider_for_action("scan", min_trust_score=0.9) is None

    def test_metrics_persist_across_instances(self, tmp_path):
        """Trust metrics survive reconstruction from the same ledger file."""
        p = tmp_path / "persist_trust.json"
        s1 = ProviderTrustScorer(p)
        s1.record_drift("prov-x", "false_positive", 0.5)
        s2 = ProviderTrustScorer(p)
        m = s2.get_trust_score("prov-x")
        assert m is not None
        assert m.trust_score.false_positives >= 1

    def test_get_provider_for_action_from_ledger_only(self, tmp_path):
        """When no cache exists, reads from ledger to find best provider."""
        p = tmp_path / "ledger_only.json"
        s1 = ProviderTrustScorer(p)
        s1.record_drift("reliable", "false_positive", 0.1)
        # Fresh scorer (no cache) reads from ledger
        s2 = ProviderTrustScorer(p)
        best = s2.get_provider_for_action("scan", min_trust_score=0.5)
        assert best == "reliable"


# ============================================================================
# Cross-Subsystem Integration Tests
# ============================================================================


class TestSubsystemsIntegration:
    """Verify subsystems can work together without conflicts."""

    def test_reputation_and_trust_together(self, tmp_path):
        """Reputation and trust subsystems operate independently."""
        rep = ReputationTracker(tmp_path / "rep.json")
        trust = ProviderTrustScorer(tmp_path / "trust.json")

        rep.observe_asset("sess-1", "target", {"is_positive": True})
        trust.record_drift("provider-a", "false_positive", 0.5)

        assert rep.get_reputation("target") is not None
        assert trust.get_trust_score("provider-a") is not None

    def test_snapshot_and_attestation_pattern(self, tmp_path):
        """Simulate the snapshot + attestation integration pattern."""
        ledger = AttestationLedger(
            tmp_path / "attest.json",
            private_key_path=tmp_path / "key",
        )
        rep = ReputationTracker(tmp_path / "rep.json")

        # Simulate a snapshot event with discovered assets
        state = {
            "working_memory": {"ports": [80, 443], "services": ["http"]},
            "findings": [],
        }
        discovered_assets = ["10.0.0.1:80", "10.0.0.1:443"]

        att = ledger.create_attestation("SESS-001", "CKPT-0001-scan", state)
        for asset in discovered_assets:
            rep.observe_asset("SESS-001", asset, {"is_positive": True})

        # Verify
        assert ledger.verify_attestation(att) is True
        for asset in discovered_assets:
            r = rep.get_reputation(asset)
            assert r is not None
            assert r.reputation.session_count == 1
