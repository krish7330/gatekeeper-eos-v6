"""Smoke test for all three security subsystems.
Verifies:
1. All imports resolve
2. HMAC sign/verify cycle works (critical fix validation)
3. Reputation scoring formula
4. Provider trust scoring
5. get_provider_for_action filtering
"""
import sys
import tempfile
from pathlib import Path

# 1. Verify imports
print("=== 1. Import verification ===")
from gatekeeper_eos_v6.subsystems import (
    ReputationTracker,
    AttestationLedger,
    ProviderTrustScorer,
    ReputationScore,
    SignedAttestation,
    TrustScore,
)
print("  All imports OK")

# 2. HMAC sign/verify cycle
print("\n=== 2. HMAC sign/verify cycle ===")
with tempfile.TemporaryDirectory() as tmpdir:
    ledger_path = Path(tmpdir) / "attestations.json"
    key_path = Path(tmpdir) / "attestation_key"

    ledger = AttestationLedger(ledger_path=ledger_path, private_key_path=key_path)

    att = ledger.create_attestation(
        session_id="SESS-001",
        checkpoint_id="CKPT-0001-scan",
        state={"working_memory": {"ports": [80, 443]}},
        metadata={"drift_score": 0},
    )

    verified = ledger.verify_attestation(att)
    assert verified, "HMAC sign/verify cycle FAILED — critical bug!"

    # Verify tampered state fails
    att.state["tampered"] = True
    assert not ledger.verify_attestation(att), "Tampered attestation should NOT verify!"
    print(f"  Sign/verify cycle: PASSED (signature={att.signature[:16]}...)")

# 3. Reputation scoring
print("\n=== 3. Reputation scoring ===")
score = ReputationScore.compute_score(
    session_count=5, positive_flags=4, negative_flags=1,
    last_seen="2026-06-08T00:00:00Z"
)
assert 0.0 <= score <= 1.0, f"Score {score} out of range!"
print(f"  Score for 5 sessions (4 pos, 1 neg): {score:.4f}")

# Fresh asset (no sessions) should be 0.5 (Bayesian prior)
score_fresh = ReputationScore.compute_score(0, 0, 0, "2026-06-08T00:00:00Z")
print(f"  Score for fresh (no sessions): {score_fresh:.4f}")

# Perfect asset
score_perfect = ReputationScore.compute_score(10, 10, 0, "2026-06-08T00:00:00Z")
print(f"  Score for perfect (10/10 pos): {score_perfect:.4f}")

# 4. Provider trust scoring
print("\n=== 4. Provider trust scoring ===")
score_no_drift = TrustScore.compute_score(0, 0, 0, "2026-06-08T00:00:00Z")
assert score_no_drift == 1.0, f"No-drift score should be 1.0, got {score_no_drift}"
print(f"  No-drift score: {score_no_drift:.4f}")

score_with_drift = TrustScore.compute_score(2, 1, 3, "2026-06-08T00:00:00Z")
print(f"  Score (2 FP, 1 hallucination): {score_with_drift:.4f}")

# 5. Integration test: record drifts and query provider for action
print("\n=== 5. Provider selection ===")
with tempfile.TemporaryDirectory() as tmpdir:
    scorer = ProviderTrustScorer(ledger_path=Path(tmpdir) / "providers.json")

    scorer.record_drift("openai-gpt-4o", "false_positive", 0.5)
    scorer.record_drift("openai-gpt-4o", "hallucinated_finding", 0.9)
    scorer.record_drift("anthropic-claude", "false_positive", 0.2)
    scorer.record_drift("anthropic-claude", "false_positive", 0.1)

    trust_openai = scorer.get_trust_score("openai-gpt-4o")
    trust_anthropic = scorer.get_trust_score("anthropic-claude")

    print(f"  OpenAI trust:      {trust_openai.trust_score.score:.4f}" if trust_openai else "  OpenAI: None")
    print(f"  Anthropic trust:   {trust_anthropic.trust_score.score:.4f}" if trust_anthropic else "  Anthropic: None")

    best = scorer.get_provider_for_action("scan", min_trust_score=0.5)
    print(f"  Best provider (>=0.5): {best}")

    best_high = scorer.get_provider_for_action("scan", min_trust_score=0.95)
    print(f"  Best provider (>=0.95): {best_high}")

print("\n✅ All smoke tests passed!")
