# Subsystems Summary

## What Was Built

Three security subsystems for gatekeeper-eos-v6, inspired by onion directory
verification patterns (PGP-signed mirror lists, cross-referencing, trust decay):

### 1. Reputation/Verification Subsystem
- **File**: `src/gatekeeper_eos_v6/subsystems/reputation_verification.py`
- **Purpose**: Cross-session asset reputation scoring
- **Scoring**: Bayesian smoothing with exponential decay (30-day half-life)
- **API**: `ReputationTracker.observe_asset()`, `get_reputation()`, `cross_reference()`

### 2. Signed Attestations
- **File**: `src/gatekeeper_eos_v6/subsystems/signed_attestations.py`
- **Purpose**: HMAC-SHA256 signed attestations for snapshot chain entries
- **Key store**: File-based or `ATTESTATION_PRIVATE_KEY` env var
- **API**: `AttestationLedger.create_attestation()`, `verify_attestation()`, `load_attestations()`

### 3. Provider Trust Scorer
- **File**: `src/gatekeeper_eos_v6/subsystems/provider_trust_scorer.py`
- **Purpose**: LLM provider trust scoring based on historical drift/hallucination
- **Scoring**: Weighted penalties (0.2× false positive, 0.3× hallucination) + decay
- **API**: `ProviderTrustScorer.record_drift()`, `get_trust_score()`, `get_provider_for_action()`

## Files Created

| File | Description |
|------|-------------|
| `src/gatekeeper_eos_v6/subsystems/__init__.py` | Package exports |
| `src/gatekeeper_eos_v6/subsystems/reputation_verification.py` | Reputation tracker |
| `src/gatekeeper_eos_v6/subsystems/signed_attestations.py` | Signed attestations |
| `src/gatekeeper_eos_v6/subsystems/provider_trust_scorer.py` | Provider trust scorer |
| `SUBSYSTEMS_SPEC.md` | Design specification |
| `SUBSYSTEMS_INTEGRATION_GUIDE.md` | Integration instructions |
| `tests/test_subsystems_smoke.py` | Quick smoke test |
| `tests/test_subsystems_unit.py` | Comprehensive unit tests |

## Bug Caught During Review

**HMAC hex-vs-bytes encoding bug**: The `_load_public_key()` and
`_load_private_key()` env var fallback both returned hex-string bytes instead of
decoded raw bytes. This would have caused every signature verification to fail
silently. Fixed with `bytes.fromhex()` in both methods.

## Smoke Test Results

```
=== 1. Import verification ===  ✅
=== 2. HMAC sign/verify cycle ===  ✅
=== 3. Reputation scoring ===  ✅
=== 4. Provider trust scoring ===  ✅
=== 5. Provider selection ===  ✅
```

## Integration Points

| Subsystem | Integrates With | Purpose |
|-----------|----------------|---------|
| ReputationTracker | `snapshot.py`, `campaign.py` | Validate discovered assets |
| AttestationLedger | `snapshot.py` | Sign snapshot checkpoint entries |
| ProviderTrustScorer | `providers.py`, `campaign.py` | Track drift, select providers |

## Usage Quick-Start

```python
from gatekeeper_eos_v6.subsystems import ReputationTracker, AttestationLedger, ProviderTrustScorer

# Reputation
rep = ReputationTracker(ledger_path=Path("data/reputation.json"))
rep.observe_asset("SESS-001", "192.168.1.1:80", {"is_positive": True})

# Attestations
al = AttestationLedger(Path("data/attestations.json"), Path("data/key"))
att = al.create_attestation("SESS-001", "CKPT-0001", {"ports": [80]})

# Provider trust
scorer = ProviderTrustScorer(ledger_path=Path("data/trust.json"))
scorer.record_drift("openai-gpt-4o-mini", "hallucinated_finding", 0.8)
```
