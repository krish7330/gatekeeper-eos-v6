# Agentic Security Subsystems — Design Specification

## Overview

Three subsystems for gatekeeper-eos-v6 inspired by onion directory verification patterns:

1. **Reputation/Verification Subsystem** — Cross-session asset reputation scoring
2. **Signed Attestations** — PGP-like signed attestations for snapshot chain entries
3. **Provider Trust Scorer** — LLM provider trust scoring based on historical drift

## 1. Reputation/Verification Subsystem

**Package**: `gatekeeper_eos_v6.subsystems.reputation_verification`

### Purpose
Cross-reference discovered assets across sessions to build reputation scores, similar to onion directory cross-referencing. Assets discovered in multiple sessions → higher trust; assets flagged as malicious → reputation penalty.

### Key Patterns
- Assets discovered in multiple sessions → higher trust
- Assets flagged as malicious in any session → reputation penalty
- Versioned attestations with drift tracking
- Exponential reputation decay (30-day half-life)

### Architecture
```
ReputationTracker (ledger-backed tracker)
  → observe_asset(session_id, asset, metadata)
  → get_reputation(asset) → ReputationScore
  → cross_reference(asset) → list[AssetReputation]
```

### Data Models
| Type | Field | Description |
|------|-------|-------------|
| `ReputationScore` | `score` | Trust score [0.0, 1.0] |
| | `session_count` | Number of sessions observing this asset |
| | `positive_flags` | Positive confirmations |
| | `negative_flags` | Malicious flags |
| | `last_seen` | ISO timestamp of last observation |
| | `decay_factor` | Time-based decay multiplier |
| `AssetReputation` | `asset_id` | Canonical identifier (IP:port, URL) |
| | `reputation` | Computed `ReputationScore` |
| | `attestations` | List of observation metadata dicts |
| | `is_flagged_malicious` | Whether any session flagged as malicious |

### Scoring Formula

```
base = (positive_flags + 1) / (session_count + positive_flags + negative_flags + 1)
decay = 0.5 ** (days_elapsed / 30.0)
score = base * decay
```

Bayesian smoothing prevents 0/1 extremes with limited data. 30-day half-life means an unobserved asset loses half its reputation every month.

### Usage Example

```python
from gatekeeper_eos_v6.subsystems import ReputationTracker

tracker = ReputationTracker(ledger_path=Path("/tmp/reputation_ledger.json"))

# Observe asset as positive in session
record = tracker.observe_asset(
    session_id="SESS-2025-recon",
    asset_id="192.168.1.1:8080",
    metadata={"is_positive": True, "is_malicious": False}
)

# Query reputation
reputation = tracker.get_reputation("192.168.1.1:8080")
print(f"Trust score: {reputation.reputation.score:.3f}")
```

---

## 2. Signed Attestations for Snapshots

**Package**: `gatekeeper_eos_v6.subsystems.signed_attestations`

### Purpose
Add cryptographic signatures to snapshot chain entries using a key stored in the ledger, similar to PGP mirror verification.

### Key Patterns
- Each snapshot entry includes an HMAC-SHA256 signature over its state
- Signature verified against the ledger's public key
- Tamper-evident ledger with chain-hash + signature
- Private key loaded from file or `ATTESTATION_PRIVATE_KEY` env var

### Architecture
```
AttestationLedger (append-only with signatures)
  → create_attestation(session_id, state, metadata)
  → verify_attestation(attestation) → bool
  → load_attestations(session_id) → list[SignedAttestation]
```

### Data Models
| Type | Field | Description |
|------|-------|-------------|
| `SignedAttestation` | `session_id` | Session identifier |
| | `checkpoint_id` | Checkpoint identifier |
| | `state` | Serialized agent state dict |
| | `chain_hash` | SHA-256(prev_chain_hash \|\| state_hash) |
| | `signature` | HMAC-SHA256 over chain_hash + state + session/checkpoint IDs |

### Signature Scheme

```
state_hash     = SHA-256(json(state))
chain_hash     = SHA-256(prev_chain_hash || state_hash)
payload        = chain_hash || state_hash || session_id || checkpoint_id
signature      = HMAC-SHA256(private_key, payload)
```

The payload binds the signature to:
- The exact state content (via state_hash)
- The hash chain position (via chain_hash)
- The session and checkpoint IDs

### Usage Example

```python
from gatekeeper_eos_v6.subsystems import AttestationLedger

ledger = AttestationLedger(
    ledger_path=Path("/tmp/attestation_ledger.json"),
    private_key_path=Path("/tmp/attestation_key")
)

# Create and sign attestation
att = ledger.create_attestation(
    session_id="SESS-2025-recon",
    checkpoint_id="CKPT-0001-scan",
    state={"working_memory": {"ports": [80, 443]}, "findings": []}
)

# Verify
assert ledger.verify_attestation(att) is True
```

---

## 3. Provider Trust Scorer

**Package**: `gatekeeper_eos_v6.subsystems.provider_trust_scorer`

### Purpose
Track LLM provider drift/hallucination rates historically and compute trust scores for routing decisions.

### Key Patterns
- Per-provider drift metrics (false positives, hallucinated findings)
- Weighted trust score decaying over time
- Policy enforcement: only high-trust providers for critical actions

### Architecture
```
ProviderTrustScorer (metrics tracker)
  → record_drift(provider_id, drift_type, severity)
  → get_trust_score(provider_id) → TrustScore
  → get_provider_for_action(action_type) → provider_id
```

### Data Models
| Type | Field | Description |
|------|-------|-------------|
| `TrustScore` | `score` | Trust score [0.0, 1.0] |
| | `total_drifts` | Total drift events |
| | `false_positives` | False positive drift count |
| | `hallucinated_findings` | Hallucinated finding count |
| `ProviderMetrics` | `provider_id` | e.g. "openai-gpt-4o-mini" |
| | `trust_score` | Computed `TrustScore` |
| | `drift_events` | List of drift event dicts |

### Scoring Formula

```
if total_drifts == 0: return 1.0
penalty = (false_positives * 0.2 + hallucinated_findings * 0.3) / (total_drifts + 1)
base = 1.0 - penalty
decay = 0.5 ** (days_elapsed / 30.0)
score = base * decay
```

Hallucinated findings are weighted higher (0.3) than false positives (0.2) because hallucinated evidence is more dangerous in a security context.

### Usage Example

```python
from gatekeeper_eos_v6.subsystems import ProviderTrustScorer

scorer = ProviderTrustScorer(ledger_path=Path("/tmp/provider_ledger.json"))

# Record a drift event
scorer.record_drift(
    provider_id="openai-gpt-4o-mini",
    drift_type="hallucinated_finding",
    severity=0.8,
    metadata={"session_id": "SESS-2025-recon"}
)

# Query trust score
trust = scorer.get_trust_score("openai-gpt-4o-mini")
print(f"Trust score: {trust.trust_score.score:.3f}")
```

---

## Integration with Gatekeeper

### Integration Points

| Subsystem | Integrates With | Integration Mechanism |
|-----------|----------------|----------------------|
| ReputationTracker | `snapshot.py` | Called when discovering assets during session execution |
| AttestationLedger | `snapshot.py` / `SnapshotLedger` | Wraps or extends existing snapshot append flow |
| ProviderTrustScorer | `providers.py` | Used in provider selection / action routing |

### Example Integration (snapshot.py)

```python
from gatekeeper_eos_v6.subsystems import ReputationTracker, AttestationLedger

reputation_tracker = ReputationTracker(ledger_path=REPUTATION_LEDGER_PATH)
attestation_ledger = AttestationLedger(
    ledger_path=ATTESTATION_LEDGER_PATH,
    private_key_path=PRIVATE_KEY_PATH
)

def take_snapshot_with_attestation(session_id, checkpoint_id, state):
    # Create signed attestation
    att = attestation_ledger.create_attestation(session_id, checkpoint_id, state)

    # Record asset reputation from discovered assets
    for asset in state.get("discovered_assets", []):
        reputation_tracker.observe_asset(
            session_id, asset, {"is_positive": True}
        )

    return att
```

---

## Security Considerations

1. **Private Key Storage** → Store in `ATTESTATION_PRIVATE_KEY` env var or secure file, never in code
2. **Ledger Integrity** → Chain-hash + HMAC signature prevent tampering
3. **Trust Decay** → Scores decay exponentially to reflect outdated metrics
4. **Bayesian Smoothing** → Prevents 0/1 extremes with limited observations
5. **Policy Enforcement** → `get_provider_for_action()` enforces min trust thresholds

## Future Enhancements

1. **Reputation** — Add cross-session consensus voting with quorum requirements
2. **Attestations** — Support asymmetric PGP keys instead of symmetric HMAC
3. **Provider Trust** — Add provider registry with auto-discovery and health checks
4. **Federated Reputation** — Share reputation data across gatekeeper instances
