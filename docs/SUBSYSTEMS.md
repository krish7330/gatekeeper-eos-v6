# Agentic Security Subsystems

## Overview

Gatekeeper-eos-v6 includes three production-ready security subsystems inspired
by onion directory verification patterns (PGP-signed mirror lists,
cross-referencing, trust decay):

1. **Reputation/Verification** — Cross-session asset reputation scoring
2. **Signed Attestations** — HMAC-SHA256 signatures for snapshot chain entries
3. **Provider Trust Scorer** — LLM provider trust scoring based on drift

## Quick Start

```python
from gatekeeper_eos_v6.subsystems import (
    ReputationTracker,
    AttestationLedger,
    ProviderTrustScorer,
)
from gatekeeper_eos_v6.subsystems.config import (
    get_reputation_ledger_path,
    get_attestation_ledger_path,
    get_trust_ledger_path,
)

# Reputation tracker
rep_tracker = ReputationTracker(get_reputation_ledger_path())

# Attestation ledger
att_ledger = AttestationLedger(
    ledger_path=get_attestation_ledger_path(),
    private_key_path=...,
)

# Trust scorer
trust_scorer = ProviderTrustScorer(get_trust_ledger_path())
```

### Configure Paths

```bash
export ATTESTATION_LEDGER_PATH="/path/to/attestations.json"
export ATTESTATION_PRIVATE_KEY_PATH="/path/to/private_key"
export REPUTATION_LEDGER_PATH="/path/to/reputation.json"
export TRUST_LEDGER_PATH="/path/to/trust.json"
```

Defaults to `/tmp/gatekeeper/` if not set.

---

## Subsystem 1: Reputation/Verification

**File**: `src/gatekeeper_eos_v6/subsystems/reputation_verification.py`

### Purpose

Cross-reference discovered assets across sessions to build reputation scores.
Assets discovered in multiple sessions → higher trust; assets flagged as
malicious → reputation penalty.

### API

```python
# Record asset observation
rep_tracker.observe_asset(
    session_id="scan-1",
    asset_id="192.168.1.1:8080",
    metadata={"is_positive": True, "discovery_method": "nmap"},
)

# Get reputation score (0.0–1.0)
rep = rep_tracker.get_reputation("192.168.1.1:8080")
print(f"Trust score: {rep.reputation.score}")

# Cross-reference attestations
attestations = rep_tracker.cross_reference("192.168.1.1:8080")
```

### Scoring Formula

```
base = (positive_flags + 1) / (positive_flags + negative_flags + 2)  # Beta(1,1) prior
decay = 0.5 ** (days_elapsed / 30.0)  # 30-day half-life
score = base * decay
```

### Key Features

- **Bayesian smoothing** — Beta(1,1) prior prevents 0/1 extremes with sparse data
- **Time-based decay** — 30-day half-life; unobserved assets lose reputation over time
- **Malicious flagging** — Any session can mark an asset as malicious
- **Cross-session tracking** — Accumulate evidence across multiple sessions
- **Append-only ledger** — All observations are immutably recorded with SHA-256 hashes

---

## Subsystem 2: Signed Attestations

**File**: `src/gatekeeper_eos_v6/subsystems/signed_attestations.py`

### Purpose

Add cryptographic signatures to snapshot chain entries for tamper evidence,
similar to PGP mirror verification.

### API

```python
# Create attestation
att = att_ledger.create_attestation(
    session_id="sess-1",
    checkpoint_id="ckpt-1",
    state={"working_memory": {...}, "findings": [...]},
    metadata={"drift_score": 0},
)

# Verify signature
assert att_ledger.verify_attestation(att)

# Load attestations by session
attestations = att_ledger.load_attestations("sess-1")
```

### Signature Scheme

```
state_hash     = SHA-256(json(state))
chain_hash     = SHA-256(prev_chain_hash || state_hash)
payload        = chain_hash || state_hash || session_id || checkpoint_id
signature      = HMAC-SHA256(private_key, payload)
```

### Key Features

- **HMAC-SHA256 signatures** — 256-bit security, constant-time verification
- **Chain hash integrity** — Each entry linked to the previous via SHA-256 chain
- **Public key storage** — Key hex stored inside the ledger file itself
- **Private key management** — From file or `ATTESTATION_PRIVATE_KEY` env var
- **Tamper evidence** — Any modification invalidates the hash chain and signature

---

## Subsystem 3: Provider Trust Scorer

**File**: `src/gatekeeper_eos_v6/subsystems/provider_trust_scorer.py`

### Purpose

Track LLM provider drift/hallucination rates historically and compute trust
scores for routing decisions.

### API

```python
# Record drift event
trust_scorer.record_drift(
    provider_id="openai-gpt-4o-mini",
    drift_type="hallucinated_finding",
    severity=0.9,
    metadata={"session_id": "sess-1", "expected": "port 80"},
)

# Get trust score (0.0–1.0)
trust = trust_scorer.get_trust_score("openai-gpt-4o-mini")
print(f"Trust score: {trust.trust_score.score}")

# Select best provider for an action
best = trust_scorer.get_provider_for_action("discover", min_trust_score=0.7)
```

### Scoring Formula

```
if total_drifts == 0: return 1.0
penalty = (false_positives * 0.2 + hallucinated_findings * 0.3) / (total_drifts + 1)
score = (1.0 - penalty) * decay
```

Hallucinated findings are weighted higher (0.3) than false positives (0.2)
because hallucinated evidence is more dangerous in a security context.

### Key Features

- **Weighted penalties** — 0.2× false positive, 0.3× hallucination
- **Time-based decay** — 30-day half-life
- **Per-provider tracking** — Independent metrics per provider
- **Drift type categorization** — `false_positive` or `hallucinated_finding`
- **Provider selection** — `get_provider_for_action()` for trust-based routing

---

## Integration Points

### Snapshot Integration (`src/gatekeeper_eos_v6/snapshot.py`)

```python
from gatekeeper_eos_v6.snapshot import SnapshotLedger, take_snapshot_with_attestation

ledger = SnapshotLedger("/path/to/snapshots.json")

snapshot, attestation = take_snapshot_with_attestation(
    ledger=ledger,
    session_id="sess-1",
    checkpoint_id="ckpt-1",
    working_memory={"key": "value"},
    tool_call_history=[{"action": "test"}],
)
```

### Campaign Integration (`src/gatekeeper_eos_v6/campaign_integration.py`)

```python
from gatekeeper_eos_v6.campaign_integration import (
    validate_discovered_asset,
    select_provider_for_action,
    record_asset_discovery,
    record_provider_drift,
)

# Validate asset reputation
valid, reason = validate_discovered_asset("192.168.1.1:8080")
if not valid:
    print(f"Skipping: {reason}")

# Select provider by trust score
provider_id, provider = select_provider_for_action("discover", min_trust=0.7)

# Record events
record_asset_discovery("sess-1", "192.168.1.1:8080", {"method": "nmap"})
record_provider_drift(provider_id, "false_positive", 0.7)
```

### Providers Integration (`src/gatekeeper_eos_v6/providers.py`)

```python
from gatekeeper_eos_v6.providers import DriftTrackingProvider, OpenAIProvider

# Wrap provider with automatic drift tracking
provider = DriftTrackingProvider(OpenAIProvider(model="gpt-4o-mini"))
result = provider.generate("Perform nmap scan on 192.168.1.1")
```

---

## Testing

```bash
# Run all subsystem tests
pytest tests/test_subsystems_smoke.py -v
pytest tests/test_subsystems_unit.py -v
pytest tests/test_subsystems_integration.py -v

# All together
pytest tests/test_subsystems_*.py -v
```

---

## Files

| File | Description |
|------|-------------|
| `src/gatekeeper_eos_v6/subsystems/__init__.py` | Package exports |
| `src/gatekeeper_eos_v6/subsystems/reputation_verification.py` | Reputation tracker |
| `src/gatekeeper_eos_v6/subsystems/signed_attestations.py` | Signed attestations |
| `src/gatekeeper_eos_v6/subsystems/provider_trust_scorer.py` | Trust scorer |
| `src/gatekeeper_eos_v6/subsystems/config.py` | Configurable paths |
| `src/gatekeeper_eos_v6/campaign_integration.py` | Campaign integration |
| `tests/test_subsystems_smoke.py` | Smoke tests (5) |
| `tests/test_subsystems_unit.py` | Unit tests (37) |
| `tests/test_subsystems_integration.py` | Integration tests (6) |

---

## Configuration

### Environment Variables

```bash
# Attestations
export ATTESTATION_LEDGER_PATH="/path/to/attestations.json"
export ATTESTATION_PRIVATE_KEY_PATH="/path/to/private_key"
export ATTESTATION_PRIVATE_KEY="your-hex-key"  # alternative to file

# Reputation
export REPUTATION_LEDGER_PATH="/path/to/reputation.json"

# Trust
export TRUST_LEDGER_PATH="/path/to/trust.json"
```

### Defaults

All paths default to `/tmp/gatekeeper/` when environment variables are not set:
- `/tmp/gatekeeper/attestations.json`
- `/tmp/gatekeeper/private_key`
- `/tmp/gatekeeper/reputation.json`
- `/tmp/gatekeeper/provider_trust.json`

---

## Security Considerations

1. **Private Key Storage** — Store in secure file or env var, never in code.
2. **Ledger Integrity** — SHA-256 chain hash + HMAC signature prevent tampering.
3. **Trust Decay** — Scores decay exponentially to prevent stale metrics.
4. **Bayesian Smoothing** — Prevents 0/1 extremes with limited observations.
5. **Policy Enforcement** — `get_provider_for_action()` enforces minimum trust thresholds.

---

## Future Enhancements

1. **Reputation** — Cross-session consensus voting with quorum requirements.
2. **Attestations** — Support asymmetric PGP keys instead of symmetric HMAC.
3. **Provider Trust** — Provider registry with auto-discovery and health checks.
4. **Federated Reputation** — Share reputation data across gatekeeper instances.
