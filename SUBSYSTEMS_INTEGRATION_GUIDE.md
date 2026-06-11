# Subsystems Integration Guide

How to integrate the three security subsystems into the gatekeeper-eos-v6 codebase.

---

## 1. Snapshot Integration (`src/gatekeeper_eos_v6/snapshot.py`)

Wire signed attestations into the existing `take_snapshot()` flow:

```python
from gatekeeper_eos_v6.subsystems import AttestationLedger

# Module-level constant
ATTESTATION_LEDGER = AttestationLedger(
    ledger_path=Path("data/attestations.json"),
    private_key_path=Path("data/attestation_key"),
)

# Modified take_snapshot() — call after the existing SnapshotLedger.append()
def take_snapshot_with_attestation(
    agent, session_id, checkpoint_id, snapshot_ledger, ...
):
    snapshot_entry = take_snapshot(agent, session_id, checkpoint_id, snapshot_ledger, ...)

    # Create signed attestation over the same state
    attestation = ATTESTATION_LEDGER.create_attestation(
        session_id=session_id,
        checkpoint_id=checkpoint_id,
        state={
            "working_memory": snapshot_entry.working_memory,
            "tool_call_history": snapshot_entry.tool_call_history,
            "conversation_summary": snapshot_entry.conversation_summary,
        },
        metadata={
            "snapshot_sequence": snapshot_entry.sequence,
            "drift_score": snapshot_entry.drift_score,
        },
    )

    return snapshot_entry, attestation
```

### Key integration points in `snapshot.py`:

| Function | Injection Point |
|----------|----------------|
| `take_snapshot()` | After `ledger.append()`, call `ATTESTATION_LEDGER.create_attestation()` |
| `context_revalidation()` | Before restoring from snapshot, verify ledger integrity + attestation signature |

---

## 2. Campaign Integration (`src/gatekeeper_eos_v6/campaign.py`)

Use reputation and trust scoring in the campaign execution loop:

```python
from gatekeeper_eos_v6.subsystems import ReputationTracker, ProviderTrustScorer

# Module-level constants
REPUTATION_TRACKER = ReputationTracker(ledger_path=Path("data/reputation_ledger.json"))
TRUST_SCORER = ProviderTrustScorer(ledger_path=Path("data/provider_ledger.json"))
```

### Provider Selection

```python
def select_provider_for_action(
    action_type: str,
    min_trust: float = 0.7,
) -> tuple[str, LLMProvider]:
    """Select the highest-trust provider above the threshold."""
    from gatekeeper_eos_v6.providers import create_llm_provider

    candidates = {
        "openai-gpt-4o-mini": lambda: create_llm_provider("openai", model="gpt-4o-mini"),
        "openai-gpt-4o": lambda: create_llm_provider("openai", model="gpt-4o"),
        "anthropic-claude-sonnet-4": lambda: create_llm_provider("anthropic", model="claude-sonnet-4-20250514"),
    }

    best_id = TRUST_SCORER.get_provider_for_action(action_type, min_trust)
    if best_id and best_id in candidates:
        return best_id, candidates[best_id]()

    # Fallback to highest-trust provider regardless of threshold
    for pid, factory in candidates.items():
        metrics = TRUST_SCORER.get_trust_score(pid)
        if metrics and metrics.trust_score.score >= 0.0:
            return pid, factory()

    raise RuntimeError("No LLM providers available")
```

### Asset Validation

```python
def validate_discovered_asset(
    asset_id: str,
    min_reputation: float = 0.6,
) -> tuple[bool, str]:
    """Check whether an asset is safe to use based on reputation."""
    rep = REPUTATION_TRACKER.get_reputation(asset_id)
    if rep is None:
        return True, "new_asset"       # Unknown → accept (with warning)
    if rep.is_flagged_malicious:
        return False, "flagged_malicious"
    if rep.reputation.score < min_reputation:
        return False, "low_reputation"
    return True, "trusted"
```

---

## 3. Providers Integration (`src/gatekeeper_eos_v6/providers.py`)

Track LLM drift after each generation call. Add to the `generate()` method of each provider:

```python
from gatekeeper_eos_v6.subsystems import ProviderTrustScorer

TRUST_SCORER = ProviderTrustScorer(ledger_path=Path("data/provider_ledger.json"))

def generate(self, prompt: str) -> str:
    """Generate with automatic drift tracking."""
    result = self._call_and_retry(prompt)

    # Heuristic drift detection (customize per provider)
    if self._looks_hallucinated(result):
        TRUST_SCORER.record_drift(
            provider_id=self.model,
            drift_type="hallucinated_finding",
            severity=0.8,
        )
    if self._looks_false_positive(result):
        TRUST_SCORER.record_drift(
            provider_id=self.model,
            drift_type="false_positive",
            severity=0.5,
        )

    return result
```

> **Note:** The `_looks_hallucinated` and `_looks_false_positive` heuristics are
> placeholder methods and should be customized based on your domain and expected
> output patterns.

---

## 4. Agentic Integration (`src/gatekeeper_eos_v6/agentic.py`)

Filter actions in the action selector based on target asset reputation:

```python
def select_action(self, strategy: str = "hybrid") -> AgentAction | None:
    """Select action, filtering targets with poor reputation."""
    action = self.selector.select_action(strategy)
    if action is None:
        return None

    # Validate target if present
    if action.target:
        valid, reason = validate_discovered_asset(action.target)
        if not valid:
            self.evidence_log.append(
                EvidenceEntry(
                    step=self.step,
                    action=action,
                    output={"skipped": True, "reason": f"Asset {action.target}: {reason}"},
                )
            )
            return None  # Skip this action

    return action
```

---

## 5. Configuration

### Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `ATTESTATION_PRIVATE_KEY` | HMAC key for signed attestations (hex) | If no key file |
| `REPUTATION_LEDGER_PATH` | Path to reputation ledger | Yes |
| `TRUST_LEDGER_PATH` | Path to provider trust ledger | Yes |
| `ATTESTATION_LEDGER_PATH` | Path to attestation ledger | Yes |

### File-based Key Storage

```bash
# Generate a 32-byte key
python3 -c "import os; open('data/attestation_key', 'wb').write(os.urandom(32))"
chmod 600 data/attestation_key
```

---

## 6. Testing the Integration

```bash
# Run subsystem unit tests
pytest tests/test_subsystems_unit.py -v

# Run smoke tests
python3 tests/test_subsystems_smoke.py

# After wiring into snapshot.py, run existing snapshot tests
pytest tests/test_snapshot.py -v

# After wiring into campaign.py, run existing campaign tests
pytest tests/test_campaign.py -v
```

---

## 7. Rolling Out

1. **Phase 1** — Enable trust scoring in non-critical paths (observe only, no enforcement)
2. **Phase 2** — Enable asset validation in warning mode (log violations, don't block)
3. **Phase 3** — Enable policy enforcement (block actions on untrusted targets/providers)
4. **Phase 4** — Add signed attestations to all snapshot checkpoints
