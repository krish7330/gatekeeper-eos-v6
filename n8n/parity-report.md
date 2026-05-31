# n8n / Agentic Runtime Parity Report

**Date:** 2026-05-31
**Scope:** Compare the three `n8n/hardened-pair-*.json` workflows against the
`agentic.py` / `campaign.py` agentic runtime in `src/gatekeeper_eos_v6/`.

---

## Workflow Comparison

| Feature | n8n Hardened Pair | Agentic Runtime | Gap |
|---------|-------------------|-----------------|-----|
| **Entry point** | Manual Trigger or Error Trigger | `AgentCore.get_next_action()` / `run_agent_loop()` | Different trigger models |
| **Idempotency** | SHA-256 idempotency key + MESSAGE_LEDGER lookup | No built-in idempotency; each `step_action()` is a new state mutation | Agentic runtime has no message-level dedup |
| **Environment toggle** | `Env Toggle` IF node (production vs sandbox) | No env toggle — `PolicyGate` validates targets/tools but doesn't switch credential sets | Credential switching is out of scope for agentic runtime |
| **State persistence** | Google Sheets (MESSAGE_LEDGER, ERRORS, METRICS) | `SnapshotLedger` (append-only JSON, SHA-256 hash chain) | Different persistence backends |
| **Error handling** | Error Trigger → Format → Log to ERRORS sheet | `AgentStateError` (drift) + `AgentStopTriggered` (stop conditions) | n8n catches all runtime errors; agentic only catches drift and stop conditions |
| **Metrics** | Schedule Trigger → Read sheets → Compute → Append METRICS | No built-in metrics aggregation | Agentic runtime has no scheduled metrics |
| **Processing logic** | Code node (replaceable business logic) | `ActionSelector.select_action()` + `execute_action` callback | Different separation of concerns |
| **Duplicate detection** | Read ledger → compare message_id → IF branch | N/A (no inbound message model) | Agentic runtime operates on actions, not messages |
| **Data model** | Google Sheets columns (message_id, status, etc.) | `WorldState` (open_ports, services, vulnerabilities, etc.) | Different domain models |
| **Policy enforcement** | Implicit in node connections | `PolicyGate.validate_action()` + `validate_output()` | Agentic has explicit, auditable policy |
| **Audit trail** | MESSAGE_LEDGER sheet rows | `EvidenceEntry` in `AgentCore.evidence_log` | Both provide immutability; different storage |
| **Recovery** | N/A — workflow restarts from trigger | `context_revalidation()` restores from last valid snapshot | Agentic has built-in state recovery |

---

## Structural Comparison

### Hardened-Pair Main (11 nodes)

```
Manual → Load Env → Env Toggle ──→ Generate Key → Read Ledger → Dup Check ──→ [dup] Cached
                                                                              └→ [new] Process → Log → Done
                                   └→ Sandbox Response
```

Key design choices:
- **Linear pipeline** — each node has one input, one output path; branches via IF nodes
- **Environment-aware** — Toggle switches between sandbox/production Twilio credentials
- **Idempotency-first** — SHA-256 key + ledger lookup before any processing
- **Business logic as placeholder** — `Process` node has a comment: "Replace this block with your actual business logic"

### Agentic Runtime Loop

```
Agent.get_next_action()
  → ActionSelector.select_action()  (rule / llm / hybrid)
    → _select_with_rules()           (4-phase state machine)
    → _check_stalled()               (tool-loop, asset-exhaustion, state-stagnation)
    → [hybrid] _select_with_llm()    (LLM fallback)
  → PolicyGate.validate_action()     (tool, command, target bounds)
  → execute_action()                 (user-provided callback)
  → Agent.step_action()              (update state, check drift, check stop conditions)
    → Drift Sentinel                 (check_agent_state_drift)
    → StopCondition.should_stop()    (max_steps, max_time, finding_severity, criteria)
↻ Repeat until halt
```

Key design choices:
- **Bounded loop** — not a linear pipeline; the agent iterates until a stop condition
- **Strategy-driven** — `decision_strategy` parameter controls rule vs LLM vs hybrid
- **Stall detection** — hybrid strategy detects and escalates rule engine dead ends
- **Audit-first** — every action is recorded in `EvidenceEntry` before state mutation
- **Recovery-native** — `context_revalidation()` is a first-class recovery mechanism

---

## Feature Parity Matrix

| Feature | n8n Hardened Pair | Agentic Runtime | Notes |
|---------|:-----------------:|:---------------:|-------|
| Input trigger | ✅ Manual/Webhook | ✅ `get_next_action()` | Different abstractions |
| Processing | ✅ Code node | ✅ `ActionSelector` | n8n is replaceable; agentic is strategy-based |
| Output persistence | ✅ Google Sheets | ✅ `SnapshotLedger` | Different backends |
| Error handling | ✅ Error Trigger | ✅ `AgentStateError` | Different error models |
| Idempotency | ✅ SHA-256 + lookup | ❌ Not built-in | Agentic needs it for message-level dedup |
| Environment toggle | ✅ Env Toggle | ❌ Not built-in | Out of scope — agentic operates under one config |
| Metrics/scheduling | ✅ Schedule Trigger | ❌ Not built-in | Could be added via `campaign.py` schedule |
| Duplicate detection | ✅ Ledger lookup | ❌ Not built-in | Depends on message model |
| Policy enforcement | ❌ Implicit | ✅ `PolicyGate` | Agentic has explicit, testable policy |
| Stall detection | ❌ Not present | ✅ Hybrid `_check_stalled` | Unique to agentic runtime |
| State recovery | ❌ N/A | ✅ `context_revalidation()` | Unique to agentic runtime |
| Hash chain audit | ❌ Not present | ✅ SHA-256 chain | Unique to agentic runtime |
| Action strategy | ❌ Fixed pipeline | ✅ Rule / LLM / Hybrid | Unique to agentic runtime |
| Drift detection | ❌ Not present | ✅ `check_agent_state_drift` | Unique to agentic runtime |

---

## Gaps

### Critical
- **No idempotency in agentic runtime**: If the same action is submitted twice,
  `step_action()` processes it as a new step. For message-processing use cases
  (like the n8n WhatsApp bot), this needs a message-level dedup layer.

### Moderate
- **No scheduled metrics**: The n8n metrics workflow provides daily health
  aggregation. The agentic runtime has no equivalent — `campaign.py` schedules
  sessions but doesn't aggregate execution metrics.
- **No credential switching**: The n8n env toggle switches Twilio credentials.
  Agentic runtime doesn't support per-action credential selection.

### Minor
- **Different persistence backends**: n8n uses Google Sheets (human-readable,
  accessible); agentic uses JSON files (programmatic, verifiable via hash chain).
- **Different error models**: n8n catches all node-level errors; agentic
  distinguishes between drift (recoverable), stop conditions (intentional), and
  action errors (policy violations).

---

## Recommendation

The two systems serve different purposes:
- **n8n Hardened Pair** is a **message-processing pipeline** — inbound messages
  are idempotent, processed once, and logged. It's designed for WhatsApp chatbot
  workflows where messages arrive via webhook.
- **Agentic Runtime** is a **bounded reasoning loop** — an agent iteratively
  selects and executes actions until requirements are met. It's designed for
  autonomous pentesting, research, and multi-session campaigns.

**No convergence needed** — the design choices reflect different workloads.
The parity gaps are architectural, not omissions. If a use case requires both
patterns (e.g., a WhatsApp chatbot with autonomous reasoning), the agentic
runtime could be invoked as an action from within the n8n pipeline, or the
n8n pipeline could be invoked as an `execute_action` callback from the
agentic runtime.

---

*Generated by Gatekeeper EOS v6 — parity analysis tool.*
