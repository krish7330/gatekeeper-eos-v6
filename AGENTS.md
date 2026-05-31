# Agent Patterns Reference

This document describes the agent orchestration and execution subsystems
available in Gatekeeper EOS v6.

---

## Part I — Agent Factory (Template-based Generation)

The factory (`src/gatekeeper_eos_v6/factory.py`) generates multi-agent AI
systems from YAML batch specs. It supports two targets (OpenAI Agents SDK,
LangGraph) and eleven orchestration patterns.

### 1. Handoffs

**Idea**: One agent transfers control to another agent for specialized handling.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | `handoffs=[handoff(specialist_agent)]` on the triage agent |
| **LangGraph** | Supervisor node routes to workers via `add_conditional_edges` |

**Best for**: Customer support triage, department routing, skill-based routing.

---

### 2. Agents as Tools

**Idea**: A main agent invokes sub-agents as if they were tools, staying in
control of the overall workflow.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | `sub_agent.as_tool(tool_name="name", tool_description="...")` |
| **LangGraph** | Workers are graph nodes called by the orchestrator via conditional routing |

**Best for**: Sub-routines within a larger task, tool composition.

---

### 3. Router Manager

**Idea**: A router agent classifies the input and dispatches to the correct
specialist agent. Specialists focus on their domain and return results directly.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | Router uses structured handoffs to dispatch |
| **LangGraph** | Router node uses `with_structured_output` to classify and route |

**Best for**: Content classification pipelines, intent-based routing.

---

### 4. Supervisor Workers

**Idea**: A supervisor agent decides which worker to call next in a loop,
iteratively building toward the final output.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | Supervisor uses workers as tools and can call them in sequence |
| **LangGraph** | Supervisor with `with_structured_output` routes to workers, workers return results to supervisor |

**Best for**: Multi-step research, code review workflows, content generation pipelines.

---

### Feature Matrix (Factory Patterns)

| Pattern | Deterministic | Looping | State Persistence | Extensible |
|---------|:---:|:---:|:---:|:---:|
| Handoffs | ✅ | ❌ | ✅ | ✅ |
| Agents as Tools | ✅ | ✅ | ✅ | ✅ |
| Router Manager | ✅ | ❌ | ✅ | ✅ |
| Supervisor Workers | ✅ | ✅ | ✅ | ✅ |

---

## Part II — Agentic Orchestrator

The agentic orchestrator (`src/gatekeeper_eos_v6/agentic.py`) implements a
bounded autonomous reasoning loop for multi-session orchestration. Unlike the
factory patterns which generate static multi-agent topologies, the orchestrator
is a runtime loop with policy enforcement, drift detection, and strategy
selection.

### Architecture

```
Signed Test Plan (scope + allowed tools + objective)
        │
        ▼
Agent Core (reasoning loop) ── asks for next action ──► Action Selector
        │                                                        │
        │◄────────── feedback (state update) ────────────────── ◄── Policy Gate
        │                                                              │
        └──────────► Drift Sentinel ──► State Updater ──────────────────┘
```

### Key Components

| Component | File | Responsibility |
|-----------|------|---------------|
| **AgentCore** | `agentic.py` | Bounded loop; owns world model, evidence log, step counter, stop conditions |
| **PolicyGate** | `agentic.py` | Validates actions against signed plan (allowed_tools, authorized_assets) |
| **Drift Sentinel** | `agentic.py` | `check_agent_state_drift()` — halts if state diverges from confirmed evidence |
| **ActionSelector** | `agentic.py` | Strategy-based next-action selection (rule, llm, hybrid) |
| **StopCondition** | `agentic.py` | Evaluates max_steps, max_time, finding_severity, success_criteria |

### Stop Reasons

| Reason | Trigger |
|--------|---------|
| `MAX_STEPS` | Step counter exceeds configured limit |
| `MAX_TIME` | Elapsed time exceeds configured limit |
| `CRITERIA_MET` | All success criteria satisfied in world state |
| `DRIFT_DETECTED` | Agent state hallucination detected by Drift Sentinel |
| `MAX_SEVERITY_FOUND` | Finding at or above target severity threshold |
| `RULE_ENGINE_STALLED` | Rule engine repeating same action with no progress (see Hybrid Strategy) |
| `HUMAN_IN_THE_LOOP` | Human approval callback rejected an action |
| `USER_HALT` | Manual interruption |
| `NO_MORE_ACTIONS` | No stop condition met but loop ended naturally |

### Safe Rules

- All actions must come from `allowed_tools` in the signed plan.
- All targets must be within `authorized_assets`.
- Agent cannot exceed `max_steps` or `max_time_seconds`.
- Agent state must not hallucinate findings (DRIFT-AGENT-STATE).
- Everything is logged immutably in the evidence log.

---

## Part III — Hybrid Strategy & Stall Detection

The hybrid strategy (`agentic.py` ActionSelector) provides a fallback path when
the deterministic rule engine cannot make progress. It lives alongside the
existing `rule` and `llm` strategies.

### Flow

```
select_action(strategy="hybrid"):
  1. Try _select_with_rules()
  2. Call _check_stalled() — three sub-checks:
     a. Tool-loop: same tool+command for 3+ consecutive calls
     b. Asset-exhaustion: all authorized assets discovered but no rotation
        (only fires after tool-loop is already detected — stall_count > 0)
     c. State-stagnation: no new state fields for 3+ consecutive calls
  3. If stalled and LLM configured → _select_with_llm() fallback
     a. If LLM returns different action → reset stall, return LLM action
     b. If LLM returns same action → mark with RULE_ENGINE_STALLED reasoning
  4. If stalled and no LLM → mark with RULE_ENGINE_STALLED reasoning
  5. If not stalled → return rule action
```

### Stall Detection Sub-checks

| Check | Detects | False-positive guard |
|-------|---------|---------------------|
| `_check_tool_loop` | Repeated identical tool+command (3+ times) | Resets on any tool/command change |
| `_check_asset_exhaustion` | All assets discovered, still targeting first one | Only fires when `_stall_count > 0` |
| `_check_state_stagnation` | No new ports/services/vulns/assets (3+ calls) | Resets on any state change |

### Trigger Criteria for Hybrid Fallback

| # | Trigger | Observable behavior |
|---|---------|-------------------|
| 1 | Tool-not-found loop | `_select_with_rules` generates a tool name not in `allowed_tools`; PolicyGate rejects; >50% evidence entries are `POLICY_VIOLATION` |
| 2 | Phase lock | Rule selector stays in same phase despite repeated actions (e.g., vuln scan returns nothing) |
| 3 | Single-target lock | Multiple `authorized_assets` but selector always targets `assets[0]` |
| 4 | Command name mismatch | Hardcoded command strings don't match YAML bindings |
| 5 | LLM no-op fallback | `_select_with_llm` returns same action as rules; `_is_stalled()` catches on post-fallback comparison |

---

## Part IV — Snapshot Subsystem

The snapshot subsystem (`src/gatekeeper_eos_v6/snapshot.py`, schema at
`schemas/snapshot.schema.json`) provides an append-only, hash-chained ledger
for agent state recovery following the **context revalidation** pattern.

### Architecture

```
SnapshotLedger (append-only JSON file with SHA-256 hash chain)
    → SnapshotIndex (in-memory O(1) lookup by session_id + checkpoint_id)
        → take_snapshot() writes entries
            → context_revalidation() restores from last valid snapshot
```

### Hash Chain

Each entry's hash chain ensures tamper evidence:

```
state_hash    = SHA-256(working_memory || tool_call_history || conversation_summary)
chain_hash    = SHA-256(prev_chain_hash || state_hash)
prev_chain_hash = ""  (genesis entry) or previous entry's chain_hash
```

### Key Functions

| Function | Purpose |
|----------|---------|
| `take_snapshot()` | Capture agent state (WorldState, evidence log, conversation summary) into a ledger entry |
| `context_revalidation()` | Full recovery: find last valid snapshot → verify hash chain → restore agent state → re-evaluate drift |

### Schema (`snapshot.schema.json`)

Top-level fields:

| Field | Type | Pattern |
|-------|------|---------|
| `entry_type` | string | `"memory_snapshot"` (const) |
| `session_id` | string | `^SESS-[a-zA-Z0-9-]+$` |
| `checkpoint_id` | string | `^CKPT-[0-9]{4}-[a-z]+(-[a-z]+)?$` |
| `hash` | string | `^[a-f0-9]{64}$` (SHA-256 hex) |
| `chain_hash` | string | `^[a-f0-9]{64}$` |
| `prev_chain_hash` | string | `^[a-f0-9]{64}$` or `""` (genesis) |
| `sequence` | integer | Monotonic sequence in ledger |

Sub-definitions: `world_state`, `service_entry`, `vulnerability_entry`,
`finding_summary` (consistent with `campaign.schema.json`), `evidence_entry`,
`agent_action`.

---

## Part V — Campaign Execution

The campaign executor (`src/gatekeeper_eos_v6/campaign.py`) orchestrates
multi-session agentic campaigns with scheduling, dependency resolution, drift
rule enforcement, and checkpoint integration.

### Schema (`schemas/agentic-plan.schema.json`)

| Field | Type | Pattern |
|-------|------|---------|
| `campaign_id` | string | `^CAMP-[a-zA-Z0-9-]+$` |
| `sessions` | array | Session definitions with schedule |
| `global_drift_rules` | array | Drift detection rules |

### Session Definition

```yaml
session_id: SESS-2025-recon
plan: PLAN-NET-001                    # plan ref or inline dict
schedule:
  start_at: "2025-06-01T00:00:00Z"
  deadline: "2025-06-30T23:59:59Z"   # optional
  max_duration: PT2H                  # ISO 8601, optional
dependencies: []                      # session IDs that must complete first
max_parallel_actions: 1
drift_rules_override: []              # optional per-session overrides
```

### Drift Rules

| ID | Description | Default Action |
|----|-------------|---------------|
| `DRIFT-TARGET` | Target scope changed | HALT |
| `DRIFT-TOOLS` | Allowed tools modified | HALT |
| `DRIFT-NET` | Network topology changed | HALT |
| `DRIFT-SCHEMA` | Plan schema changed | HALT |
| `DRIFT-PLAN` | Plan parameters changed | HALT |
| `DRIFT-EXPIRY` | Plan expired | HALT |
| `DRIFT-AGENT-STATE` | Agent hallucinated evidence | HALT |

### Dependency Resolution

`DependencyResolver` produces a topological ordering of sessions as layers.
All sessions in layer N must complete before any session in layer N+1 can start.
Circular dependencies are detected via DFS and reported during validation.

### Campaign Executor Flow

```
CampaignExecutor.run_agentic_session():
  1. Build AgentCore from session's inline plan (agentic_config)
  2. Create PolicyGate from plan's allowed_tools / authorized_assets
  3. Write initial checkpoint (status: running)
  4. If snapshot_dir configured:
     - Create SnapshotLedger for the session
     - Take initial snapshot (CKPT-0000-init)
     - Wrap execute_action to snapshot before each step (CKPT-NNNN-pre)
  5. Run agent loop via run_agent_loop()
  6. If halted due to drift → attempt context_revalidation restore
  7. Take final snapshot (CKPT-FINAL)
  8. Write final checkpoint with stop reason and stats
```

---

## Summary

| Subsystem | File(s) | Core Responsibility |
|-----------|---------|-------------------|
| **Agent Factory** | `factory.py` | Template-based multi-agent code generation (OpenAI/LangGraph) |
| **Agentic Orchestrator** | `agentic.py` | Bounded autonomous loop with policy, drift, and strategy |
| **Hybrid Strategy** | `agentic.py` | Rule→LLM fallback with stall detection (RULE_ENGINE_STALLED) |
| **Snapshot** | `snapshot.py`, `snapshot.schema.json` | Append-only hash-chained ledger for state recovery |
| **Campaign** | `campaign.py`, `agentic-plan.schema.json` | Multi-session orchestration with scheduling, deps, drift |
