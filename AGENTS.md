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

---

## Part VI — LLM Provider Configuration

The LLM provider subsystem (`src/gatekeeper_eos_v6/providers.py`) provides a
unified interface for LLM-based action selection within the agentic
orchestrator. Four providers are supported, all implementing the same
`LLMProvider` ABC.

### Provider Matrix

| Provider | Config `type` | Model Example | Env Var | SDK |
|----------|---------------|---------------|---------|-----|
| **OpenAI** | `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` | `openai` |
| **Anthropic** | `anthropic` | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` | `anthropic` |
| **Google (Gemini)** | `google` / `gemini` | `gemini-2.0-flash` | `GEMINI_API_KEY` | `google-genai` |
| **Groq** (via OpenAI compat) | `openai` + `base_url` | `llama-3.3-70b-versatile` | `OPENAI_API_KEY` (set to Groq key) | `openai` |
| **OpenRouter** | `openrouter` | `meta-llama/llama-3.2-3b-instruct:free` | `OPENROUTER_API_KEY` | `openai` (OpenAI SDK) |
| **Mock** | `mock` | `mock` | None | Built-in |

### YAML Configuration

All providers are wired through the `llm_provider_config` block in a session's
`agentic_config`:

```yaml
llm_provider_config:
  type: openai              # Provider type (required)
  model: gpt-4o-mini       # Model name (required)
  temperature: 0.2          # Sampling temperature (optional, default 0.2)
  max_tokens: 1024          # Max response tokens (optional, default 1024)
  base_url: ...             # Custom base URL (optional, openai only)
  api_key: ...              # Explicit key (optional, prefers env var)
  max_retries: 3            # Retry attempts (optional, default 3)
```

### Provider-Specific Examples

**OpenAI** (default — uses `OPENAI_API_KEY`):
```yaml
llm_provider_config:
  type: openai
  model: gpt-4o-mini
  temperature: 0.2
  max_tokens: 1024
```

**Anthropic** (uses `ANTHROPIC_API_KEY`):
```yaml
llm_provider_config:
  type: anthropic
  model: claude-sonnet-4-20250514
  temperature: 0.3
  max_tokens: 2048
```

**Google Gemini** (uses `GEMINI_API_KEY`):
```yaml
llm_provider_config:
  type: google
  model: gemini-2.0-flash
  temperature: 0.2
  max_tokens: 2048
```

**Groq** (OpenAI-compatible — uses `OPENAI_API_KEY` set to Groq key):
```yaml
llm_provider_config:
  type: openai
  model: llama-3.3-70b-versatile
  base_url: https://api.groq.com/openai/v1
  temperature: 0.1
  max_tokens: 1024
  max_retries: 3            # handles Groq 429s automatically
```

**OpenRouter** (uses `OPENROUTER_API_KEY` — single key for many models):
```yaml
llm_provider_config:
  type: openrouter
  model: meta-llama/llama-3.2-3b-instruct:free
  temperature: 0.2
  max_tokens: 1024
```

OpenRouter provides access to many models through a single OpenAI-compatible
endpoint.  Free models like ``meta-llama/llama-3.2-3b-instruct:free`` require
no billing.  See https://openrouter.ai/models for the full catalog.

**Mock** (no API key needed — for testing / offline):
```yaml
llm_provider_config:
  type: mock
  model: mock
```

### Rate Limiting & Retries

All production providers (OpenAI, Anthropic, Google, OpenRouter) automatically apply:

| Feature | Details |
|---------|---------|
| **RateLimiter** | Token bucket, 60 capacity / 3 tokens/sec default |
| **Retry logic** | Exponential backoff with jitter, default 3 retries |
| **Retryable errors** | 429 (rate limit), 503 (unavailable), 502/500 (server), connection/timeout errors |
| **Non-retryable** | 400, 401, 403, 404, JSON decode errors |
| **Metrics** | Each provider tracks `retry_count`, `total_retry_delay`, `last_rate_limit_hit` |

### Custom Rate Limiter Config (YAML)

Override the default token-bucket rate limiter per session by adding a
`rate_limiter_config` block inside `llm_provider_config`:

```yaml
llm_provider_config:
  type: openai
  model: gpt-4o-mini
  rate_limiter_config:
    capacity: 120                # Max burst (default 60)
    tokens_per_second: 5.0       # Steady-state refill (default 3.0)
```

For low-quota API tiers, reduce throughput:
```yaml
llm_provider_config:
  type: anthropic
  model: claude-sonnet-4-20250514
  rate_limiter_config:
    capacity: 10                 # Conservative burst
    tokens_per_second: 1.0       # ~1 RPM steady state
```

### Circuit Breaker (YAML)

A circuit breaker prevents cascading failures by fast-rejecting calls after
repeated failures. Configure it per session inside `llm_provider_config`:

```yaml
llm_provider_config:
  type: openai
  model: gpt-4o-mini
  circuit_breaker_config:
    failure_threshold: 5         # Consecutive failures before opening (default 5)
    recovery_timeout: 60.0       # Seconds before half-open retry (default 60)
    half_open_max_retries: 3     # Test calls in half-open state (default 3)
```

**States**:

| State | Behaviour |
|-------|-----------|
| **CLOSED** | Normal operation; failures increment a counter |
| **OPEN** | All calls fast-reject with fallback (empty string); agent falls back to rule-based selection |
| **HALF_OPEN** | Limited test calls allowed; success → CLOSED, failure → OPEN |

**Example — aggressive circuit breaker for unstable endpoints**:
```yaml
llm_provider_config:
  type: openai
  model: llama-3.3-70b-versatile
  base_url: https://api.groq.com/openai/v1
  circuit_breaker_config:
    failure_threshold: 3         # Open after 3 consecutive failures
    recovery_timeout: 30.0       # Retry after 30 seconds
    half_open_max_retries: 2     # 2 test calls before deciding
  rate_limiter_config:
    capacity: 20
    tokens_per_second: 2.0
```

Both `rate_limiter_config` and `circuit_breaker_config` can be specified
together (as above). They work with all three production providers (OpenAI,
Anthropic, Google).

### Factory Usage (Python)

```python
from gatekeeper_eos_v6.providers import create_llm_provider

# OpenAI
p = create_llm_provider("openai", model="gpt-4o-mini")

# Anthropic
p = create_llm_provider("anthropic", model="claude-sonnet-4-20250514")

# Google Gemini
p = create_llm_provider("google", model="gemini-2.0-flash")

# Groq (OpenAI-compatible)
p = create_llm_provider("openai", model="llama-3.3-70b-versatile",
                        base_url="https://api.groq.com/openai/v1")

# OpenRouter (single key for many models)
p = create_llm_provider("openrouter",
                         model="meta-llama/llama-3.2-3b-instruct:free")

# Generate an action
response = p.generate('{"tool": "nmap", "command": "discover"}')
```

### Provider Switching Pattern

To switch providers in a multi-session campaign, each session's
`agentic_config` specifies its own `llm_provider_config`. This allows
different sessions to use different providers — e.g., Groq for fast
reconnaissance, Claude for report generation, Gemini for cross-referencing.

### Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `ValueError: Missing API key` | Env var not set | Export `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, or `OPENROUTER_API_KEY` |
| `ConnectionError` to OpenRouter | Network issue or OpenRouter outage | Verify `OPENROUTER_API_KEY` is valid and check status.openrouter.ai |
| Frequent 429 errors | Rate limit exceeded | Increase `max_retries`, reduce `tokens_per_second` in `RateLimiter`, or check provider quota |
| Empty responses from `generate()` | API error (non-retryable) | Check `provider.retry_count` and `provider.last_rate_limit_hit` for diagnostics |
| Consistent empty responses after initial failures | Circuit breaker is OPEN | Check `provider._circuit_breaker.state`, `failure_count`, and `_last_failure_time`. Increase `failure_threshold` or `recovery_timeout`, or call `circuit_breaker.reset()` manually |
| Timeout errors | Network / slow model | Increase `max_retries` or use a faster model |

---

## Summary

| Subsystem | File(s) | Core Responsibility |
|-----------|---------|-------------------|
| **Agent Factory** | `factory.py` | Template-based multi-agent code generation (OpenAI/LangGraph) |
| **Agentic Orchestrator** | `agentic.py` | Bounded autonomous loop with policy, drift, and strategy |
| **Hybrid Strategy** | `agentic.py` | Rule→LLM fallback with stall detection (RULE_ENGINE_STALLED) |
| **Snapshot** | `snapshot.py`, `snapshot.schema.json` | Append-only hash-chained ledger for state recovery |
| **Campaign** | `campaign.py`, `agentic-plan.schema.json` | Multi-session orchestration with scheduling, deps, drift |
| **LLM Providers** | `providers.py` | Multi-provider LLM interface (OpenAI, Anthropic, Google, Groq, Mock) with rate limiting & retries |
