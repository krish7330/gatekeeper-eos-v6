# OpenRouter Provider

> **Run Gatekeeper EOS agentic sessions through OpenRouter's unified API** — access 200+ models (Llama, Phi, DeepSeek, Mistral, Qwen, and more) through a single OpenAI-compatible endpoint.

The `OpenRouterProvider` is a drop-in LLM provider backed by [OpenRouter](https://openrouter.ai/). It inherits from `OpenAIProvider` and uses the OpenAI Python SDK under the hood, so every capability of the OpenAI provider (generate, retry, circuit breaker, rate limiter) works identically.

---

## Quick Start

### 1. Get an API key

1. Go to [openrouter.ai/keys](https://openrouter.ai/keys)
2. Click **Create Key** and copy the `sk-or-v1-...` value

### 2. Set the environment variable

```bash
export OPENROUTER_API_KEY="sk-or-v1-your-key-here"
```

### 3. Run the live smoke test

```bash
uv run python -m pytest tests/test_live_openrouter.py -v
```

Expected output (all 6 pass):

```
tests/test_live_openrouter.py ✓✓✓✓✓✓ (6 passed)
```

> **Cost:** The smoke test uses the free tier (`meta-llama/llama-3.2-3b-instruct:free` and `microsoft/phi-3-mini-4k-instruct:free`) — zero cost.

---

## Model Selection

OpenRouter uses **model IDs** (not short names). Free models require a `:free` suffix.

| Model | OpenRouter ID | Cost |
|-------|---------------|------|
| Llama 3.2 3B | `meta-llama/llama-3.2-3b-instruct:free` | Free |
| Phi-3 Mini | `microsoft/phi-3-mini-4k-instruct:free` | Free |
| DeepSeek Chat | `deepseek/deepseek-chat:free` | Free |
| Mistral 7B | `mistralai/mistral-7b-instruct:free` | Free |
| Qwen 2.5 | `qwen/qwen-2.5-7b-instruct:free` | Free |
| Llama 3.3 70B | `meta-llama/llama-3.3-70b-instruct` | Pay-per-token |
| GPT-4o | `openai/gpt-4o` | Pay-per-token (via OpenRouter) |

Browse the full catalog at [openrouter.ai/models](https://openrouter.ai/models).

---

## Provider Configuration

The `OpenRouterProvider` accepts the same parameters as `OpenAIProvider`, plus OpenRouter-specific defaults.

### Basic

```python
from gatekeeper_eos_v6.providers import OpenRouterProvider

provider = OpenRouterProvider(
    model="meta-llama/llama-3.2-3b-instruct:free",
    temperature=0.2,
    max_tokens=1024,
)
```

### With Rate Limiter

```python
from gatekeeper_eos_v6.providers import OpenRouterProvider, RateLimiter

provider = OpenRouterProvider(
    model="meta-llama/llama-3.2-3b-instruct:free",
    rate_limiter=RateLimiter(capacity=15, tokens_per_second=3.0),
)
```

### With Circuit Breaker

```python
from gatekeeper_eos_v6.providers import OpenRouterProvider, CircuitBreaker

provider = OpenRouterProvider(
    model="meta-llama/llama-3.2-3b-instruct:free",
    circuit_breaker=CircuitBreaker(failure_threshold=7, recovery_timeout=120),
)
```

### Explicit API Key

```python
provider = OpenRouterProvider(
    api_key="sk-or-v1-explicit-key",  # overrides OPENROUTER_API_KEY env
    model="meta-llama/llama-3.2-3b-instruct:free",
)
```

### Custom Base URL (proxy / self-hosted)

```python
provider = OpenRouterProvider(
    base_url="http://localhost:8080/v1",  # custom endpoint
)
```

---

## Agentic Config Forwarding

When using `AgentCore.from_agentic_config()`, the `llm_provider_config` block is forwarded directly to the provider constructor. The following fields are supported:

```yaml
llm_provider_config:
  type: openrouter                     # REQUIRED: selects OpenRouterProvider
  model: meta-llama/llama-3.2-3b-instruct:free
  temperature: 0.2                     # optional, default 0.2
  max_tokens: 1024                     # optional, default 1024
  timeout: 30                          # optional, default 60
  max_retries: 3                       # optional, default 0
  base_url: https://openrouter.ai/api/v1  # optional, uses OpenRouter default
  api_key: sk-or-v1-...                # optional, overrides env var
  rate_limiter_config:                 # optional, creates a RateLimiter
    capacity: 15
    tokens_per_second: 3.0
  circuit_breaker_config:              # optional, creates a CircuitBreaker
    failure_threshold: 7
    recovery_timeout: 120
    half_open_max_retries: 3
```

### Example: Campaign spec

```yaml
# specs/openrouter-broadcast.yaml
campaign_id: CAMP-OPENROUTER-2026-Q3
sessions:
  - session_id: SESS-or-llama-recon
    strategy: llm
    llm_model: meta-llama/llama-3.2-3b-instruct:free
    plan:
      agentic_config:
        enabled: true
        llm_provider_config:
          type: openrouter
          model: meta-llama/llama-3.2-3b-instruct:free
          rate_limiter_config:
            capacity: 10
            tokens_per_second: 2.0
          circuit_breaker_config:
            failure_threshold: 5
            recovery_timeout: 60
```

For a full campaign example with 6 sessions covering different models and strategies, see [`specs/openrouter-broadcast.yaml`](../specs/openrouter-broadcast.yaml).

---

## Spec Reference

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `type` | **Yes** | — | Must be `"openrouter"` |
| `model` | No | `meta-llama/llama-3.2-3b-instruct:free` | OpenRouter model ID |
| `api_key` | No | `OPENROUTER_API_KEY` env var | Inline key (overrides env) |
| `temperature` | No | `0.2` | Sampling temperature |
| `max_tokens` | No | `1024` | Max tokens in response |
| `timeout` | No | `60` | HTTP request timeout (seconds) |
| `max_retries` | No | `0` | Retries on transient failures |
| `base_url` | No | `https://openrouter.ai/api/v1` | API endpoint |
| `rate_limiter_config` | No | — | Dict with `capacity` and `tokens_per_second` |
| `circuit_breaker_config` | No | — | Dict with `failure_threshold`, `recovery_timeout`, `half_open_max_retries` |

---

## Testing

### Test Suite (917+ tests, 0 failures)

```bash
uv run python -m pytest tests/ -q
```

All OpenRouter provider unit tests are mocked — no API key required:

| Test | Location | What it verifies |
|------|----------|------------------|
| `TestOpenRouterProvider` (6 tests) | `tests/test_agentic.py:2046` | Key requirement, model, base URL, generate, factory |
| `test_openrouter_forwarding_api_key` | `tests/test_agentic.py` | `api_key` + `model` forwarded via `from_agentic_config` |
| `test_openrouter_forwarding_custom_model` | `tests/test_agentic.py` | Custom `model` + `max_retries` forwarded |
| `test_openrouter_rate_limiter_config` | `tests/test_agentic.py` | Rate limiter config forwarded |
| `test_openrouter_circuit_breaker_config` | `tests/test_agentic.py` | Circuit breaker config forwarded |
| `test_openrouter_both_configs` | `tests/test_agentic.py` | Both configs forwarded together |
| `test_openrouter_no_configs` | `tests/test_agentic.py` | Absent configs → not forwarded |

### Live Smoke Test (requires API key)

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
uv run python -m pytest tests/test_live_openrouter.py -v
```

The smoke test (`tests/test_live_openrouter.py`) automatically **skips** when the key is absent:

```
tests/test_live_openrouter.py ssssss (6 skipped in 0.02s)
```

Six live tests cover:

| Test | What it exercises |
|------|-------------------|
| `test_live_initialization` | Provider init with real key + free model |
| `test_live_generate_returns_valid_json` | Real API call, JSON parse, call_count tracking |
| `test_live_generate_with_custom_model` | Second free model (Phi-3) |
| `test_live_create_llm_provider_factory` | `create_llm_provider("openrouter")` factory path |
| `test_live_with_rate_limiter` | RateLimiter attached to provider |
| `test_live_with_circuit_breaker` | CircuitBreaker attached (CLOSED state) |

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `ValueError: OPENROUTER_API_KEY not set` | Missing API key | `export OPENROUTER_API_KEY="sk-or-v1-..."` or pass `api_key=` to constructor |
| `401 Unauthorized` | Invalid or revoked API key | Generate a new key at [openrouter.ai/keys](https://openrouter.ai/keys) |
| `402 Payment Required` | Free model exhausted or account has no credits | Use a different free model or add credits |
| `429 Too Many Requests` | Rate limited by OpenRouter | Add a `RateLimiter` (see config above) or reduce request frequency |
| `Model not found` | Invalid model ID | Check the exact model ID at [openrouter.ai/models](https://openrouter.ai/models); remember `:free` suffix for free models |
| `Empty response from live API` | Model returned non-JSON or failed | Check `OPENROUTER_API_KEY`, model availability, and network |
| `Provider not found in factory` | Wrong provider type string | Use `"openrouter"` (not `"openai"` or `"OpenRouter"`) |
| Tests skip with `s` not `PASSED` | No `OPENROUTER_API_KEY` env var | Set the key and re-run — this is the expected behavior |

---

## Architecture

```
┌──────────────────┐     ┌──────────────────────────┐     ┌─────────────────┐
│  AgentCore        │────▶│  OpenRouterProvider       │────▶│  OpenAI SDK      │
│  from_agentic_    │     │  (inherits OpenAIProvider)│     │  (chat.completions│
│  config()         │     │  — rate_limiter           │     │   .create)       │
│                  │     │  — circuit_breaker        │     │                 │
│                  │     │  — max_retries            │     │                 │
└──────────────────┘     └──────────────────────────┘     └────────┬────────┘
                                                                    │
                                                                    ▼
                                                          ┌─────────────────┐
                                                          │  OpenRouter API  │
                                                          │  (unified /v1)   │
                                                          │  200+ models     │
                                                          └─────────────────┘
```

Key design points:

- **`OpenRouterProvider`** subclasses `OpenAIProvider` — the `generate()` method is inherited, using `self._client.chat.completions.create()` under the hood
- **Rate limiter** and **circuit breaker** wrap `generate()` at the provider level, independent of the underlying SDK
- **Config forwarding** happens in `AgentCore.from_agentic_config()`, which reads `llm_provider_config` and passes the parameters through to the provider constructor
- **Mock tests** patch `openai.OpenAI` (not `OpenRouterProvider`) since the parent class uses the OpenAI SDK — this means OpenRouter tests follow the same mocking pattern as OpenAI tests

---

## Related Files

| File | Purpose |
|------|---------|
| [`src/gatekeeper_eos_v6/providers.py`](../src/gatekeeper_eos_v6/providers.py) | `OpenRouterProvider`, `RateLimiter`, `CircuitBreaker` implementation |
| [`specs/openrouter-broadcast.yaml`](../specs/openrouter-broadcast.yaml) | Full campaign spec with 6 OpenRouter sessions |
| [`tests/test_agentic.py`](../tests/test_agentic.py) | Unit tests for OpenRouter provider + config forwarding |
| [`tests/test_live_openrouter.py`](../tests/test_live_openrouter.py) | Live smoke test (skips without API key) |
