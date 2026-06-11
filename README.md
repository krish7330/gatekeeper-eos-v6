# gatekeeper-eos-v6

> **Generate production-ready multi-agent AI systems from a single YAML spec.**

[![Tests](https://img.shields.io/badge/tests-917%20passed-brightgreen)](tests/)
[![OpenRouter](https://img.shields.io/badge/OpenRouter-️-supported-blue)](docs/openrouter.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](pyproject.toml)

Gatekeeper EOS v6 is a **code-generation factory** for multi-agent AI systems. Define your agents and orchestration pattern in YAML — the factory renders a complete, runnable Python project using the OpenAI Agents SDK or LangGraph.

---

## Features

### Code Generation Factory

- **2 targets** — `openai` (Agents SDK) and `langgraph`
- **11 orchestration patterns** — chain, handoffs, broadcast, debate, consensus, reflection, router_manager, supervisor_workers, agents_as_tools, planner_executor, multi_session
- **21 ready-made specs** — covering healthcare, legal, security, content, research, and more
- **Batch generation** — regenerate all systems with one command via `specs/batch.yaml`
- **OpenAI-compatible** — works with any provider (Groq, OpenRouter, etc.) via `OPENAI_BASE_URL`
- **OpenRouter** — 200+ models through a single endpoint with rate limiter and circuit breaker support ([docs](docs/openrouter.md))

### Agentic Runtime

- **Bounded autonomous loop** — `AgentCore` with world model, evidence log, PolicyGate, and Drift Sentinel
- **Hybrid strategy** — rule-based action selection with LLM fallback and stall detection (`RULE_ENGINE_STALLED`)
- **Snapshot ledger** — append-only SHA-256 hash-chained ledger for agent state recovery via context revalidation
- **Campaign executor** — multi-session orchestration with scheduling, dependency resolution, and drift rule enforcement

### Test Coverage

- **917 tests** — covering generation, validation, agentic loop, snapshot integrity, hybrid stall detection, E2E YAML, campaign orchestration, and OpenRouter provider

---

## Quick Start

```bash
git clone https://github.com/krishanumala/gatekeeper-eos-v6
cd gatekeeper-eos-v6
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Generate a single system
python -m gatekeeper_eos_v6 specs/data-pipeline-chain.yaml

# Run it
cd generated/data-pipeline-chain
export OPENAI_API_KEY=your_groq_key
export OPENAI_BASE_URL=https://api.groq.com/openai/v1
export OPENAI_MODEL=llama-3.3-70b-versatile
python main.py

# Or generate all 21 systems
python -m gatekeeper_eos_v6 specs/batch.yaml
```

---

## Security Subsystems

Gatekeeper-eos-v6 includes three production-ready security subsystems for
agentic workflows:

| Subsystem | Purpose | File |
|-----------|---------|------|
| **Reputation/Verification** | Cross-session asset reputation scoring | `subsystems/reputation_verification.py` |
| **Signed Attestations** | HMAC-SHA256 signatures for snapshots | `subsystems/signed_attestations.py` |
| **Provider Trust Scorer** | LLM drift/hallucination tracking | `subsystems/provider_trust_scorer.py` |

### Quick Start

```bash
# Configure paths (defaults to /tmp/gatekeeper/)
export ATTESTATION_LEDGER_PATH="/tmp/gatekeeper/attestations.json"
export REPUTATION_LEDGER_PATH="/tmp/gatekeeper/reputation.json"
export TRUST_LEDGER_PATH="/tmp/gatekeeper/trust.json"

# Run subsystem tests
pytest tests/test_subsystems_*.py -v
```

```python
from gatekeeper_eos_v6.subsystems import ReputationTracker, AttestationLedger, ProviderTrustScorer
from gatekeeper_eos_v6.subsystems.config import get_reputation_ledger_path

# Track asset reputation
rep = ReputationTracker(get_reputation_ledger_path())
rep.observe_asset("sess-1", "10.0.0.1:80", {"is_positive": True})

# Sign snapshots
att = AttestationLedger(/tmp/ledger.json, /tmp/key.pem)
a = att.create_attestation("sess-1", "ckpt-1", {"ports": [80]})
assert att.verify_attestation(a)

# Score provider trust
trust = ProviderTrustScorer()
trust.record_drift("provider-1", "hallucinated_finding", 0.9)
```

See [`docs/SUBSYSTEMS.md`](docs/SUBSYSTEMS.md) for full documentation.

---

## File Bridge Workflow

Terminal output in Freebuff/Codebuff is not reliably copyable. Use the **file bridge** instead: all output is automatically saved to files in `logs/` so you can open them in any editor and copy/paste cleanly.

### Scripts

| Command | What it does | Log file saved to |
|---|---|---|
| `./run.sh` | Generate all 21 systems + run 105 tests | `logs/run_<stamp>.log`, `logs/generate_<stamp>.log`, `logs/test_<stamp>.log` |
| `./run.sh --gen-only` | Generate systems only | `logs/generate_<stamp>.log` |
| `./run.sh --test-only` | Run tests only | `logs/test_<stamp>.log` |
| `./run.sh --filter <name>` | Generate a single system | `logs/generate_<stamp>.log` |
| `./run_all.sh` | Run 5 agents against the API | `logs/run_all_<stamp>.log` |
| `./output.sh` | Copy latest log → `output.md` for pasting | `output.md` |
| `./output.sh generate` | Copy latest generate log → `output.md` | `output.md` |
| `./output.sh test` | Copy latest test log → `output.md` | `output.md` |
| `./output.sh run_all` | Copy latest run_all log → `output.md` | `output.md` |

### Quick copy workflow

```bash
# 1. Run the pipeline
./run.sh

# 2. Copy latest result to output.md
./output.sh

# 3. Open and paste into Perplexity
code output.md
```

### Direct CLI logging

The factory CLI also supports a `--log` flag that saves output directly:

```bash
python -m gatekeeper_eos_v6 specs/batch.yaml --log
# → Log saved: logs/generate_<stamp>.log
```

---

## Creating a Custom Spec

```yaml
systems:
- name: my-pipeline
  description: A custom data pipeline
  target: openai
  pattern: chain
  model: gpt-4o
  example_input: Analyze this dataset.
  agents:
  - name: extractor
    instructions: You are a data extractor. Parse the input and return structured data.
  - name: analyzer
    instructions: You are an analyst. Identify trends and insights from the extracted data.
  - name: formatter
    instructions: You are a formatter. Produce a clean executive report from the analysis.

---

## Project Structure

```
├── run.sh              # Main pipeline: generate + test
├── run_all.sh          # Agent test runner (calls API)
├── output.sh           # Copy latest log to output.md
├── specs/              # YAML system specifications
│   ├── batch.yaml      # All 21 systems (batch generation)
│   └── *.yaml          # Individual system specs
├── templates/          # Jinja2 code generation templates
│   ├── openai/         # OpenAI Agents SDK templates
│   └── langgraph/      # LangGraph templates
├── generated/          # Output directory (generated code)
├── logs/               # Run logs (file bridge for copy/paste)
├── src/                # Factory source code
├── tests/              # 105 tests
└── pyproject.toml
```

