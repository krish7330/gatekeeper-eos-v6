# Contributing to Agent Factory

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Table of Contents

- [Setup](#setup)
- [Development Workflow](#development-workflow)
- [Project Architecture](#project-architecture)
- [Adding a New Pattern](#adding-a-new-pattern)
- [Adding a New Target](#adding-a-new-target)
- [Adding a New Spec](#adding-a-new-spec)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [CI / CD](#ci--cd)

---

## Setup

### Prerequisites

- Python 3.11+
- `git`

### Clone and install

```bash
git clone https://github.com/krish7330/gatekeeper-eos-v6.git
cd gatekeeper-eos-v6

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install the package with dev dependencies
pip install -e ".[dev]"
```

### Verify your setup

```bash
# Run the tests
python -m pytest tests/ -v --tb=short

# Generate all 17 example systems
factory specs/batch.yaml
# or: python -m gatekeeper_eos_v6 specs/batch.yaml

# Preview mode — no files written
factory specs/batch.yaml --preview

# List available targets and patterns
factory specs/batch.yaml --list-patterns
```

---

## Development Workflow

1. **Create a feature branch:** `git checkout -b feat/my-new-pattern`
2. **Make your changes** — see guides below
3. **Run tests:** `python -m pytest tests/ -v --tb=short`
4. **Generate all systems:** `factory specs/batch.yaml` (validates templates render without errors)
5. **Run the full CI suite locally:** see [CI / CD](#ci--cd)
6. **Commit and push:** follow the [commit style](#commit-messages) below
7. **Open a pull request**

---

## Project Architecture

```
gatekeeper-eos-v6/
├── src/
│   └── gatekeeper_eos_v6/
│       ├── __init__.py          # Package init
│       ├── __main__.py          # python -m gatekeeper_eos_v6 entry point
│       ├── factory.py           # CLI + spec parsing + code generation (factory patterns)
│       ├── agentic.py           # Bounded autonomous loop — AgentCore, PolicyGate, Drift Sentinel, Hybrid Strategy
│       ├── snapshot.py          # Append-only hash-chained ledger — context revalidation recovery
│       ├── campaign.py          # Multi-session orchestration — scheduling, deps, drift rules
│       ├── checkpoint.py        # Checkpoint read/write/rollback
│       ├── locks.py             # Lock manager (mutex, semaphore, RW lock)
│       └── perplexity_client.py # External API client
├── schemas/
│   ├── snapshot.schema.json     # SnapshotEntry data contract (hash chain, world state)
│   └── agentic-plan.schema.json # Agentic config and campaign plan schema
├── specs/
│   ├── batch.yaml               # Batch spec defining all example systems
│   └── *.yaml                   # Individual YAML system specs
├── templates/                   # Jinja2 templates — one folder per (target, pattern)
│   ├── openai/                  # OpenAI Agents SDK target
│   │   ├── handoffs/
│   │   │   ├── main.py.j2
│   │   │   └── requirements.txt.j2
│   │   └── ...                  # 9 more patterns
│   └── langgraph/               # LangGraph target
│       └── ...                  # Mirror of the same patterns
├── generated/                   # Output directory (gitignored)
├── n8n/                         # n8n workflow exports (Alance V1, Hardened Pair)
├── tests/
│   ├── test_spec_parsing.py     # Spec validation tests
│   ├── test_generation.py       # Template rendering + file output tests
│   ├── test_agentic.py          # AgentCore, PolicyGate, ActionSelector, hybrid stall tests
│   ├── test_e2e_yaml.py         # End-to-end YAML config → AgentCore → stop condition tests
│   ├── test_snapshot.py         # Snapshot ledger integrity, take_snapshot, context_revalidation
│   └── test_campaign.py         # Campaign YAML validation, dependency resolution, executor
├── scripts/
│   └── run_and_analyze.py      # Agent run + analysis harness
├── README.md
├── CONTRIBUTING.md
├── AGENTS.md                    # Agent pattern reference — factory + runtime subsystems
├── TECHNICAL_DESIGN.md          # Alance V1 n8n architecture
└── pyproject.toml
```

### Key Files

| File | Purpose |
|------|---------|
| `src/gatekeeper_eos_v6/factory.py` | CLI entry point — parses args, loads YAML, validates, renders Jinja2 templates, writes output. |
| `src/gatekeeper_eos_v6/agentic.py` | Bounded autonomous loop — `AgentCore`, `PolicyGate`, `Drift Sentinel`, `ActionSelector` (rule/llm/hybrid). |
| `src/gatekeeper_eos_v6/snapshot.py` | Append-only hash-chained ledger — `SnapshotLedger`, `take_snapshot()`, `context_revalidation()`. |
| `src/gatekeeper_eos_v6/campaign.py` | Multi-session orchestration — `CampaignExecutor`, `DependencyResolver`, drift rule enforcement. |
| `templates/{target}/{pattern}/main.py.j2` | Jinja2 template for generated system's `main.py`. |
| `templates/{target}/{pattern}/requirements.txt.j2` | Jinja2 template for `requirements.txt`. |
| `specs/batch.yaml` | All example systems for the factory. |
| `schemas/snapshot.schema.json` | SnapshotEntry JSON Schema with hash chain, world state, evidence, agent action. |
| `schemas/agentic-plan.schema.json` | Agentic config schema — decision strategy, stop conditions, rule engine config. |
| `tests/test_generation.py` | Parameterized tests for factory template rendering. |
| `tests/test_agentic.py` | 620+ tests for agentic loop, hybrid stall detection, drift sentinel, PolicyGate CIDR. |
| `tests/test_e2e_yaml.py` | 37 E2E tests loading YAML config → AgentCore → stop condition → snapshot → drift recovery. |
| `tests/test_snapshot.py` | 52 tests for SnapshotLedger integrity, take_snapshot, context_revalidation. |

---

## Adding a New Pattern

This is the most common contribution. Adding a pattern requires **templates** and a **registry entry** — no changes to the factory's core logic.

### Step 1: Create templates

```bash
mkdir -p templates/openai/<pattern_name>
mkdir -p templates/langgraph/<pattern_name>
```

Each target needs two files:

**`templates/openai/<pattern_name>/main.py.j2`** — The Jinja2 template for the system's `main.py`. Template variables available:

| Variable | Type | Description |
|----------|------|-------------|
| `system.name` | str | System name from the spec |
| `system.description` | str | System description |
| `system.target` | str | Target framework (`openai` or `langgraph`) |
| `system.pattern` | str | Pattern name |
| `system.model` | str | LLM model (e.g., `gpt-4o`) |
| `system.example_input` | str | Default user input |
| `system.agents` | list[dict] | List of agents, each with `name` and `instructions` |
| `system.max_rounds` | int | (Optional) Max rounds for loop-based patterns |

**Conventions for OpenAI templates:**
- Use `asyncio` + `agents` package
- Read `USER_INPUT` from environment, fall back to `system.example_input`
- Read `OPENAI_API_KEY` from environment
- Print clear headers between agent outputs (`===`, `---` separators)
- Handle the pattern's orchestration logic inline (for loops, `asyncio.gather()`, etc.)

**`templates/openai/<pattern_name>/requirements.txt.j2`** — Dependencies:

```jinja
openai-agents>=0.0.6
```

### Step 2: Register the pattern

In `src/gatekeeper_eos_v6/factory.py`, add the new pattern to `SUPPORTED_PATTERNS`:

```python
SUPPORTED_PATTERNS = {
    "handoffs", "agents_as_tools", "router_manager",
    "supervisor_workers", "chain", "broadcast",
    "reflection", "debate", "consensus",
    "planner_executor", "<your_pattern>",
}
```

That's it — no other code changes needed. The factory automatically discovers templates by `{target}/{pattern}/` directory structure.

### Step 3: Add a spec entry

Add at least one system to `specs/batch.yaml` to exercise the new pattern:

```yaml
- name: my-new-pattern-system
  description: "Demonstrates the new pattern."
  target: openai       # or langgraph; add entries for both if possible
  pattern: <your_pattern>
  model: gpt-4o
  example_input: "Your example input here."
  agents:
    - name: agent_a
      instructions: "Instructions for agent A."
    - name: agent_b
      instructions: "Instructions for agent B."
```

> **Tip:** Add entries for **both** `openai` and `langgraph` targets if you created both templates. This ensures full test coverage.

### Step 4: Verify

```bash
# Tests will automatically parameterize over the new pattern
python -m pytest tests/ -v --tb=short

# Generate all systems (including your new one)
factory specs/batch.yaml

# Check the generated output
cat generated/<your-system-name>/main.py
```

### Design Principles for Templates

| Principle | Why |
|-----------|-----|
| **Self-contained** | Each `main.py` should be runnable with just `pip install -r requirements.txt && python main.py`. |
| **Idiomatic** | Match the target SDK's conventions. OpenAI templates use `asyncio` + `Runner.run()`. LangGraph templates use `StateGraph` + nodes. |
| **Readable** | Generated code should look hand-written — clear variable names, comments, and consistent formatting. |
| **Configurable** | Support `USER_INPUT` and `OPENAI_API_KEY` env vars. Loop-based patterns should respect `max_rounds` from the spec. |
| **Informative** | Print clear section headers so users can follow the agent interaction. Show agent names, round numbers, and final output clearly. |

### Template Examples

Study these existing templates for reference:

- **`templates/openai/broadcast/main.py.j2`** — `asyncio.gather()` parallel execution with result merging
- **`templates/openai/reflection/main.py.j2`** — For-loop with generator/critic and `APPROVED` keyword check
- **`templates/langgraph/broadcast/main.py.j2`** — Fan-out / fan-in with `StateGraph` and `add_conditional_edges`
- **`templates/openai/consensus/main.py.j2`** — Independent analysis → synthesis with `asyncio.gather()` and structured consensus prompt
- **`templates/openai/planner_executor/main.py.j2`** — Three-phase plan → execute → verify with sequential executor chaining
- **`templates/openai/handoffs/main.py.j2`** — Agent handoffs via `Agent(handoffs=[...])`
- **`templates/openai/agents_as_tools/main.py.j2`** — `agent.as_tool()` wrapping
- **`templates/openai/router_manager/main.py.j2`** — Conditional dispatch with `handoffs`
- **`templates/openai/supervisor_workers/main.py.j2`** — Dynamic routing with supervisor loop

---

## Adding a New Target

Adding a new target (e.g., Amazon Bedrock, CrewAI, Autogen) requires more work than adding a pattern.

### Steps

1. **Add the target to `SUPPORTED_TARGETS`** in `factory.py`:

   ```python
   SUPPORTED_TARGETS = {"openai", "langgraph", "<your_target>"}
   ```

2. **Create templates** for all 10 patterns under `templates/<your_target>/`:

```bash
mkdir -p templates/<your_target>/{handoffs,agents_as_tools,router_manager,supervisor_workers,chain,broadcast,reflection,debate,consensus,planner_executor}
```

   Each needs `main.py.j2` and `requirements.txt.j2`. See existing targets for reference.

3. **Add spec entries** to `specs/batch.yaml` for each pattern under the new target.

4. **Verify** — tests will automatically parameterize over the new target:

   ```bash
   python -m pytest tests/ -v --tb=short
   factory specs/batch.yaml
   ```

### Design Guidelines for a New Target

- Match the target SDK's idiomatic patterns
- Keep the same env-var conventions (`USER_INPUT`, target-specific API keys)
- Print the same structured output format (clear headers, agent names, final output)

---

## Adding a New Spec

Adding an example system to `specs/batch.yaml` is a great way to showcase a pattern.

```yaml
- name: your-system-name
  description: "A one-line description of what this system does."
  target: openai           # or langgraph
  pattern: handoffs        # or any registered pattern
  model: gpt-4o
  example_input: "The default user input for this system."
  agents:
    - name: agent_one
      instructions: >-
        Instructions for the first agent. Be specific about the agent's
        role, tone, and behavior.
    - name: agent_two
      instructions: >-
        Instructions for the second agent.
```

### Guidelines for Good Specs

- Each spec should demonstrate a **realistic use case**, not a toy example
- Agent instructions should be **specific and detailed** — generic instructions produce generic behavior
- Use `example_input` that **exercises the pattern** (e.g., a debate prompt for Debate, a multi-part request for Handoffs)
- Prefer **concrete domains** (legal, healthcare, finance, code) over abstract ones
- Keep `name` concise and URL-friendly (kebab-case)

---

## Coding Standards

### Python

- **Target:** Python 3.11+
- **Style:** Follow [PEP 8](https://peps.python.org/pep-0008/)
- **Types:** Use type annotations on all function signatures
- **Naming:** `snake_case` for functions/variables, `UPPER_CASE` for constants, `PascalCase` for classes
- **Docstrings:** Use triple-quote docstrings for all public functions

### Jinja2 Templates

- **File naming:** `main.py.j2` and `requirements.txt.j2` (mirrors the output filename)
- **Template context:** Only use `system.*` variables, which are guaranteed by the factory
- **Whitespace control:** Use `{%-` and `-%}` for Jinja2 whitespace trimming where needed
- **No hardcoded values:** Use `{{ system.model }}` instead of hardcoding `gpt-4o`
- **Favor readability:** Generated code should look like it was hand-written

### YAML Specs

- Use `>-` (folded block scalar) for multi-line descriptions and instructions
- Keep `name` fields kebab-case and URL-friendly
- Every agent needs both `name` and `instructions`

### Commit Messages

Follow [conventional commits](https://www.conventionalcommits.org/):

```
type(scope): short description

Optional longer body explaining what and why.
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

Examples:
```
feat(patterns): add reflection pattern with generator + critic loop
docs(readme): add architecture comparison table
fix(ci): exclude non-package dirs from setuptools flat-layout discovery
test(generation): add syntax validation for generated main.py
```

---

## Testing Guidelines

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v --tb=short

# Run a specific test file
python -m pytest tests/test_generation.py -v --tb=short

# Run a specific test
python -m pytest tests/test_spec_parsing.py::test_validate_spec_valid -v

# Run tests matching a pattern (e.g., all reflection tests)
python -m pytest tests/ -v -k "reflection"
```

### Test Architecture

#### Factory Tests
- **`test_spec_parsing.py`** — Tests for `load_spec()` and `validate_spec()`. Validates well-formed specs, missing fields, invalid targets/patterns.
- **`test_generation.py`** — Tests for `generate_system()` and `generate_all()`. Validates all output files, syntax, content, preview mode.

#### Agentic Runtime Tests
- **`test_agentic.py`** (620+ tests) — Covers:
  - `AgentCore`: world model update, evidence logging, drift detection
  - `PolicyGate`: tool/command/target validation, CIDR matching, wildcard hostnames
  - `ActionSelector`: rule-based action selection, LLM mode, hybrid strategy
  - **Hybrid stall detection**: `_check_tool_loop`, `_check_asset_exhaustion` (FP-gated), `_check_state_stagnation`
  - `RULE_ENGINE_STALLED`: LLM fallback with same/different action, no-LLM fallback, agent loop halting
  - `run_agent_loop`: full loop with PolicyGate, stop conditions, drift sentinel
- **`test_e2e_yaml.py`** (37 tests) — End-to-end YAML config → `AgentCore` → stop conditions → snapshots → drift recovery. Covers multi-asset discovery without false stall.
- **`test_snapshot.py`** (52 tests) — `SnapshotLedger`: append, verify integrity, verify_entry_integrity, reload. `take_snapshot()` with full agent state. `context_revalidation()` with failure modes (no snapshot, broken hash chain, drift after restore). Schema validation against `snapshot.schema.json`.
- **`test_campaign.py`** — Campaign YAML validation, dependency resolution, drift rule enforcement, `CampaignExecutor`.

### What to Test When Adding a Factory Pattern

The parameterized tests in `test_generation.py` automatically cover new patterns if they're added to `SUPPORTED_PATTERNS`. You don't need to write new test functions — just ensure:

1. The pattern name is added to `SUPPORTED_PATTERNS`
2. Templates exist for at least one target
3. A spec entry exists in `specs/batch.yaml`
4. `pytest tests/` passes

### What to Test When Adding to the Agentic Runtime

When adding features to `agentic.py`, `snapshot.py`, or `campaign.py`:

1. Write tests in the appropriate `tests/test_*.py` file
2. Run specific test file first: `python -m pytest tests/test_agentic.py -v`
3. Run E2E tests: `python -m pytest tests/test_e2e_yaml.py -v`
4. Run full suite before commit: `python -m pytest tests/ -q`
5. Verify no regression: compare against the known baseline of 733+ tests passing

### What to Test When Adding a New Target

Tests parameterize over `SUPPORTED_TARGETS`. Ensure:

1. The target is added to `SUPPORTED_TARGETS`
2. Templates exist for all 11 patterns under `templates/<new_target>/`
3. Spec entries exist for the new target in `specs/batch.yaml`
4. `pytest tests/` passes

---

## Pull Request Process

1. **Create a feature branch** from `master`
2. **Make your changes** — include tests and documentation updates
3. **Run the full test suite** — `python -m pytest tests/ -v --tb=short`
4. **Generate all systems** — `factory specs/batch.yaml` (validates all templates)
5. **Update the README** if your change affects:
   - The list of patterns or targets
   - The Pattern Gallery or Architecture Comparison section
   - The decision tree or pattern selection guide
6. **Push your branch** and open a PR against `master`
7. **CI must pass** — the workflow runs tests on Python 3.11, 3.12, and 3.13, generates all systems, and validates syntax
8. **Request a review** from a maintainer

### PR Checklist

- [ ] Tests pass locally (`pytest tests/ -v --tb=short`)
- [ ] All systems generate (`factory specs/batch.yaml`)
- [ ] CI passes on GitHub
- [ ] README updated if patterns/targets changed
- [ ] At least one spec entry added for new patterns
- [ ] No `generated/` files committed (it's in `.gitignore`)
- [ ] Commit messages follow conventional commits

---

## CI / CD

The project uses GitHub Actions for continuous integration.

### Workflow (`.github/workflows/ci.yml`)

On every push/PR to `master`, the CI pipeline:

1. **Sets up Python** (3.11, 3.12, 3.13 matrix)
2. **Installs dependencies** via `pip install -e ".[dev]"`
3. **Runs tests** — `pytest tests/ -v --tb=short`
4. **Generates all systems** — `factory specs/batch.yaml`
5. **Validates Python syntax** of all generated `main.py` files
6. **Runs preview mode** (both normal and verbose)
7. **Verifies `.gitignore`** includes `generated/`

### Running CI locally

```bash
# Install from scratch to match CI
pip install -e ".[dev]"

# Run the same steps CI runs
python -m pytest tests/ -v --tb=short
factory specs/batch.yaml
factory specs/batch.yaml --preview
factory specs/batch.yaml --preview --verbose

# Validate generated syntax
python -c "
import ast
from pathlib import Path
for f in sorted(Path('generated').glob('*/main.py')):
    code = f.read_text()
    ast.parse(code)
    print(f'  OK {f.parent.name}/main.py ({len(code.splitlines())} lines)')
"
```

---

## Getting Help

- Open an issue on GitHub for bugs or feature requests
- Use discussions for questions about patterns, templates, or architecture
- Check the [Pattern Gallery](README.md#pattern-gallery--when-to-use-each-pattern) in the README for pattern guidance

---

*Agent Factory is maintained by its contributors. Thanks for helping improve it!*
