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

# Generate all 12 example systems
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
│       ├── __init__.py         # Package init
│       ├── __main__.py         # python -m gatekeeper_eos_v6 entry point
│       └── factory.py          # CLI + spec parsing + code generation
├── specs/
│   └── batch.yaml              # Batch spec defining all example systems
├── templates/                  # Jinja2 templates — one folder per (target, pattern)
│   ├── openai/                 # OpenAI Agents SDK target
│   │   ├── handoffs/
│   │   │   ├── main.py.j2
│   │   │   └── requirements.txt.j2
│   │   └── ...                 # 7 more patterns
│   └── langgraph/              # LangGraph target
│       └── ...                 # Mirror of the same patterns
├── generated/                  # Output directory (gitignored)
├── tests/
│   ├── test_spec_parsing.py    # Spec validation tests
│   └── test_generation.py      # Template rendering + file output tests
├── README.md
├── CONTRIBUTING.md
└── pyproject.toml
```

### Key Files

| File | Purpose |
|------|---------|
| `src/gatekeeper_eos_v6/factory.py` | CLI entry point — parses args, loads YAML, validates, renders Jinja2 templates, writes output. All orchestration logic lives here. |
| `templates/{target}/{pattern}/main.py.j2` | Jinja2 template for the system's `main.py`. Receives the `system` dict as template context. |
| `templates/{target}/{pattern}/requirements.txt.j2` | Jinja2 template for `requirements.txt`. |
| `specs/batch.yaml` | The source of truth for all example systems. Every pattern should have at least one entry here. |
| `tests/test_generation.py` | Parameterized tests that render every target/pattern combination and verify file output, syntax, and content. |

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
    "reflection", "debate", "<your_pattern>",
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

2. **Create templates** for all 8 patterns under `templates/<your_target>/`:

   ```bash
   mkdir -p templates/<your_target>/{handoffs,agents_as_tools,router_manager,supervisor_workers,chain,broadcast,reflection,debate}
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

- **`test_spec_parsing.py`** — Tests for `load_spec()` and `validate_spec()`. Validates that:
  - A well-formed spec produces no errors
  - Missing fields produce appropriate errors
  - Invalid targets/patterns are rejected
  - All valid target/pattern combinations pass validation

- **`test_generation.py`** — Tests for `generate_system()` and `generate_all()`. Validates that:
  - All 5 output files are created for every target/pattern combination
  - Generated `main.py` references all agent names
  - Generated files have non-zero content
  - `--preview` mode prints a file tree without writing files
  - `--preview --verbose` shows line counts and byte sizes

### What to Test When Adding a Pattern

The parameterized tests in `test_generation.py` automatically cover new patterns if they're added to `SUPPORTED_PATTERNS`. You don't need to write new test functions — just ensure:

1. The pattern name is added to `SUPPORTED_PATTERNS`
2. Templates exist for at least one target
3. A spec entry exists in `specs/batch.yaml` (or you test with `make_system()`)
4. `pytest tests/` passes

### What to Test When Adding a Target

Similarly, tests parameterize over `SUPPORTED_TARGETS`. Ensure:

1. The target is added to `SUPPORTED_TARGETS`
2. Templates exist for all 8 patterns under `templates/<new_target>/`
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
