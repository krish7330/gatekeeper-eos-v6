# Agent Factory — `gatekeeper-eos-v6`

Generate complete multi-agent AI systems from a single YAML batch specification.

## Features

- **Two targets**: [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) and [LangGraph](https://langchain-ai.github.io/langgraph/)
- **Four patterns**:
  - **Handoffs** — agents delegate tasks to each other
  - **Agents as Tools** — agents call other agents as sub-routines
  - **Router Manager** — a router classifies input and dispatches to specialists
  - **Supervisor Workers** — a supervisor orchestrates workers via structured routing
- **Template-based** — all generated code uses Jinja2 templates for easy customization
- **Deterministic output** — one folder per system with `main.py`, `README.md`,
  `AGENTS.md`, and `requirements.txt`

## Quickstart

```bash
# Install dependencies
pip install pyyaml jinja2 pytest

# Generate all systems from the example batch spec
python factory.py specs/batch.yaml

# Or generate into a custom directory
python factory.py specs/batch.yaml -o my_output
```

## Usage

```
usage: factory.py [-h] [--output OUTPUT] [--list-patterns] [--preview]
                  [--verbose] spec

Generate multi-agent AI systems from YAML specs.

positional arguments:
  spec                  Path to YAML spec file (e.g. specs/batch.yaml)

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output directory (default: ./generated)
  --list-patterns       List available targets and patterns, then exit
  --preview             Preview folder structure without writing any files
  --verbose, -v         Show per-file line counts and sizes in preview mode
```

### Examples

```bash
# Preview the output structure without writing anything
python factory.py specs/batch.yaml --preview

# Preview with detailed file stats (lines, bytes per file)
python factory.py specs/batch.yaml --preview --verbose

# Generate all systems
python factory.py specs/batch.yaml
```

## Spec Format

```yaml
systems:
  - name: my-system
    description: "A short description"
    target: openai           # or langgraph
    pattern: handoffs        # or agents_as_tools, router_manager, supervisor_workers
    model: gpt-4o
    example_input: "What agents can you use?"
    agents:
      - name: agent_one
        instructions: "Instructions for this agent."
      - name: agent_two
        instructions: "Instructions for another agent."
```

## Project Structure

```
gatekeeper-eos-v6/
├── factory.py              # CLI orchestrator
├── README.md               # This file
├── AGENTS.md               # Agent patterns reference
├── specs/
│   └── batch.yaml          # Example batch spec
├── templates/
│   ├── openai/             # OpenAI Agents SDK templates
│   │   ├── handoffs/
│   │   ├── agents_as_tools/
│   │   ├── router_manager/
│   │   └── supervisor_workers/
│   └── langgraph/          # LangGraph templates
│       ├── handoffs/
│       ├── agents_as_tools/
│       ├── router_manager/
│       └── supervisor_workers/
├── generated/              # Output directory
└── tests/
    ├── test_spec_parsing.py
    └── test_generation.py
```

## Testing

```bash
pytest tests/ -v
```

## Adding a New Pattern

1. Create `templates/<target>/<new_pattern>/main.py.j2`
2. Create `templates/<target>/<new_pattern>/requirements.txt.j2`
3. Add the pattern name to `SUPPORTED_PATTERNS` in `factory.py`
4. Done — no other code changes needed.
