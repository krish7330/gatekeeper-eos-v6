# Agent Factory — `gatekeeper-eos-v6`

Generate complete multi-agent AI systems from a single YAML batch specification.

## Features

- **Two targets**: [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) and [LangGraph](https://langchain-ai.github.io/langgraph/)
- **Seven patterns**:
  - **Handoffs** — agents delegate tasks to each other
  - **Agents as Tools** — agents call other agents as sub-routines
  - **Chain** — linear pipeline where each agent passes output to the next
  - **Broadcast / Mesh** — fan-out: all agents analyze the same input in parallel, then results are merged
  - **Reflection** — generator + critic loop: output is iteratively refined until approved or max rounds reached
  - **Router Manager** — a router classifies input and dispatches to specialists
  - **Supervisor Workers** — a supervisor orchestrates workers via structured routing
- **Template-based** — all generated code uses Jinja2 templates for easy customization
- **Deterministic output** — one folder per system with `main.py`, `README.md`,
  `AGENTS.md`, and `requirements.txt`

## Pattern Gallery — When to Use Each Pattern

### Decision Tree

```
How should your agents coordinate?
│
├── Sequential steps, each feeding into the next?
│   └── Is the flow strictly linear (A → B → C)?
│       └── → **Chain**
│
├── One agent decides where work goes?
│   ├── Does it classify then delegate to known specialists?
│   │   └── → **Router Manager**
│   └── Does it dynamically route with feedback loops?
│       └── → **Supervisor Workers**
│
├── All agents need to analyze the same input?
│   ├── From different perspectives, independently?
│   │   └── → **Broadcast / Mesh**
│   └── Debating opposing positions toward consensus?
│       └── (future) → **Debate / Consensus**
│
├── Output needs iterative quality improvement?
│   └── → **Reflection** (generator + critic loop)
│
├── Agents seamlessly hand off to each other mid-conversation?
│   └── → **Handoffs**
│
└── A single orchestrator calls specialists as tools?
    └── → **Agents as Tools**
```

### At a Glance

| Pattern | Coordination | Best For | Agents | Loop? |
|---------|-------------|----------|--------|-------|
| **Chain** | Sequential pipeline | Data processing, content pipelines, staged analysis | N (general) | No |
| **Router Manager** | Classification → dispatch | Support triage, content routing, intent-based dispatch | 3+ (router + specialists) | No |
| **Supervisor Workers** | Dynamic routing with feedback | Research, task decomposition, multi-step reasoning | 3+ (supervisor + workers) | Yes (supervisor re-routes) |
| **Broadcast / Mesh** | Parallel fan-out, fan-in | Market analysis, code audit, multi-perspective review | N (all parallel) | No |
| **Reflection** | Generate → critique → revise | Code review, essay drafting, iterative refinement | 2 (generator + critic) | Yes (up to `max_rounds`) |
| **Handoffs** | Agent-to-agent delegation | Customer support, conversational workflows | N (general) | No |
| **Agents as Tools** | Orchestrator calls specialists | Code review, research, tool-augmented workflows | 3+ (orchestrator + tools) | No |

---

### Chain

**When to use:** You have a fixed sequence of processing stages where each stage depends on the previous one. The flow is known at design time.

**Real-world analogy:** An assembly line — each station adds value and passes the workpiece to the next.

**Generated architecture (OpenAI):**
```
input → agent[0] → agent[1] → ... → agent[N-1] → output
```
Each agent receives `result.final_output` from the previous agent. The pipeline depth is defined by the number of agents in the spec.

**Generated architecture (LangGraph):**
```
START → agent[0] → agent[1] → ... → agent[N-1] → END
```
A linear DAG where each node is a function that calls an LLM with the accumulated messages.

**Best for:**
- Multi-stage data processing pipelines
- Content generation where each phase builds on the last (outline → draft → polish)
- Compliance or review workflows with fixed gates

**Avoid when:** You need dynamic routing, parallel processing, or iterative refinement.

---

### Router Manager

**When to use:** Input can be classified into distinct categories, and each category has a dedicated specialist. The router decides once, then the specialist handles it.

**Real-world analogy:** A hospital triage nurse who directs patients to the right department.

**Generated architecture (OpenAI):**
```
        ┌── specialist[0]
input → router ── specialist[1]
        └── specialist[2]
```
The router classifies the input and uses `Agent.handoffs()` to transfer to the matched specialist. The specialist handles the full interaction.

**Generated architecture (LangGraph):**
```
             ┌── specialist[0]
START → router ── specialist[1] ──→ (back to router or END)
             └── specialist[2]
```
The router chooses the next specialist via conditional edges. After a specialist responds, control returns to the router for further routing or completion.

**Best for:**
- Customer support triage (billing, technical, refund)
- Content classification and routing
- Intent-based dispatch systems

**Avoid when:** The number of categories is very large or dynamic, or when tasks require multi-step collaboration between specialists.

---

### Supervisor Workers

**When to use:** Tasks need to be broken down dynamically, delegated to workers, and their results synthesized. The supervisor has a feedback loop.

**Real-world analogy:** A team lead who assigns tasks, reviews progress, and re-assigns as needed until the project is complete.

**Generated architecture (OpenAI):**
```
                ┌── worker[0]
supervisor ─── ── worker[1]  (via handoffs)
                └── worker[2]
```
The supervisor decides the next worker and passes context. Workers return results to the supervisor, who decides next steps or finishes.

**Generated architecture (LangGraph):**
```
                     ┌── worker[0]
START → supervisor ──── worker[1]  ──→ (back to supervisor or END)
                     └── worker[2]
```
The supervisor routes to a worker via conditional edges. Workers return to the supervisor for further routing. The supervisor can choose `FINISH` to end.

**Best for:**
- Research tasks that decompose into sub-questions
- Complex multi-step reasoning
- Dynamic task execution where the plan emerges at runtime

**Avoid when:** The workflow is fixed and known upfront (use Chain instead), or when you need simple classification (use Router Manager).

---

### Broadcast / Mesh

**When to use:** The same input should be analyzed from multiple independent perspectives simultaneously. Results are then merged for a composite view.

**Real-world analogy:** A panel of experts each giving their independent opinion, then a moderator summarizing.

**Generated architecture (OpenAI):**
```
        ┌── agent[0]
input ──── agent[1] ──→ asyncio.gather() ──→ merge
        └── agent[2]
```
All agents receive the same input via `asyncio.gather()`. Each runs independently. Results are displayed per-agent and combined.

**Generated architecture (LangGraph):**
```
        ┌── agent[0] ──┐
START ──── agent[1] ──── collector ──→ END
        └── agent[2] ──┘
```
Fan-out edges from `START` to every agent node (parallel execution). Fan-in edges from every agent to a `collector` node that synthesizes results.

**Best for:**
- Multi-perspective analysis (e.g., code audit from security + performance + style angles)
- Market research with technical, fundamental, and sentiment analysis
- Any scenario where independent parallel opinions add value

**Avoid when:** Agents need to build on each other's output (use Chain), or when a single agent is sufficient.

---

### Reflection

**When to use:** Output quality matters enough to warrant iterative self-critique. A generator produces content, a critic reviews it, and the loop continues until quality standards are met.

**Real-world analogy:** A writer drafts, an editor marks up, the writer revises — repeat until the editor approves.

**Generated architecture (OpenAI):**
```
              ┌─── APPROVED ──→ output
generator ──→ critic ── feedback ──→ generator (loop)
                                          │
                              max_rounds ──┘──→ output
```
A `for` loop running `Runner.run()` for each agent. The critic checks for the `APPROVED` keyword. If found, the loop breaks. Otherwise, the generator revises based on the critic's feedback.

**Generated architecture (LangGraph):**
```
START → generator → critic → router ──→ END (if approved or max rounds)
                                    └──→ generator (loop back)
```
State tracks `round` and `approved` flags. A `router` function checks both conditions to decide whether to loop back or finish. The generator's final output is extracted from the second-to-last AI message.

**Best for:**
- Iterative code review and improvement
- Essay or content drafting with editorial feedback
- Any task where quality improves through critique cycles

**Configure:** Set `max_rounds` in the YAML spec (default: 3).

**Avoid when:** Speed is critical (reflection adds latency), or when a single pass suffices.

---

### Handoffs

**When to use:** Agents need to transfer control mid-conversation based on context. The user interacts with one agent at a time, but the conversation can move between agents seamlessly.

**Real-world analogy:** A receptionist who transfers your call to the right department, then the specialist takes over.

**Generated architecture (OpenAI):**
```
triage agent ──handoff──→ billing agent
         └──handoff──→ refund agent
         └──handoff──→ technical agent
```
The triage agent uses `Agent.handoffs()` to transfer to a specialist. Only one agent is active at a time. The specialist handles the conversation independently.

**Generated architecture (LangGraph):**
```
START → triage ──→ billing ──→ (back to triage or END)
         └──→ refund ──→ (back to triage or END)
         └──→ technical ──→ (back to triage or END)
```
The triage node routes to a specialist via conditional edges. Specialists return to triage for further routing.

**Best for:**
- Customer support with multiple departments
- Conversational agents that need to escalate
- Workflows where the path depends on user responses

**Avoid when:** All agents should process the same input (use Broadcast), or when you want a single orchestrator (use Agents as Tools).

---

### Agents as Tools

**When to use:** One orchestrator agent should be able to call specialist agents as tools/functions. The orchestrator decides when and how to use each specialist.

**Real-world analogy:** A general contractor who hires electricians, plumbers, and carpenters as needed, deciding when to call each.

**Generated architecture (OpenAI):**
```
                  ┌── specialist[0] (tool)
orchestrator ─── ── specialist[1] (tool)
                  └── specialist[2] (tool)
```
Specialists are converted to tools via `agent.as_tool()`. The orchestrator receives them as `tools=specialist_tools` and chooses when to invoke each.

**Generated architecture (LangGraph):**
```
                  ┌── specialist[0]
START → supervisor ── specialist[1]  ──→ (back to supervisor or END)
                  └── specialist[2]
```
The supervisor uses conditional edges to route to a specialist, then the specialist returns control to the supervisor for the next decision.

**Best for:**
- Code review (reviewer calls linter + style checker as tools)
- Research (researcher calls search + summarize + fact-check as tools)
- Any scenario where the orchestrator needs fine-grained control over tool selection

**Avoid when:** The routing is simple classification (use Router Manager), or when agents should own their conversations (use Handoffs).

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
    pattern: handoffs        # or agents_as_tools, broadcast, chain, reflection, router_manager, supervisor_workers
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
│   │   ├── agents_as_tools/
│   │   ├── broadcast/
│   │   ├── chain/
│   │   ├── handoffs/
│   │   ├── reflection/
│   │   ├── router_manager/
│   │   └── supervisor_workers/
│   └── langgraph/          # LangGraph templates
│       ├── agents_as_tools/
│       ├── broadcast/
│       ├── chain/
│       ├── handoffs/
│       ├── reflection/
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
