# Agent Factory — `gatekeeper-eos-v6`

Generate complete multi-agent AI systems from a single YAML batch specification.

## Features

- **Two targets**: [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) and [LangGraph](https://langchain-ai.github.io/langgraph/)
- **Ten patterns**:
  - **Handoffs** — agents delegate tasks to each other
  - **Agents as Tools** — agents call other agents as sub-routines
  - **Chain** — linear pipeline where each agent passes output to the next
  - **Broadcast / Mesh** — fan-out: all agents analyze the same input in parallel, then results are merged
  - **Debate / Consensus** — multiple agents argue from assigned positions, then a judge evaluates and selects the best argument
  - **Reflection** — generator + critic loop: output is iteratively refined until approved or max rounds reached
  - **Router Manager** — a router classifies input and dispatches to specialists
  - **Supervisor Workers** — a supervisor orchestrates workers via structured routing
  - **Consensus** — independent analysis from multiple perspectives, then a synthesizer identifies agreement and disagreement
  - **Planner-Executor** — a planner decomposes goals into tasks, executors work through them, a verifier checks results
- **Template-based** — all generated code uses Jinja2 templates for easy customization
- **Deterministic output** — one folder per system with `main.py`, `README.md`,
  `AGENTS.md`, and `requirements.txt`

## Pattern Gallery — When to Use Each Pattern

### Decision Tree

```
How should your agents coordinate?
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
│   ├── Debating opposing positions toward consensus?
│   │   └── → **Debate / Consensus**
│   └── Independently, then finding agreement/disagreement?
│       └── → **Consensus**
│
├── Output needs iterative quality improvement?
│   └── → **Reflection** (generator + critic loop)
│
├── A plan is created first, then executed step-by-step?
│   └── → **Planner-Executor**
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
| **Chain** | Sequential pipeline | Data processing, content pipelines, staged analysis | N | No |
| **Debate / Consensus** | Parallel positions, judge verdict | Policy analysis, legal reasoning, decision-making with trade-offs | 3+ (N-1 debaters + judge) | No |
| **Router Manager** | Classification → dispatch | Support triage, content routing, intent-based dispatch | 3+ (router + specialists) | No |
| **Supervisor Workers** | Dynamic routing with feedback | Research, task decomposition, multi-step reasoning | 3+ (supervisor + workers) | Yes (supervisor re-routes) |
| **Consensus** | Independent analysis → synthesis | Risk assessment, multi-perspective review, finding agreement | 3+ (N-1 analysts + synthesizer) | No |
| **Broadcast / Mesh** | Parallel fan-out, fan-in | Market analysis, code audit, multi-perspective review | N (all parallel) | No |
| **Reflection** | Generate → critique → revise | Code review, essay drafting, iterative refinement | 2 (generator + critic) | Yes (up to `max_rounds`) |
| **Planner-Executor** | Plan → execute → verify | Feature planning, project execution, complex workflows | 3+ (planner + executors + verifier) | No |
| **Handoffs** | Agent-to-agent delegation | Customer support, conversational workflows | N (general) | No |
| **Agents as Tools** | Orchestrator calls specialists | Code review, research, tool-augmented workflows | 3+ (orchestrator + tools) | No |

---

## Architecture Comparison

### Tradeoffs at a Glance

| Pattern | Latency | Cost / Run | Determinism | Parallelism | Failure Mode | Ideal Agent Count |
|---------|---------|------------|-------------|-------------|--------------|-------------------|
| **Chain** | 🟢 O(N) sequential | N calls | 🟢 High — fixed pipeline | Sequential | One agent fails → pipeline stalls; no recovery | 2–5 |
| **Broadcast** | 🟢 O(1) wall-clock | N calls | 🟢 Medium — all run same input | Full parallel | One agent fails → partial results still merged | 2–8 |
| **Debate** | 🟢 O(1) wall-clock | N calls | 🟡 Medium — depends on judge quality | Full parallel (debaters) | Weak judge → poor verdict; debater failure → missing perspective | 3–6 |
| **Consensus** | 🟢 O(1) wall-clock | N calls | 🟢 Medium — synthesis-driven | Full parallel (analysts) | Weak synthesizer → false consensus; analyst misses key perspective | 3–6 |
| **Reflection** | 🟡 O(R) sequential (R = rounds) | 2R calls | 🟡 Low — output evolves each round | Sequential (loop) | Critic always approves → no iteration; critic never approves → max rounds waste | 2 (fixed) |
| **Router Manager** | 🟢 O(1) sequential | 2 calls | 🟢 High — classification → dispatch | Sequential | Misclassification → wrong specialist; no recovery path | 3–6 |
| **Supervisor Workers** | 🟡 O(N) sequential with loops | Variable | 🔴 Low — dynamic, emergent | Sequential with loops | Supervisor loops forever → no termination guarantee; worker confusion | 3–6 |
| **Planner-Executor** | 🟡 O(N) sequential (plan → execute → verify) | N+2 calls | 🟢 Medium — structured phases | Sequential (phases) | Planner creates unexecutable plan → executor fails; verifier too strict → false rejection | 3–5 |
| **Handoffs** | 🟢 O(1) sequential | 1–N calls | 🟡 Medium — depends on triage | Sequential | Triage misroutes → user frustration; no built-in escalation if wrong | 2–5 |
| **Agents as Tools** | 🟢 O(1) sequential | Variable | 🟡 Medium — orchestrated | Sequential (tool calls) | Orchestrator over-tools → wasted calls; tool failure → orchestrator must handle | 3–6 |

> **Legend:** 🟢 Low/High — favorable — 🟡 Medium — acceptable — 🔴 High/Low — caution

### Cost & Latency

| Scenario | Best Pattern | Why |
|----------|-------------|-----|
| Need the **fastest** answer | **Broadcast** or **Router Manager** | Single round-trip; no loops |
| Need the **cheapest** answer | **Chain** (2 agents) | Minimal calls with linear flow |
| Need the **highest quality** | **Reflection** | Iterative refinement up to `max_rounds` |
| Need **both speed and quality** | **Debate** | Parallel arguments + single judge pass |
| Need **structured multi-perspective review** | **Consensus** | Independent analysis + synthesis identifies agreement |
| Need **step-by-step plan then execute** | **Planner-Executor** | Decomposes, executes, then verifies |
| **Budget-constrained** (fixed call count) | **Chain**, **Broadcast**, **Router Manager**, **Consensus** | Predictable N calls |
| **Variable budget** (adaptive) | **Supervisor Workers** | Supervisor decides how many calls |

### Failure Modes & Mitigations

| Pattern | Failure Mode | Impact | Mitigation in Template |
|---------|-------------|--------|----------------------|
| **Chain** | Agent produces bad intermediate output | All downstream agents operate on garbage | Each agent must validate/parse input; templates use structured prompts |
| **Broadcast** | One agent hallucinates or fails | Partial result lost; remaining agents unaffected | `asyncio.gather()` collects all — survivor outputs still merge |
| **Debate** | Judge favors wrong argument | Verdict is incorrect | Judge prompt explicitly instructs evidence-based evaluation; debaters must cite specifics |
| **Consensus** | Weak synthesizer produces false consensus | Analysis appears agreed but misses critical disagreement | Synthesizer prompt explicitly requires listing both agreement and disagreement points |
| **Consensus** | Analyst misses key perspective | Blind spot in the synthesis | Analyst instructions cover specific angles; more agents reduce blind-spot risk |
| **Reflection** | Critic always approves prematurely | Low-quality output accepted | `APPROVED` keyword check is strict (`startswith`); critic instructed to require high standards |
| **Reflection** | Critic never approves | Exhausts `max_rounds` — output is last revision, not necessarily good | Template shows final output regardless; user sees all rounds |
| **Router Manager** | Router misclassifies | Wrong specialist receives the task | Router instructions emphasize accuracy; no recovery in current template |
| **Supervisor Workers** | Supervisor loops indefinitely | Infinite runtime, unbounded cost | No hard termination safeguard — rely on LLM choosing `FINISH`; consider adding max-turn limit |
| **Planner-Executor** | Planner creates unexecutable plan | Executor agents fail on impossible tasks | Planner instructions emphasize feasibility, concrete steps, and actionable tasks |
| **Planner-Executor** | Verifier is too strict | Valid output rejected, users see false negatives | Verifier prompt focuses on correctness criteria; final output still shown to user |
| **Handoffs** | Triage misroutes | Specialist can't handle the request | Specialist has full context; no recovery handoff in current template |
| **Agents as Tools** | Orchestrator calls too many tools | Wasted API calls | Tool descriptions must be clear; orchestrator decides invocation count |

### Pattern Selection Guide

**Ask these questions in order to narrow your choice:**

1. **Do agents need to see each other's outputs?**
   - No → **Broadcast** (independent), **Debate** (opposing positions), or **Consensus** (independent + synthesis)
   - Yes → Chain, Reflection, or Supervisor Workers
   - Yes, but phases are structured → **Planner-Executor** (plan → sequential execute → verify)

2. **Is the execution path known at design time?**
   - Yes, fixed → **Chain**
   - No, dynamic → **Supervisor Workers**, **Router Manager**, or **Handoffs**

3. **Does the same agent handle the full conversation?**
   - No, conversation moves between agents → **Handoffs**
   - Yes, one orchestrator decides → **Agents as Tools**

4. **Does quality need to improve iteratively?**
   - Yes → **Reflection**
   - No → All other patterns

5. **What's the maximum acceptable latency?**
   - < 2 sequential calls → **Broadcast**, **Debate**, **Router Manager**
   - 2–5 sequential calls → **Chain**, **Handoffs**, **Agents as Tools**
   - Variable / loop-capable → **Reflection**, **Supervisor Workers**

### Quick Decision Matrix

```
                         Sequential
                             │
          Fixed pipeline ◄───┼───► Dynamic routing
                │            │            │
            Chain            │      Supervisor Workers
                             │
                    ┌────────┴────────┐
                    │                 │
               Same input        Different tasks
                    │                 │
          ┌────────┼────────┐         │
          │        │        │         │
     Independent Opposing  Iterative  One orchestrator
          │        │        │         │
      Broadcast  Debate  Reflection   │
                              ┌───────┴───────┐
                              │               │
                          Classify then   Call as tools
                          hand off            │
                              │        Agents as Tools
                         Router Mgr

                      Conversational handoff?
                              │
                          Handoffs
```

---

### Debate / Consensus

**When to use:** A decision involves trade-offs and you want multiple perspectives argued and evaluated. Different positions should be represented and a judge should weigh the evidence.

**How it works:** The first N-1 agents each argue from their assigned position (pro, con, neutral, etc.) in parallel. The last agent acts as a judge — it reviews all arguments and delivers a verdict on which is strongest, or synthesizes a consensus.

**Real-world analogy:** A courtroom trial: the prosecution and defense present their cases, then the judge delivers a verdict based on the strength of arguments.

**Generated architecture (OpenAI):**
```
        ┌── debater[0] ──┐
input ──── debater[1] ──── asyncio.gather() ──→ judge → verdict
        └── debater[2] ──┘
```
All debaters receive the same input via `asyncio.gather()`. The judge receives all debate positions and produces a final verdict.

**Generated architecture (LangGraph):**
```
        ┌── debater[0] ──┐
START ──── debater[1] ──── judge ──→ END
        └── debater[2] ──┘
```
Fan-out edges from `START` to every debater node (parallel execution). Fan-in edges from all debaters to the judge node.

**Best for:**
- Policy analysis and decision-making with trade-offs
- Legal reasoning and case analysis
- Any scenario where surfacing multiple sides of an issue adds value
- Multi-perspective evaluation where one answer must be selected

**Note:** Last agent in the spec must be the judge. The judge receives all debate arguments and selects the best.

**Avoid when:** You want a simple composite view (use Broadcast instead), or when agents should converge iteratively (use Reflection).

---

### Chain

**When to use:** You have a fixed sequence of processing stages where each stage depends on the previous one. The flow is known at design time.

**How it works:** A linear pipeline where each agent receives the previous agent's output as its input. The processing stages and their order are fixed at design time.

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

**How it works:** A router agent classifies the input and hands off to the matching specialist agent. The specialist handles the task independently, and control may return to the router for follow-up routing.

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

**How it works:** A supervisor agent dynamically decomposes tasks and routes them to worker agents. Workers return results to the supervisor, which decides the next step or finishes when the task is complete.

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

**How it works:** The same input is sent to all agents in parallel. Each agent analyzes it independently from its assigned perspective. All responses are then collected and merged into a unified summary.

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

**How it works:** A generator agent produces an initial output, then a critic agent reviews it and provides feedback. If the critic approves (via an `APPROVED` keyword), the loop exits. Otherwise, the generator revises based on the critique and the cycle repeats up to `max_rounds`.

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

**How it works:** A triage agent receives the input and transfers (hands off) the conversation to the most appropriate specialist agent. Only one agent is active at a time, and specialists can hand off back to triage for further routing.

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

**How it works:** Specialist agents are wrapped as callable tools via `agent.as_tool()`. An orchestrator agent receives these tools and decides when to invoke each one based on the task at hand. The orchestrator retains full control over tool selection and ordering.

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
pip install -e ".[dev]"

# Generate all systems from the example batch spec
factory specs/batch.yaml

# Or generate into a custom directory
factory specs/batch.yaml -o my_output

# Or use python -m
python -m gatekeeper_eos_v6 specs/batch.yaml
```

## Usage

```
usage: factory [-h] [--output OUTPUT] [--list-patterns] [--preview]
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
factory specs/batch.yaml --preview

# Preview with detailed file stats (lines, bytes per file)
factory specs/batch.yaml --preview --verbose

# Generate all systems
factory specs/batch.yaml
```

## End-to-End Tutorial

This tutorial walks through the full lifecycle of Agent Factory — from generating your first system to creating custom specs and adding new patterns.

> **Prerequisites:** Python 3.11+, `pip install -e ".[dev]"`

---

### Part 1: Generate your first system

Let's start by previewing what will be generated, then generating everything.

```bash
# Step 1 — Preview the full output structure (no files written)
factory specs/batch.yaml --preview
# or: python -m gatekeeper_eos_v6 specs/batch.yaml --preview
```

This shows a file tree for each of the 17 systems without writing anything. You'll see each system's pattern, target, and agent count:

```
Previewing 17 system(s) in ./generated/ …

  ./generated/customer-support-openai/
  ├── main.py
  ├── requirements.txt
  ├── README.md
  ├── AGENTS.md
  └── system.yaml

    target: openai  |  pattern: handoffs  |  agents: 4
  ...
```

```bash
# Step 2 — Generate all 17 systems
factory specs/batch.yaml
# or: python -m gatekeeper_eos_v6 specs/batch.yaml
```

Expected output:

```
Generating 17 system(s) …
  ✓ customer-support-openai → .../generated/customer-support-openai
  ✓ research-assistant-langgraph → .../generated/research-assistant-langgraph
  ✓ code-review-langgraph → .../generated/code-review-langgraph
  ✓ content-pipeline-openai → .../generated/content-pipeline-openai
  ✓ data-pipeline-chain → .../generated/data-pipeline-chain
  ✓ content-moderation-chain → .../generated/content-moderation-chain
  ✓ market-analysis-broadcast → .../generated/market-analysis-broadcast
  ✓ code-audit-broadcast → .../generated/code-audit-broadcast
  ✓ essay-writer-reflection → .../generated/essay-writer-reflection
  ✓ policy-debate-openai → .../generated/policy-debate-openai
  ✓ legal-verdict-langgraph → .../generated/legal-verdict-langgraph
  ✓ code-review-reflection → .../generated/code-review-reflection

Done — 17 system(s) generated in ./generated/
```

---

### Part 2: Inspect the output

Each generated system folder contains 5 files. Let's explore one in detail:

```bash
# Pick a system and look at its structure
ls -la generated/customer-support-openai/
```

```
README.md          # System overview — pattern, agents, quickstart
AGENTS.md          # Agent role descriptions and instructions
main.py            # Run this to start the system
requirements.txt   # Python dependencies
system.yaml        # Original spec config (shareable, reproducible)
```

#### What each file contains

| File | Purpose | Generated by |
|------|---------|-------------|
| `main.py` | The runnable multi-agent system — imports SDKs, defines agents, orchestrates the pattern | Jinja2 template at `templates/{target}/{pattern}/main.py.j2` |
| `README.md` | Documentation for this specific system — how to run, list of agents, generated-by note | `factory.py` — `_generate_readme()` |
| `AGENTS.md` | All agent instructions for this system in a reference document | `factory.py` — `_generate_agents_md()` |
| `requirements.txt` | Python dependencies (openai-agents, langgraph, etc.) | Jinja2 template |
| `system.yaml` | The exact YAML spec used to generate this system — for sharing or re-generating | `factory.py` — `_generate_system_config()` |

Let's peek at the generated code structure. The specific implementation depends on the pattern, but here's what a typical `main.py` looks like:

```bash
# See the first 30 lines of a generated system
head -30 generated/customer-support-openai/main.py
```

Output (simplified):

```python
"""
Customer Support System — Multi-agent AI system generated by Agent Factory.

Pattern: handoffs (openai)
Agents: triage, billing, refund, technical
Run with:  python main.py
"""

import os
import asyncio
from agents import Agent, Runner

# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

triage = Agent(
    name="triage",
    instructions="You are the first point of contact. Route users ...",
    handoffs=[billing, refund, technical],  # agent objects, not strings
)

billing = Agent(
    name="billing",
    instructions="You are a billing specialist. Handle invoice questions ...",
)
...
```

Each generated `main.py` is a **fully runnable** Python script. You can run it directly (see Part 4).

---

### Part 3: Create a custom spec

Now let's create a custom YAML spec for a **social media content team** that uses the Broadcast pattern — three content creators in parallel, each writing for a different platform.

Create `specs/social-media.yaml`:

```yaml
# specs/social-media.yaml
systems:
  - name: social-media-campaign
    description: >
      A social media content team. Three writers produce posts for Twitter,
      LinkedIn, and Instagram in parallel, then a curator selects the best.
    target: openai
    pattern: broadcast
    model: gpt-4o
    example_input: "Announce our new product launch: Agent Factory v1.0"
    agents:
      - name: twitter_writer
        instructions: >
          You are a Twitter/X content strategist. Write short, punchy posts
          under 280 characters. Use hashtags strategically. Make every word
          count. Aim for engagement and retweets.
      - name: linkedin_writer
        instructions: >
          You are a LinkedIn content specialist. Write professional,
          thought-leadership posts. Use a conversational but polished tone.
          Include relevant industry context and a call to action.
      - name: instagram_writer
        instructions: >
          You are an Instagram content creator. Write visually descriptive
          captions that complement images. Use emojis, line breaks, and
          storytelling. Include relevant hashtags in a separate paragraph.
```

Now generate it:

```bash
factory specs/social-media.yaml
# or: python -m gatekeeper_eos_v6 specs/social-media.yaml
```

You'll get a new system at `generated/social-media-campaign/`.

```bash
ls generated/social-media-campaign/
# → README.md  AGENTS.md  main.py  requirements.txt  system.yaml
```

> **Try it yourself:** Change the `pattern` field to `chain` and re-generate. Notice how the same agents produce a completely different architecture — sequential pipeline instead of parallel broadcast.

---

### Part 4: Run a generated system

Each generated `main.py` is a standalone Python script. To run it:

```bash
# 1. Set your OpenAI API key
export OPENAI_API_KEY=sk-...

# 2. Install the system's dependencies
cd generated/customer-support-openai
pip install -r requirements.txt

# 3. Run with default example input
python main.py

# 4. Or provide your own input via environment variable
USER_INPUT="I need a refund for order #12345" python main.py
```

Each system prints the full agent interaction. For example, the **Debate** pattern (`policy-debate-openai`):

```
$ python generated/policy-debate-openai/main.py

=== POLICY DEBATE: Should social media platforms ban political advertising? ===

--- Proponent ---
I argue IN FAVOR of banning political advertising on social media...

--- Opponent ---
I argue AGAINST banning political advertising on social media...

--- Neutral Analyst ---
Objective analysis of both positions...

=== JUDGE'S VERDICT ===
After evaluating all arguments, I find the strongest position is...
```

Or the **Reflection** pattern (`essay-writer-reflection`):

```
$ python generated/essay-writer-reflection/main.py

--- Round 1 ---
[Writer produces initial draft...]
[Editor provides critique...]

--- Round 2 ---
[Writer revises based on feedback...]
[Editor approves: "APPROVED"]

=== FINAL OUTPUT ===
[Final essay with revisions applied...]
(Completed in 2 rounds)
```

> **Tip:** Generated systems require an `OPENAI_API_KEY`. The templates use `gpt-4o` by default. Set `USER_INPUT` to customize the prompt without editing the code.

---

### Part 5: Add a new pattern

Agent Factory is designed to be extensible. Adding a new pattern requires only a template and a registry entry — no code changes to the factory itself.

Let's add a **"Summarizer"** pattern — a single agent that summarizes content, with optional detail level.

#### 1. Create the OpenAI template

```bash
mkdir -p templates/openai/summarizer
```

`templates/openai/summarizer/main.py.j2`:

```jinja
"""
{{ system.name }} — Generated by Agent Factory
Pattern: summarizer (openai)
"""

import os
import asyncio
from agents import Agent, Runner

SYSTEM_PROMPT = """{{ system.agents[0].instructions }}"""

DETAIL_LEVEL = os.environ.get("DETAIL", "balanced")

async def main():
    user_input = os.environ.get("USER_INPUT", "{{ system.example_input }}")

    agent = Agent(
        name="{{ system.agents[0].name }}",
        instructions=f"{SYSTEM_PROMPT}\n\nDetail level: {DETAIL_LEVEL}",
        model="{{ system.model }}",
    )

    result = await Runner.run(agent, input=user_input)
    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print('-' * 60)
    print(f"\n{result.final_output}")

if __name__ == "__main__":
    asyncio.run(main())
```

`templates/openai/summarizer/requirements.txt.j2`:

```
openai-agents>=0.0.6
```

> The filename `requirements.txt.j2` matters — it mirrors the existing template pattern and ensures the factory renders it into `requirements.txt` in the output folder.

#### 2. Register the pattern in factory.py

Edit `src/gatekeeper_eos_v6/factory.py` and add `"summarizer"` to `SUPPORTED_PATTERNS`:

```python
SUPPORTED_PATTERNS = {"handoffs", "agents_as_tools", "router_manager",
                      "supervisor_workers", "chain", "broadcast",
                      "reflection", "debate", "summarizer"}
```

That's it — no other code changes needed.

#### 3. Create a spec and generate

```yaml
# specs/summarizer.yaml
systems:
  - name: document-summarizer
    description: "Summarizes documents at configurable detail levels."
    target: openai
    pattern: summarizer
    model: gpt-4o
    example_input: "Summarize the key concepts of multi-agent AI systems."
    agents:
      - name: summarizer
        instructions: >
          You are a professional summarizer. Read the provided content and
          produce a clear, well-structured summary. Adapt to the requested
          detail level: 'brief' for 2-3 sentences, 'balanced' for a paragraph,
          'detailed' for a multi-section breakdown.
```

```bash
factory specs/summarizer.yaml
ls generated/document-summarizer/
# → README.md  AGENTS.md  main.py  requirements.txt  system.yaml

# Run with different detail levels
DETAIL=brief python generated/document-summarizer/main.py
DETAIL=detailed python generated/document-summarizer/main.py
```

#### What about LangGraph?

For a LangGraph counterpart, create `templates/langgraph/summarizer/main.py.j2` with a simple state-graph approach:

```bash
mkdir -p templates/langgraph/summarizer
# Create main.py.j2 using a single-node StateGraph with a summary node
```

With LangGraph, the summarizer pattern would use a minimal `StateGraph` — one node that calls the LLM with the content and returns a summary. The pattern registration is the same: add `"summarizer"` to `SUPPORTED_PATTERNS`.

---

**What you've learned:**

| Concept | You did it |
|---------|-----------|
| Preview & generate | `factory specs/batch.yaml --preview` then `factory specs/batch.yaml` |
| Understand output | Explored 5 files per system |
| Create a custom spec | Wrote `specs/social-media.yaml` with Broadcast pattern |
| Run a generated system | Executed `main.py` with `OPENAI_API_KEY` |
| Add a new pattern | Created `summarizer` templates + registered in `src/gatekeeper_eos_v6/factory.py` |

Next steps: browse the [Pattern Gallery](#pattern-gallery--when-to-use-each-pattern) to choose the right pattern for your use case, or dive into the [templates/](templates/) directory to see how existing patterns are implemented.

## Spec Format

```yaml
systems:
  - name: my-system
    description: "A short description"
    target: openai           # or langgraph
    pattern: handoffs        # or agents_as_tools, broadcast, chain, consensus, debate, planner_executor, reflection, router_manager, supervisor_workers
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
├── src/
│   └── gatekeeper_eos_v6/
│       ├── __init__.py         # Package init
│       ├── __main__.py         # python -m gatekeeper_eos_v6 entry point
│       └── factory.py          # CLI orchestrator
├── specs/
│   └── batch.yaml              # Example batch spec
├── templates/
│   ├── openai/                 # OpenAI Agents SDK templates
│   │   ├── agents_as_tools/
│   │   ├── broadcast/
│   │   ├── chain/
│   │   ├── consensus/
│   │   ├── debate/
│   │   ├── handoffs/
│   │   ├── planner_executor/
│   │   ├── reflection/
│   │   ├── router_manager/
│   │   └── supervisor_workers/
│   └── langgraph/              # LangGraph templates
│       ├── agents_as_tools/
│       ├── broadcast/
│       ├── chain/
│       ├── consensus/
│       ├── debate/
│       ├── handoffs/
│       ├── planner_executor/
│       ├── reflection/
│       ├── router_manager/
│       └── supervisor_workers/
├── generated/                  # Output directory (gitignored)
├── tests/
│   ├── test_spec_parsing.py
│   └── test_generation.py
├── README.md
├── CONTRIBUTING.md
└── pyproject.toml
```

## Testing

```bash
pytest tests/ -v
```

## Adding a New Pattern

1. Create `templates/<target>/<new_pattern>/main.py.j2`
2. Create `templates/<target>/<new_pattern>/requirements.txt.j2`
3. Add the pattern name to `SUPPORTED_PATTERNS` in `src/gatekeeper_eos_v6/factory.py`
4. Done — no other code changes needed.
