# Agent Patterns Reference

This document describes the four agent orchestration patterns supported by
Agent Factory.

---

## 1. Handoffs

**Idea**: One agent transfers control to another agent for specialized handling.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | `handoffs=[handoff(specialist_agent)]` on the triage agent |
| **LangGraph** | Supervisor node routes to workers via `add_conditional_edges` |

**Best for**: Customer support triage, department routing, skill-based routing.

---

## 2. Agents as Tools

**Idea**: A main agent invokes sub-agents as if they were tools, staying in
control of the overall workflow.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | `sub_agent.as_tool(tool_name="name", tool_description="...")` |
| **LangGraph** | Workers are graph nodes called by the orchestrator via conditional routing |

**Best for**: Sub-routines within a larger task, tool composition.

---

## 3. Router Manager

**Idea**: A router agent classifies the input and dispatches to the correct
specialist agent. Specialists focus on their domain and return results directly.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | Router uses structured handoffs to dispatch |
| **LangGraph** | Router node uses `with_structured_output` to classify and route |

**Best for**: Content classification pipelines, intent-based routing.

---

## 4. Supervisor Workers

**Idea**: A supervisor agent decides which worker to call next in a loop,
iteratively building toward the final output.

| Target | Implementation |
|--------|---------------|
| **OpenAI** | Supervisor uses workers as tools and can call them in sequence |
| **LangGraph** | Supervisor with `with_structured_output` routes to workers, workers return results to supervisor |

**Best for**: Multi-step research, code review workflows, content generation pipelines.

---

## Feature Matrix

| Pattern | Deterministic | Looping | State Persistence | Extensible |
|---------|:---:|:---:|:---:|:---:|
| Handoffs | ✅ | ❌ | ✅ | ✅ |
| Agents as Tools | ✅ | ✅ | ✅ | ✅ |
| Router Manager | ✅ | ❌ | ✅ | ✅ |
| Supervisor Workers | ✅ | ✅ | ✅ | ✅ |
