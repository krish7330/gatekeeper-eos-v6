# Personal Jarvis — Vision v2.0

**Date:** 2026-06-11

---

## Mission

Build a personal JARVIS-like assistant spanning Mac and Android that is useful, safe, reliable, and extensible through small, verifiable releases.

Jarvis is not a chatbot. Jarvis is an ecosystem of trusted capabilities.

---

## Core Philosophy

### Reliability Before Intelligence
A capability is not part of Jarvis because it is imagined. A capability becomes part of Jarvis only after it has been: **Built → Shipped → Observed → Trusted**.

### Ship Before Expand
Every feature begins as the smallest useful artifact.

**Rule:** v0.1 before v1.0. No upgrades before first release.

### Default Deny
Jarvis earns autonomy. Unknown actions are rejected.

**Principle:** Explicit permission = ALLOW. Everything else = BLOCK.

### Consecutive Execution Cycles
Progress is measured by shipped artifacts. Ideas do not count. Artifacts do.

**Primary metric:** Speed Integer = Number of consecutive shipped cycles.

---

## Architecture

```
Personal Jarvis
├── Gatekeeper (Control Plane)       — ACTIVE
├── Oracle (Validation Modules)      — SHIPPED
├── Medical AI Audit                 — PLANNED
├── Debate Agents                    — PLANNED
├── Security Evaluation              — PLANNED
└── EOS Constitution                 — PLANNED
```

## Development Strategy

- **Phase 1:** Ship tiny artifacts. ✅
- **Phase 2:** Compose artifacts into systems. ✅
- **Phase 3:** Compose systems into Jarvis.

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Speed Integer | 5 | 10 |
| Integration Depth | 2 | 3 |
| Scope Violations | 0 | 0 |

## Pre-Staged Cycles

### Cycle 6 — Integration Depth 3

**Artifact:** `jarvis.py` CLI — User Request → Gatekeeper → Oracle → Structured Result

**Contract:**
- `python jarvis.py oracle <pdf_path>` triggers Gatekeeper evaluation
- ALLOW → dispatch to Oracle `extract_red_spans()` → print JSON to stdout
- BLOCK → exit 3 with reason
- One end-to-end test

### Cycle 7 — Medical AI Audit v0.1

**Artifact:** `medical_audit.py` — single fairness metric

**Contract:**
- `demographic_parity_difference(group1_rate, group2_rate) → float`
- One test: `test_parity_zero_when_equal`
- No dataset loading, no calibration curves

### Cycle 8 — EOS Constitution v0.1

**Artifact:** `constitution.json` — executable policy ruleset

**Contract:**
- JSON with rule objects (action, condition, effect)
- One test asserting it loads and validates
- Not a philosophy doc — a file Gatekeeper can consume

## Daily Question

*Did something become usable today?*

---

*Jarvis is built one finished artifact at a time.*
