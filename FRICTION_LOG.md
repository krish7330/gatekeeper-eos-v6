# Cycle 15A — Simulated Fresh User Friction Log

**Date:** 2026-06-11
**Simulation:** Fresh temp directory, `git clone` → `pip install -r requirements.txt` → `python demo.py`

---

## Friction Points (by severity)

### [HIGH] 1. Demo is a black box — no --help, no customization, no next steps

**Location:** `demo.py`
**Observed:** User runs `python demo.py` once, sees pretty output, gets exit 0. Then... now what? No `--help` flag, no way to customize rates, no exploration path. The demo runs exactly one scenario with hardcoded values (0.72, 0.45) and exits. User feels like they watched a screensaver.

**Severity:** High — directly impacts the primary user workflow
**Type:** Missing capability

### [MEDIUM] 2. No "what next" guidance after demo completes

**Location:** `demo.py` (end of output)
**Observed:** After "Demo Complete ✅" and the chain diagram, the only post-demo message is "Temp workspace cleaned up." No suggestions for further exploration, no link to README, no "try `python demo.py --help`".

**Severity:** Medium — user completes task but doesn't know how to continue
**Type:** Missing guidance

### [MEDIUM] 3. `python3` vs `python` ambiguity

**Location:** `README.md`
**Observed:** README says `python3 -m venv .venv` and `python3 demo.py`. On macOS this is correct (`python` doesn't exist by default). But on Linux with `python-is-python3` installed, `python` also works. On Windows, the command is `python`. A user who tries `python` on a fresh macOS system gets "command not found".

**Severity:** Medium — blocks first-time setup on some systems
**Type:** Documentation

**Fix applied (Cycle 14):** README now uses `python3` consistently in the Jarvis section.

### [LOW] 4. Two "Quick Start" sections could confuse skimmers

**Location:** `README.md`
**Observed:** The README has "Personal Jarvis — Quick Start" at the top (uses `pip install -r requirements.txt`) and "Quick Start (Code Generation)" further down (uses `pip install -e ".[dev]"`). A user skimming might follow the wrong one and get confused by unrelated features.

**Severity:** Low — attentive users will notice the section headers
**Type:** Documentation / UX

### [LOW] 5. Box-drawing characters may not render in all terminals

**Location:** `demo.py` (uses `╔╗║╚╝┌─│`)
**Observed:** The demo uses Unicode box-drawing characters for visual appeal. These render correctly on modern macOS Terminal, iTerm2, and Linux terminals with UTF-8 support. They may render as garbage on Windows cmd.exe, older terminals, or SSH clients without UTF-8.

**Severity:** Low — cosmetic, doesn't affect functionality
**Type:** Compatibility

### [LOW] 6. Temp audit log is destroyed after demo

**Location:** `demo.py` (uses `tempfile.TemporaryDirectory`)
**Observed:** The audit log is created inside a temporary directory that is automatically deleted when the `with` block exits. A curious user might want to inspect the audit log after the demo runs.

**Severity:** Low — demo is a proof-of-concept, not a production tool
**Type:** Design tradeoff

### [LOW] 7. "Scenario A" is unexplained

**Location:** `demo.py` (Step 1 output)
**Observed:** The demo prints 'Request: "Run a medical audit on Scenario A"' but doesn't explain what scenarios are, what "Scenario A" represents, or how medical auditing works. The terminology assumes domain knowledge.

**Severity:** Low — the step-by-step output is educational enough for most users
**Type:** Documentation / clarity

### [LOW] 8. Test badge shows 917 tests (project-wide, not Jarvis-specific)

**Location:** `README.md` (badge)
**Observed:** The badge says `tests-917-passed` which is the total count for the code generation factory tests. A user running only the Jarvis demo might wonder why they see 917 tests when only 38 are Jarvis-specific.

**Severity:** Low — cosmetic badge, doesn't affect usage
**Type:** Documentation

---

## Fix Applied

**Issue #1 (HIGH) — Demo is a black box**

Implemented:
- `--help` / `-h` flag with usage description (table stakes for any CLI)
- Descriptive step labels explaining what each component does
- ASCII-only output (no Unicode box-drawing characters)
- "What next?" section at end of output with exploration suggestions

**Result:** User can run `python demo.py --help` for guidance, see clear step-by-step explanations, and get next-step suggestions after completion. No new capabilities were added — pure usability polish.
