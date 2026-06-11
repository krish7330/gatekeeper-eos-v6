# Changelog

## Cycle 5 — Repository Durability (2026-06-11)

`8321293` | Tag: `v0.3.0`

- VISION.md — Jarvis v2.0 founding philosophy, architecture, and metrics
- CHANGELOG.md — Complete history of all shipped cycles
- **Artifact Durability:** A stranger can now clone the repo and understand what exists

---

## Cycle 4 — Oracle → Gatekeeper Integration (2026-06-11)

`1b6553d`

- Oracle now invokes `GatekeeperPolicy.evaluate_action()` before reading any PDF
- ALLOW → Oracle proceeds with extraction
- BLOCK → Oracle exits with code 3 and `"Gatekeeper: BLOCKED"` message
- 2 end-to-end integration tests (ALLOW path + BLOCK path)
- **Integration Depth:** 2

---

## Cycle 3 — Gatekeeper v0.2 (2026-06-11)

`26b28ea`

- Decoupled policy state from code: `policy.json` at project root
- Workspace boundary enforcement: `read_file` only allowed within `/workspace`
- Failsafe zero-trust: missing config → BLOCK ALL
- Richer decision responses with `reason` field
- 5 tests (allow within workspace, block unauthorized tool, block outside workspace, block missing tool, failsafe on missing config)

---

## Cycle 2 — Gatekeeper v0.1 (2026-06-11)

`e5f3839`

- Binary whitelist policy: explicit allow, everything else block
- `GatekeeperPolicy` class with `evaluate_action()` method
- 3 tests (allow read_file, block execute_shell, block missing tool)
- **Property:** Unknown tool → BLOCK, Missing tool → BLOCK

---

## Cycle 1 — Oracle v0.1 (2026-06-11)

`ae4a1b6`

- Red text extractor for Oracle 1Z0-082 PDF exam prep
- RGB-constrained color detection (R≥180, G≤100, B≤100 on 0–255 scale)
- Binary JSON output schema: `red_answers.json`
- Handles PyMuPDF packed integer color format (0xRRGGBB)
- **Property:** Only red-colored text spans extracted
