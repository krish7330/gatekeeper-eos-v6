# Validation Checklist

Run through these checks before deploying or regenerating.

## Prerequisites

- [ ] Python 3.11+
- [ ] `uv` installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- [ ] Dependencies installed: `uv sync`

## Factory / Codegen Run

- [ ] `specs/batch.yaml` is valid YAML
- [ ] All 21 individual specs under `specs/` are valid
- [ ] Generation works: `uv run python -m gatekeeper_eos_v6 specs/batch.yaml --log`

## Agentic Runtime Validation

- [ ] Full test suite passes: `uv run pytest tests/ -q` (733+ passed, 22 skipped)
- [ ] Agentic loop tests: `uv run pytest tests/test_agentic.py -q` (620+ tests)
- [ ] E2E YAML tests: `uv run pytest tests/test_e2e_yaml.py -v` (37 tests, covers multi-asset hybrid)
- [ ] Snapshot integrity: `uv run pytest tests/test_snapshot.py -q` (52 tests)
- [ ] Hybrid stall detection: `uv run pytest tests/test_agentic.py -v -k Hybrid` (20+ tests)

## Live API Run (optional)

- [ ] `OPENAI_API_KEY` is set
- [ ] `OPENAI_BASE_URL` points to a valid provider endpoint
- [ ] `OPENAI_MODEL` is a model the provider supports

## n8n Workflow Import

- [ ] 3 workflow JSONs pass import validation: `uv run python scripts/validate_n8n_import.py`
- [ ] Twilio credentials configured (sandbox + production)
- [ ] Google Sheets OAuth2 configured (`GoogleSheetsAlance`)
- [ ] Telegram bot token configured (`TelegramAlanceBot`)
- [ ] Google Sheet created with 6 tabs (MESSAGE_LEDGER, CONVERSATIONS, LEADS, STATE_DRIFT, ERRORS, HEALTHMETRICS)
- [ ] `YOUR_GOOGLE_SHEET_ID` replaced in all workflows
- [ ] `YOUR_TELEGRAM_CHAT_ID` replaced in error workflow
- [ ] `+14155238886` Twilio sender number replaced (if using a different number)

## Architecture Decision

- [x] CONVERSATIONS strategy: **append-only** (settled — use sheet formula view if a one-row-per-conversation display is needed later)

---

## Quick one-liner

```bash
uv run pytest tests/ -q && uv run python scripts/validate_n8n_import.py && echo "✓ All checks passed (733+ tests)"
```
