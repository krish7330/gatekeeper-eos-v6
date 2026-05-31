# gatekeeper-eos-v6 Makefile
#
# Quick reference:
#   make           # alias for make all
#   make test      # run pytest
#   make dry-run   # validate all specs (no files written)
#   make generate  # generate all systems (writes files)
#   make ci        # dry-run + test (bypasses pre-commit hook)
#   make agent-test# run 5 agents against real API
#   make output    # copy latest run log to output.md
#   make all       # full pipeline: generate → test → output
#   make clean     # remove generated/

PYTHON = uv run python

.PHONY: help default test dry-run generate ci agent-test output all clean research analyze bridge-status bridge-config bridge-watch auto auto-report auto-schedule run-and-analyze

# ── Help ──────────────────────────────────────────────────────────
help:
	@echo "gatekeeper-eos-v6 targets:"
	@echo ""
	@echo "  make           full pipeline: generate + test + output"
	@echo "  make test      run pytest (105 tests)"
	@echo "  make dry-run   validate specs without writing files"
	@echo "  make generate  generate all 21 systems (writes files)"
	@echo "  make ci        dry-run + test (for CI workflows)"
	@echo "  make agent-test run 5 agents against real API"
	@echo "  make output    copy latest log to output.md"
	@echo "  make all       generate → test → output"
	@echo "  make clean     remove generated/"
	@echo ""
	@echo "Bridge targets (requires PERPLEXITY_API_KEY):"
	@echo "  make research <query>   research question via Perplexity"
	@echo "  make analyze [file]     analyze log/output with Perplexity"
	@echo "  make bridge-status      show bridge status and activity"
	@echo "  make bridge-config      show bridge configuration"
	@echo "  make bridge-watch       watch logs/ and auto-analyze"
	@echo ""
	@echo "Automation targets:"
	@echo "  make auto               run pipeline + generate report + Perplexity analysis"
	@echo "  make auto-report        generate report.json from latest logs"
	@echo "  make auto-schedule      show cron/launchd install instructions"
	@echo ""
	@head -3 README.md 2>/dev/null

default: all

# ── Run tests ────────────────────────────────────────────────────
test:
	$(PYTHON) -m pytest tests/ -v

# ── Dry-run all specs (no files written) ─────────────────────────
dry-run:
	$(PYTHON) -m gatekeeper_eos_v6 specs/batch.yaml --dry-run

# ── Generate all systems (writes files, auto-logs) ───────────────
generate:
	$(PYTHON) -m gatekeeper_eos_v6 specs/batch.yaml --log

# ── CI chain: dry-run then test (bypass pre-commit hook) ─────────
ci:
	SKIP_PRECOMMIT=1 $(MAKE) dry-run
	SKIP_PRECOMMIT=1 $(MAKE) test

# ── Run 5 agents against real API ────────────────────────────────
agent-test:
	./run_all.sh

# ── Copy latest run log to output.md ─────────────────────────────
output:
	./output.sh run

# ── Full pipeline ────────────────────────────────────────────────
all: generate test output

# ── Perplexity bridge ────────────────────────────────────────────
research:
	$(PYTHON) -m gatekeeper_eos_v6.bridge research $(filter-out $@,$(MAKECMDGOALS))

analyze:
	$(PYTHON) -m gatekeeper_eos_v6.bridge analyze $(filter-out $@,$(MAKECMDGOALS))

bridge-status:
	$(PYTHON) -m gatekeeper_eos_v6.bridge status

bridge-config:
	$(PYTHON) -m gatekeeper_eos_v6.bridge config

bridge-watch:
	$(PYTHON) -m gatekeeper_eos_v6.bridge watch

%:
	@: # swallow unrecognised targets so `make research "query"` works

# ── Automated pipeline + analysis ─────────────────────────────────
run-and-analyze:
	$(PYTHON) scripts/run_and_analyze.py

auto: run-and-analyze

auto-report:
	$(PYTHON) -m gatekeeper_eos_v6.reporter --pretty

auto-schedule:
	@echo "To install nightly cron (2am):"
	@echo "  crontab -e"
	@echo "  # Add this line:"
	@echo "  0 2 * * * cd $(PWD) && uv run python scripts/run_and_analyze.py --quiet"
	@echo ""
	@echo "To install via launchd:"
	@echo "  cp com.gatekeeper.eos-v6.plist ~/Library/LaunchAgents/"
	@echo "  launchctl load ~/Library/LaunchAgents/com.gatekeeper.eos-v6.plist"

# ── Clean generated files ────────────────────────────────────────
clean:
	rm -rf generated/
