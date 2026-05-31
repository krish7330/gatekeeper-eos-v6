#!/usr/bin/env zsh
# run.sh — gatekeeper-eos-v6 helper: generate + test + log everything
#
# Usage:
#   ./run.sh                     # generate all systems & run tests
#   ./run.sh --test-only         # skip generation, run tests only
#   ./run.sh --gen-only          # generate only, skip tests
#   ./run.sh --filter <name>     # generate a single system by name
#
# All output is tee'd to logs/ for easy copy/paste later.

set -e

LOG_DIR="logs"
mkdir -p "$LOG_DIR"

STAMP=$(date +%Y%m%d_%H%M%S)
RUN_LOG="$LOG_DIR/run_$STAMP.log"
GEN_LOG="$LOG_DIR/generate_$STAMP.log"
TEST_LOG="$LOG_DIR/test_$STAMP.log"

MODE="${1:-full}"
FILTER="${2:-}"

echo "============================================================"
echo "  gatekeeper-eos-v6 run | $(date)"
echo "  Log: $RUN_LOG"
echo "============================================================"
echo "" | tee -a "$RUN_LOG"

# ── 1. Generate ──────────────────────────────────────────────────
if [[ "$MODE" != "--test-only" ]]; then
  echo ">>> Generating systems …" | tee -a "$RUN_LOG"
  echo "" | tee -a "$RUN_LOG"

  CMD="uv run python -m gatekeeper_eos_v6 specs/batch.yaml --log"
  if [[ "$MODE" == "--filter" && -n "$FILTER" ]]; then
    CMD="$CMD --filter $FILTER"
  fi

  # Run generation — factory's --log flag auto-saves to logs/; 
  # we also tee to a separate log for the wrapper
  eval "$CMD" 2>&1 | tee -a "$GEN_LOG"
  GEN_EXIT=${pipestatus[1]:-$?}

  echo "" | tee -a "$RUN_LOG"
  if [[ $GEN_EXIT -eq 0 ]]; then
    echo "✅ Generation succeeded (log: $GEN_LOG)" | tee -a "$RUN_LOG"
  else
    echo "❌ Generation failed (exit=$GEN_EXIT, log: $GEN_LOG)" | tee -a "$RUN_LOG"
  fi
  echo "" | tee -a "$RUN_LOG"
fi

if [[ "$MODE" == "--gen-only" ]]; then
  echo "============================================================"
  echo "  Full log: $GEN_LOG"
  echo "============================================================"
  exit 0
fi

# ── 2. Run tests ─────────────────────────────────────────────────
echo ">>> Running tests …" | tee -a "$RUN_LOG"
echo "" | tee -a "$RUN_LOG"

uv run python -m pytest tests/ -v 2>&1 | tee -a "$TEST_LOG"
TEST_EXIT=${pipestatus[1]:-$?}

echo "" | tee -a "$RUN_LOG"
if [[ $TEST_EXIT -eq 0 ]]; then
  echo "✅ All tests passed (log: $TEST_LOG)" | tee -a "$RUN_LOG"
else
  echo "❌ Tests failed (exit=$TEST_EXIT, log: $TEST_LOG)" | tee -a "$RUN_LOG"
fi

echo "" | tee -a "$RUN_LOG"
echo "============================================================"
echo "  Full run log: $RUN_LOG"
echo "============================================================"

exit $TEST_EXIT
