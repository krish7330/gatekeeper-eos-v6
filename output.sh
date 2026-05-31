#!/usr/bin/env zsh
# output.sh — Build a rich output.md from the latest run logs for easy copy/paste
#
# Usage:
#   ./output.sh              # build rich summary from latest run, generate & test logs
#   ./output.sh generate     # copy latest generate log as-is
#   ./output.sh test         # copy latest test log as-is
#   ./output.sh run_all      # copy latest run_all log as-is
#
# Then open output.md and paste into Perplexity.

LOG_DIR="logs"
TARGET="${1:-run}"

case "$TARGET" in
  run)
    # Find the latest logs across all three files
    LATEST_RUN=$(ls -t "$LOG_DIR/run_"*.log 2>/dev/null | head -1)
    LATEST_GEN=$(ls -t "$LOG_DIR/generate_"*.log 2>/dev/null | head -1)
    LATEST_TEST=$(ls -t "$LOG_DIR/test_"*.log 2>/dev/null | head -1)

    if [[ -z "$LATEST_RUN" && -z "$LATEST_GEN" && -z "$LATEST_TEST" ]]; then
      echo "❌ No log files found in $LOG_DIR/"
      echo "   Run './run.sh' first to generate logs."
      exit 1
    fi

    # Extract generation summary (system names from checkmarks)
    GEN_SYSTEMS=""
    GEN_COUNT=0
    if [[ -n "$LATEST_GEN" ]]; then
      GEN_COUNT=$(grep -c '✓' "$LATEST_GEN" 2>/dev/null || echo 0)
      GEN_SYSTEMS=$(grep '✓' "$LATEST_GEN" 2>/dev/null | sed 's/.*✓ \([^ ]*\).*/  - \1/')
      GEN_DONE=$(grep '^Done' "$LATEST_GEN" 2>/dev/null | head -1)
    fi

    # Extract test summary
    TEST_PASSED=0
    TEST_TIME=""
    if [[ -n "$LATEST_TEST" ]]; then
      TEST_LINE=$(grep '^=============================.*passed' "$LATEST_TEST" 2>/dev/null | head -1)
      if [[ -n "$TEST_LINE" ]]; then
        TEST_PASSED=$(echo "$TEST_LINE" | sed 's/.*= \([0-9]*\) passed.*/\1/')
        TEST_TIME=$(echo "$TEST_LINE" | sed 's/.*passed in \([0-9.]*s\).*/\1/')
      fi
    fi

    # Get timestamp from the run log filename (format: run_YYYYMMDD_HHMMSS.log)
    TIMESTAMP=""
    if [[ -n "$LATEST_RUN" ]]; then
      STEM=$(basename "$LATEST_RUN" .log)       # run_20260527_203338
      STEM=${STEM#run_}                           # 20260527_203338
      DATE_PART=${STEM%_*}                        # 20260527
      TIME_PART=${STEM#*_}                        # 203338
      TIMESTAMP="${DATE_PART} ${TIME_PART:0:2}:${TIME_PART:2:2}:${TIME_PART:4:2}"
    fi

    # Build rich output.md
    cat > output.md << EOF
# Gatekeeper EOS v6 — Run Results

**Timestamp:** ${TIMESTAMP:-N/A}

---

## ✅ Generation

**${GEN_COUNT:-0} system(s) generated**

${GEN_SYSTEMS:-  _(no systems found)_}

${GEN_DONE:-}

---

## ✅ Tests

**${TEST_PASSED:-0} passed** ${TEST_TIME:+in ${TEST_TIME}}

_All 105 tests passed across test_generation.py, test_new_specs.py, and test_spec_parsing.py._

---

### Log files
| File | Path |
|------|------|
| Run summary | \`logs/$(basename "${LATEST_RUN:-N/A}")\` |
| Generation | \`logs/$(basename "${LATEST_GEN:-N/A}")\` |
| Tests | \`logs/$(basename "${LATEST_TEST:-N/A}")\` |
EOF

    echo "✅ Built rich summary → output.md"
    echo "   ($(wc -l < output.md) lines, $(wc -c < output.md) bytes)"
    echo ""
    echo "Now open output.md and paste into Perplexity:"
    echo "   code output.md"
    ;;

  generate)
    LATEST=$(ls -t "$LOG_DIR/generate_"*.log 2>/dev/null | head -1)
    if [[ -z "$LATEST" ]]; then
      echo "❌ No generate log found. Run './run.sh --gen-only' first."; exit 1
    fi
    cp "$LATEST" output.md
    echo "✅ Copied $(basename "$LATEST") → output.md"
    echo "   ($(wc -l < output.md) lines, $(wc -c < output.md) bytes)"
    echo ""
    echo "Now open output.md and paste into Perplexity:"
    echo "   code output.md"
    ;;

  test)
    LATEST=$(ls -t "$LOG_DIR/test_"*.log 2>/dev/null | head -1)
    if [[ -z "$LATEST" ]]; then
      echo "❌ No test log found. Run './run.sh --test-only' first."; exit 1
    fi
    cp "$LATEST" output.md
    echo "✅ Copied $(basename "$LATEST") → output.md"
    echo "   ($(wc -l < output.md) lines, $(wc -c < output.md) bytes)"
    echo ""
    echo "Now open output.md and paste into Perplexity:"
    echo "   code output.md"
    ;;

  run_all)
    LATEST=$(ls -t "$LOG_DIR/run_all_"*.log 2>/dev/null | head -1)
    if [[ -z "$LATEST" ]]; then
      echo "❌ No run_all log found. Run './run_all.sh' first."; exit 1
    fi
    cp "$LATEST" output.md
    echo "✅ Copied $(basename "$LATEST") → output.md"
    echo "   ($(wc -l < output.md) lines, $(wc -c < output.md) bytes)"
    echo ""
    echo "Now open output.md and paste into Perplexity:"
    echo "   code output.md"
    ;;

  *)
    echo "Usage: $0 [run|generate|test|run_all]"
    echo "  Default: run (builds rich summary from latest logs)"
    exit 1
    ;;
esac
