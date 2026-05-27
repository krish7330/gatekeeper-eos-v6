#!/usr/bin/env zsh
# gatekeeper-eos-v6 - automated agent test runner
# Usage: ./run_all.sh [model] ["custom input"]

MODEL=${1:-meta-llama/llama-4-scout-17b-16e-instruct}
INPUT=${2:-""}
LOG_DIR="logs"
SUMMARY_MD="$LOG_DIR/summary.md"
STAMP=$(date +%Y%m%d_%H%M%S)
FALLBACK="llama-3.1-8b-instant"

mkdir -p "$LOG_DIR"

export OPENAI_API_KEY=$(grep GROQ_API_KEY ~/.zshrc | cut -d= -f2)
export OPENAI_BASE_URL='https://api.groq.com/openai/v1'
export OPENAI_MODEL="$MODEL"
[[ -n "$INPUT" ]] && export USER_INPUT="$INPUT"

AGENTS=(incident-classifier code-audit-broadcast code-review-langgraph legal-verdict-langgraph security-threat-consensus)
PASS=0
FAIL=0
FAIL_LIST=()

echo ""
echo "==> gatekeeper-eos-v6 | Model: $MODEL | $(date)"
echo "------------------------------------------------------"
echo ""
echo "## Run: $STAMP | Model: $MODEL" >> "$SUMMARY_MD"

for name in "${AGENTS[@]}"; do
  LOG="$LOG_DIR/${name}_$STAMP.log"
  printf "  %-38s" "$name"

  (cd "generated/$name" && timeout 90 python3 main.py > "../../$LOG" 2>&1)

  STATUS=""
  if grep -q '^openai.RateLimitError' "$LOG" 2>/dev/null; then
    printf "[RATE LIMIT] retrying fallback... "
    export OPENAI_MODEL=$FALLBACK
    (cd "generated/$name" && timeout 90 python3 main.py > "../../$LOG" 2>&1)
    export OPENAI_MODEL=$MODEL
    if grep -q '^openai.' "$LOG" 2>/dev/null; then
      STATUS="FAIL"
      FAIL=$((FAIL+1))
      FAIL_LIST+=("$name")
    else
      STATUS="PASS(fallback)"
      PASS=$((PASS+1))
    fi
  elif grep -q '^openai.' "$LOG" 2>/dev/null; then
    STATUS="FAIL"
    FAIL=$((FAIL+1))
    FAIL_LIST+=("$name")
  else
    STATUS="PASS"
    PASS=$((PASS+1))
  fi

  echo "$STATUS"
  LAST=$(grep -v '^$' "$LOG" | tail -1)
  echo "     $LAST"
  echo "- [$STATUS] $name: $LAST" >> "$SUMMARY_MD"

  sleep 5
done

echo ""
echo "------------------------------------------------------"
echo "RESULT: $PASS/${#AGENTS[@]} passed"
if [[ ${#FAIL_LIST[@]} -gt 0 ]]; then
  echo "Failed: ${FAIL_LIST[*]}"
fi
echo "Audit: $SUMMARY_MD"
