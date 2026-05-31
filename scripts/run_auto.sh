#!/usr/bin/env bash
set -e

PROJECT_DIR="$HOME/Documents/Projects/gatekeeper-eos-v6"
LOG_FILE="$PROJECT_DIR/automation_run.log"

# Log rotation: keep last 5000 lines
touch "$LOG_FILE"
tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"

# Timestamp & resource telemetry
date >> "$LOG_FILE"
echo " -> Hardware & Resource Allocation Profile:" >> "$LOG_FILE"
pmset -g batt | grep -E 'InternalBattery' >> "$LOG_FILE" 2>&1 || true
ps -A -o %cpu,%mem,comm | sort -nr | head -n 3 >> "$LOG_FILE"

# Quiet hours: suppress speech between 11PM and 7AM
CURRENT_HOUR=$(date +%H)
if [ "$CURRENT_HOUR" -ge 23 ] || [ "$CURRENT_HOUR" -lt 7 ]; then
  VOICE_CMD="echo ' -> [Quiet Hours Window Active] Verbal audio warning muted.'"
else
  VOICE_CMD="say -v Samantha 'Alert. Gatekeeper build compilation failure encountered.'"
fi

cd "$PROJECT_DIR"
source .venv/bin/activate

# ---- Step 1: Generator ----
echo '[1/5] Executing Core Code Generator Engine...' >> "$LOG_FILE"
python3 -m gatekeeper_eos_v6 specs/batch.yaml >> "$LOG_FILE" 2>&1

# ---- Step 2: Incident Classifier Quote Patch ----
echo '[2/5] Running Incident Classifier Quote Substitution Patch...' >> "$LOG_FILE"
python3 << 'PYEOF' >> "$LOG_FILE" 2>&1
from pathlib import Path

p = Path('generated/incident-classifier/main.py')
if not p.exists():
    print('[patch] generated/incident-classifier/main.py not found, skipping')
else:
    text = p.read_text()

    # Broken pattern: stray backslash before final single quote in example_input
    orig = (
        'user_input = os.environ.get("USER_INPUT", '
        '"User reports: \\"VPN connection keeps dropping after the latest update. '
        'I can connect for about 2 minutes then get disconnected. '
        'Other users in my office are experiencing the same issue. '
        "We\\'re on macOS Sequoia.\\\"'"
    )

    # Fixed pattern: properly terminated string
    fixed = (
        'user_input = os.environ.get("USER_INPUT", '
        '"User reports: VPN connection keeps dropping after the latest update. '
        'I can connect for about 2 minutes then get disconnected. '
        'Other users in my office are experiencing the same issue. '
        "We're on macOS Sequoia.\")"
    )

    if orig in text:
        p.write_text(text.replace(orig, fixed))
        print('[patch] Quote substitution applied successfully.')
    else:
        print('[patch] Pattern not found — generated code already correct, skipping.')
PYEOF

# ---- Step 3: Compilation Check ----
echo '[3/5] Verifying Codebase Integrity via Compilation Check...' >> "$LOG_FILE"
if python3 -c "
import sys, compileall
res = compileall.compile_dir('generated', maxlevels=3, quiet=1)
sys.exit(0) if res else sys.exit(1)
" >> "$LOG_FILE" 2>&1; then
  echo ' -> Evaluation Status: ALL SYSTEMS PASSING' >> "$LOG_FILE"
else
  echo ' -> Evaluation Status: COMPILATION EXCEPTION DROPPED' >> "$LOG_FILE"
  eval "$VOICE_CMD" >> "$LOG_FILE" 2>&1
  false
fi

# ---- Step 4: Git Commit ----
echo '[4/5] Capturing Stable Code Diff to Git Version Control Snapshot...' >> "$LOG_FILE"
git add . >> "$LOG_FILE" 2>&1
git commit -m "Auto-build: $(date '+%Y-%m-%d %H:%M:%S') [Max Loop Cycle]" >> "$LOG_FILE" 2>&1 || echo ' [nothing to commit]' >> "$LOG_FILE"

# ---- Step 5: Git Push ----
echo '[5/5] Backing Up Changes to Remote Master Tree Repository Branch...' >> "$LOG_FILE"
git push origin master >> "$LOG_FILE" 2>&1 && echo '-------------------------------------------------------' >> "$LOG_FILE"
