#!/bin/zsh
set -euo pipefail
cd "$HOME/Documents/Projects/gatekeeper-eos-v6"
PYTHONNOUSERSITE=1 "$HOME/Documents/Projects/gatekeeper-eos-v6/.venv/bin/factory" specs/batch.yaml --dry-run
