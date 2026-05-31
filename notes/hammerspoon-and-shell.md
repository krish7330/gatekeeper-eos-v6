# Shell / Python / Hammerspoon — Three Worlds

A quick-reference guide for where code lives and runs in the gatekeeper-eos-v6 workflow.

---

## 1. Shell world (zsh / Terminal)

**Role:** Navigate the file system, activate environments, launch programs.

**Lives in:** Terminal prompt, `.sh` scripts (`run.sh`, `output.sh`, `run_all.sh`).

**Examples:**
```bash
cd ~/Documents/Projects/gatekeeper-eos-v6
source .venv/bin/activate
python -m gatekeeper_eos_v6 specs/batch.yaml --log
./run.sh
./output.sh
code output.md
```

**Rule of thumb:** If it starts with `cd`, `ls`, `source`, `python -m`, `./`, `git`, or has flags like `--dry-run`, it's shell.

**Never do at the shell prompt:**
- Python assignments (`user_input = os.environ.get(...)`)
- Lua/Hammerspoon code (`hs.hotkey.bind(...)`)

---

## 2. Python world

**Role:** Logic, data handling, CLIs, code generation, patching.

**Lives in:**
- `.py` files (e.g., `src/gatekeeper_eos_v6/factory.py`, `generated/incident-classifier/main.py`)
- Inline heredocs: `python3 - <<'PY' ... PY`

**Examples:**
```python
import os
user_input = os.environ.get("USER_INPUT", "default")
from pathlib import Path
text = Path("file.txt").read_text()
```

**How to trigger from shell:**
```bash
source .venv/bin/activate
python -m gatekeeper_eos_v6 specs/batch.yaml --log
```

**Rule of thumb:** If it starts with `import`, uses `def`, `class`, `os.environ`, or `pathlib`, it's Python. Run it inside a `.py` file or a Python heredoc — never type it raw at the shell prompt.

---

## 3. Hammerspoon / Lua world

**Role:** macOS automation — hotkeys, window management, app launchers.

**Lives in:** `~/.hammerspoon/init.lua` only.

**Examples:**
```lua
hs.hotkey.bind({"cmd","alt","ctrl"}, "F", function()
  hs.application.launchOrFocus("Terminal.app")
  hs.timer.doAfter(0.3, function()
    hs.eventtap.keyStrokes("cd ~/Documents/Projects/gatekeeper-eos-v6 && freebuff")
    hs.eventtap.keyStroke({"return"}, 0)
  end)
end)
```

**How to apply changes:**
1. Edit `~/.hammerspoon/init.lua`
2. Click Hammerspoon menu bar icon → Reload Config
3. Test the hotkey

**Rule of thumb:** If it starts with `hs.`, it's Lua for Hammerspoon. It goes in `init.lua`, not in the shell.

---

## Quick mental model

| World | Mnemonic | Trigger |
|-------|----------|---------|
| **S**hell (zsh) | **S**etup & **S**tart | Typed at prompt or in `.sh` scripts |
| **P**ython | **P**rocess logic | `.py` files or `python3 - <<'PY'` |
| **H**ammerspoon | **H**otkeys & **H**ud | `~/.hammerspoon/init.lua` |

**When in doubt, ask:** "Does this instruct the OS, Python, or Hammerspoon?"

---

## 🚦 Quick classifier: one glance

Before you paste a line, check the **first word/character**:

| Starts with | World | Goes in |
|---|---|---|
| `hs.` | **Lua / Hammerspoon** | `~/.hammerspoon/init.lua` |
| `import`, `from`, `def`, `class`, `os.` | **Python** | `.py` file or `python3 - <<'PY'` heredoc |
| `cd`, `ls`, `source`, `python`, `git`, `./`, flags like `--dry-run` | **Shell (zsh)** | `➜` prompt or `.sh` script |

### Quick test — classify these:

```bash
from pathlib import Path
```
→ **Python world** (starts with `from`). Goes in `.py` file or heredoc.

```bash
hs.hotkey.bind({"cmd"}, "F", function() end)
```
→ **Lua world** (starts with `hs.`). Goes in `~/.hammerspoon/init.lua`.

```bash
source .venv/bin/activate
```
→ **Shell world** (starts with `source`). Goes at the `➜` prompt.

One glance at the opening token. That's all it takes.

### 🧠 Edge case: inline Python via shell

```bash
python3 -c 'import os; print(os.getcwd())'
```
→ **Shell world** (starts with `python`). The shell is the carrier; the Python code lives **inside** the `-c` quotes.

**Rule:** If the line starts with `python`, `python3`, `node`, `bash`, etc., it's **shell** — those are programs being launched. What follows (flags, arguments, inline scripts) runs inside that program, not in the terminal.

---

*Created 2026-05-27 — from the gatekeeper-eos-v6 project session.*
*Updated 2026-05-27 — added quick classifier table and edge case.*
*Updated 2026-05-28 — added pre-commit hook chain, Makefile targets, and Hammerspoon hotkey reference.*

---

## Pre-commit hook chain

**File:** `.git/hooks/pre-commit` (shell world)

### What it does

The hook runs three checks in a fast-fail chain — stop at the first failure:

1. **Venv guard** — Refuse to run if `.venv/bin/python3` doesn't exist.
   ```bash
   PYTHON=".venv/bin/python3"
   if [[ ! -f "$PYTHON" ]]; then
     echo "❌ No venv at $PYTHON. Run: python3 -m venv .venv && source .venv/bin/activate && pip install -e ."
     exit 1
   fi
   ```

2. **YAML syntax validation** — Parse `specs/batch.yaml` before rendering.
   ```bash
   "$PYTHON" -c "import yaml, sys; yaml.safe_load(open('specs/batch.yaml')); print('✅ YAML valid')"
   ```

3. **Dry-run all specs** — Render each template without writing files.
   ```bash
   "$PYTHON" -m gatekeeper_eos_v6 specs/batch.yaml --dry-run
   ```

All three use `.venv/bin/python3` — never `/usr/bin/python3`. This prevents `ModuleNotFoundError: No module named 'yaml'`.

### How to bypass (debugging)

Set `SKIP_PRECOMMIT=1` to skip all checks:
```bash
SKIP_PRECOMMIT=1 git commit -m "wip: checkpoint"
```

The hook exits immediately with code 0 when this variable is set, so it's safe for emergencies, debugging CI failures, or committing draft changes.

### Installation

```bash
chmod +x .git/hooks/pre-commit   # make it executable
```

Git runs `.git/hooks/pre-commit` automatically on every `git commit`. If it's not executable, Git silently skips it.

### Testing the hook

```bash
# Test full chain (expect success)
.git/hooks/pre-commit

# Test bypass
SKIP_PRECOMMIT=1 .git/hooks/pre-commit  # → exits 0 silently

# Test venv guard (move .venv temporarily)
mv .venv .venv.bak
.git/hooks/pre-commit  # → exits 1 with instructions
mv .venv.bak .venv
```

---

## Makefile targets

**File:** `Makefile` (shell world)

| Target | Command | What it does |
|--------|---------|--------------|
| `make help` | — | Print all targets with descriptions |
| `make test` | `uv run python -m pytest tests/ -v` | Run 105 unit tests |
| `make dry-run` | `uv run python -m gatekeeper_eos_v6 specs/batch.yaml --dry-run` | Validate all specs, no files written |
| `make generate` | `uv run python -m gatekeeper_eos_v6 specs/batch.yaml --log` | Generate all 21 systems, auto-logged |
| `make ci` | dry-run → test (SKIP_PRECOMMIT=1) | CI workflow chaining |
| `make agent-test` | `./run_all.sh` | Run 5 agents against real API |
| `make output` | `./output.sh run` | Copy latest log to `output.md` |
| `make all` | generate → test → output | Full pipeline |
| `make clean` | `rm -rf generated/` | Remove generated files |

All targets resolve Python via `uv run python` — never `/usr/bin/python3`. This prevents `ModuleNotFoundError: No module named 'yaml'`.

---

## Hammerspoon hotkeys

**File:** `~/.hammerspoon/init.lua` (Lua world)

### Quick reference

| Hotkey | Trigger | What it runs | Use when |
|--------|---------|--------------|----------|
| `⌘⌥⌃R` | Reload config | `hs.reload()` | After editing `init.lua` |
| `⌘⌥⌃T` | Open Terminal | `launchOrFocus("Terminal.app")` | Need a shell |
| `⌘⌥⌃F` | **Status check** | `freebuff` in project dir | Quick pulse check |
| `⌘⌥⌃G` | **Full CI** | `make ci` in project dir | Validate everything before commit |

### `⌘⌥⌃F` — status / quick check

Types `freebuff` in the project directory. Fast — opens the Freebuff status panel for a quick pulse check. Use this when you want to see what Freebuff reports without running a full pipeline.

```lua
-- ⌘⌥⌃F: Open Terminal → cd to gatekeeper-eos-v6 → launch freebuff
hs.hotkey.bind({"cmd", "alt", "ctrl"}, "F", function()
  hs.application.launchOrFocus("Terminal.app")
  hs.timer.doAfter(0.3, function()
    hs.eventtap.keyStrokes("cd ~/Documents/Projects/gatekeeper-eos-v6 && freebuff")
    hs.eventtap.keyStroke({}, "return")
  end)
end)
```

### `⌘⌥⌃G` — full CI validation

Types `make ci` in the project directory. Runs the full CI chain (dry-run all specs → run all tests). Takes a few seconds. Use this before committing, pushing, or when you want a thorough validation.

```lua
-- ⌘⌥⌃G: Run full CI pipeline (dry-run + test) in gatekeeper-eos-v6
hs.hotkey.bind({"cmd", "alt", "ctrl"}, "G", function()
  hs.application.launchOrFocus("Terminal.app")
  hs.timer.doAfter(0.3, function()
    hs.eventtap.keyStrokes("cd ~/Documents/Projects/gatekeeper-eos-v6 && make ci")
    hs.eventtap.keyStroke({}, "return")
  end)
end)
```

### Distinction

| Hotkey | Cost | What validates | When to press |
|--------|------|----------------|---------------|
| `⌘⌥⌃F` | Instant | Nothing — opens Freebuff panel | "Am I in the right state?" |
| `⌘⌥⌃G` | ~1-2s | 21 specs dry-run + 105 tests | "Ready to commit/push" |

**⚠️ Gotcha (both):** `hs.eventtap.keyStroke({}, "return")` — the first arg is **modifiers** (empty table), the second is the **key name**. Inverting them (e.g., `{"return"}, nil`) silently does nothing.

### Install & test

1. Append the desired block to `~/.hammerspoon/init.lua`
2. Save — `pathwatcher` auto-reloads (or `⌘⌥⌃R` / menu bar → Reload Config)
3. Press the hotkey to test

### Error mode

If nothing happens:
- Check `~/.hammerspoon/init.lua` for syntax errors (missing comma, mismatched parenthesis)
- Fix & save → `pathwatcher` auto-reloads
- Check Hammerspoon is running (menu bar icon visible)
- Verify the `keyStroke` call: `({}, "return")` — modifiers first, key second
