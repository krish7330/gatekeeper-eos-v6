#!/usr/bin/env python3
"""bridge — automated bridge between freebuff (coding) and Perplexity (research).

Connects the gatekeeper pipeline output to Perplexity AI for automatic
research-backed analysis, creating a closed loop without manual copy/paste.

Commands
────────
    bridge research "<query>"   ──  Ask a research question via Perplexity
    bridge analyze [file]       ──  Analyze an output/log file with Perplexity
    bridge watch                ──  Watch logs/ for new files, auto-analyze
    bridge status               ──  Show recent bridge activity
    bridge config               ──  Show current bridge configuration

Invocations are logged to ``logs/bridge_<stamp>.log`` so every result is
captured for reference — the same file-bridge pattern used elsewhere.

Configuration
─────────────
Reads ``bridge.yaml`` from the project root if present.  Values can be
overridden via ``PERPLEXITY_*`` environment variables.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
from pathlib import Path
from typing import Any

# This import works because the package is installed with `pip install -e .`
from gatekeeper_eos_v6.perplexity_client import (
    PerplexityClient,
    PerplexityResponse,
    load_log,
)
from gatekeeper_eos_v6.factory import Tee

# ── Paths ────────────────────────────────────────────────────────────────────

HERE = Path(__file__).resolve().parent.parent.parent
LOG_DIR = HERE / "logs"
CONFIG_PATH = HERE / "bridge.yaml"


# ── Default configuration ────────────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "model": "sonar-pro",
    "max_tokens": 4096,
    "temperature": 0.3,
    "timeout": 60,
    "watch_interval": 10,  # seconds between polls
    "auto_analyze": False,  # watch mode only — auto-analyze new files
    "analysis_goal": "Identify key findings, patterns, and actionable insights.",
    "research_from_log": True,  # send log context with research queries
}


# ── Config loader ────────────────────────────────────────────────────────────


def load_config() -> dict[str, Any]:
    """Load bridge.yaml if it exists, overlaying defaults."""
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            import yaml  # type: ignore[import-untyped]

            with open(CONFIG_PATH) as f:
                user = yaml.safe_load(f) or {}
            config.update(user)
        except Exception as exc:
            print(f"⚠️  Warning: could not parse {CONFIG_PATH}: {exc}", file=sys.stderr)
    return config


def get_client(config: dict[str, Any] | None = None) -> PerplexityClient:
    """Create a configured PerplexityClient."""
    cfg = config or load_config()
    return PerplexityClient(
        model=cfg.get("model"),
        max_tokens=cfg.get("max_tokens"),
        timeout=cfg.get("timeout", 60),
    )


# ── Logging ──────────────────────────────────────────────────────────────────


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def open_bridge_log() -> tuple[Path, Any]:
    """Create a timestamped bridge log and return (path, file_handle)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"bridge_{stamp()}.log"
    fh = open(path, "w", encoding="utf-8")
    return path, fh


# ── Response display ─────────────────────────────────────────────────────────


def print_response(
    resp: PerplexityResponse,
    title: str = "",
    show_cost: bool = True,
) -> None:
    """Pretty-print a PerplexityResponse to stdout."""
    if title:
        print(f"\n{'═' * 60}")
        print(f"  {title}")
        print(f"{'═' * 60}")
    if resp.error:
        print(f"\n❌  Error: {resp.error}")
        return
    print(f"\n{resp.content}")
    if resp.citations:
        print(f"\n{'─' * 40}")
        print("  Sources")
        print(f"{'─' * 40}")
        for i, url in enumerate(resp.citations, 1):
            print(f"  {i:>2}. {url}")
    if show_cost and resp.usage.total_cost > 0:
        print(
            f"\n  Cost: ${resp.usage.total_cost:.6f}  "
            f"(in: {resp.usage.prompt_tokens} tok, "
            f"out: {resp.usage.completion_tokens} tok)"
        )


# ── Commands ─────────────────────────────────────────────────────────────────


def cmd_research(args: argparse.Namespace) -> int:
    """research <query>: send a research query to Perplexity.

    If a file path is provided via --context, its contents are sent alongside
    the query for grounded analysis.
    """
    config = load_config()
    client = get_client(config)
    query = " ".join(args.query)

    context: str | None = None
    if args.context:
        try:
            # Truncate to same limit as client.research() for consistency
            context = load_log(args.context, max_chars=8000)
        except FileNotFoundError:
            print(f"❌  Context file not found: {args.context}", file=sys.stderr)
            return 1

    # Set up logging
    log_path, log_fh = open_bridge_log()
    cm = redirect_stdout(Tee(sys.stdout, log_fh))
    cm.__enter__()
    try:
        print(f"\n  🔍  Research: {query[:120]}{'…' if len(query) > 120 else ''}")
        if args.context:
            print(f"  📎  Context: {args.context}")

        resp = client.research(query, context=context)

        title = f"Research Result  [{resp.model}]"
        if args.format == "json":
            print(json.dumps({
                "content": resp.content,
                "citations": resp.citations,
                "model": resp.model,
                "usage": {
                    "total_cost": resp.usage.total_cost,
                    "prompt_tokens": resp.usage.prompt_tokens,
                    "completion_tokens": resp.usage.completion_tokens,
                },
            }, indent=2))
        else:
            print_response(resp, title=title)

        print(f"\n  📝  Log saved: {log_path}")
    finally:
        cm.__exit__(None, None, None)
        log_fh.close()
    return 0 if not resp.error else 1


def cmd_analyze(args: argparse.Namespace) -> int:
    """analyze [file]: analyze a log/output file with Perplexity.

    If no file is specified, the most recent log file from logs/ is used.
    """
    config = load_config()
    client = get_client(config)

    # Resolve the file to analyze
    file_path: Path | None = None
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"❌  File not found: {file_path}", file=sys.stderr)
            return 1
    else:
        # Auto-detect most recent non-bridge log
        if not LOG_DIR.exists():
            print("❌  No logs/ directory found. Run a pipeline first.", file=sys.stderr)
            return 1
        logs = sorted(
            (p for p in LOG_DIR.glob("*.log") if not p.name.startswith("bridge_")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not logs:
            print("❌  No log files found in logs/. Run a pipeline first.", file=sys.stderr)
            return 1
        file_path = logs[0]
        print(f"  📄  Auto-detected: {file_path}")

    content = load_log(str(file_path))
    goal = args.goal or config.get("analysis_goal", DEFAULT_CONFIG["analysis_goal"])

    log_path, log_fh = open_bridge_log()
    cm = redirect_stdout(Tee(sys.stdout, log_fh))
    cm.__enter__()
    try:
        print(f"\n  🔬  Analyzing: {file_path.name} ({len(content)} chars)")

        resp = client.analyze(content, analysis_goal=goal)

        title = f"Analysis  [{resp.model}]"
        if args.format == "json":
            print(json.dumps({
                "file": str(file_path),
                "content": resp.content,
                "citations": resp.citations,
                "model": resp.model,
            }, indent=2))
        else:
            print_response(resp, title=title)

        print(f"\n  📝  Log saved: {log_path}")
    finally:
        cm.__exit__(None, None, None)
        log_fh.close()
    return 0 if not resp.error else 1


def cmd_watch(args: argparse.Namespace) -> int:
    """watch: poll logs/ for new files and auto-analyze them.

    Runs until interrupted (Ctrl+C).
    """
    config = load_config()
    client = get_client(config)
    interval = config.get("watch_interval", DEFAULT_CONFIG["watch_interval"])
    auto = args.auto or config.get("auto_analyze", False)
    goal = config.get("analysis_goal", DEFAULT_CONFIG["analysis_goal"])

    if not LOG_DIR.exists():
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n  👀  Watching logs/ every {interval}s  (Ctrl+C to stop)")
    if auto:
        print(f"  🔬  Auto-analyze: ON  — new files analyzed instantly")
    print()

    seen: set[str] = set(str(p) for p in LOG_DIR.iterdir() if p.is_file())

    try:
        while True:
            current = set(str(p) for p in LOG_DIR.iterdir() if p.is_file())
            new_files = current - seen

            for path_str in sorted(new_files):
                path = Path(path_str)
                # Skip bridge logs to avoid infinite loop
                if path.name.startswith("bridge_"):
                    continue

                print(f"\n  📄  New file detected: {path.name}")
                if auto:
                    content = load_log(str(path))
                    resp = client.analyze(content, analysis_goal=goal)
                    print_response(
                        resp,
                        title=f"Auto-analysis: {path.name}  [{resp.model}]",
                        show_cost=False,
                    )

            seen = current
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n  👋  Watch stopped.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:  # noqa: ARG001
    """status: show recent bridge activity and configuration."""
    config = load_config()

    print(f"\n{'═' * 50}")
    print("  Bridge Status")
    print(f"{'═' * 50}")
    print(f"\n  Model:     {config.get('model', 'sonar-pro')}")
    print(f"  Max toks:  {config.get('max_tokens', 4096)}")
    print(f"  Temp:      {config.get('temperature', 0.3)}")
    print(f"  Watch int: {config.get('watch_interval', 10)}s")

    # API key check
    key = os.environ.get("PERPLEXITY_API_KEY", "")
    if key:
        print(f"  API key:   ✓  set ({key[:8]}…{key[-4:]})")
    else:
        print(f"  API key:   ✗  not set (export PERPLEXITY_API_KEY)")

    # Config file
    if CONFIG_PATH.exists():
        content = CONFIG_PATH.read_text().strip()
        print(f"  Config:    {CONFIG_PATH} ({len(content)} chars)")
    else:
        print(f"  Config:    (none — using defaults)")

    # Recent bridge logs
    if LOG_DIR.exists():
        logs = sorted(
            LOG_DIR.glob("bridge_*.log"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if logs:
            print(f"\n  Recent activity:")
            for p in logs[:5]:
                stamp_str = datetime.fromtimestamp(p.stat().st_mtime).strftime(
                    "%H:%M:%S %m/%d"
                )
                size = p.stat().st_size
                print(f"    {stamp_str}  {p.name}  ({size} B)")
        else:
            print(f"\n  No bridge activity yet.")
    else:
        print(f"\n  No logs/ directory.")
    print()
    return 0


def cmd_config(args: argparse.Namespace) -> int:  # noqa: ARG001
    """config: show the effective bridge configuration as YAML."""
    config = load_config()
    import yaml  # type: ignore[import-untyped]

    print(yaml.dump(config, default_flow_style=False, sort_keys=False))
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bridge",
        description="Bridge between freebuff and Perplexity AI — research, analyze, automate.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── research ────────────────────────────────────────────────────────
    p_research = sub.add_parser("research", help="Ask a research question via Perplexity")
    p_research.add_argument("query", nargs="+", help="Research question")
    p_research.add_argument(
        "--context", "-c",
        help="Optional file path to use as grounding context for the query",
    )
    p_research.add_argument(
        "--format", "-f", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    # ── analyze ─────────────────────────────────────────────────────────
    p_analyze = sub.add_parser("analyze", help="Analyze a log/output file with Perplexity")
    p_analyze.add_argument(
        "file", nargs="?", default=None,
        help="Path to log/output file (default: most recent in logs/)",
    )
    p_analyze.add_argument(
        "--goal", "-g",
        help="Custom analysis goal (overrides bridge.yaml)",
    )
    p_analyze.add_argument(
        "--format", "-f", choices=["text", "json"], default="text",
    )

    # ── watch ───────────────────────────────────────────────────────────
    p_watch = sub.add_parser("watch", help="Watch logs/ for new files and auto-analyze")
    p_watch.add_argument(
        "--auto", "-a", action="store_true",
        help="Enable auto-analysis of new files (default: from bridge.yaml)",
    )

    # ── status ──────────────────────────────────────────────────────────
    sub.add_parser("status", help="Show bridge status and recent activity")

    # ── config ──────────────────────────────────────────────────────────
    sub.add_parser("config", help="Show effective bridge configuration")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command_map = {
        "research": cmd_research,
        "analyze": cmd_analyze,
        "watch": cmd_watch,
        "status": cmd_status,
        "config": cmd_config,
    }

    if args.command in command_map:
        return command_map[args.command](args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
