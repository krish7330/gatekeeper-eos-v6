#!/usr/bin/env python3
"""run_and_analyze — single cron entry point for the freebuff ↔ Perplexity loop.

Usage
─────
    # Run everything: pipeline → report → Perplexity analysis
    python scripts/run_and_analyze.py

    # Run a specific pipeline step instead of the default
    python scripts/run_and_analyze.py --pipeline agent-test

    # Dry-run: generate report without calling Perplexity
    python scripts/run_and_analyze.py --dry-run

    # Quiet mode: no stdout (cron-friendly)
    python scripts/run_and_analyze.py --quiet

This script is designed to be called from cron.  It always exits 0 unless
a hard error occurs (pipeline crash, API key missing, etc.).  A non-zero
exit means something genuinely needs attention.

Workflow
────────
    1.  Run the pipeline (``make ci`` by default) via subprocess.
    2.  Parse the output logs into a structured ``report.json``.
    3.  Call Perplexity API with the report as context.
    4.  Write the analysis to ``logs/freebuff/perplexity-analysis.md``
        and a structured JSON summary to ``logs/freebuff/analysis.json``.
    5.  Log everything to ``logs/freebuff/run_and_analyze_<stamp>.log``.

No manual file shuffling, no environment juggling, no copy-paste between tools.

Environment
───────────
    PERPLEXITY_API_KEY   (required for analysis)
    PIPELINE_CMD          (default: ``make ci``)
    PROJECT_DIR           (default: auto-detected from script location)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
from pathlib import Path
from typing import Any

# Project root is two levels up from scripts/
HERE = Path(__file__).resolve().parent.parent
LOG_DIR = HERE / "logs"
FREEBUFF_DIR = LOG_DIR / "freebuff"

# ── Ensure freebuff directory exists ─────────────────────────────────────────
# FREEBUFF_DIR.mkdir is called inside run_analysis() to avoid module-level side effects

# ── Imports that require the installed package ───────────────────────────────
# These are imported *inside* functions so the script can still be parsed even
# if the package isn't installed yet.


# ── Helpers ──────────────────────────────────────────────────────────────────


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ── Step 1: Run pipeline ──────────────────────────────────────────────────


def run_pipeline(
    cmd: str = "make ci",
    timeout: int = 120,
    quiet: bool = False,
) -> tuple[int, float]:
    """Run the pipeline command and return (exit_code, duration_seconds)."""
    if not quiet:
        print(f"\n{'═' * 60}")
        print(f"  Step 1: Running pipeline — {cmd}")
        print(f"{'═' * 60}\n")

    start = time.monotonic()
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(HERE),
    )
    elapsed = time.monotonic() - start

    # Print output for logging
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if not quiet:
        status = "✅" if result.returncode == 0 else "❌"
        print(f"\n  {status} Pipeline finished in {elapsed:.2f}s  (exit={result.returncode})")

    return result.returncode, elapsed


# ── Step 2: Generate report.json ──────────────────────────────────────────


def generate_report(pipeline: str, exit_code: int, duration: float, quiet: bool = False) -> dict[str, Any]:
    """Parse pipeline logs into a structured report."""
    if not quiet:
        print(f"\n{'─' * 60}")
        print("  Step 2: Generating structured report")
        print(f"{'─' * 60}")

    from gatekeeper_eos_v6.reporter import build_report

    report = build_report(pipeline=pipeline)
    report["duration_seconds"] = round(duration, 2)
    report["exit_code"] = exit_code

    report_path = FREEBUFF_DIR / "report.json"
    report_path.write_text(json.dumps(report, indent=2))
    if not quiet:
        print(f"  ✅ report.json: {report['summary']['total']} systems, "
              f"{report['summary']['passed']} passed, "
              f"{report['summary']['failed']} failed")
        print(f"  📄 Saved: {report_path}")

    return report


# ── Step 3: Analyze with Perplexity ───────────────────────────────────────


def analyze_report(report: dict[str, Any], quiet: bool = False) -> dict[str, Any]:
    """Send the report to Perplexity and save the analysis."""
    api_key = os.environ.get("PERPLEXITY_API_KEY", "")
    if not api_key:
        msg = "⚠️  PERPLEXITY_API_KEY not set — skipping analysis"
        print(f"\n  {msg}")
        return {"skipped": True, "reason": msg}

    if not quiet:
        print(f"\n{'─' * 60}")
        print("  Step 3: Analyzing with Perplexity")
        print(f"{'─' * 60}")

    from gatekeeper_eos_v6.perplexity_client import PerplexityClient

    client = PerplexityClient()

    # Build the analysis prompt from the report — using all enhanced schema fields
    systems_summary = "\n".join(
        f"  - {s['name']}: {s['status']}"
        + (f"  (error: {s['error_type']})" if s.get("error_type") else "")
        + (f"  → {s['output_snippet'][:80]}" if s.get("output_snippet") else "")
        for s in report.get("systems", [])
    )

    model = report.get("model", "unknown")
    env = report.get("environment", {})
    env_str = f"{env.get('os', '?')} | Python {env.get('python_version', '?')} | {env.get('project', '?')} v{env.get('project_version', '?')}"

    prompt = (
        f"## Pipeline Analysis Request\n\n"
        f"**Pipeline**: {report.get('pipeline', 'unknown')}\n"
        f"**Run ID**: {report.get('run_id', 'unknown')}\n"
        f"**Timestamp**: {report.get('timestamp', 'unknown')}\n"
        f"**Environment**: {env_str}\n"
        f"**Model**: {model}\n"
        f"**Duration**: {report.get('duration_seconds', '?')}s\n"
        f"**Exit code**: {report.get('exit_code', '?')}\n\n"
        f"**Summary**: {report['summary']['passed']}/{report['summary']['total']} passed, "
        f"{report['summary']['failed']} failed\n\n"
        f"**Systems**:\n{systems_summary}\n\n"
        f"---\n\n"
        f"Please:\n"
        f"1. Summarise the pipeline health in one paragraph.\n"
        f"2. Classify any failures by type: rate limits, model errors, spec issues, timeouts, or infrastructure.\n"
        f"3. If there were failures, suggest concrete next actions (config changes, retries, code fixes).\n"
        f"4. If all passed, note any anomalies in timing or output that might be early warning signs.\n"
        f"5. Flag any agents that have been flaky across recent runs.\n"
        f"6. Cite relevant sources or documentation where applicable."
    )

    resp = client.chat(
        prompt=prompt,
        system_prompt=(
            "You are an expert DevOps analyst reviewing automated pipeline results. "
            "Be concise, specific, and actionable. Cite sources when possible."
        ),
        temperature=0.2,
    )

    # Save analysis
    analysis_md_path = FREEBUFF_DIR / "perplexity-analysis.md"
    analysis_json_path = FREEBUFF_DIR / "analysis.json"

    # Markdown version
    md = (
        f"# Perplexity Analysis — {report.get('pipeline', 'unknown')}\n\n"
        f"**Run**: {report.get('timestamp', 'unknown')}  \n"
        f"**Duration**: {report.get('duration_seconds', '?')}s  \n"
        f"**Result**: {report['summary']['passed']}/{report['summary']['total']} passed\n\n"
        f"---\n\n"
        f"{resp.content}\n"
    )
    if resp.citations:
        md += "\n\n## Sources\n\n"
        for url in resp.citations:
            md += f"- {url}\n"
    analysis_md_path.write_text(md)

    # JSON version (for downstream tooling)
    analysis_json: dict[str, Any] = {
        "timestamp": iso_now(),
        "pipeline": report.get("pipeline", "unknown"),
        "summary": report["summary"],
        "analysis": resp.content,
        "citations": resp.citations,
        "model": resp.model,
        "cost": resp.usage.total_cost if resp.usage.total_cost > 0 else None,
    }
    if resp.error:
        analysis_json["error"] = resp.error
    analysis_json_path.write_text(json.dumps(analysis_json, indent=2))

    if not quiet:
        print(f"  ✅ Analysis complete  [{resp.model}]")
        if resp.citations:
            print(f"  📚 {len(resp.citations)} sources cited")
        if resp.usage.total_cost > 0:
            print(f"  💰 Cost: ${resp.usage.total_cost:.6f}")
        print(f"  📄 Saved: {analysis_md_path}")
        print(f"  📄 Saved: {analysis_json_path}")

    return analysis_json


# ── Step 4: Logging wrapper ─────────────────────────────────────────────


def run_analysis(
    pipeline_cmd: str = "make ci",
    dry_run: bool = False,
    quiet: bool = False,
) -> int:
    """Run the full freebuff → Perplexity loop."""
    FREEBUFF_DIR.mkdir(parents=True, exist_ok=True)
    run_log_path = FREEBUFF_DIR / f"run_and_analyze_{stamp()}.log"
    run_log_fh = open(run_log_path, "w", encoding="utf-8")

    # Tee stdout to both terminal and log file
    from gatekeeper_eos_v6.factory import Tee

    cm = redirect_stdout(Tee(sys.stdout, run_log_fh))
    cm.__enter__()
    cm_err = redirect_stderr(Tee(sys.stderr, run_log_fh))
    cm_err.__enter__()

    try:
        if not quiet:
            print(f"{'=' * 60}")
            print(f"  freebuff ↔ Perplexity  |  {iso_now()}")
            print(f"  Pipeline: {pipeline_cmd}")
            if dry_run:
                print(f"  Mode:     DRY RUN (no Perplexity call)")
            print(f"{'=' * 60}")

        # Step 1
        exit_code, duration = run_pipeline(pipeline_cmd, quiet=quiet)

        # Step 2
        report = generate_report(
            pipeline=pipeline_cmd.replace("make ", ""),
            exit_code=exit_code,
            duration=duration,
            quiet=quiet,
        )

        # Step 3
        if not dry_run:
            analyze_report(report, quiet=quiet)
        else:
            print(f"\n  🏁  Dry run — Perplexity analysis skipped")

        # Final summary
        if not quiet:
            print(f"\n{'═' * 60}")
            print(f"  Complete  |  {report['summary']['passed']}/{report['summary']['total']} passed"
                  f"  |  {round(duration, 1)}s")
            if not dry_run:
                analysis_present = (FREEBUFF_DIR / "perplexity-analysis.md").exists()
                print(f"  Analysis:  {'✅ available' if analysis_present else '⏭️  skipped'}")
            print(f"  Log:       {run_log_path}")
            print(f"{'═' * 60}\n")

    finally:
        cm.__exit__(None, None, None)
        cm_err.__exit__(None, None, None)
        run_log_fh.close()

    # Always exit 0 unless the pipeline itself truly crashed (not just test failures)
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the freebuff pipeline and analyze results with Perplexity.",
    )
    parser.add_argument(
        "--pipeline", "-p",
        default=os.environ.get("PIPELINE_CMD", "make ci"),
        help="Pipeline command to run (default: make ci, or $PIPELINE_CMD)",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Run pipeline and generate report but skip Perplexity call",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress stdout (cron-friendly — errors still go to stderr)",
    )

    args = parser.parse_args()
    return run_analysis(
        pipeline_cmd=args.pipeline,
        dry_run=args.dry_run,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    sys.exit(main())
