#!/usr/bin/env python3
"""reporter — generate structured JSON reports from pipeline runs.

Reads the latest pipeline logs and ``summary.md``, then emits a stable
``report.json`` that downstream tools (Perplexity bridge, dashboards,
CI) can consume without parsing raw text.

Output structure (``logs/freebuff/report.json``)
------------------------------------------------

.. code-block:: json

    {
      "pipeline": "ci",
      "run_id": "20260527_220000",
      "timestamp": "2026-05-27T22:00:00",
      "duration_seconds": 0.42,
      "exit_code": 0,
      "model": "meta-llama/llama-4-scout-17b-16e-instruct",
      "environment": {
        "python_version": "3.11.9",
        "os": "darwin",
        "project": "gatekeeper-eos-v6",
        "project_version": "1.0.0"
      },
      "systems": [
        {
          "name": "incident-classifier",
          "status": "pass",           -- "pass" | "fail" | "error"
          "error_type": null,           -- "rate_limit" | "model_error" | "timeout" | "import_error" | null
          "output_snippet": "[Classification: network]",
          "last_run_at": "2026-05-27T20:23:30"
        }
      ],
      "summary": {
        "total": 5,
        "passed": 5,
        "failed": 0
      },
      "bridge": {
        "analysis_path": "logs/freebuff/perplexity-analysis.md",
        "analysis_time": "2026-05-27T22:01:00",
        "status": "available" | "pending" | "not_run"
      },
      "source_files": [
        "logs/summary.md",
        "logs/run_all_20260527_202330.log"
      ]
    }

Schema contract
---------------
Every ``report.json`` guarantees these top-level keys:

``pipeline``
    Name of the pipeline that was run (e.g. ``ci``, ``all``, ``agent-test``).

``run_id``
    Unique identifier for this run, derived from the timestamp.

``timestamp``
    ISO-8601 timestamp when the report was generated.

``duration_seconds``
    Wall-clock duration of the pipeline run, or ``null`` if unknown.

``exit_code``
    Exit code of the pipeline process, or ``null`` if unknown.

``model``
    Primary model used for agent runs (extracted from summary.md headers),
    or ``null`` if unavailable.

``environment``
    Diagnostic context — Python version, OS, project name and version.
    Helps distinguish runs across different machines or environments.

``systems``
    **Deduplicated** list of systems — one entry per unique system name.
    Each entry has:

    - ``name``:       System identifier (e.g. ``incident-classifier``).
    - ``status``:     ``pass``, ``fail``, or ``error``.
    - ``error_type``: Machine-readable error category (``rate_limit``,
                      ``model_error``, ``timeout``, ``import_error``, or
                      ``null`` if passing or type is unknown).
    - ``output_snippet``: Last non-empty line of output, truncated to 200
                          characters.
    - ``last_run_at``:    ISO-8601 timestamp of this system's most recent
                          run, or the run timestamp if per-system timing is
                          unavailable.

``summary``
    Roll-up counts: ``total``, ``passed``, ``failed``.

``bridge``
    Link to the Perplexity analysis artifact, or ``null`` if analysis
    hasn't been run yet.  Fields:

    - ``analysis_path``: Relative path to ``perplexity-analysis.md``.
    - ``analysis_time``: ISO-8601 timestamp of when analysis was done.
    - ``status``:        One of ``available``, ``pending``, ``not_run``.

``source_files``
    List of file paths that contributed data to this report.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent.parent.parent
LOG_DIR = HERE / "logs"
FREEBUFF_DIR = LOG_DIR / "freebuff"
SUMMARY_MD = LOG_DIR / "summary.md"


# ── Helpers ──────────────────────────────────────────────────────────────────


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _get_env_info() -> dict[str, str]:
    """Return diagnostic environment info."""
    import platform

    return {
        "python_version": platform.python_version(),
        "os": platform.system().lower(),
        "project": "gatekeeper-eos-v6",
        "project_version": "1.0.0",
    }


def _read_or_empty(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return ""


def _infer_error_type(status: str, output_snippet: str) -> str | None:
    """Try to infer a machine-readable error category from the output."""
    if status == "pass":
        return None
    snippet_lower = output_snippet.lower()
    if "rate limit" in snippet_lower or "ratelimit" in snippet_lower:
        return "rate_limit"
    if "timeout" in snippet_lower:
        return "timeout"
    if "import" in snippet_lower and "error" in snippet_lower:
        return "import_error"
    if "model" in snippet_lower and "error" in snippet_lower:
        return "model_error"
    return None


# ── Parsers ──────────────────────────────────────────────────────────────────


def _parse_summary_md(text: str) -> tuple[list[dict[str, Any]], str | None, str | None]:
    """Parse summary.md into structured system entries, model name, and run ID.

    Returns
    -------
    (systems, model, run_id)
        ``systems`` is a deduplicated list — only the **most recent** run's
        systems are included.
    """
    systems: list[dict[str, Any]] = []
    model: str | None = None
    run_id: str | None = None

    # Track run sections: split on "## Run:" headers
    sections = re.split(r"^## Run:", text, flags=re.MULTILINE)

    for section in reversed(sections):
        section = section.strip()
        if not section:
            continue

        current_systems: list[dict[str, Any]] = []
        sect_model: str | None = None
        sect_run_id: str | None = None

        # Extract model from header (e.g., "20260527_202330 | Model: meta-llama/...")
        # `re.split` leaves a leading space, so we strip() before matching
        header_line = section.splitlines()[0].strip() if section.splitlines() else ""
        m = re.match(r"(\S+)\s*\|\s*Model:\s*(\S+)", header_line)
        if m:
            sect_run_id = m.group(1)
            sect_model = m.group(2)

        # Parse system lines
        for line in section.splitlines():
            line = line.strip()
            m = re.match(
                r"^- \[(PASS|FAIL|PASS\(fallback\)|ERROR)\]\s+(\S+):\s*(.*)", line
            )
            if m:
                raw_status = m.group(1).lower()
                if raw_status.startswith("pass"):
                    status = "pass"
                elif raw_status == "fail":
                    status = "fail"
                else:
                    status = "error"

                name = m.group(2)
                snippet = m.group(3).strip()[:200]
                error_type = _infer_error_type(status, snippet)

                current_systems.append(
                    {
                        "name": name,
                        "status": status,
                        "error_type": error_type,
                        "output_snippet": snippet,
                    }
                )

        if current_systems:
            # This is the most recent run with data — use it
            systems = current_systems
            model = sect_model
            run_id = sect_run_id
            break

    return systems, model, run_id


def _parse_run_all_log(log_path: Path) -> dict[str, Any]:
    """Parse a run_all_*.log into structured data."""
    text = _read_or_empty(log_path)
    result: dict[str, Any] = {
        "model": "",
        "systems": [],
    }

    # Extract model
    m = re.search(r"Model:\s*(\S+)", text)
    if m:
        result["model"] = m.group(1)

    # Extract system results
    for line in text.splitlines():
        line = line.strip()
        # e.g., "  incident-classifier                PASS"
        m = re.match(r"^\s{2}(\S+)\s{20,}(PASS|FAIL|PASS\(fallback\)|ERROR|RATE LIMIT)", line)
        if m:
            raw_status = m.group(2).lower()
            if raw_status.startswith("pass"):
                status = "pass"
            elif raw_status == "fail":
                status = "fail"
            else:
                status = "error"
            result["systems"].append(
                {
                    "name": m.group(1),
                    "status": status,
                }
            )

    return result


def _parse_run_log(log_path: Path) -> dict[str, Any]:
    """Parse a run_*.log (from run.sh) into structured data."""
    text = _read_or_empty(log_path)
    result: dict[str, Any] = {
        "generation": None,
        "tests": None,
    }

    # Generation result
    m = re.search(r"(✅|❌)\s*(Generation succeeded|Generation failed)", text)
    if m:
        result["generation"] = "pass" if m.group(1) == "✅" else "fail"

    # Test result
    m = re.search(r"(✅|❌)\s*(All tests passed|Tests failed)", text)
    if m:
        result["tests"] = "pass" if m.group(1) == "✅" else "fail"

    return result


# ── Main reporter ────────────────────────────────────────────────────────────


def build_report(pipeline: str = "ci") -> dict[str, Any]:
    """Build a structured report from the latest pipeline artifacts.

    Parameters
    ----------
    pipeline:
        Which pipeline was run (``ci``, ``all``, ``agent-test``, etc.)
    """
    now = iso_now()
    run_id = stamp()
    report: dict[str, Any] = {
        "pipeline": pipeline,
        "run_id": run_id,
        "timestamp": now,
        "duration_seconds": None,
        "exit_code": None,
        "model": None,
        "environment": _get_env_info(),
        "systems": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
        "source_files": [],
        "bridge": None,
    }

    # ── 1. Parse summary.md for agent-test results (primary) ────────────
    summary_text = _read_or_empty(SUMMARY_MD)
    if summary_text.strip():
        systems, model, run_id_from_summary = _parse_summary_md(summary_text)
        if systems:
            report["systems"] = systems
            report["source_files"].append("logs/summary.md")
        if model:
            report["model"] = model
        if run_id_from_summary:
            # Prefer the run ID from the actual pipeline run
            report["run_id"] = run_id_from_summary

    # ── 2. Parse latest run_all_*.log for richer detail ─────────────────
    logs = sorted(
        (p for p in LOG_DIR.glob("run_all_*.log")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if logs:
        run_all_data = _parse_run_all_log(logs[0])
        # Use run_all log data only if summary.md was empty
        if not report["systems"] and run_all_data["systems"]:
            report["systems"] = [
                {
                    "name": s["name"],
                    "status": s["status"],
                    "error_type": None,
                    "output_snippet": None,
                }
                for s in run_all_data["systems"]
            ]
        if run_all_data["model"] and not report["model"]:
            report["model"] = run_all_data["model"]
        report["source_files"].append(f"logs/{logs[0].name}")

    # ── 3. Parse latest run_*.log for generation/test results ───────────
    logs_run = sorted(
        (p for p in LOG_DIR.glob("run_*.log") if not p.name.startswith("run_all_")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if logs_run:
        run_data = _parse_run_log(logs_run[0])
        if run_data.get("generation") is not None:
            report["generation_status"] = run_data["generation"]
            report["test_status"] = run_data["tests"]
        report["source_files"].append(f"logs/{logs_run[0].name}")

    # ── 4. Attach last_run_at to each system ────────────────────────────
    # Prefer the pipeline run timestamp from summary.md over the report generation time
    if "run_id" in report and report["run_id"] and len(str(report["run_id"])) >= 8:
        try:
            run_ts = datetime.strptime(str(report["run_id"]), "%Y%m%d_%H%M%S").isoformat(timespec="seconds")
        except ValueError:
            run_ts = now
    else:
        run_ts = now
    for sys_entry in report["systems"]:
        sys_entry["last_run_at"] = run_ts

    # ── 5. Compute summary ──────────────────────────────────────────────
    passed = sum(1 for s in report["systems"] if s["status"] == "pass")
    failed = sum(1 for s in report["systems"] if s["status"] in ("fail", "error"))
    report["summary"] = {
        "total": len(report["systems"]),
        "passed": passed,
        "failed": failed,
    }

    # ── 6. Check for existing bridge analysis ───────────────────────────
    analysis_path = FREEBUFF_DIR / "perplexity-analysis.md"
    if analysis_path.exists():
        report["bridge"] = {
            "analysis_path": str(analysis_path),
            "analysis_time": datetime.fromtimestamp(
                analysis_path.stat().st_mtime
            ).isoformat(timespec="seconds"),
            "status": "available",
        }
    else:
        analysis_json_path = FREEBUFF_DIR / "analysis.json"
        if analysis_json_path.exists():
            report["bridge"] = {
                "analysis_path": str(analysis_json_path),
                "analysis_time": datetime.fromtimestamp(
                    analysis_json_path.stat().st_mtime
                ).isoformat(timespec="seconds"),
                "status": "pending",  # JSON exists but no .md yet
            }

    return report


# ── CLI ──────────────────────────────────────────────────────────────────────


def cli() -> int:
    """CLI entry point::

        python -m gatekeeper_eos_v6.reporter           # → report.json
        python -m gatekeeper_eos_v6.reporter --pretty   # → pretty-printed stdout
    """
    pretty = "--pretty" in sys.argv or "-p" in sys.argv

    pipeline = "ci"
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in ("--pretty", "-p"):
            continue
        if not arg.startswith("-"):
            pipeline = arg
            break

    report = build_report(pipeline=pipeline)
    indent = 2 if pretty else None
    output = json.dumps(report, indent=indent)

    if pretty:
        print(output)
    else:
        # Write to logs/freebuff/report.json
        FREEBUFF_DIR.mkdir(parents=True, exist_ok=True)
        (FREEBUFF_DIR / "report.json").write_text(output)
        print(f"✅ Report saved: {FREEBUFF_DIR / 'report.json'}")
        print(f"   {report['summary']['total']} systems, "
              f"{report['summary']['passed']} passed, "
              f"{report['summary']['failed']} failed")

    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(cli())
