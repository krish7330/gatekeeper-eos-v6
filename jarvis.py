#!/usr/bin/env python3
"""jarvis.py — Personal Jarvis CLI entry point.

Usage:
    python jarvis.py oracle <pdf_path>

Flow:
    User Request → Gatekeeper evaluation → ALLOW? → Dispatch to Oracle → JSON result
"""
import importlib.util
import json
import sys

from src.gatekeeper_eos_v6.policy import GatekeeperPolicy


def _load_oracle():
    """Load oracle_v0.1.py module (dot in filename, use spec_from_file_location)."""
    spec = importlib.util.spec_from_file_location("oracle_v0_1", "oracle_v0.1.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _print_result(status: str, data: dict, exit_code: int = 0):
    """Print structured result as JSON and exit."""
    result = {"status": status, **data}
    print(json.dumps(result, indent=2))
    sys.exit(exit_code)


def cmd_oracle(args: list[str], policy: GatekeeperPolicy):
    """Oracle: extract red text from a PDF."""
    if len(args) < 1:
        _print_result("error", {"error": "Usage: jarvis oracle <pdf_path>"}, 1)

    pdf_path = args[0]

    # Gatekeeper gate
    decision = policy.evaluate_action({"tool": "read_file", "target": pdf_path})
    if decision["status"] == "BLOCK":
        _print_result("blocked", {
            "reason": decision.get("reason", "Not authorized."),
            "target": pdf_path,
        }, 3)

    # Load and dispatch to Oracle
    oracle_mod = _load_oracle()
    spans = oracle_mod.extract_red_spans(pdf_path)
    _print_result("ok", {
        "module": "oracle",
        "target": pdf_path,
        "total_spans": len(spans),
        "spans": spans,
    })


def main():
    if len(sys.argv) < 2:
        print("Usage: python jarvis.py <module> [args...]", file=sys.stderr)
        print("Modules: oracle", file=sys.stderr)
        sys.exit(1)

    policy = GatekeeperPolicy()
    module = sys.argv[1]
    args = sys.argv[2:]

    if module == "oracle":
        cmd_oracle(args, policy)
    else:
        _print_result("error", {
            "error": f"Unknown module: '{module}'",
            "available": ["oracle"],
        }, 1)


if __name__ == "__main__":
    main()
