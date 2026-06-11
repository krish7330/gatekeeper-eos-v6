#!/usr/bin/env python3
"""jarvis.py — Personal Jarvis CLI entry point.

Usage:
    python jarvis.py oracle <pdf_path>
    python jarvis.py medical-audit <rate1> <rate2>

Flow:
    User Request → Gatekeeper evaluation → ALLOW? → Dispatch to module → Result
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


def _print_plain(message: str):
    """Print plain text result (non-JSON modules)."""
    print(message)


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


def cmd_medical_audit(args: list[str], policy: GatekeeperPolicy):
    """Medical AI Audit: compute demographic parity difference."""
    if len(args) < 2:
        print("Usage: python jarvis.py medical-audit <group1_rate> <group2_rate>", file=sys.stderr)
        sys.exit(1)

    try:
        rate1 = float(args[0])
        rate2 = float(args[1])
    except ValueError:
        print("Error: Rates must be floating-point numbers.", file=sys.stderr)
        sys.exit(1)

    # Gatekeeper gate
    decision = policy.evaluate_action({"tool": "medical_audit"})
    if decision["status"] == "BLOCK":
        _print_result("blocked", {
            "reason": decision.get("reason", "Not authorized."),
            "tool": "medical_audit",
        }, 3)

    # Dispatch to Medical AI
    from medical_audit import demographic_parity_difference
    diff = demographic_parity_difference(rate1, rate2)
    _print_plain(f"Parity difference: {diff:.4f}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python jarvis.py <module> [args...]", file=sys.stderr)
        print("Modules: oracle, medical-audit", file=sys.stderr)
        sys.exit(1)

    policy = GatekeeperPolicy()
    module = sys.argv[1]
    args = sys.argv[2:]

    if module == "oracle":
        cmd_oracle(args, policy)
    elif module == "medical-audit":
        cmd_medical_audit(args, policy)
    else:
        _print_result("error", {
            "error": f"Unknown module: '{module}'",
            "available": ["oracle", "medical-audit"],
        }, 1)


if __name__ == "__main__":
    main()
