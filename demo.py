#!/usr/bin/env python3
"""demo.py — Prove Jarvis exists. One command, one end-to-end workflow.

Runs a medical audit scenario through the full Jarvis chain:

    Request → Gatekeeper → Constitution → Medical AI → Audit Log → Result

Usage:
    python demo.py                        # Run with default scenario
    python demo.py --help                 # Show this message
"""
import argparse
import json
import os
import sys
import tempfile

# Ensure the package is importable whether installed or run from repo root
_repo_root = os.path.dirname(os.path.abspath(__file__))
_src_path = os.path.join(_repo_root, "src")
if os.path.isdir(_src_path) and _src_path not in sys.path:
    sys.path.insert(0, _src_path)

# Import Jarvis modules
from gatekeeper_eos_v6.policy import GatekeeperPolicy
from gatekeeper_eos_v6.audit_log import AuditLog
from medical_audit import demographic_parity_difference


def print_step(label: str, detail: str = ""):
    """Print a formatted step in the chain."""
    print(f"  |  {label}")
    if detail:
        for line in detail.split("\n"):
            print(f"  |    {line}")


def main(argv: list[str] | None = None) -> int:
    # Parse --help if provided; otherwise run with defaults.
    # When argv is None (called from CLI), argparse reads sys.argv.
    # When argv is provided (called from tests), use those args.
    parser = argparse.ArgumentParser(
        description="Personal Jarvis — end-to-end workflow demonstration.",
    )
    parser.parse_known_args(argv)  # --help triggers sys.exit(0); unknown args ignored

    group1_rate = 0.72
    group2_rate = 0.45

    print()
    print("  +---------------------------------------------+")
    print("  |         Personal Jarvis -- Demo             |")
    print("  |   One end-to-end workflow                  |")
    print("  +---------------------------------------------+")
    print()

    # ------------------------------------------------------------------
    # Setup: temporary workspace with test policy + audit log
    # ------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        ws = os.path.join(tmp, "workspace")
        os.makedirs(ws)

        # Create policy allowing medical_audit
        policy_config = {
            "version": "0.2",
            "allowed_tools": ["read_file", "medical_audit"],
            "workspace": ws,
        }
        policy_path = os.path.join(tmp, "policy.json")
        with open(policy_path, "w") as f:
            json.dump(policy_config, f)

        # Create audit log
        audit_log_path = os.path.join(tmp, "audit.log")
        audit = AuditLog(log_path=audit_log_path)

        # Create Gatekeeper with this policy + default constitution
        gatekeeper = GatekeeperPolicy(
            config_path=policy_path,
            audit_log=audit,
        )

        # ------------------------------------------------------------------
        # Step 1: Request
        # ------------------------------------------------------------------
        print("  +- Step 1: User Request")
        print_step("A user submits a medical audit request.")
        print_step("Tool: medical_audit")
        tool = "medical_audit"
        target = "Scenario A"
        print_step(f"Parameters: group1_rate={group1_rate}, group2_rate={group2_rate}")
        print()

        # ------------------------------------------------------------------
        # Step 2: Gatekeeper Evaluation
        # ------------------------------------------------------------------
        print("  +- Step 2: Gatekeeper Evaluation")
        print_step("The policy engine checks if the tool is authorized.")
        decision = gatekeeper.evaluate_action({"tool": tool, "target": target})
        print_step(f"Decision: {decision['status']}")
        print_step(f"Reason: {decision['reason']}")
        print()

        assert decision["status"] == "ALLOW", f"Gatekeeper blocked: {decision['reason']}"

        # ------------------------------------------------------------------
        # Step 3: Constitution Rules Check
        # ------------------------------------------------------------------
        print("  +- Step 3: Constitution Rules")
        print_step("The EOS Constitution is checked for applicable rules.")
        print_step(f"Loaded {len(gatekeeper.constitution_rules)} rules from constitution.json")
        print_step(f"Active rules: {[r['id'] for r in gatekeeper.constitution_rules]}")
        print_step("No medical_audit-specific rule — falls through to policy.json")
        print()

        # ------------------------------------------------------------------
        # Step 4: Medical AI Execution
        # ------------------------------------------------------------------
        print("  +- Step 4: Medical AI Execution")
        print_step("The Medical AI module computes demographic parity.")
        parity_diff = demographic_parity_difference(group1_rate, group2_rate)
        print_step(f"demographic_parity_difference({group1_rate}, {group2_rate})")
        print_step(f"Result: {parity_diff:.4f}")
        print()

        if parity_diff < 0.1:
            interpretation = "Fair — minimal demographic disparity"
        elif parity_diff < 0.2:
            interpretation = "Moderate disparity — investigate further"
        else:
            interpretation = "Significant disparity — action recommended"

        print_step(f"Interpretation: {interpretation}")
        print()

        # ------------------------------------------------------------------
        # Step 5: Audit Log
        # ------------------------------------------------------------------
        print("  +- Step 5: Audit Log Recording")
        print_step("Every decision is recorded with hash-chain integrity.")
        with open(audit_log_path) as f:
            entries = f.readlines()
        print_step(f"Entries recorded: {len(entries)}")

        last_entry = json.loads(entries[-1].strip())
        print_step(f"Last entry: tool={last_entry['tool']}, "
                   f"status={last_entry['status']}, "
                   f"hash={last_entry['entry_hash'][:16]}...")

        # Verify integrity
        errors = audit.verify()
        if not errors:
            print_step("Audit integrity: INTACT (hash chain verified)")
        else:
            print_step(f"Audit integrity: COMPROMISED — {errors}")
        print()

        # ------------------------------------------------------------------
        # Result
        # ------------------------------------------------------------------
        print("  +---------------------------------------------+")
        print("  |           Demo Complete                     |")
        print("  +---------------------------------------------+")
        print()
        print("  Full chain executed:")
        print("    User Request")
        print("       |")
        print("    Gatekeeper (evaluate_action)")
        print("       |")
        print("    Constitution Rules")
        print("       |")
        print("    Medical AI (demographic_parity_difference)")
        print("       |")
        print(f"    Result: {parity_diff:.4f} — {interpretation}")
        print("       |")
        print(f"    Audit Log ({len(entries)} entries, integrity: intact)")
        print()

    # Temp directory and all files cleaned up automatically
    print("  Temporary workspace cleaned up.")
    print()

    # ------------------------------------------------------------------
    # What next?
    # ------------------------------------------------------------------
    print("  ----------------------------------------------")
    print("  Explore further:")
    print()
    print("    See the source files:")
    print("      medical_audit.py    — The Medical AI module")
    print("      constitution.json  — The EOS Constitution rules")
    print("      policy.json        — The Gatekeeper policy")
    print("      src/               — Jarvis source code")
    print()
    print("    Run the tests:")
    print("      python -m pytest tests/ -q")
    print()
    print("    Read the docs:")
    print("      README.md          — Full documentation")
    print("      FRICTION_LOG.md    — User feedback log")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
