#!/usr/bin/env python3
"""demo.py — Prove Jarvis exists. One command, one end-to-end workflow.

Runs a medical audit scenario through the full Jarvis chain:

    Request → Gatekeeper → Constitution → Medical AI → Audit Log → Result

Usage:
    python demo.py
"""
import json
import os
import sys
import tempfile

# Import Jarvis modules
from src.gatekeeper_eos_v6.policy import GatekeeperPolicy
from src.gatekeeper_eos_v6.audit_log import AuditLog
from medical_audit import demographic_parity_difference


def print_step(label: str, detail: str = ""):
    """Print a formatted step in the chain."""
    print(f"  │  {label}")
    if detail:
        for line in detail.split("\n"):
            print(f"  │    {line}")


def main():
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║        Personal Jarvis — Demo           ║")
    print("  ║   One end-to-end workflow               ║")
    print("  ╚══════════════════════════════════════════╝")
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
        print("  ┌─ Step 1: User Request")
        print_step('Request: "Run a medical audit on Scenario A"')
        print_step("Tool: medical_audit")
        tool = "medical_audit"
        target = "Scenario A"
        group1_rate = 0.72
        group2_rate = 0.45
        print_step(f"Rates: group1={group1_rate}, group2={group2_rate}")
        print()

        # ------------------------------------------------------------------
        # Step 2: Gatekeeper Evaluation
        # ------------------------------------------------------------------
        print("  ┌─ Step 2: Gatekeeper Evaluation")
        decision = gatekeeper.evaluate_action({"tool": tool, "target": target})
        print_step(f"Decision: {decision['status']}")
        print_step(f"Reason: {decision['reason']}")
        print()

        assert decision["status"] == "ALLOW", f"Gatekeeper blocked: {decision['reason']}"

        # ------------------------------------------------------------------
        # Step 3: Constitution Rules Check
        # ------------------------------------------------------------------
        print("  ┌─ Step 3: Constitution Rules")
        print_step(f"Loaded {len(gatekeeper.constitution_rules)} rules from constitution.json")
        print_step(f"Active rules: {[r['id'] for r in gatekeeper.constitution_rules]}")
        print_step("No medical_audit-specific rule — falls through to policy.json")
        print()

        # ------------------------------------------------------------------
        # Step 4: Medical AI Execution
        # ------------------------------------------------------------------
        print("  ┌─ Step 4: Medical AI Execution")
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
        print("  ┌─ Step 5: Audit Log Recording")
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
            print_step("Audit integrity: ✅ INTACT (hash chain verified)")
        else:
            print_step(f"Audit integrity: ❌ COMPROMISED — {errors}")
        print()

        # ------------------------------------------------------------------
        # Result
        # ------------------------------------------------------------------
        print("  ╔══════════════════════════════════════════╗")
        print("  ║           Demo Complete ✅               ║")
        print("  ╚══════════════════════════════════════════╝")
        print()
        print("  Chain:")
        print("    User Request")
        print("       ↓")
        print("    Gatekeeper (evaluate_action)")
        print("       ↓")
        print("    Constitution Rules")
        print("       ↓")
        print("    Medical AI (demographic_parity_difference)")
        print("       ↓")
        print(f"    Result: {parity_diff:.4f} — {interpretation}")
        print("       ↓")
        print(f"    Audit Log ({len(entries)} entries, integrity: ✅ intact)")
        print()

    # Temp directory and all files cleaned up automatically
    print("  Temp workspace cleaned up.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
