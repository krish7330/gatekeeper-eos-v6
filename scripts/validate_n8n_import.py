#!/usr/bin/env python3
"""
Validate n8n workflow exports for import readiness.

Checks:
- Valid JSON structure
- Required node types present
- Credential references exist
- Placeholders not missed
- Node connections are valid
"""

import json
import sys
from pathlib import Path


WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / "n8n"

REQUIRED_NODES = {
    "alance-main.json": {
        "min_nodes": 27,
        "required_types": {"n8n-nodes-base.webhook", "n8n-nodes-base.code", "n8n-nodes-base.googleSheets", "n8n-nodes-base.if", "n8n-nodes-base.noOp", "n8n-nodes-base.twilio", "n8n-nodes-base.telegram", "n8n-nodes-base.set"},
        "required_nodes": [
            "Webhook", "Extract Payload", "Read MESSAGE_LEDGER",
            "Check Duplicate", "Is Duplicate?", "Cancel/Stop Check",
            "Is Cancel?", "Keyword Scorer", "State Machine", "Is Drift?",
            "Build Reply", "Is Production?", "Send Reply (Production)",
            "Send Reply (Sandbox)", "Fallback Reply", "Append MESSAGE_LEDGER",
            "Append CONVERSATIONS", "Booking Complete?", "Append LEADS", "Done",
        ],
        "node_credentials": {
            "Send Reply (Production)": {"twilioApi": "TwilioProduction"},
            "Send Reply (Sandbox)": {"twilioApi": "TwilioSandbox"},
        },
        "placeholders": ["YOUR_GOOGLE_SHEET_ID", "YOUR_TELEGRAM_CHAT_ID", "+14155238886"],
        "webhook_path": "twilio-webhook",
    },
    "alance-error.json": {
        "min_nodes": 4,
        "required_types": {"n8n-nodes-base.errorTrigger", "n8n-nodes-base.code", "n8n-nodes-base.telegram", "n8n-nodes-base.googleSheets"},
        "required_nodes": [
            "Error Trigger", "Format Error", "Telegram Alert", "Log to ERRORS Sheet",
        ],
        "node_credentials": {
            "Telegram Alert": {"telegramApi": "TelegramAlanceBot"},
            "Log to ERRORS Sheet": {"googleSheetsOAuth2Api": "GoogleSheetsAlance"},
        },
        "placeholders": ["YOUR_TELEGRAM_CHAT_ID", "YOUR_GOOGLE_SHEET_ID"],
    },
    "alance-metrics.json": {
        "min_nodes": 6,
        "required_types": {"n8n-nodes-base.scheduleTrigger", "n8n-nodes-base.googleSheets", "n8n-nodes-base.merge", "n8n-nodes-base.code"},
        "required_nodes": [
            "Schedule Trigger", "Read MESSAGE_LEDGER", "Read ERRORS",
            "Merge Data Sources", "Compute Metrics", "Append HEALTHMETRICS",
        ],
        "node_credentials": {
            "Read MESSAGE_LEDGER": {"googleSheetsOAuth2Api": "GoogleSheetsAlance"},
            "Read ERRORS": {"googleSheetsOAuth2Api": "GoogleSheetsAlance"},
            "Append HEALTHMETRICS": {"googleSheetsOAuth2Api": "GoogleSheetsAlance"},
        },
        "placeholders": ["YOUR_GOOGLE_SHEET_ID"],
    },
}


def validate_json(path: Path) -> list[str]:
    """Validate that the file is a JSON array with one workflow."""
    errors = []
    try:
        data = json.loads(path.read_text(), strict=False)
    except json.JSONDecodeError as e:
        return [f"  ✗ Invalid JSON: {e}"]

    if not isinstance(data, list) or len(data) == 0:
        errors.append(f"  ✗ Expected non-empty array, got {type(data).__name__}")

    return errors


def validate_workflow(path: Path, checks: dict) -> list[str]:
    """Run all validation checks against a workflow file."""
    errors = []
    data = json.loads(path.read_text(), strict=False)
    workflow = data[0]

    name = workflow.get("name", "UNNAMED")
    print(f"\n  Name: {name}")

    # Node count
    nodes = workflow.get("nodes", [])
    node_count = len(nodes)
    print(f"  Nodes: {node_count} (min expected: {checks['min_nodes']})")
    if node_count < checks["min_nodes"]:
        errors.append(f"  ✗ Expected ≥{checks['min_nodes']} nodes, got {node_count}")

    # Node names
    node_names = {n.get("name") for n in nodes}
    for req_node in checks["required_nodes"]:
        if req_node not in node_names:
            errors.append(f"  ✗ Missing required node: {req_node}")

    # Node types
    types_found = {n.get("type") for n in nodes}
    for req_type in checks["required_types"]:
        if req_type not in types_found:
            errors.append(f"  ✗ Missing required type: {req_type}")        # Credentials (per-node expectations)
        node_creds = checks.get("node_credentials", {})
        for node in nodes:
            node_name = node.get("name", "")
            expected = node_creds.get(node_name, {})
            actual = node.get("credentials") or {}
            for key, expected_name in expected.items():
                actual_name = actual.get(key)
                if actual_name != expected_name:
                    errors.append(
                        f"  ✗ Node '{node_name}' credential '{key}': "
                        f"expected '{expected_name}', got '{actual_name}'"
                    )

    # Placeholder detection — ensure all placeholders have been replaced
    file_text = path.read_text()
    unresolved = [ph for ph in checks["placeholders"] if ph in file_text]
    if unresolved:
        for ph in unresolved:
            errors.append(f"  ✗ Placeholder '{ph}' still present — needs replacement")
    else:
        print(f"  ✓ All {len(checks['placeholders'])} placeholder(s) replaced")

    # Webhook path
    webhook_path = checks.get("webhook_path")
    if webhook_path:
        if webhook_path not in file_text:
            errors.append(f"  ✗ Webhook path '/{webhook_path}' not found")

    # Connections integrity
    connections = workflow.get("connections", {})
    if not connections:
        errors.append("  ✗ No connections defined")

    # Verify all connection source nodes exist and all connection targets exist
    for src_name, outputs in connections.items():
        if src_name not in node_names:
            errors.append(f"  ✗ Connection source '{src_name}' not found in nodes list")
        for output_list in outputs.get("main", []):
            for conn in output_list:
                target = conn.get("node")
                if target and target not in node_names:
                    errors.append(f"  ✗ Connection target '{target}' not found in nodes list")

    # Settings
    settings = workflow.get("settings", {})
    if not settings:
        errors.append("  ✗ No settings defined")

    # Sticky note (README)
    has_sticky = any(n.get("type") == "n8n-nodes-base.stickyNote" for n in nodes)
    if not has_sticky:
        errors.append("  ✗ No README sticky note found")

    return errors


def main() -> int:
    """Validate all workflow files."""
    print("=" * 60)
    print("  n8n Workflow Import Validation")
    print("=" * 60)

    if not WORKFLOWS_DIR.exists():
        print(f"\n  ✗ Workflows directory not found: {WORKFLOWS_DIR}")
        return 1

    any_errors = False

    for filename, checks in REQUIRED_NODES.items():
        path = WORKFLOWS_DIR / filename
        if not path.exists():
            print(f"\n  ✗ File not found: {filename}")
            any_errors = True
            continue

        print(f"\n── {filename} ─{'─' * (50 - len(filename))}")

        # JSON validation
        json_errors = validate_json(path)
        for err in json_errors:
            print(err)
        if json_errors:
            any_errors = True
            continue

        # Workflow validation
        wf_errors = validate_workflow(path, checks)
        for err in wf_errors:
            print(err)
        if wf_errors:
            any_errors = True
        else:
            print("  ✓ All checks passed")

    print()

    # Summary
    all_sheets = ["MESSAGE_LEDGER", "CONVERSATIONS", "LEADS", "STATE_DRIFT", "ERRORS", "HEALTHMETRICS"]
    all_creds = ["TwilioSandbox", "TwilioProduction", "GoogleSheetsAlance", "TelegramAlanceBot"]

    print("── Required Sheet Tabs ──")
    missing = [s for s in all_sheets if s not in open(WORKFLOWS_DIR / "alance-main.json").read()]
    if missing:
        print(f"  ✗ Missing sheet references: {missing}")
        any_errors = True
    else:
        print("  ✓ All 6 sheet tabs referenced")

    print("\n── Required Credentials ──")
    cred_count = sum(
        open(WORKFLOWS_DIR / f).read().count(c)
        for f in ["alance-main.json", "alance-error.json", "alance-metrics.json"]
        for c in all_creds
    )
    if cred_count == 0:
        print("  ✗ No credential references found")
        any_errors = True
    else:
        print(f"  ✓ {cred_count} credential references across all workflows")

    print("\n" + "=" * 60)
    if any_errors:
        print("  Result: ✗ ISSUES FOUND — review errors above before import")
        return 1
    else:
        print("  Result: ✓ READY FOR IMPORT")
        return 0


if __name__ == "__main__":
    sys.exit(main())
