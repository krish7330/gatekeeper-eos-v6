"""Tests for AuditLog — append, hash chain integrity, verification, Gatekeeper integration."""
import json
import os
import tempfile

import pytest

from src.gatekeeper_eos_v6.audit_log import AuditLog
from src.gatekeeper_eos_v6.policy import GatekeeperPolicy


@pytest.fixture
def log_path() -> str:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        f.close()
    yield f.name
    if os.path.exists(f.name):
        os.remove(f.name)


def test_append_entry(log_path: str):
    """AuditLog.append() writes a JSONL entry and returns it."""
    audit = AuditLog(log_path)
    entry = audit.append(tool="read_file", target="/workspace/doc.txt", status="ALLOW", reason="OK")
    assert entry["tool"] == "read_file"
    assert entry["status"] == "ALLOW"
    assert "entry_hash" in entry
    assert "timestamp" in entry

    # Verify it was written to disk
    with open(log_path) as f:
        lines = f.readlines()
    assert len(lines) == 1
    saved = json.loads(lines[0].strip())
    assert saved["entry_hash"] == entry["entry_hash"]


def test_hash_chain(log_path: str):
    """Multiple entries form a hash chain (prev_hash links)."""
    audit = AuditLog(log_path)
    e1 = audit.append(tool="read_file", target="/workspace/a.txt", status="ALLOW", reason="OK")
    e2 = audit.append(tool="read_file", target="/etc/passwd", status="BLOCK", reason="Outside workspace")
    e3 = audit.append(tool="unknown_tool", target="", status="BLOCK", reason="Not authorized")

    assert e1["prev_hash"] is None
    assert e2["prev_hash"] == e1["entry_hash"]
    assert e3["prev_hash"] == e2["entry_hash"]


def test_verify_integrity(log_path: str):
    """verify() returns empty list for intact chain."""
    audit = AuditLog(log_path)
    audit.append(tool="read_file", target="/workspace/a.txt", status="ALLOW", reason="OK")
    audit.append(tool="read_file", target="/etc/passwd", status="BLOCK", reason="Outside workspace")

    errors = audit.verify()
    assert errors == [], f"Expected no errors, got: {errors}"


def test_verify_detects_tamper(log_path: str):
    """verify() detects tampered entry_hash."""
    audit = AuditLog(log_path)
    audit.append(tool="read_file", target="/workspace/a.txt", status="ALLOW", reason="OK")

    # Tamper the log file
    with open(log_path, "r") as f:
        data = f.read()
    with open(log_path, "w") as f:
        f.write(data.replace("ALLOW", "BLOCK"))  # modify content breaks hash

    errors = audit.verify()
    assert len(errors) >= 1
    assert "entry_hash mismatch" in errors[0]


def test_verify_detects_broken_chain(log_path: str):
    """verify() detects broken prev_hash chain."""
    audit = AuditLog(log_path)
    audit.append(tool="read_file", target="/workspace/a.txt", status="ALLOW", reason="OK")
    audit.append(tool="read_file", target="/etc/passwd", status="BLOCK", reason="Outside workspace")

    # Break the chain by inserting a fake entry
    fake_entry = '{"tool":"fake","prev_hash":"badhash","entry_hash":"fakehash"}\n'
    with open(log_path, "a") as f:
        f.write(fake_entry)

    errors = audit.verify()
    assert any("hash chain broken" in e for e in errors)


def test_audit_wired_into_gatekeeper(tmp_path):
    """GatekeeperPolicy records decisions to AuditLog when configured."""
    log_file = tmp_path / "test_audit.log"
    audit = AuditLog(log_path=str(log_file))

    # Write policy file BEFORE creating GatekeeperPolicy
    with open("test_policy.json", "w") as f:
        json.dump({"allowed_tools": ["read_file"], "workspace": "/workspace"}, f)

    policy = GatekeeperPolicy(config_path="test_policy.json", constitution_path=None, audit_log=audit)

    # ALLOW decision
    decision1 = policy.evaluate_action({"tool": "read_file", "target": "/workspace/doc.txt"})
    assert decision1["status"] == "ALLOW"

    # BLOCK decision
    decision2 = policy.evaluate_action({"tool": "read_file", "target": "/etc/passwd"})
    assert decision2["status"] == "BLOCK"

    # Verify audit log has both entries
    with open(log_file) as f:
        lines = f.readlines()
    assert len(lines) == 2
    e1 = json.loads(lines[0])
    e2 = json.loads(lines[1])
    assert e1["status"] == "ALLOW"
    assert e2["status"] == "BLOCK"
    assert e2["prev_hash"] == e1["entry_hash"]

    # Verify chain integrity
    errors = audit.verify()
    assert errors == [], f"Expected no errors, got: {errors}"


def test_audit_does_not_block_without_log(tmp_path):
    """GatekeeperPolicy works normally without audit_log configured."""
    with open("test_policy.json", "w") as f:
        json.dump({"allowed_tools": ["read_file"], "workspace": "/workspace"}, f)
    policy = GatekeeperPolicy(config_path="test_policy.json", constitution_path=None, audit_log=None)
    decision = policy.evaluate_action({"tool": "read_file", "target": "/workspace/doc.txt"})
    assert decision["status"] == "ALLOW"


def test_audit_integrity_after_tamper(tmp_path):
    """After tampering the log, verify detects it."""
    log_file = tmp_path / "test_audit.log"
    audit = AuditLog(log_path=str(log_file))

    with open("test_policy.json", "w") as f:
        json.dump({"allowed_tools": ["read_file"], "workspace": "/workspace"}, f)
    policy = GatekeeperPolicy(config_path="test_policy.json", constitution_path=None, audit_log=audit)
    policy.evaluate_action({"tool": "read_file", "target": "/workspace/doc.txt"})
    policy.evaluate_action({"tool": "read_file", "target": "/etc/passwd"})

    # Verify initially intact
    assert audit.verify() == []

    # Tamper
    with open(log_file, "r") as f:
        content = f.read()
    with open(log_file, "w") as f:
        f.write(content.replace("ALLOW", "DENY"))

    # Verify now detects tamper
    errors = audit.verify()
    assert len(errors) >= 1
