"""Tests for Gatekeeper v0.3: Constitution-driven policy"""
import pytest
import json
import os
from src.gatekeeper_eos_v6.policy import GatekeeperPolicy

TEST_POLICY_PATH = "test_policy.json"
TEST_CONSTITUTION_PATH = "test_constitution.json"


@pytest.fixture(autouse=True)
def setup_teardown():
    """Create a test policy file before each test, remove after."""
    with open(TEST_POLICY_PATH, "w") as f:
        json.dump({
            "allowed_tools": ["read_file"],
            "workspace": "/workspace"
        }, f)
    yield
    if os.path.exists(TEST_POLICY_PATH):
        os.remove(TEST_POLICY_PATH)
    if os.path.exists(TEST_CONSTITUTION_PATH):
        os.remove(TEST_CONSTITUTION_PATH)


@pytest.fixture
def policy():
    return GatekeeperPolicy(config_path=TEST_POLICY_PATH, constitution_path=None)


# --- Existing policy tests (v0.2) ---

def test_allow_read_file_within_workspace(policy):
    """read_file → target within workspace → ALLOW"""
    payload = {"tool": "read_file", "target": "/workspace/report.txt"}
    result = policy.evaluate_action(payload)
    assert result["status"] == "ALLOW"


def test_block_unauthorized_tool(policy):
    """unauthorized tool → BLOCK"""
    payload = {"tool": "execute_shell", "target": "ls -la"}
    result = policy.evaluate_action(payload)
    assert result["status"] == "BLOCK"


def test_block_read_file_outside_workspace(policy):
    """read_file → target outside workspace → BLOCK"""
    payload = {"tool": "read_file", "target": "/etc/passwd"}
    result = policy.evaluate_action(payload)
    assert result["status"] == "BLOCK"


def test_block_missing_tool(policy):
    """no tool specified → default deny → BLOCK"""
    payload = {}
    result = policy.evaluate_action(payload)
    assert result["status"] == "BLOCK"


def test_failsafe_on_missing_config():
    """If config file is missing, Gatekeeper must default to BLOCK all."""
    policy = GatekeeperPolicy(config_path="nonexistent_policy.json", constitution_path=None)
    payload = {"tool": "read_file", "target": "/workspace/file.txt"}
    result = policy.evaluate_action(payload)
    assert result["status"] == "BLOCK"


# --- Constitution-driven tests (v0.3) ---

def _make_constitution(rules: list[dict]) -> str:
    """Write constitution rules to test file and return path."""
    with open(TEST_CONSTITUTION_PATH, "w") as f:
        json.dump({"version": "0.1", "rules": rules}, f)
    return TEST_CONSTITUTION_PATH


def test_constitution_allows_known_tool():
    """Known tool passes constitution 'tool not in allowed_tools' check → ALLOW."""
    rules = [
        {
            "id": "block-unknown",
            "action": "*",
            "effect": "BLOCK",
            "condition": "tool not in allowed_tools",
        }
    ]
    const_path = _make_constitution(rules)
    policy = GatekeeperPolicy(config_path=TEST_POLICY_PATH, constitution_path=const_path)

    # read_file is in allowed_tools, so constitution's 'tool not in allowed_tools' doesn't match
    result = policy.evaluate_action({"tool": "read_file", "target": "/workspace/report.txt"})
    assert result["status"] == "ALLOW"


def test_constitution_blocks_outside_workspace():
    """Constitution rule 'target does not start with workspace' → BLOCK."""
    rules = [
        {
            "id": "block-outside-workspace",
            "action": "read_file",
            "effect": "BLOCK",
            "condition": "target does not start with workspace",
        }
    ]
    const_path = _make_constitution(rules)
    policy = GatekeeperPolicy(config_path=TEST_POLICY_PATH, constitution_path=const_path)

    result = policy.evaluate_action({"tool": "read_file", "target": "/etc/passwd"})
    assert result["status"] == "BLOCK"
    assert "Constitution rule" in result["reason"]


def test_constitution_allows_explicit():
    """Constitution rule 'target starts with workspace' → ALLOW takes priority."""
    rules = [
        {
            "id": "allow-in-workspace",
            "action": "read_file",
            "effect": "ALLOW",
            "condition": "target starts with workspace",
        },
        {
            "id": "block-outside",
            "action": "read_file",
            "effect": "BLOCK",
            "condition": "target does not start with workspace",
        },
    ]
    const_path = _make_constitution(rules)
    policy = GatekeeperPolicy(config_path=TEST_POLICY_PATH, constitution_path=const_path)

    # Policy.json allows read_file + workspace, and constitution allows it too
    result = policy.evaluate_action({"tool": "read_file", "target": "/workspace/doc.txt"})
    assert result["status"] == "ALLOW"
    assert "Constitution rule" in result["reason"]

    # Outside workspace → blocked by constitution
    result = policy.evaluate_action({"tool": "read_file", "target": "/tmp/doc.txt"})
    assert result["status"] == "BLOCK"
    assert "Constitution rule" in result["reason"]


def test_constitution_unknown_tool_blocked():
    """Constitution blocks tools not in allowed_tools, even if policy would allow."""
    rules = [
        {
            "id": "block-unknown",
            "action": "*",
            "effect": "BLOCK",
            "condition": "tool not in allowed_tools",
        }
    ]
    const_path = _make_constitution(rules)
    policy = GatekeeperPolicy(config_path=TEST_POLICY_PATH, constitution_path=const_path)

    result = policy.evaluate_action({"tool": "not_in_whitelist"})
    assert result["status"] == "BLOCK"
    assert "Constitution rule" in result["reason"]
