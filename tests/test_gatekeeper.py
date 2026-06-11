"""Tests for Gatekeeper v0.2: Workspace boundary enforcement"""
import pytest
import json
import os
from src.gatekeeper_eos_v6.policy import GatekeeperPolicy

TEST_POLICY_PATH = "test_policy.json"


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


@pytest.fixture
def policy():
    return GatekeeperPolicy(config_path=TEST_POLICY_PATH)


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
    policy = GatekeeperPolicy(config_path="nonexistent_policy.json")
    payload = {"tool": "read_file", "target": "/workspace/file.txt"}
    result = policy.evaluate_action(payload)
    assert result["status"] == "BLOCK"
