"""Tests for Gatekeeper v0.1: Binary whitelist policy"""
import pytest
from src.gatekeeper_eos_v6.policy import GatekeeperPolicy


@pytest.fixture
def policy():
    return GatekeeperPolicy()


def test_allow_read_file(policy):
    """allowed tool → ALLOW"""
    payload = {"tool": "read_file"}
    assert policy.evaluate_action(payload)["status"] == "ALLOW"


def test_block_execute_shell(policy):
    """unauthorized tool → BLOCK"""
    payload = {"tool": "execute_shell"}
    assert policy.evaluate_action(payload)["status"] == "BLOCK"


def test_block_missing_tool(policy):
    """no tool specified → default deny"""
    payload = {}
    assert policy.evaluate_action(payload)["status"] == "BLOCK"
