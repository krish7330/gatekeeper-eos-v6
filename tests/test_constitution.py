"""Tests for EOS Constitution v0.1 — executable policy ruleset."""
import json


CONSTITUTION_PATH = "constitution.json"


def test_constitution_loads():
    """constitution.json loads and has required structure."""
    with open(CONSTITUTION_PATH) as f:
        data = json.load(f)

    assert data["version"] == "0.1"
    assert len(data["rules"]) >= 1

    for rule in data["rules"]:
        assert "id" in rule
        assert "action" in rule
        assert "effect" in rule
        assert rule["effect"] in ("ALLOW", "BLOCK"), f"Invalid effect: {rule['effect']}"
