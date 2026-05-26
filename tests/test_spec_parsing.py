"""Tests for spec parsing and validation logic."""

import sys
from pathlib import Path

import pytest
import yaml

# Add project root to sys.path so we can import factory
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from factory import load_spec, validate_spec, SUPPORTED_TARGETS, SUPPORTED_PATTERNS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def valid_spec() -> dict:
    return {
        "systems": [
            {
                "name": "test-system",
                "description": "A test system",
                "target": "openai",
                "pattern": "handoffs",
                "model": "gpt-4o",
                "example_input": "Hello",
                "agents": [
                    {"name": "agent_a", "instructions": "Do thing A."},
                    {"name": "agent_b", "instructions": "Do thing B."},
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# load_spec
# ---------------------------------------------------------------------------
def test_load_spec(tmp_path: Path):
    """load_spec returns a dict from a YAML file."""
    spec_file = tmp_path / "test.yaml"
    spec_file.write_text("systems:\n  - name: x\n    target: openai\n    pattern: handoffs\n    agents:\n      - name: a\n        instructions: i\n")
    result = load_spec(str(spec_file))
    assert isinstance(result, dict)
    assert len(result["systems"]) == 1


def test_load_spec_missing_file():
    """load_spec raises FileNotFoundError for missing path."""
    with pytest.raises(FileNotFoundError):
        load_spec("/nonexistent/path.yaml")


# ---------------------------------------------------------------------------
# validate_spec
# ---------------------------------------------------------------------------
def test_validate_spec_valid(valid_spec):
    """A well-formed spec returns no errors."""
    assert validate_spec(valid_spec) == []


def test_validate_spec_empty_systems():
    """An empty systems list returns an error."""
    errors = validate_spec({"systems": []})
    assert len(errors) >= 1
    assert "at least one system" in errors[0].lower()


def test_validate_spec_no_systems():
    """Missing systems key returns an error."""
    errors = validate_spec({})
    assert len(errors) >= 1


def test_validate_spec_missing_name(valid_spec):
    """A system without a name returns an error."""
    del valid_spec["systems"][0]["name"]
    errors = validate_spec(valid_spec)
    assert any("name" in e for e in errors)


def test_validate_spec_invalid_target(valid_spec):
    """An unsupported target returns an error."""
    valid_spec["systems"][0]["target"] = "unknown"
    errors = validate_spec(valid_spec)
    assert any("target" in e.lower() for e in errors)


def test_validate_spec_invalid_pattern(valid_spec):
    """An unsupported pattern returns an error."""
    valid_spec["systems"][0]["pattern"] = "unknown"
    errors = validate_spec(valid_spec)
    assert any("pattern" in e.lower() for e in errors)


def test_validate_spec_missing_agents(valid_spec):
    """A system without agents returns an error."""
    del valid_spec["systems"][0]["agents"]
    errors = validate_spec(valid_spec)
    assert any("agent" in e.lower() for e in errors)


@pytest.mark.parametrize("target", sorted(SUPPORTED_TARGETS))
@pytest.mark.parametrize("pattern", sorted(SUPPORTED_PATTERNS))
def test_all_target_pattern_combinations(target, pattern):
    """All valid target+pattern combos should pass validation."""
    spec = {
        "systems": [
            {
                "name": f"{target}-{pattern}",
                "target": target,
                "pattern": pattern,
                "agents": [{"name": "agent_a", "instructions": "Do thing."}],
            }
        ]
    }
    assert validate_spec(spec) == []
