"""Focused tests for new batch spec entries: security-threat-consensus and document-pipeline-planner."""

from pathlib import Path

import pytest
import yaml

from gatekeeper_eos_v6.factory import (
    load_spec,
    validate_spec,
    generate_system,
    SUPPORTED_TARGETS,
    SUPPORTED_PATTERNS,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BATCH_SPEC = PROJECT_ROOT / "specs" / "batch.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_templates():
    """Return a Jinja2 Environment pointing at the real templates dir."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    templates_dir = PROJECT_ROOT / "templates"
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _get_spec_by_name(spec: dict, name: str) -> dict | None:
    """Find a system definition by name in the batch spec."""
    for sys_def in spec.get("systems", []):
        if sys_def["name"] == name:
            return sys_def
    return None


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def batch_spec():
    """Load the batch.yaml spec once per module."""
    return load_spec(str(BATCH_SPEC))


# ---------------------------------------------------------------------------
# security-threat-consensus — happy path
# ---------------------------------------------------------------------------

SECURITY_THREAT = "security-threat-consensus"


def test_security_threat_spec_exists(batch_spec):
    """The security-threat-consensus spec must be present in batch.yaml."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    assert sys_def is not None, f"{SECURITY_THREAT} not found in batch.yaml"


def test_security_threat_has_correct_target(batch_spec):
    """Must use consensus/langgraph."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    assert sys_def["target"] in SUPPORTED_TARGETS
    assert sys_def["target"] == "langgraph"


def test_security_threat_has_correct_pattern(batch_spec):
    """Must use the consensus pattern."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    assert sys_def["pattern"] in SUPPORTED_PATTERNS
    assert sys_def["pattern"] == "consensus"


def test_security_threat_has_five_agents(batch_spec):
    """Must have exactly 5 agents: 4 analysts + 1 synthesizer."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    agents = sys_def["agents"]
    assert len(agents) == 5, f"Expected 5 agents, got {len(agents)}"


def test_security_threat_agent_names(batch_spec):
    """Agent names must match the security threat domain."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    names = [a["name"] for a in sys_def["agents"]]
    expected = {"network_analyst", "application_analyst", "social_analyst",
                "physical_analyst", "synthesizer"}
    assert set(names) == expected, f"Agent names mismatch: {names}"


def test_security_threat_last_agent_is_synthesizer(batch_spec):
    """Consensus pattern requires the last agent to be the synthesizer."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    assert sys_def["agents"][-1]["name"] == "synthesizer"


def test_security_threat_all_agents_have_instructions(batch_spec):
    """Every agent must have non-empty instructions."""
    sys_def = _get_spec_by_name(batch_spec, SECURITY_THREAT)
    for agent in sys_def["agents"]:
        assert agent.get("instructions", "").strip(), (
            f"Agent '{agent['name']}' has empty instructions"
        )


def test_security_threat_generates_successfully(tmp_path):
    """Generate the system and verify output files."""
    from unittest.mock import patch

    spec = load_spec(str(BATCH_SPEC))
    sys_def = _get_spec_by_name(spec, SECURITY_THREAT)

    with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        out_dir = generate_system(sys_def, env)

    assert out_dir.exists()
    assert (out_dir / "main.py").exists()
    assert (out_dir / "main.py").stat().st_size > 50
    assert (out_dir / "system.yaml").exists()


def test_security_threat_generated_code_mentions_all_agents(tmp_path):
    """Generated main.py should reference all 5 agent names."""
    from unittest.mock import patch

    spec = load_spec(str(BATCH_SPEC))
    sys_def = _get_spec_by_name(spec, SECURITY_THREAT)

    with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        out_dir = generate_system(sys_def, env)

    main_code = (out_dir / "main.py").read_text()
    for agent in sys_def["agents"]:
        assert agent["name"].casefold() in main_code.casefold(), (
            f"Agent '{agent['name']}' not found in generated code"
        )


# ---------------------------------------------------------------------------
# security-threat-consensus — adversarial: missing synthesizer
# ---------------------------------------------------------------------------

def test_consensus_without_synthesizer_still_generates(tmp_path):
    """Consensus with only analysts (no synthesizer) should still generate
    valid files — the template handles missing roles gracefully."""
    from unittest.mock import patch

    # Only 4 analysts, no synthesizer
    sys_def = {
        "name": "consensus-no-synth",
        "target": "langgraph",
        "pattern": "consensus",
        "model": "gpt-4o",
        "example_input": "Test input",
        "agents": [
            {"name": "network", "instructions": "Analyze network threats."},
            {"name": "appsec", "instructions": "Analyze application threats."},
            {"name": "social", "instructions": "Analyze social threats."},
            {"name": "physical", "instructions": "Analyze physical threats."},
        ],
    }

    with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        out_dir = generate_system(sys_def, env)

    assert out_dir.exists()
    assert (out_dir / "main.py").exists()
    assert (out_dir / "main.py").stat().st_size > 50
    # Should still generate valid Python (even if the consensus pattern
    # expects a synthesizer as the last agent)
    code = (out_dir / "main.py").read_text()
    for agent in sys_def["agents"]:
        assert agent["name"].casefold() in code.casefold()


def test_consensus_with_empty_agents_raises_validation_error(tmp_path):
    """A consensus spec with zero agents should fail validation."""
    sys_def = {
        "name": "consensus-empty",
        "target": "langgraph",
        "pattern": "consensus",
        "model": "gpt-4o",
        "example_input": "Test",
        "agents": [],
    }
    errors = validate_spec({"systems": [sys_def]})
    assert len(errors) > 0


# ---------------------------------------------------------------------------
# document-pipeline-planner — happy path
# ---------------------------------------------------------------------------

DOC_PIPELINE = "document-pipeline-planner"


def test_document_pipeline_spec_exists(batch_spec):
    """The document-pipeline-planner spec must be present in batch.yaml."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    assert sys_def is not None, f"{DOC_PIPELINE} not found in batch.yaml"


def test_document_pipeline_has_correct_target(batch_spec):
    """Must use planner_executor/openai."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    assert sys_def["target"] in SUPPORTED_TARGETS
    assert sys_def["target"] == "openai"


def test_document_pipeline_has_correct_pattern(batch_spec):
    """Must use the planner_executor pattern."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    assert sys_def["pattern"] in SUPPORTED_PATTERNS
    assert sys_def["pattern"] == "planner_executor"


def test_document_pipeline_has_five_agents(batch_spec):
    """Must have exactly 5 agents: planner + 3 executors + verifier."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    agents = sys_def["agents"]
    assert len(agents) == 5, f"Expected 5 agents, got {len(agents)}"


def test_document_pipeline_agent_names(batch_spec):
    """Agent names must match the document pipeline domain."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    names = [a["name"] for a in sys_def["agents"]]
    expected = {"planner", "extractor", "analyst", "formatter", "qa_verifier"}
    assert set(names) == expected, f"Agent names mismatch: {names}"


def test_document_pipeline_first_agent_is_planner(batch_spec):
    """Planner-Executor pattern requires the first agent to be the planner."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    assert sys_def["agents"][0]["name"] == "planner"


def test_document_pipeline_last_agent_is_verifier(batch_spec):
    """Planner-Executor pattern requires the last agent to be the verifier."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    assert sys_def["agents"][-1]["name"] == "qa_verifier"


def test_document_pipeline_all_agents_have_instructions(batch_spec):
    """Every agent must have non-empty instructions."""
    sys_def = _get_spec_by_name(batch_spec, DOC_PIPELINE)
    for agent in sys_def["agents"]:
        assert agent.get("instructions", "").strip(), (
            f"Agent '{agent['name']}' has empty instructions"
        )


def test_document_pipeline_generates_successfully(tmp_path):
    """Generate the system and verify output files."""
    from unittest.mock import patch

    spec = load_spec(str(BATCH_SPEC))
    sys_def = _get_spec_by_name(spec, DOC_PIPELINE)

    with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        out_dir = generate_system(sys_def, env)

    assert out_dir.exists()
    assert (out_dir / "main.py").exists()
    assert (out_dir / "main.py").stat().st_size > 50
    assert (out_dir / "system.yaml").exists()


def test_document_pipeline_generated_code_mentions_all_agents(tmp_path):
    """Generated main.py should reference all 5 agent names."""
    from unittest.mock import patch

    spec = load_spec(str(BATCH_SPEC))
    sys_def = _get_spec_by_name(spec, DOC_PIPELINE)

    with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        out_dir = generate_system(sys_def, env)

    main_code = (out_dir / "main.py").read_text()
    for agent in sys_def["agents"]:
        assert agent["name"].casefold() in main_code.casefold(), (
            f"Agent '{agent['name']}' not found in generated code"
        )


# ---------------------------------------------------------------------------
# document-pipeline-planner — adversarial: minimal 2-agent planner_executor
# ---------------------------------------------------------------------------

def test_planner_executor_with_two_agents_generates(tmp_path):
    """Planner-Executor with only planner + verifier (no executors) should
    still generate valid files — the template handles the edge case."""
    from unittest.mock import patch

    sys_def = {
        "name": "pe-minimal",
        "target": "openai",
        "pattern": "planner_executor",
        "model": "gpt-4o",
        "example_input": "Test input",
        "agents": [
            {"name": "planner", "instructions": "Plan the work."},
            {"name": "verifier", "instructions": "Verify the output."},
        ],
    }

    with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        out_dir = generate_system(sys_def, env)

    assert out_dir.exists()
    assert (out_dir / "main.py").exists()
    assert (out_dir / "main.py").stat().st_size > 50
    code = (out_dir / "main.py").read_text()
    assert "planner".casefold() in code.casefold()
    assert "verifier".casefold() in code.casefold()





# ---------------------------------------------------------------------------
# Cross-spec consistency
# ---------------------------------------------------------------------------

def test_all_new_specs_have_example_input(batch_spec):
    """Both new specs must have non-empty example_input."""
    for name in [SECURITY_THREAT, DOC_PIPELINE]:
        sys_def = _get_spec_by_name(batch_spec, name)
        assert sys_def.get("example_input", "").strip(), (
            f"{name} is missing example_input"
        )


def test_all_new_specs_have_description(batch_spec):
    """Both new specs must have non-empty descriptions."""
    for name in [SECURITY_THREAT, DOC_PIPELINE]:
        sys_def = _get_spec_by_name(batch_spec, name)
        assert sys_def.get("description", "").strip(), (
            f"{name} is missing description"
        )


def test_all_new_specs_generated_code_is_valid_python(tmp_path):
    """Generated main.py for both new specs must be syntactically valid Python."""
    import ast
    from unittest.mock import patch

    spec = load_spec(str(BATCH_SPEC))
    env = _load_templates()

    for name in [SECURITY_THREAT, DOC_PIPELINE]:
        sys_def = _get_spec_by_name(spec, name)
        with patch("gatekeeper_eos_v6.factory.GENERATED_DIR", tmp_path):
            out_dir = generate_system(sys_def, env)
        code = (out_dir / "main.py").read_text()
        try:
            ast.parse(code)
        except SyntaxError as e:
            pytest.fail(f"Syntax error in {name}/main.py: {e}")
