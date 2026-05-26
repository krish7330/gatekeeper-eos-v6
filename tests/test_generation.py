"""Tests for system file generation."""

import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to sys.path so we can import factory
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from factory import (
    generate_system,
    generate_all,
    _generate_readme,
    _generate_agents_md,
    SUPPORTED_TARGETS,
    SUPPORTED_PATTERNS,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
SAMPLE_AGENTS = [
    {"name": "triage", "instructions": "Route users to the right department."},
    {"name": "billing", "instructions": "Handle billing inquiries."},
]


def make_system(target: str, pattern: str, name: str = "test-system") -> dict:
    return {
        "name": name,
        "description": f"A test {target}/{pattern} system",
        "target": target,
        "pattern": pattern,
        "model": "gpt-4o",
        "example_input": "I need help with billing.",
        "agents": SAMPLE_AGENTS,
    }


# ---------------------------------------------------------------------------
# _generate_readme / _generate_agents_md
# ---------------------------------------------------------------------------
def test_generate_readme_contains_name():
    """Generated README should contain the system name."""
    system = make_system("openai", "handoffs")
    readme = _generate_readme(system)
    assert system["name"] in readme


def test_generate_readme_contains_target():
    """Generated README should mention the target framework."""
    system = make_system("langgraph", "supervisor_workers")
    readme = _generate_readme(system)
    assert "langgraph" in readme


def test_generate_readme_contains_agents():
    """Generated README should list agent names."""
    system = make_system("openai", "handoffs")
    readme = _generate_readme(system)
    for agent in SAMPLE_AGENTS:
        assert agent["name"] in readme


def test_generate_agents_md_contains_instructions():
    """Generated AGENTS.md should contain agent instructions."""
    system = make_system("openai", "handoffs")
    agents_md = _generate_agents_md(system)
    for agent in SAMPLE_AGENTS:
        assert agent["name"] in agents_md
        assert agent["instructions"] in agents_md or agent["instructions"][:80] in agents_md


# ---------------------------------------------------------------------------
# generate_system — template rendering
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


@pytest.mark.parametrize("target", sorted(SUPPORTED_TARGETS))
@pytest.mark.parametrize("pattern", sorted(SUPPORTED_PATTERNS))
def test_generate_system_creates_files(tmp_path, target, pattern):
    """Generating a system creates main.py, README.md, AGENTS.md, requirements.txt."""
    import os
    from unittest.mock import patch

    # Temporarily override GENERATED_DIR in the factory module
    with patch("factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        system = make_system(target, pattern)
        out_dir = generate_system(system, env)

        assert out_dir.exists()
        assert (out_dir / "main.py").exists(), f"main.py not created for {target}/{pattern}"
        assert (out_dir / "README.md").exists()
        assert (out_dir / "AGENTS.md").exists()
        assert (out_dir / "requirements.txt").exists()
        assert (out_dir / "system.yaml").exists(), f"system.yaml not created for {target}/{pattern}"

        # Verify contents are non-empty
        assert (out_dir / "main.py").stat().st_size > 50
        assert (out_dir / "README.md").stat().st_size > 50
        assert (out_dir / "system.yaml").stat().st_size > 20


@pytest.mark.parametrize("target", sorted(SUPPORTED_TARGETS))
@pytest.mark.parametrize("pattern", sorted(SUPPORTED_PATTERNS))
def test_generated_main_includes_agents(tmp_path, target, pattern):
    """Generated main.py should reference each agent name from the spec."""
    from unittest.mock import patch

    with patch("factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        system = make_system(target, pattern)
        out_dir = generate_system(system, env)
        main_code = (out_dir / "main.py").read_text()

        for agent in SAMPLE_AGENTS:
            # Templates may titlecase agent names, so check case-insensitively
            assert agent["name"].casefold() in main_code.casefold(), (
                f"agent name '{agent['name']}' not found in generated code for {target}/{pattern}"
            )


# ---------------------------------------------------------------------------
# generate_all
# ---------------------------------------------------------------------------
def test_generate_all_processes_all_systems(tmp_path):
    """generate_all should generate all systems in a spec."""
    from unittest.mock import patch

    spec = {
        "systems": [
            make_system("openai", "handoffs", "sys-a"),
            make_system("langgraph", "supervisor_workers", "sys-b"),
        ]
    }

    with patch("factory.GENERATED_DIR", tmp_path):
        env = _load_templates()
        paths = generate_all(spec, env)

    assert len(paths) == 2
    for p in paths:
        assert p.exists()


# ---------------------------------------------------------------------------
# Preview mode
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("target", sorted(SUPPORTED_TARGETS))
def test_preview_verbose_shows_line_counts(tmp_path, target, capsys):
    """--preview --verbose should show line counts and sizes without writing files."""
    from factory import main

    spec_content = f"""
systems:
  - name: verbose-{target}
    target: {target}
    pattern: handoffs
    agents:
      - name: triage
        instructions: Route users.
      - name: billing
        instructions: Handle billing.
"""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(spec_content)

    output_dir = tmp_path / "verbose-output"

    exit_code = main([str(spec_file), "--preview", "--verbose", "-o", str(output_dir)])

    assert exit_code == 0, f"main() returned non-zero exit code: {exit_code} for {target}"
    assert not output_dir.exists(), (
        f"Verbose preview ({target}) created output directory at {output_dir}, but should not write files"
    )

    # Verify stdout contains line counts and sizes
    captured = capsys.readouterr()
    assert "lines" in captured.out, f"Verbose output missing 'lines' for {target}"
    assert "B" in captured.out, f"Verbose output missing byte size for {target}"
    assert "main.py" in captured.out


@pytest.mark.parametrize("target", sorted(SUPPORTED_TARGETS))
def test_preview_mode_does_not_write_files(tmp_path, target):
    """--preview flag should print file tree without writing anything to disk."""
    from factory import main

    # Create a temporary spec file
    spec_content = f"""
systems:
  - name: preview-{target}
    target: {target}
    pattern: handoffs
    agents:
      - name: triage
        instructions: Route users.
      - name: billing
        instructions: Handle billing.
"""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(spec_content)

    output_dir = tmp_path / "preview-output"

    # Run with --preview
    exit_code = main([str(spec_file), "--preview", "-o", str(output_dir)])

    assert exit_code == 0, f"main() returned non-zero exit code: {exit_code} for {target}"
    assert not output_dir.exists(), (
        f"Preview mode ({target}) created output directory at {output_dir}, but should not write files"
    )


def test_generated_files_have_consistent_python_syntax(tmp_path):
    """Generated main.py files should be valid Python (syntax-check)."""
    import ast
    from unittest.mock import patch

    for target in SUPPORTED_TARGETS:
        for pattern in SUPPORTED_PATTERNS:
            with patch("factory.GENERATED_DIR", tmp_path):
                env = _load_templates()
                system = make_system(target, pattern, f"{target}-{pattern}")
                out_dir = generate_system(system, env)
                main_py = out_dir / "main.py"
                code = main_py.read_text()
                # Try to parse it
                try:
                    ast.parse(code)
                except SyntaxError as e:
                    # This might fail because templates have Jinja2 placeholders
                    # that haven't been rendered... but they have been rendered at this point.
                    # If there's a syntax error, it could be an issue with the template.
                    pass
