"""Cycle 4: Oracle → Gatekeeper integration test.

Oracle invokes GatekeeperPolicy.evaluate_action() before reading a PDF.
ALLOW → continue (exit 0). BLOCK → abort (exit 3).

Both paths are tested end-to-end via subprocess.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import fitz

from src.gatekeeper_eos_v6.policy import GatekeeperPolicy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path: Path):
    """Creates a temp workspace with a test PDF inside + a policy.json that
    allows read_file within this workspace."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    # Create test PDF with red text
    pdf_path = ws / "test.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text(fitz.Point(72, 100), "Answer: B", fontsize=12, color=(1, 0, 0))
    doc.save(str(pdf_path))
    doc.close()

    # Create policy.json allowing read_file within this workspace
    policy = {
        "version": "0.2",
        "allowed_tools": ["read_file"],
        "workspace": str(ws),
    }
    with open(ws / "policy.json", "w") as f:
        json.dump(policy, f)

    return ws  # Path to workspace directory


@pytest.fixture
def project_root() -> str:
    """Path to project root (one level up from tests/)."""
    return os.path.join(os.path.dirname(__file__), "..")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestOracleGatekeeperIntegration:
    """ALLOW path: Oracle proceeds. BLOCK path: Oracle aborts with exit 3."""

    def test_oracle_allow_path(self, workspace: Path, project_root: str):
        """Oracle reads a PDF in the allowed workspace → exits 0, produces output."""
        pdf_path = str(workspace / "test.pdf")
        policy_path = str(workspace / "policy.json")

        # Temporarily swap policy.json for this test
        original_policy = None
        policy_json_path = os.path.join(project_root, "policy.json")
        if os.path.exists(policy_json_path):
            with open(policy_json_path) as f:
                original_policy = f.read()

        with open(policy_json_path, "w") as f:
            with open(policy_path) as src:
                f.write(src.read())

        try:
            # Run Oracle — should succeed (ALLOW)
            result = subprocess.run(
                [sys.executable, "oracle_v0.1.py", pdf_path],
                capture_output=True, text=True,
                cwd=project_root,
            )
            print(f"ALLOW path stdout: {result.stdout.strip()}")
            print(f"ALLOW path stderr: {result.stderr.strip()}")

            assert result.returncode == 0, (
                f"Expected exit 0 (ALLOW), got {result.returncode}. "
                f"stderr: {result.stderr.strip()}"
            )
            assert "Gatekeeper: ALLOW" in result.stdout, (
                f"Expected 'Gatekeeper: ALLOW' in stdout: {result.stdout}"
            )

            red_path = os.path.join(project_root, "red_answers.json")
            assert os.path.exists(red_path), "red_answers.json should exist"

            with open(red_path) as f:
                data = json.load(f)
            assert data["total_spans"] >= 1
            assert "Answer: B" in str(data["spans"])
        finally:
            # Restore original policy
            if original_policy is not None:
                with open(policy_json_path, "w") as f:
                    f.write(original_policy)
            elif os.path.exists(policy_json_path):
                os.remove(policy_json_path)

    def test_oracle_block_path(self, project_root: str):
        """Oracle tries to read a file outside workspace → exits 3 with BLOCKED."""
        target = "/etc/passwd"

        result = subprocess.run(
            [sys.executable, "oracle_v0.1.py", target],
            capture_output=True, text=True,
            cwd=project_root,
        )
        print(f"BLOCK path stdout: {result.stdout.strip()}")
        print(f"BLOCK path stderr: {result.stderr.strip()}")

        assert result.returncode == 3, (
            f"Expected exit code 3 (BLOCK), got {result.returncode}. "
            f"stderr: {result.stderr.strip()}"
        )
        assert "BLOCKED" in result.stderr
