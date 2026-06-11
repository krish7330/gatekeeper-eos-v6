"""Cycle 6: jarvis.py CLI — end-to-end tests for User→Gatekeeper→Oracle flow."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import fitz


@pytest.fixture
def workspace(tmp_path: Path):
    """Creates a temp workspace with a test PDF and matching policy.json."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    pdf_path = ws / "test.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text(fitz.Point(72, 100), "Answer: C", fontsize=12, color=(1, 0, 0))
    doc.save(str(pdf_path))
    doc.close()

    policy = {
        "version": "0.2",
        "allowed_tools": ["read_file"],
        "workspace": str(ws),
    }
    with open(ws / "policy.json", "w") as f:
        json.dump(policy, f)

    return ws


@pytest.fixture
def project_root() -> str:
    return os.path.join(os.path.dirname(__file__), "..")


class TestJarvisCLI:
    """End-to-end tests for jarvis.py CLI."""

    def test_jarvis_oracle_allow(self, workspace: Path, project_root: str):
        """jarvis oracle <pdf_within_workspace> → ALLOW → JSON result with spans."""
        pdf_path = str(workspace / "test.pdf")

        # Swap policy.json to allow this workspace
        policy_json = os.path.join(project_root, "policy.json")
        original = None
        if os.path.exists(policy_json):
            with open(policy_json) as f:
                original = f.read()

        with open(policy_json, "w") as f:
            f.write(open(os.path.join(workspace, "policy.json")).read())

        try:
            result = subprocess.run(
                [sys.executable, "jarvis.py", "oracle", pdf_path],
                capture_output=True, text=True, cwd=project_root,
            )
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")

            assert result.returncode == 0, f"Expected 0, got {result.returncode}: {result.stderr}"
            data = json.loads(result.stdout)
            assert data["status"] == "ok"
            assert data["module"] == "oracle"
            assert data["total_spans"] >= 1
            assert "Answer: C" in str(data["spans"])
        finally:
            if original is not None:
                with open(policy_json, "w") as f:
                    f.write(original)

    def test_jarvis_oracle_block(self, project_root: str):
        """jarvis oracle <file_outside_workspace> → BLOCK → exit 3."""
        result = subprocess.run(
            [sys.executable, "jarvis.py", "oracle", "/etc/passwd"],
            capture_output=True, text=True, cwd=project_root,
        )
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")

        assert result.returncode == 3, f"Expected 3, got {result.returncode}"
        data = json.loads(result.stdout)
        assert data["status"] == "blocked"

    def test_jarvis_unknown_module(self, project_root: str):
        """jarvis <unknown_module> → error."""
        result = subprocess.run(
            [sys.executable, "jarvis.py", "nonexistent"],
            capture_output=True, text=True, cwd=project_root,
        )
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert data["status"] == "error"

    # --- Medical Audit tests ---

    def test_jarvis_medical_audit_allow(self, project_root: str):
        """jarvis medical-audit with allowed tool → parity difference printed."""
        # Swap policy.json to allow medical_audit
        policy_json = os.path.join(project_root, "policy.json")
        original = None
        if os.path.exists(policy_json):
            with open(policy_json) as f:
                original = f.read()

        with open(policy_json, "w") as f:
            json.dump({
                "version": "0.2",
                "allowed_tools": ["read_file", "medical_audit"],
                "workspace": "/workspace",
            }, f)

        try:
            result = subprocess.run(
                [sys.executable, "jarvis.py", "medical-audit", "0.7", "0.5"],
                capture_output=True, text=True, cwd=project_root,
            )
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")

            assert result.returncode == 0, f"Expected 0, got {result.returncode}: {result.stderr}"
            assert "Parity difference: 0.2000" in result.stdout
        finally:
            if original is not None:
                with open(policy_json, "w") as f:
                    f.write(original)

    def test_jarvis_medical_audit_blocked(self, project_root: str):
        """jarvis medical-audit without allowance → blocked."""
        # Ensure medical_audit is NOT in allowed_tools (default policy)
        result = subprocess.run(
            [sys.executable, "jarvis.py", "medical-audit", "0.7", "0.5"],
            capture_output=True, text=True, cwd=project_root,
        )
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")

        assert result.returncode == 3, f"Expected 3, got {result.returncode}"
        data = json.loads(result.stdout)
        assert data["status"] == "blocked"

    def test_jarvis_medical_audit_bad_args(self, project_root: str):
        """jarvis medical-audit with invalid args → error."""
        result = subprocess.run(
            [sys.executable, "jarvis.py", "medical-audit", "not_a_number"],
            capture_output=True, text=True, cwd=project_root,
        )
        assert result.returncode == 1
