"""Cycle 13: demo.py — end-to-end test proving Jarvis exists."""
import subprocess
import sys
import os


def test_demo_runs():
    """demo.py executes end-to-end workflow and exits 0."""
    project_root = os.path.join(os.path.dirname(__file__), "..")
    result = subprocess.run(
        [sys.executable, "demo.py"],
        capture_output=True, text=True, cwd=project_root,
    )
    print(result.stdout)
    if result.stderr:
        print(f"stderr: {result.stderr}")

    assert result.returncode == 0, f"Expected 0, got {result.returncode}: {result.stderr}"
    assert "Demo Complete" in result.stdout
    assert "Gatekeeper" in result.stdout
    assert "Medical AI" in result.stdout
    assert "Audit Log" in result.stdout
    assert "INTACT" in result.stdout
