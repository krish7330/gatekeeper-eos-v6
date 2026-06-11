"""Tests for Medical AI Audit v0.1."""
import medical_audit


def test_parity_zero_when_equal():
    """Equal rates → difference is 0."""
    diff = medical_audit.demographic_parity_difference(0.5, 0.5)
    assert diff == 0.0, f"Expected 0, got {diff}"
