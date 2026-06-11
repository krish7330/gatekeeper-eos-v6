"""medical_audit.py — v0.1: binary demographic parity check."""


def demographic_parity_difference(group1_rate: float, group2_rate: float) -> float:
    """Return absolute difference between two positive outcome rates.

    Measures demographic parity: the difference in positive outcome
    rates between two groups. Closer to 0 = more fair.

    Args:
        group1_rate: Positive outcome rate for group 1 (0.0–1.0)
        group2_rate: Positive outcome rate for group 2 (0.0–1.0)

    Returns:
        Absolute difference between the two rates.
    """
    return abs(group1_rate - group2_rate)
