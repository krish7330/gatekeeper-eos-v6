"""Campaign integration for subsystems.

Provides convenience functions for using reputation tracking,
trust scoring, and asset validation in campaign orchestration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from gatekeeper_eos_v6.subsystems import (
    ReputationTracker,
    ProviderTrustScorer,
)
from gatekeeper_eos_v6.subsystems.config import (
    get_reputation_ledger_path,
    get_trust_ledger_path,
)


# Module-level trackers (initialized lazily)
_REPUTATION_TRACKER: ReputationTracker | None = None
_TRUST_SCORER: ProviderTrustScorer | None = None


def get_reputation_tracker() -> ReputationTracker:
    """Get or create the reputation tracker (lazy init)."""
    global _REPUTATION_TRACKER
    if _REPUTATION_TRACKER is None:
        _REPUTATION_TRACKER = ReputationTracker(get_reputation_ledger_path())
    return _REPUTATION_TRACKER


def get_trust_scorer() -> ProviderTrustScorer:
    """Get or create the trust scorer (lazy init)."""
    global _TRUST_SCORER
    if _TRUST_SCORER is None:
        _TRUST_SCORER = ProviderTrustScorer(get_trust_ledger_path())
    return _TRUST_SCORER


def validate_discovered_asset(
    asset_id: str,
    min_reputation: float = 0.6,
) -> tuple[bool, str]:
    """Validate a discovered asset using reputation tracking.

    Args:
        asset_id: Canonical asset identifier (e.g., IP:port, URL).
        min_reputation: Minimum reputation score required (default 0.6).

    Returns:
        Tuple of (is_valid, reason).
    """
    tracker = get_reputation_tracker()
    rep = tracker.get_reputation(asset_id)

    if not rep:
        return True, "new_asset"

    if rep.is_flagged_malicious:
        return False, "flagged_malicious"

    if rep.reputation.score < min_reputation:
        return False, f"low_reputation ({rep.reputation.score:.2f})"

    return True, "trusted"


def select_provider_for_action(
    action_type: str,
    min_trust: float = 0.7,
) -> tuple[str, Any]:
    """Select LLM provider for an action based on trust score.

    Args:
        action_type: Type of action (e.g., "discover", "analyze", "report").
        min_trust: Minimum trust score required (default 0.7).

    Returns:
        Tuple of (provider_id, provider_instance).

    Raises:
        ValueError: If no provider meets trust threshold.
    """
    scorer = get_trust_scorer()

    best = scorer.get_provider_for_action(action_type, min_trust)
    if best:
        # Lazily create the provider instance
        from gatekeeper_eos_v6.providers import create_llm_provider

        provider = create_llm_provider(
            provider_type=best.split("-")[0],  # e.g. "openai" from "openai-gpt-4o-mini"
            model=best,
        )
        return best, provider

    raise ValueError(
        f"No provider with trust >= {min_trust}. "
        "Consider lowering the threshold or checking provider drift metrics."
    )


def record_asset_discovery(
    session_id: str,
    asset_id: str,
    metadata: dict[str, Any],
) -> None:
    """Record asset discovery with reputation tracking.

    Args:
        session_id: Session identifier.
        asset_id: Canonical asset identifier.
        metadata: Discovery metadata (e.g., discovery_method, confidence).
    """
    tracker = get_reputation_tracker()
    tracker.observe_asset(session_id, asset_id, metadata)


def record_provider_drift(
    provider_id: str,
    drift_type: str,
    severity: float,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Record provider drift with trust scoring.

    Args:
        provider_id: Provider identifier.
        drift_type: Type of drift ("false_positive" or "hallucinated_finding").
        severity: Severity score (0.0-1.0).
        metadata: Additional metadata.
    """
    if metadata is None:
        metadata = {}
    scorer = get_trust_scorer()
    scorer.record_drift(provider_id, drift_type, severity, metadata)
