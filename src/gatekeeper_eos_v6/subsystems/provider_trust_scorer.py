"""Provider trust scoring subsystem for LLM drift/hallucination tracking.

Tracks LLM provider drift rates historically and computes trust scores for routing
decisions. Similar to ONION.live's policy enforcement on intermediaries.

Architecture:
    ProviderTrustScorer (metrics tracker)
        -> record_drift(provider_id, drift_type, severity)
        -> get_trust_score(provider_id) -> TrustScore
        -> get_provider_for_action(action_type) -> provider_id

Key patterns:
- Per-provider drift metrics (false positives, hallucinated findings)
- Weighted trust score decaying over time
- Policy enforcement: only high-trust providers for critical actions
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TrustScorerError(Exception):
    """Base error for trust scoring operations."""


class TrustScorerLedgerError(TrustScorerError):
    """Raised when ledger operations fail (corruption, I/O error)."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TrustScore:
    """Trust score for a provider (0.0–1.0)."""

    score: float = 0.0
    total_drifts: int = 0
    false_positives: int = 0
    hallucinated_findings: int = 0
    last_drift_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    def __post_init__(self) -> None:
        self.score = max(0.0, min(1.0, self.score))

    @staticmethod
    def compute_score(
        false_positives: int,
        hallucinated_findings: int,
        total_drifts: int,
        last_drift_at: str,
    ) -> float:
        """Compute trust score with decay.

        Score = 1.0 - (false_positives * 0.2 + hallucinated_findings * 0.3) / (total_drifts + 1)
        Then apply exponential decay based on time since last_drift_at.
        """
        if total_drifts == 0:
            return 1.0

        penalty = (false_positives * 0.2 + hallucinated_findings * 0.3) / (
            total_drifts + 1
        )
        base = max(0.0, 1.0 - penalty)

        # Time-based decay (exponential, 30-day half-life)
        now = datetime.now(timezone.utc)
        last = datetime.fromisoformat(last_drift_at)
        days_elapsed = (now - last).days
        decay = 0.5 ** (days_elapsed / 30.0)

        return base * decay


@dataclass
class ProviderMetrics:
    """Metrics for a single provider."""

    provider_id: str
    trust_score: TrustScore
    drift_events: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class ProviderLedger:
    """Append-only ledger for provider drift events."""

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = ledger_path
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.write_text(
                '{"metrics": {}, "drift_events": []}', encoding="utf-8"
            )

    def record_drift(
        self,
        provider_id: str,
        drift_type: str,
        severity: float,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Record drift event. Returns sequence number."""
        if metadata is None:
            metadata = {}
        ledger_data = self._load()
        sequence = len(ledger_data["drift_events"]) + 1

        event = {
            "sequence": sequence,
            "provider_id": provider_id,
            "drift_type": drift_type,
            "severity": severity,
            "metadata": metadata,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        ledger_data["drift_events"].append(event)

        # Update metrics
        if provider_id not in ledger_data["metrics"]:
            ledger_data["metrics"][provider_id] = {
                "total_drifts": 0,
                "false_positives": 0,
                "hallucinated_findings": 0,
                "last_drift_at": event["timestamp"],
            }

        metrics = ledger_data["metrics"][provider_id]
        metrics["total_drifts"] += 1
        if drift_type == "false_positive":
            metrics["false_positives"] += 1
        elif drift_type == "hallucinated_finding":
            metrics["hallucinated_findings"] += 1
        metrics["last_drift_at"] = event["timestamp"]

        self._save(ledger_data)
        return sequence

    def load_metrics(self, provider_id: str) -> dict[str, Any] | None:
        """Load metrics for a provider."""
        ledger_data = self._load()
        return ledger_data["metrics"].get(provider_id)

    def load_drift_events(self, provider_id: str) -> list[dict[str, Any]]:
        """Load drift events for a provider."""
        ledger_data = self._load()
        return [
            e for e in ledger_data["drift_events"] if e["provider_id"] == provider_id
        ]

    def _load(self) -> dict[str, Any]:
        data = self.ledger_path.read_text(encoding="utf-8")
        return json.loads(data)

    def _save(self, ledger_data: dict[str, Any]) -> None:
        self.ledger_path.write_text(
            json.dumps(ledger_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class ProviderTrustScorer:
    """Trust scorer for LLM providers."""

    def __init__(self, ledger_path: Path) -> None:
        self.ledger = ProviderLedger(ledger_path)
        self._cache: dict[str, ProviderMetrics] = {}

    def record_drift(
        self,
        provider_id: str,
        drift_type: str,
        severity: float,
        metadata: dict[str, Any] | None = None,
    ) -> ProviderMetrics:
        """Record drift event for a provider."""
        if metadata is None:
            metadata = {}
        self.ledger.record_drift(provider_id, drift_type, severity, metadata)

        # Update cache
        if provider_id not in self._cache:
            self._cache[provider_id] = ProviderMetrics(
                provider_id=provider_id, trust_score=TrustScore()
            )

        metrics = self._cache[provider_id]
        metrics.trust_score.total_drifts += 1
        metrics.drift_events.append(
            {
                "drift_type": drift_type,
                "severity": severity,
                "metadata": metadata,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        if drift_type == "false_positive":
            metrics.trust_score.false_positives += 1
        elif drift_type == "hallucinated_finding":
            metrics.trust_score.hallucinated_findings += 1

        metrics.trust_score.last_drift_at = datetime.now(timezone.utc).isoformat()

        # Recompute score
        metrics.trust_score.score = TrustScore.compute_score(
            metrics.trust_score.false_positives,
            metrics.trust_score.hallucinated_findings,
            metrics.trust_score.total_drifts,
            metrics.trust_score.last_drift_at,
        )

        metrics.trust_score.last_updated = datetime.now(timezone.utc).isoformat()
        return metrics

    def get_trust_score(self, provider_id: str) -> ProviderMetrics | None:
        """Get trust score for a provider (from cache or load from ledger)."""
        if provider_id in self._cache:
            return self._cache[provider_id]

        metrics_data = self.ledger.load_metrics(provider_id)
        if not metrics_data:
            return None

        events = self.ledger.load_drift_events(provider_id)
        metrics = ProviderMetrics(
            provider_id=provider_id,
            trust_score=TrustScore(
                total_drifts=metrics_data["total_drifts"],
                false_positives=metrics_data["false_positives"],
                hallucinated_findings=metrics_data["hallucinated_findings"],
                last_drift_at=metrics_data["last_drift_at"],
            ),
            drift_events=events,
        )

        metrics.trust_score.score = TrustScore.compute_score(
            metrics.trust_score.false_positives,
            metrics.trust_score.hallucinated_findings,
            metrics.trust_score.total_drifts,
            metrics.trust_score.last_drift_at,
        )

        self._cache[provider_id] = metrics
        return metrics

    def get_provider_for_action(
        self, action_type: str, min_trust_score: float = 0.7
    ) -> str | None:
        """Select provider for an action based on trust score.

        Policy: only use providers with trust score >= min_trust_score for critical actions.
        Iterates all known providers and returns the highest-trust one above the threshold.
        """
        best_provider: str | None = None
        best_score = -1.0

        # Check cached providers first
        for provider_id, metrics in self._cache.items():
            if metrics.trust_score.score >= min_trust_score:
                if metrics.trust_score.score > best_score:
                    best_score = metrics.trust_score.score
                    best_provider = provider_id

        # Fall back to ledger data for providers not in cache
        if not best_provider:
            ledger_data = self.ledger._load()
            for provider_id in ledger_data.get("metrics", {}):
                if provider_id in self._cache:
                    continue
                metrics_data = ledger_data["metrics"][provider_id]
                score = TrustScore.compute_score(
                    metrics_data.get("false_positives", 0),
                    metrics_data.get("hallucinated_findings", 0),
                    metrics_data.get("total_drifts", 0),
                    metrics_data.get("last_drift_at", ""),
                )
                if score >= min_trust_score and score > best_score:
                    best_score = score
                    best_provider = provider_id

        return best_provider
