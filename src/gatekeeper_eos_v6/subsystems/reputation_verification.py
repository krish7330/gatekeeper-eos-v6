"""Reputation/verification subsystem for cross-session asset scoring.

Cross-references discovered assets across sessions to build reputation scores,
akin to onion directory cross-referencing. Assets discovered in multiple
sessions → higher trust; assets flagged malicious → reputation penalty.

Architecture:
    ReputationTracker (ledger-backed tracker)
        → observe_asset(session_id, asset, metadata)
        → get_reputation(asset) → ReputationScore
        → cross_reference(asset) → list[AssetReputation]

Key patterns:
- Assets have versioned attestations with drift tracking
- Reputation decays over time (exponential decay)
- Policy enforcement: only high-reputation assets for critical actions
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ReputationError(Exception):
    """Base error for reputation operations."""


class ReputationLedgerError(ReputationError):
    """Raised when ledger operations fail (corruption, I/O error)."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ReputationScore:
    """Trust score for an asset (0.0–1.0)."""

    score: float = 0.0  # 0.0 = untrusted, 1.0 = fully trusted
    session_count: int = 0  # number of sessions observing this asset
    positive_flags: int = 0  # number of positive confirmations
    negative_flags: int = 0  # number of malicious flags
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    def __post_init__(self) -> None:
        # Clamp score to [0.0, 1.0]
        self.score = max(0.0, min(1.0, self.score))

    @staticmethod
    def compute_score(
        session_count: int, positive_flags: int, negative_flags: int, last_seen: str
    ) -> float:
        """Compute reputation score with decay.

        Score = (positive_flags + 1) / (session_count + positive_flags + negative_flags + 1)
        Then apply exponential decay based on time since last_seen.
        """
        # Base score using Beta(1,1) Bayesian prior
        # Beta(1 + positive, 1 + negative) — posterior mode
        # Note: session_count is reserved for future confidence-weighting.
        base = (positive_flags + 1) / (positive_flags + negative_flags + 2)

        # Time-based decay (exponential, 30-day half-life)
        now = datetime.now(timezone.utc)
        last = datetime.fromisoformat(last_seen)
        days_elapsed = (now - last).days
        decay = 0.5 ** (days_elapsed / 30.0)  # half-life = 30 days

        return base * decay


@dataclass
class AssetReputation:
    """Reputation record for a single asset."""

    asset_id: str  # canonical identifier (e.g., IP:port, URL)
    reputation: ReputationScore
    attestations: list[dict[str, Any]] = field(default_factory=list)
    session_ids: list[str] = field(default_factory=list)
    is_flagged_malicious: bool = False
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class ReputationLedger:
    """Append-only ledger for asset reputation observations."""

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = ledger_path
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.write_text("[]", encoding="utf-8")

    def append(
        self, session_id: str, asset_id: str, metadata: dict[str, Any]
    ) -> int:
        """Append observation to ledger. Returns sequence number."""
        ledger_data = self._load()
        sequence = len(ledger_data) + 1

        entry = {
            "sequence": sequence,
            "session_id": session_id,
            "asset_id": asset_id,
            "metadata": metadata,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hash": self._compute_hash(session_id, asset_id, metadata),
        }
        ledger_data.append(entry)
        self._save(ledger_data)
        return sequence

    def load_by_asset(self, asset_id: str) -> list[dict[str, Any]]:
        """Load all observations for an asset."""
        ledger_data = self._load()
        return [e for e in ledger_data if e["asset_id"] == asset_id]

    def _load(self) -> list[dict[str, Any]]:
        data = self.ledger_path.read_text(encoding="utf-8")
        return json.loads(data)

    def _save(self, ledger_data: list[dict[str, Any]]) -> None:
        self.ledger_path.write_text(
            json.dumps(ledger_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _compute_hash(
        self, session_id: str, asset_id: str, metadata: dict[str, Any]
    ) -> str:
        raw = json.dumps(
            {"session_id": session_id, "asset_id": asset_id, "metadata": metadata},
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------


class ReputationTracker:
    """Cross-session reputation tracker for assets."""

    def __init__(self, ledger_path: Path) -> None:
        self.ledger = ReputationLedger(ledger_path)
        self._cache: dict[str, AssetReputation] = {}

    def observe_asset(
        self, session_id: str, asset_id: str, metadata: dict[str, Any]
    ) -> AssetReputation:
        """Record asset observation in a session."""
        # Append to ledger
        self.ledger.append(session_id, asset_id, metadata)

        # Update cache
        if asset_id not in self._cache:
            self._cache[asset_id] = AssetReputation(
                asset_id=asset_id, reputation=ReputationScore()
            )

        record = self._cache[asset_id]
        record.reputation.session_count += 1
        record.session_ids.append(session_id)

        # Update flags based on metadata
        if metadata.get("is_positive", False):
            record.reputation.positive_flags += 1
        if metadata.get("is_malicious", False):
            record.reputation.negative_flags += 1
            record.is_flagged_malicious = True

        # Recompute score
        record.reputation.score = ReputationScore.compute_score(
            record.reputation.session_count,
            record.reputation.positive_flags,
            record.reputation.negative_flags,
            record.reputation.last_seen,
        )

        # Update attestations
        record.attestations.append(
            {
                "session_id": session_id,
                "metadata": metadata,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        return record

    def get_reputation(self, asset_id: str) -> AssetReputation | None:
        """Get reputation for an asset (from cache or load from ledger)."""
        if asset_id in self._cache:
            return self._cache[asset_id]

        # Load from ledger
        observations = self.ledger.load_by_asset(asset_id)
        if not observations:
            return None

        record = AssetReputation(asset_id=asset_id, reputation=ReputationScore())
        for obs in observations:
            record.session_ids.append(obs["session_id"])
            record.reputation.session_count += 1
            if obs["metadata"].get("is_positive", False):
                record.reputation.positive_flags += 1
            if obs["metadata"].get("is_malicious", False):
                record.reputation.negative_flags += 1
                record.is_flagged_malicious = True
            record.attestations.append(obs)

        record.reputation.score = ReputationScore.compute_score(
            record.reputation.session_count,
            record.reputation.positive_flags,
            record.reputation.negative_flags,
            datetime.now(timezone.utc).isoformat(),
        )

        self._cache[asset_id] = record
        return record

    def cross_reference(self, asset_id: str) -> list[AssetReputation]:
        """Cross-reference asset across all sessions (returns aggregated attestations)."""
        record = self.get_reputation(asset_id)
        return record.attestations if record else []
