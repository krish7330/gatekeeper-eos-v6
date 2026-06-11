"""Snapshot subsystem — append-only hash-chained ledger for agent state recovery.

Stores agent memory snapshots in an immutable, tamper-evident ledger.
Each snapshot captures the agent's full operational context (working_memory,
tool_call_history, conversation_summary) at a validated checkpoint.

Architecture:
    SnapshotLedger (append-only JSON file with hash chain)
        → SnapshotIndex (in-memory O(1) lookup by session_id + checkpoint_id)
            → take_snapshot() writes entries
                → context_revalidation() restores from last valid snapshot

The ledger is external to the agent — the agent cannot modify it,
nor does it control when snapshots are taken or restored.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gatekeeper_eos_v6.agentic import WorldState, EvidenceEntry, AgentAction, AgentCore
from gatekeeper_eos_v6.subsystems import AttestationLedger, AttestationError


# Module-level attestation ledger (initialized lazily)
_ATTESTATION_LEDGER: AttestationLedger | None = None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SnapshotError(Exception):
    """Base error for snapshot operations."""


class SnapshotIntegrityError(SnapshotError):
    """Raised when a snapshot's hash chain is broken (tampering detected)."""


class SnapshotNotFoundError(SnapshotError):
    """Raised when a requested snapshot does not exist in the index."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SnapshotEntry:
    """A single snapshot entry in the append-only ledger.

    Each entry records the agent's full operational context at a moment
    when drift_score == 0 (all invariants satisfied).

    The hash chain ensures tamper evidence:
        chain_hash = SHA-256(prev_chain_hash || SHA-256(state))
    """

    entry_type: str = "memory_snapshot"
    session_id: str = ""
    checkpoint_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Serialized agent state
    working_memory: dict[str, Any] = field(default_factory=dict)
    conversation_summary: str = ""
    tool_call_history: list[dict[str, Any]] = field(default_factory=list)

    # Hash chain
    hash: str = ""
    chain_hash: str = ""
    prev_chain_hash: str = ""

    # Metadata
    drift_score: int = 0
    invariants_satisfied: list[str] = field(default_factory=list)
    approval_token_id: str = ""

    # Sequence number in the ledger (set when appended)
    sequence: int = 0

    @staticmethod
    def _compute_hash(state: dict[str, Any]) -> str:
        """Compute SHA-256 of the serialized state."""
        raw = json.dumps(state, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _compute_chain_hash(prev_chain_hash: str, state_hash: str) -> str:
        """Compute chained hash: SHA-256(prev_chain_hash || state_hash)."""
        raw = f"{prev_chain_hash}||{state_hash}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def to_ledger_entry(self) -> dict[str, Any]:
        """Serialize to a ledger-storable dict."""
        return {
            "entry_type": self.entry_type,
            "session_id": self.session_id,
            "checkpoint_id": self.checkpoint_id,
            "timestamp": self.timestamp,
            "working_memory": self.working_memory,
            "conversation_summary": self.conversation_summary,
            "tool_call_history": self.tool_call_history,
            "hash": self.hash,
            "chain_hash": self.chain_hash,
            "prev_chain_hash": self.prev_chain_hash,
            "metadata": {
                "drift_score": self.drift_score,
                "invariants_satisfied": self.invariants_satisfied,
                "approval_token_id": self.approval_token_id,
            },
            "sequence": self.sequence,
        }

    @classmethod
    def from_ledger_entry(cls, data: dict[str, Any]) -> SnapshotEntry:
        """Deserialize from a ledger dict."""
        metadata = data.get("metadata", {})
        return cls(
            entry_type=data.get("entry_type", "memory_snapshot"),
            session_id=data.get("session_id", ""),
            checkpoint_id=data.get("checkpoint_id", ""),
            timestamp=data.get("timestamp", ""),
            working_memory=data.get("working_memory", {}),
            conversation_summary=data.get("conversation_summary", ""),
            tool_call_history=data.get("tool_call_history", []),
            hash=data.get("hash", ""),
            chain_hash=data.get("chain_hash", ""),
            prev_chain_hash=data.get("prev_chain_hash", ""),
            drift_score=metadata.get("drift_score", 0),
            invariants_satisfied=metadata.get("invariants_satisfied", []),
            approval_token_id=metadata.get("approval_token_id", ""),
            sequence=data.get("sequence", 0),
        )


# ---------------------------------------------------------------------------
# Snapshot index — in-memory O(1) lookup
# ---------------------------------------------------------------------------


class SnapshotIndex:
    """In-memory index for fast snapshot retrieval.

    Keyed by (session_id, checkpoint_id) → SnapshotEntry.
    Also maintains a list of all entries sorted by sequence for hash chain
    verification.

    Rebuilt on startup by scanning the ledger file.
    """

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], SnapshotEntry] = {}
        self._by_sequence: list[SnapshotEntry] = []

    def add(self, entry: SnapshotEntry) -> None:
        """Add an entry to the index."""
        key = (entry.session_id, entry.checkpoint_id)
        self._by_key[key] = entry
        self._by_sequence.append(entry)

    def get(self, session_id: str, checkpoint_id: str) -> SnapshotEntry | None:
        """Retrieve a snapshot by session_id and checkpoint_id (O(1))."""
        return self._by_key.get((session_id, checkpoint_id))

    def get_last_valid(
        self, session_id: str, max_drift_score: int = 0
    ) -> SnapshotEntry | None:
        """Find the most recent snapshot for a session with drift_score <= max_drift_score.

        Scans entries in reverse sequence order and returns the first match.

        Args:
            session_id: Session to search for.
            max_drift_score: Maximum acceptable drift score (default 0 = clean).

        Returns:
            The most recent valid SnapshotEntry, or None if none found.
        """
        for entry in reversed(self._by_sequence):
            if entry.session_id == session_id and entry.drift_score <= max_drift_score:
                return entry
        return None

    def get_by_session(self, session_id: str) -> list[SnapshotEntry]:
        """Get all snapshots for a session, sorted by sequence ascending."""
        return [e for e in self._by_sequence if e.session_id == session_id]

    def all_entries(self) -> list[SnapshotEntry]:
        """Return all entries in sequence order (for hash chain verification)."""
        return list(self._by_sequence)

    def clear(self) -> None:
        """Clear all entries (for reset)."""
        self._by_key.clear()
        self._by_sequence.clear()

    def rebuild_from_ledger(self, ledger_entries: list[dict[str, Any]]) -> None:
        """Rebuild the index from a list of ledger entry dicts.

        Args:
            ledger_entries: Raw ledger entries from the file, in sequence order.
        """
        self.clear()
        for i, raw in enumerate(ledger_entries):
            entry = SnapshotEntry.from_ledger_entry(raw)
            # Ensure sequence matches position in list
            object.__setattr__(entry, "sequence", i)
            self.add(entry)

    @property
    def size(self) -> int:
        return len(self._by_sequence)


# ---------------------------------------------------------------------------
# Snapshot ledger — append-only JSON file with hash chain
# ---------------------------------------------------------------------------


class SnapshotLedger:
    """Append-only, hash-chained ledger stored as a JSON file.

    The ledger file is a JSON array of entries. Each entry includes:
      - The state blob (working_memory, tool_call_history, etc.)
      - A SHA-256 hash of the state
      - A chain_hash linking to the previous entry

    Integrity is verified by recomputing the hash chain from the first entry.
    Any broken link indicates tampering.
    """

    def __init__(self, ledger_path: Path | str) -> None:
        self._path = Path(ledger_path)
        self._index = SnapshotIndex()
        self._dirty = False

        # Load existing ledger on init
        if self._path.exists():
            self._load()

    @property
    def index(self) -> SnapshotIndex:
        return self._index

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> None:
        """Load all entries from the ledger file and rebuild the index."""
        try:
            raw = self._path.read_text(encoding="utf-8")
            if not raw.strip():
                entries: list[dict[str, Any]] = []
            else:
                entries = json.loads(raw)
                if not isinstance(entries, list):
                    entries = []
        except (json.JSONDecodeError, OSError):
            entries = []

        self._index.rebuild_from_ledger(entries)

    def _save(self) -> None:
        """Write all entries to the ledger file."""
        entries = [e.to_ledger_entry() for e in self._index.all_entries()]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self._dirty = False

    def append(
        self,
        session_id: str,
        checkpoint_id: str,
        working_memory: dict[str, Any],
        tool_call_history: list[dict[str, Any]] | None = None,
        conversation_summary: str = "",
        drift_score: int = 0,
        invariants_satisfied: list[str] | None = None,
        approval_token_id: str = "",
    ) -> SnapshotEntry:
        """Append a new snapshot entry to the ledger.

        Automatically computes the hash chain:
          - hash = SHA-256(working_memory + tool_call_history)
          - chain_hash = SHA-256(prev_chain_hash || hash)

        Args:
            session_id: Session identifier.
            checkpoint_id: Checkpoint identifier.
            working_memory: Serialized agent state (WorldState.to_dict()).
            tool_call_history: List of action dicts (AgentAction.to_dict()).
            conversation_summary: Optional text summary of the conversation.
            drift_score: Drift score at snapshot time (0 = clean).
            invariants_satisfied: List of invariant IDs that held at snapshot time.
            approval_token_id: Optional approval token.

        Returns:
            The newly created SnapshotEntry.

        Raises:
            SnapshotError: On write failure.
        """
        # Determine the previous chain hash
        all_entries = self._index.all_entries()
        prev_chain_hash = all_entries[-1].chain_hash if all_entries else ""

        # Compute state hash
        state_dict = {
            "working_memory": working_memory,
            "tool_call_history": tool_call_history or [],
            "conversation_summary": conversation_summary,
        }
        state_hash = SnapshotEntry._compute_hash(state_dict)
        chain_hash = SnapshotEntry._compute_chain_hash(prev_chain_hash, state_hash)

        # Build entry
        entry = SnapshotEntry(
            session_id=session_id,
            checkpoint_id=checkpoint_id,
            working_memory=working_memory,
            tool_call_history=tool_call_history or [],
            conversation_summary=conversation_summary,
            hash=state_hash,
            chain_hash=chain_hash,
            prev_chain_hash=prev_chain_hash,
            drift_score=drift_score,
            invariants_satisfied=invariants_satisfied or [],
            approval_token_id=approval_token_id,
            sequence=len(all_entries),
        )

        # Add to index
        self._index.add(entry)
        self._dirty = True

        # Persist immediately
        try:
            self._save()
        except OSError as e:
            raise SnapshotError(f"Failed to write snapshot ledger: {e}") from e

        return entry

    def verify_integrity(self) -> list[str]:
        """Verify the hash chain integrity of the entire ledger.

        Recomputes every hash and chain_hash from the first entry.

        Returns:
            List of integrity violations (empty = ledger is intact).
        """
        violations: list[str] = []
        entries = self._index.all_entries()

        prev_chain_hash = ""
        for i, entry in enumerate(entries):
            # Recompute state hash
            state_dict = {
                "working_memory": entry.working_memory,
                "tool_call_history": entry.tool_call_history,
                "conversation_summary": entry.conversation_summary,
            }
            expected_hash = SnapshotEntry._compute_hash(state_dict)
            if entry.hash != expected_hash:
                violations.append(
                    f"Entry {i} ({entry.session_id}/{entry.checkpoint_id}): "
                    f"state hash mismatch (expected {expected_hash}, got {entry.hash})"
                )
                continue  # Chain is broken, no point checking further

            # Recompute chain hash
            expected_chain = SnapshotEntry._compute_chain_hash(prev_chain_hash, entry.hash)
            if entry.chain_hash != expected_chain:
                violations.append(
                    f"Entry {i} ({entry.session_id}/{entry.checkpoint_id}): "
                    f"chain hash mismatch (expected {expected_chain}, got {entry.chain_hash})"
                )
                continue

            prev_chain_hash = entry.chain_hash

        return violations

    def verify_entry_integrity(self, sequence: int) -> list[str]:
        """Verify integrity of a single entry and its chain link.

        Args:
            sequence: Sequence number of the entry to verify.

        Returns:
            List of violations (empty = entry is intact).
        """
        violations: list[str] = []
        entries = self._index.all_entries()

        if sequence < 0 or sequence >= len(entries):
            violations.append(f"Sequence {sequence} out of range (0-{len(entries) - 1})")
            return violations

        entry = entries[sequence]

        # Recompute state hash
        state_dict = {
            "working_memory": entry.working_memory,
            "tool_call_history": entry.tool_call_history,
            "conversation_summary": entry.conversation_summary,
        }
        expected_hash = SnapshotEntry._compute_hash(state_dict)
        if entry.hash != expected_hash:
            violations.append(
                f"Entry {sequence}: state hash mismatch"
            )

        # Recompute chain hash
        prev_chain = entries[sequence - 1].chain_hash if sequence > 0 else ""
        expected_chain = SnapshotEntry._compute_chain_hash(prev_chain, entry.hash)
        if entry.chain_hash != expected_chain:
            violations.append(
                f"Entry {sequence}: chain hash mismatch"
            )

        return violations

    def reload(self) -> None:
        """Reload the ledger from disk (for external modification detection)."""
        self._load()


# ---------------------------------------------------------------------------
# take_snapshot — capture agent state
# ---------------------------------------------------------------------------


def take_snapshot(
    agent: AgentCore,
    session_id: str,
    checkpoint_id: str,
    ledger: SnapshotLedger,
    drift_score: int = 0,
    invariants_satisfied: list[str] | None = None,
    approval_token_id: str = "",
    conversation_summary: str = "",
) -> SnapshotEntry:
    """Capture the current agent state as a snapshot in the ledger.

    Extracts the agent's working memory (WorldState), tool call history,
    and optional conversation summary, then appends a new entry to the
    append-only ledger.

    Args:
        agent: The AgentCore to snapshot.
        session_id: Session identifier.
        checkpoint_id: Checkpoint identifier (should be unique per snapshot).
        ledger: The SnapshotLedger to append to.
        drift_score: Current drift score (0 = clean, >0 = drift detected).
        invariants_satisfied: List of invariant IDs that held at snapshot time.
        approval_token_id: Optional approval token.
        conversation_summary: Optional conversation text summary.

    Returns:
        The newly created SnapshotEntry.
    """
    # Serialize agent state (deep-copy to prevent mutation of stored data)
    working_memory = copy.deepcopy(agent.state.to_dict())

    # Serialize tool call history — each to_dict() creates a fresh dict
    tool_call_history: list[dict[str, Any]] = []
    for evidence in agent.evidence_log:
        tool_call_history.append(evidence.to_dict())

    return ledger.append(
        session_id=session_id,
        checkpoint_id=checkpoint_id,
        working_memory=working_memory,
        tool_call_history=tool_call_history,
        conversation_summary=conversation_summary,
        drift_score=drift_score,
        invariants_satisfied=invariants_satisfied,
        approval_token_id=approval_token_id,
    )


# ---------------------------------------------------------------------------
# context_revalidation — full recovery procedure
# ---------------------------------------------------------------------------


def context_revalidation(
    agent: AgentCore,
    session_id: str,
    ledger: SnapshotLedger,
    max_drift_score: int = 0,
) -> tuple[SnapshotEntry, list[str]]:
    """Perform the full context revalidation recovery procedure.

    Steps (from the design doc):
      1. Halt the session (the caller should ensure agent is halted).
      2. Find the last valid snapshot with drift_score <= max_drift_score.
      3. Retrieve and verify the snapshot (hash chain integrity).
      4. Restore agent state from the snapshot.
      5. Re-evaluate invariants (verify drift_score).
      6. Return the restored entry and any warnings.

    Args:
        agent: The AgentCore to restore state into.
        session_id: Session to recover.
        ledger: The SnapshotLedger containing snapshots.
        max_drift_score: Maximum acceptable drift score (default 0 = clean).

    Returns:
        (restored_entry, warnings):
            restored_entry: The SnapshotEntry that was used for recovery.
            warnings: List of warnings (empty = clean recovery).

    Raises:
        SnapshotNotFoundError: If no valid snapshot exists for this session.
        SnapshotIntegrityError: If the snapshot's hash chain is broken.
    """
    warnings: list[str] = []

    # Step 1: Ensure halted
    if not agent.halted:
        agent.halted = True
        warnings.append("Agent was not halted — forcing halt before revalidation")

    # Step 2: Find last valid snapshot
    entry = ledger.index.get_last_valid(session_id, max_drift_score)
    if entry is None:
        raise SnapshotNotFoundError(
            f"No valid snapshot found for session '{session_id}' "
            f"with drift_score <= {max_drift_score}"
        )

    # Step 3: Verify integrity
    violations = ledger.verify_entry_integrity(entry.sequence)
    if violations:
        raise SnapshotIntegrityError(
            f"Snapshot integrity check failed for "
            f"session '{session_id}' checkpoint '{entry.checkpoint_id}': "
            f"{'; '.join(violations)}"
        )

    # Step 4: Restore agent state
    #   - working_memory → WorldState (deep-copied to prevent mutation of
    #     the SnapshotEntry's stored dict, which would break the hash chain
    #     when step_action later appends to state lists)
    #   - tool_call_history → evidence_log + previous_actions
    restored_state = WorldState.from_dict(copy.deepcopy(entry.working_memory))
    agent.state = restored_state

    # Restore evidence log and previous actions from tool call history
    agent.evidence_log.clear()
    agent.previous_actions.clear()
    for tc in entry.tool_call_history:
        try:
            evidence = EvidenceEntry(
                step=tc.get("step", 0),
                action=AgentAction(
                    tool=tc.get("action", {}).get("tool", ""),
                    command=tc.get("action", {}).get("command", ""),
                    arguments=tc.get("action", {}).get("arguments", {}),
                    target=tc.get("action", {}).get("target", ""),
                    reasoning=tc.get("action", {}).get("reasoning", ""),
                ),
                output=tc.get("output", {}),
                timestamp=tc.get("timestamp", ""),
            )
            agent.evidence_log.append(evidence)
            agent.previous_actions.append(evidence.action)
        except (KeyError, TypeError):
            warnings.append(f"Skipped malformed tool call history entry at step {tc.get('step', '?')}")

    # Reset step counter based on evidence log length
    agent.step = len(agent.evidence_log)

    # Reset the halted flag (restored state is clean)
    agent.halted = False
    agent.stop_reason = None

    # Step 5: Re-evaluate drift
    from gatekeeper_eos_v6.agentic import check_agent_state_drift

    if agent._drift_check_enabled:
        drift_violations = check_agent_state_drift(agent.state, agent.evidence_log)
        if drift_violations:
            warnings.append(
                f"Drift detected after restoration ({len(drift_violations)} violations): "
                + "; ".join(drift_violations)
            )
            agent.halted = True
        elif entry.drift_score > 0:
            warnings.append(
                f"Snapshot had drift_score={entry.drift_score} but post-restoration "
                f"drift check passed — setting score to 0"
            )

    return entry, warnings


# ---------------------------------------------------------------------------
# Signed attestation integration
# ---------------------------------------------------------------------------


def get_attestation_ledger() -> AttestationLedger:
    """Get or create the module-level attestation ledger (lazy init)."""
    global _ATTESTATION_LEDGER
    if _ATTESTATION_LEDGER is None:
        private_key_path = Path("/etc/gatekeeper/attestation_key")
        ledger_path = Path("/var/log/gatekeeper/attestations.json")
        _ATTESTATION_LEDGER = AttestationLedger(ledger_path, private_key_path)
    return _ATTESTATION_LEDGER


def take_snapshot_with_attestation(
    ledger: SnapshotLedger,
    session_id: str,
    checkpoint_id: str,
    working_memory: dict[str, Any],
    tool_call_history: list[dict[str, Any]] | None = None,
    conversation_summary: str = "",
    drift_score: int = 0,
    invariants_satisfied: list[str] | None = None,
    approval_token_id: str = "",
) -> tuple[SnapshotEntry, Any]:
    """Take a snapshot and create a signed attestation for it.

    Args:
        ledger: SnapshotLedger instance.
        session_id: Session identifier.
        checkpoint_id: Checkpoint identifier.
        working_memory: Serialized agent state.
        tool_call_history: List of action dicts.
        conversation_summary: Optional text summary.
        drift_score: Drift score at snapshot time (0 = clean).
        invariants_satisfied: List of invariant IDs.
        approval_token_id: Optional approval token.

    Returns:
        Tuple of (SnapshotEntry, SignedAttestation).
    """
    # Create regular snapshot
    snapshot = ledger.append(
        session_id=session_id,
        checkpoint_id=checkpoint_id,
        working_memory=working_memory,
        tool_call_history=tool_call_history,
        conversation_summary=conversation_summary,
        drift_score=drift_score,
        invariants_satisfied=invariants_satisfied,
        approval_token_id=approval_token_id,
    )

    # Create signed attestation
    attestation_ledger = get_attestation_ledger()
    state = {
        "working_memory": working_memory,
        "tool_call_history": tool_call_history or [],
        "conversation_summary": conversation_summary,
        "drift_score": drift_score,
        "snapshot_sequence": snapshot.sequence,
    }
    metadata = {
        "checkpoint_id": checkpoint_id,
        "invariants_satisfied": invariants_satisfied or [],
        "approval_token_id": approval_token_id,
    }
    attestation = attestation_ledger.create_attestation(
        session_id=session_id,
        checkpoint_id=checkpoint_id,
        state=state,
        metadata=metadata,
    )

    return snapshot, attestation
