"""Tests for the snapshot subsystem.

Covers: SnapshotEntry hash chain, SnapshotIndex, SnapshotLedger,
take_snapshot, context_revalidation, and integrity breach detection.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from gatekeeper_eos_v6.snapshot import (
    SnapshotEntry,
    SnapshotIndex,
    SnapshotLedger,
    SnapshotError,
    SnapshotIntegrityError,
    SnapshotNotFoundError,
    take_snapshot,
    context_revalidation,
)
from gatekeeper_eos_v6.agentic import (
    WorldState,
    AgentCore,
    AgentAction,
    EvidenceEntry,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def sample_world_state() -> WorldState:
    return WorldState(
        open_ports=[22, 80, 443],
        services=[{"name": "nginx", "version": "1.24"}],
        vulnerabilities=[{"id": "CVE-2024-1234", "severity": "critical"}],
        discovered_assets=["10.0.0.10"],
        findings_summary=[{"title": "Open nginx", "severity": "medium"}],
    )


@pytest.fixture
def sample_agent(sample_world_state) -> AgentCore:
    agent = AgentCore(
        allowed_tools=[{"name": "nmap", "allowed_commands": ["scan"]}],
        authorized_assets=["10.0.0.10"],
        objective="Test",
        max_steps=10,
        _drift_check_enabled=False,
    )
    agent.state = sample_world_state
    agent.step = 3
    # Add some evidence
    for i in range(3):
        action = AgentAction(
            tool="nmap", command="scan",
            arguments={"port": 80 + i},
            target="10.0.0.10",
            reasoning=f"Step {i + 1}",
        )
        agent.evidence_log.append(EvidenceEntry(
            step=i + 1,
            action=action,
            output={"open_ports": [80 + i]},
        ))
        agent.previous_actions.append(action)
    return agent


@pytest.fixture
def empty_agent() -> AgentCore:
    return AgentCore(
        allowed_tools=[],
        authorized_assets=[],
        objective="Test",
        max_steps=10,
        _drift_check_enabled=False,
    )


@pytest.fixture
def ledger_path(tmp_path) -> Path:
    return tmp_path / "snapshots" / "ledger.json"


@pytest.fixture
def ledger(ledger_path) -> SnapshotLedger:
    return SnapshotLedger(ledger_path)


# ===========================================================================
# SnapshotEntry
# ===========================================================================


class TestSnapshotEntry:
    def test_compute_hash_deterministic(self):
        state = {"working_memory": {"open_ports": [80]}, "tool_call_history": [], "conversation_summary": ""}
        h1 = SnapshotEntry._compute_hash(state)
        h2 = SnapshotEntry._compute_hash(state)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_compute_hash_different_inputs(self):
        a = {"working_memory": {"open_ports": [80]}, "tool_call_history": [], "conversation_summary": ""}
        b = {"working_memory": {"open_ports": [443]}, "tool_call_history": [], "conversation_summary": ""}
        assert SnapshotEntry._compute_hash(a) != SnapshotEntry._compute_hash(b)

    def test_compute_chain_hash(self):
        prev = "abc"
        h = SnapshotEntry._compute_chain_hash(prev, "def")
        assert len(h) == 64
        assert h != prev

    def test_chain_hash_depends_on_prev(self):
        h1 = SnapshotEntry._compute_chain_hash("prev1", "state_hash")
        h2 = SnapshotEntry._compute_chain_hash("prev2", "state_hash")
        assert h1 != h2

    def test_to_ledger_entry_has_all_fields(self):
        entry = SnapshotEntry(
            session_id="SESS-test",
            checkpoint_id="CKPT-001",
            working_memory={"open_ports": [80]},
            hash="abc123",
            chain_hash="def456",
            drift_score=0,
        )
        d = entry.to_ledger_entry()
        assert d["entry_type"] == "memory_snapshot"
        assert d["session_id"] == "SESS-test"
        assert d["checkpoint_id"] == "CKPT-001"
        assert d["metadata"]["drift_score"] == 0
        assert d["hash"] == "abc123"
        assert d["chain_hash"] == "def456"

    def test_from_ledger_entry_round_trip(self):
        entry = SnapshotEntry(
            session_id="SESS-test",
            checkpoint_id="CKPT-001",
            working_memory={"open_ports": [22, 80]},
            tool_call_history=[{"step": 1, "action": {"tool": "nmap"}}],
            hash="abc",
            chain_hash="def",
            drift_score=0,
            invariants_satisfied=["INV-001"],
        )
        d = entry.to_ledger_entry()
        restored = SnapshotEntry.from_ledger_entry(d)
        assert restored.session_id == entry.session_id
        assert restored.checkpoint_id == entry.checkpoint_id
        assert restored.working_memory == entry.working_memory
        assert restored.tool_call_history == entry.tool_call_history
        assert restored.drift_score == entry.drift_score
        assert restored.invariants_satisfied == entry.invariants_satisfied
        assert restored.hash == entry.hash

    def test_default_drift_score_zero(self):
        entry = SnapshotEntry()
        assert entry.drift_score == 0

    def test_default_sequence_zero(self):
        entry = SnapshotEntry()
        assert entry.sequence == 0


# ===========================================================================
# SnapshotIndex
# ===========================================================================


class TestSnapshotIndex:
    def test_empty_index(self):
        idx = SnapshotIndex()
        assert idx.size == 0

    def test_add_and_get(self):
        idx = SnapshotIndex()
        entry = SnapshotEntry(session_id="SESS-recon", checkpoint_id="CKPT-001")
        idx.add(entry)
        retrieved = idx.get("SESS-recon", "CKPT-001")
        assert retrieved is entry

    def test_get_nonexistent(self):
        idx = SnapshotIndex()
        assert idx.get("SESS-x", "CKPT-x") is None

    def test_get_last_valid_empty(self):
        idx = SnapshotIndex()
        assert idx.get_last_valid("SESS-test") is None

    def test_get_last_valid_returns_most_recent(self):
        idx = SnapshotIndex()
        e1 = SnapshotEntry(session_id="SESS-test", checkpoint_id="CKPT-001", drift_score=0, sequence=0)
        e2 = SnapshotEntry(session_id="SESS-test", checkpoint_id="CKPT-002", drift_score=0, sequence=1)
        e3 = SnapshotEntry(session_id="SESS-test", checkpoint_id="CKPT-003", drift_score=1, sequence=2)
        idx.add(e1)
        idx.add(e2)
        idx.add(e3)

        # Last valid with drift_score=0 should be e2 (sequence 1)
        result = idx.get_last_valid("SESS-test", max_drift_score=0)
        assert result is not None
        # Since we need to match sequence order, entry with sequence 1 is the last with drift_score=0
        # Actually e2 has sequence 1 and drift_score=0. Let me check: entries are added in order.
        # e1 (seq 0, drift 0), e2 (seq 1, drift 0), e3 (seq 2, drift 1)
        # get_last_valid iterates in reverse: e3 first (drift 1, skip), e2 (drift 0, match)
        assert result.checkpoint_id == "CKPT-002"

    def test_get_last_valid_filters_by_session(self):
        idx = SnapshotIndex()
        idx.add(SnapshotEntry(session_id="SESS-a", checkpoint_id="CKPT-001", drift_score=0, sequence=0))
        idx.add(SnapshotEntry(session_id="SESS-b", checkpoint_id="CKPT-001", drift_score=0, sequence=1))
        result = idx.get_last_valid("SESS-a")
        assert result is not None
        assert result.session_id == "SESS-a"

    def test_get_by_session(self):
        idx = SnapshotIndex()
        idx.add(SnapshotEntry(session_id="SESS-a", checkpoint_id="CKPT-001", sequence=0))
        idx.add(SnapshotEntry(session_id="SESS-b", checkpoint_id="CKPT-001", sequence=1))
        results = idx.get_by_session("SESS-a")
        assert len(results) == 1
        assert results[0].session_id == "SESS-a"

    def test_rebuild_from_ledger(self):
        ledger_data = [
            {
                "entry_type": "memory_snapshot",
                "session_id": "SESS-a",
                "checkpoint_id": "CKPT-001",
                "hash": "h1",
                "chain_hash": "c1",
                "prev_chain_hash": "",
                "metadata": {"drift_score": 0},
                "sequence": 0,
            },
            {
                "entry_type": "memory_snapshot",
                "session_id": "SESS-a",
                "checkpoint_id": "CKPT-002",
                "hash": "h2",
                "chain_hash": "c2",
                "prev_chain_hash": "c1",
                "metadata": {"drift_score": 0},
                "sequence": 1,
            },
        ]
        idx = SnapshotIndex()
        idx.rebuild_from_ledger(ledger_data)
        assert idx.size == 2
        assert idx.get("SESS-a", "CKPT-002") is not None

    def test_clear(self):
        idx = SnapshotIndex()
        idx.add(SnapshotEntry(session_id="SESS-a", checkpoint_id="CKPT-001"))
        assert idx.size == 1
        idx.clear()
        assert idx.size == 0


# ===========================================================================
# SnapshotLedger
# ===========================================================================


class TestSnapshotLedger:
    def test_new_ledger_empty(self, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        assert ledger.index.size == 0
        # File is created lazily on first append, not in constructor

    def test_append_creates_entry(self, ledger):
        entry = ledger.append(
            session_id="SESS-recon",
            checkpoint_id="CKPT-001",
            working_memory={"open_ports": [80]},
        )
        assert entry.session_id == "SESS-recon"
        assert entry.checkpoint_id == "CKPT-001"
        assert entry.sequence == 0
        assert entry.chain_hash != ""
        assert entry.prev_chain_hash == ""
        assert ledger.index.size == 1

    def test_append_multiple_entries(self, ledger):
        e1 = ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        e2 = ledger.append("SESS-a", "CKPT-002", {"ports": [443]})
        e3 = ledger.append("SESS-a", "CKPT-003", {"ports": [22]})
        assert e1.sequence == 0
        assert e2.sequence == 1
        assert e3.sequence == 2
        assert e1.prev_chain_hash == ""
        assert e2.prev_chain_hash == e1.chain_hash
        assert e3.prev_chain_hash == e2.chain_hash
        assert ledger.index.size == 3

    def test_append_persists_to_disk(self, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        # Re-read from disk
        raw = ledger_path.read_text()
        data = json.loads(raw)
        assert len(data) == 1
        assert data[0]["session_id"] == "SESS-a"

    def test_reload_restores_index(self, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        ledger.append("SESS-a", "CKPT-002", {"ports": [443]})

        # Create a new ledger instance pointing to the same file
        ledger2 = SnapshotLedger(ledger_path)
        assert ledger2.index.size == 2
        assert ledger2.index.get("SESS-a", "CKPT-001") is not None
        assert ledger2.index.get("SESS-a", "CKPT-002") is not None

    def test_verify_integrity_clean(self, ledger):
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        ledger.append("SESS-a", "CKPT-002", {"ports": [443]})
        ledger.append("SESS-a", "CKPT-003", {"ports": [22]})
        violations = ledger.verify_integrity()
        assert violations == []

    def test_verify_integrity_with_tampered_state(self, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        ledger.append("SESS-a", "CKPT-002", {"ports": [443]})

        # Tamper with the file on disk
        raw = json.loads(ledger_path.read_text())
        raw[1]["working_memory"]["ports"] = [9999]  # Change state
        ledger_path.write_text(json.dumps(raw, indent=2))

        # Re-read and verify
        ledger.reload()
        violations = ledger.verify_integrity()
        assert len(violations) >= 1
        assert any("hash mismatch" in v for v in violations)

    def test_verify_integrity_with_tampered_chain_hash(self, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        ledger.append("SESS-a", "CKPT-002", {"ports": [443]})

        # Tamper with chain hash
        raw = json.loads(ledger_path.read_text())
        raw[1]["chain_hash"] = "tampered"
        ledger_path.write_text(json.dumps(raw, indent=2))

        ledger.reload()
        violations = ledger.verify_integrity()
        assert len(violations) >= 1

    def test_verify_entry_integrity_clean(self, ledger):
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        ledger.append("SESS-a", "CKPT-002", {"ports": [443]})
        violations = ledger.verify_entry_integrity(1)
        assert violations == []

    def test_verify_entry_integrity_tampered(self, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        ledger.append("SESS-a", "CKPT-002", {"ports": [443]})

        # Tamper
        raw = json.loads(ledger_path.read_text())
        raw[1]["working_memory"]["ports"] = [6666]
        ledger_path.write_text(json.dumps(raw, indent=2))

        ledger.reload()
        violations = ledger.verify_entry_integrity(1)
        assert len(violations) >= 1

    def test_verify_entry_out_of_range(self, ledger):
        ledger.append("SESS-a", "CKPT-001", {"ports": [80]})
        violations = ledger.verify_entry_integrity(5)
        assert len(violations) >= 1
        assert any("out of range" in v for v in violations)

    def test_append_saves_metadata(self, ledger):
        entry = ledger.append(
            session_id="SESS-recon",
            checkpoint_id="CKPT-001",
            working_memory={"ports": [80]},
            drift_score=0,
            invariants_satisfied=["INV-001", "INV-002"],
            approval_token_id="tok-abc",
        )
        assert entry.drift_score == 0
        assert entry.invariants_satisfied == ["INV-001", "INV-002"]
        assert entry.approval_token_id == "tok-abc"

    def test_reload_handles_empty_file(self, tmp_path):
        p = tmp_path / "empty_ledger.json"
        p.write_text("")
        ledger = SnapshotLedger(p)
        assert ledger.index.size == 0

    def test_reload_handles_missing_file(self, tmp_path):
        p = tmp_path / "missing.json"
        ledger = SnapshotLedger(p)
        assert ledger.index.size == 0


# ===========================================================================
# take_snapshot
# ===========================================================================


class TestTakeSnapshot:
    def test_take_snapshot_basic(self, sample_agent, ledger):
        entry = take_snapshot(
            agent=sample_agent,
            session_id="SESS-recon",
            checkpoint_id="CKPT-001",
            ledger=ledger,
            drift_score=0,
        )
        assert entry.session_id == "SESS-recon"
        assert entry.checkpoint_id == "CKPT-001"
        assert entry.working_memory["open_ports"] == [22, 80, 443]
        assert entry.hash != ""
        assert entry.chain_hash != ""
        assert len(entry.tool_call_history) == 3  # 3 evidence entries

    def test_take_snapshot_persists(self, sample_agent, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        raw = json.loads(ledger_path.read_text())
        assert len(raw) == 1
        assert raw[0]["working_memory"]["open_ports"] == [22, 80, 443]

    def test_take_snapshot_with_conversation(self, sample_agent, ledger):
        entry = take_snapshot(
            agent=sample_agent,
            session_id="SESS-recon",
            checkpoint_id="CKPT-001",
            ledger=ledger,
            conversation_summary="Initial recon complete. Found 3 open ports.",
        )
        assert "Found 3 open ports" in entry.conversation_summary

    def test_take_snapshot_with_invariants(self, sample_agent, ledger):
        entry = take_snapshot(
            agent=sample_agent,
            session_id="SESS-recon",
            checkpoint_id="CKPT-001",
            ledger=ledger,
            drift_score=0,
            invariants_satisfied=["INV-001", "INV-003"],
            approval_token_id="tok-xyz",
        )
        assert entry.invariants_satisfied == ["INV-001", "INV-003"]
        assert entry.approval_token_id == "tok-xyz"

    def test_take_snapshot_empty_agent(self, empty_agent, ledger):
        entry = take_snapshot(
            agent=empty_agent,
            session_id="SESS-empty",
            checkpoint_id="CKPT-001",
            ledger=ledger,
        )
        assert entry.working_memory["open_ports"] == []
        assert entry.tool_call_history == []

    def test_take_snapshot_multiple(self, sample_agent, ledger):
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-002", ledger=ledger)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-003", ledger=ledger)

        assert ledger.index.size == 3
        assert ledger.index.get("SESS-recon", "CKPT-003") is not None

    def test_hash_chain_across_snapshots(self, sample_agent, ledger):
        e1 = take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)
        e2 = take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-002", ledger=ledger)
        e3 = take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-003", ledger=ledger)

        assert e1.prev_chain_hash == ""
        assert e2.prev_chain_hash == e1.chain_hash
        assert e3.prev_chain_hash == e2.chain_hash

        violations = ledger.verify_integrity()
        assert violations == []


# ===========================================================================
# context_revalidation
# ===========================================================================


class TestContextRevalidation:
    def test_revalidation_restores_state(self, sample_agent, ledger):
        """Take a snapshot, modify agent, then restore."""
        original_ports = list(sample_agent.state.open_ports)

        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        # Modify agent state (simulate drift)
        sample_agent.state.open_ports.append(9999)
        sample_agent.halted = True
        assert 9999 in sample_agent.state.open_ports

        # Restore
        restored_entry, warnings = context_revalidation(
            agent=sample_agent,
            session_id="SESS-recon",
            ledger=ledger,
        )
        assert restored_entry.checkpoint_id == "CKPT-001"
        assert sample_agent.state.open_ports == original_ports
        assert not sample_agent.halted

    def test_revalidation_restores_tool_call_history(self, sample_agent, ledger):
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        # Clear agent's history
        sample_agent.evidence_log.clear()
        sample_agent.previous_actions.clear()
        sample_agent.halted = True

        restored_entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger,
        )
        assert len(sample_agent.evidence_log) == 3  # Restored from snapshot
        assert len(sample_agent.previous_actions) == 3
        assert sample_agent.step == 3

    def test_revalidation_no_valid_snapshot_raises(self, empty_agent, ledger):
        with pytest.raises(SnapshotNotFoundError, match="No valid snapshot"):
            context_revalidation(
                agent=empty_agent,
                session_id="SESS-nonexistent",
                ledger=ledger,
            )

    def test_revalidation_with_drifted_snapshot(self, sample_agent, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger, drift_score=0)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-002", ledger=ledger, drift_score=1)

        # Should find CKPT-001 (drift_score=0)
        sample_agent.halted = True
        restored_entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger, max_drift_score=0,
        )
        assert restored_entry.checkpoint_id == "CKPT-001"

    def test_revalidation_with_only_drifted_snapshot(self, sample_agent, ledger):
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger, drift_score=2)

        sample_agent.halted = True
        with pytest.raises(SnapshotNotFoundError):
            context_revalidation(
                agent=sample_agent, session_id="SESS-recon", ledger=ledger,
                max_drift_score=0,
            )

    def test_revalidation_tampered_snapshot_raises(self, sample_agent, ledger_path):
        ledger = SnapshotLedger(ledger_path)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        # Tamper with state
        raw = json.loads(ledger_path.read_text())
        raw[0]["working_memory"]["open_ports"] = [6666]
        ledger_path.write_text(json.dumps(raw, indent=2))
        ledger.reload()

        sample_agent.halted = True
        with pytest.raises(SnapshotIntegrityError, match="integrity"):
            context_revalidation(
                agent=sample_agent, session_id="SESS-recon", ledger=ledger,
            )

    def test_revalidation_forces_halt_if_not_halted(self, sample_agent, ledger):
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        # Agent is NOT halted
        sample_agent.halted = False
        restored_entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger,
        )
        assert len(warnings) >= 1
        assert any("forcing halt" in w.lower() for w in warnings)

    def test_revalidation_preserves_restored_state(self, sample_agent, ledger):
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        sample_agent.halted = True
        restored_entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger,
        )
        assert not sample_agent.halted
        assert sample_agent.stop_reason is None

        # Agent can now resume — should return a valid action
        next_action = sample_agent.get_next_action()
        assert next_action is not None
        assert isinstance(next_action.tool, str) and len(next_action.tool) > 0


# ===========================================================================
# Integration: multiple sessions
# ===========================================================================


class TestSnapshotIntegration:
    def test_multiple_sessions_independent_recovery(self, sample_agent, empty_agent, ledger):
        """Multiple sessions can each have their own snapshots and recover independently."""
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)
        take_snapshot(agent=empty_agent, session_id="SESS-vuln", checkpoint_id="CKPT-001", ledger=ledger)

        # Recover SESS-recon
        sample_agent.halted = True
        e1, w1 = context_revalidation(agent=sample_agent, session_id="SESS-recon", ledger=ledger)
        assert e1.session_id == "SESS-recon"
        assert sample_agent.state.open_ports == [22, 80, 443]

        # Recover SESS-vuln
        empty_agent.halted = True
        e2, w2 = context_revalidation(agent=empty_agent, session_id="SESS-vuln", ledger=ledger)
        assert e2.session_id == "SESS-vuln"
        assert empty_agent.state.open_ports == []

    def test_ledger_append_only_no_deletion(self, sample_agent, ledger):
        """Snapshots should accumulate; no deletion occurs."""
        for i in range(10):
            take_snapshot(
                agent=sample_agent,
                session_id="SESS-recon",
                checkpoint_id=f"CKPT-{i:03d}",
                ledger=ledger,
            )
        assert ledger.index.size == 10
        violations = ledger.verify_integrity()
        assert violations == []

    def test_recovery_from_oldest_snapshot(self, sample_agent, ledger):
        """If recent snapshots have drift, fall back to older clean ones."""
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger, drift_score=0)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-002", ledger=ledger, drift_score=1)
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-003", ledger=ledger, drift_score=2)

        sample_agent.halted = True
        entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger, max_drift_score=0,
        )
        assert entry.checkpoint_id == "CKPT-001"

    def test_recovery_skips_other_sessions(self, sample_agent, empty_agent, ledger):
        """Cross-session snapshots should not interfere."""
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)
        take_snapshot(agent=empty_agent, session_id="SESS-other", checkpoint_id="CKPT-001", ledger=ledger)

        sample_agent.halted = True
        entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger,
        )
        assert entry.session_id == "SESS-recon"

    def test_integrity_check_on_reload(self, sample_agent, ledger_path):
        """After reload, integrity should be verifiable."""
        ledger = SnapshotLedger(ledger_path)
        for i in range(5):
            take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id=f"CKPT-{i:03d}", ledger=ledger)

        # Reload
        ledger.reload()
        violations = ledger.verify_integrity()
        assert violations == []

    def test_restore_cleans_hallucinated_state(self, sample_agent, ledger):
        """After restoration, the previously hallucinated state is replaced with clean snapshot data."""
        take_snapshot(agent=sample_agent, session_id="SESS-recon", checkpoint_id="CKPT-001", ledger=ledger)

        # Simulate drift: add a hallucinated port to the state
        sample_agent.state.open_ports.append(9999)
        sample_agent.halted = True

        # Restore — the state BEFORE the hallucination is in the snapshot
        entry, warnings = context_revalidation(
            agent=sample_agent, session_id="SESS-recon", ledger=ledger,
        )
        # The restoration overwrites state with the clean snapshot
        assert sample_agent.state.open_ports == [22, 80, 443]
        assert 9999 not in sample_agent.state.open_ports
        assert not sample_agent.halted
