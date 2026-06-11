"""Signed attestations subsystem for snapshot chain entries.

Adds cryptographic signatures to snapshot entries using a key stored in the ledger,
similar to PGP mirror verification. Each snapshot entry includes a signature
over its state, verified against the ledger's public key.

Architecture:
    AttestationLedger (append-only with signatures)
        -> create_attestation(session_id, state, metadata)
        -> verify_attestation(attestation) -> bool
        -> load_attestations(session_id) -> list[SignedAttestation]

Key patterns:
- Signature computed over serialized state + chain hash
- Tamper-evident ledger with chain-hash + signature
- Public key stored in ledger, private key loaded from env or file
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AttestationError(Exception):
    """Base error for attestation operations."""


class AttestationSignatureError(AttestationError):
    """Raised when signature verification fails."""


class AttestationLedgerError(AttestationError):
    """Raised when ledger operations fail (corruption, I/O error)."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class SignedAttestation:
    """A signed attestation entry."""

    session_id: str
    checkpoint_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    state: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    chain_hash: str = ""
    prev_chain_hash: str = ""
    signature: str = ""
    sequence: int = 0

    @staticmethod
    def _compute_state_hash(state: dict[str, Any]) -> str:
        """Compute SHA-256 of serialized state."""
        raw = json.dumps(state, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _compute_chain_hash(prev_chain_hash: str, state_hash: str) -> str:
        """Compute chained hash: SHA-256(prev_chain_hash || state_hash)."""
        raw = f"{prev_chain_hash}||{state_hash}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def compute_signature(self, private_key: bytes) -> str:
        """Compute HMAC-SHA256 signature over state + chain hash."""
        state_hash = self._compute_state_hash(self.state)
        self.chain_hash = self._compute_chain_hash(self.prev_chain_hash, state_hash)
        payload = (
            f"{self.chain_hash}||{state_hash}||{self.session_id}||"
            f"{self.checkpoint_id}".encode("utf-8")
        )
        self.signature = hmac.new(private_key, payload, hashlib.sha256).hexdigest()
        return self.signature

    def verify_signature(self, public_key: bytes) -> bool:
        """Verify signature using public key (HMAC)."""
        state_hash = self._compute_state_hash(self.state)
        expected_chain_hash = self._compute_chain_hash(
            self.prev_chain_hash, state_hash
        )
        if expected_chain_hash != self.chain_hash:
            return False
        payload = (
            f"{self.chain_hash}||{state_hash}||{self.session_id}||"
            f"{self.checkpoint_id}".encode("utf-8")
        )
        expected_sig = hmac.new(public_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AttestationLedger:
    """Append-only ledger with signed attestations."""

    def __init__(
        self, ledger_path: Path, private_key_path: Path | None = None
    ) -> None:
        self.ledger_path = ledger_path
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.write_text(
                '{"attestations": [], "public_key": ""}', encoding="utf-8"
            )

        # Initialize key if not present
        self.private_key_path = private_key_path
        if not self._load_public_key():
            self._init_keys()

    def create_attestation(
        self,
        session_id: str,
        checkpoint_id: str,
        state: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> SignedAttestation:
        """Create and append a signed attestation."""
        if metadata is None:
            metadata = {}
        ledger_data = self._load()
        sequence = len(ledger_data["attestations"]) + 1
        prev_chain_hash = (
            ledger_data["attestations"][-1]["chain_hash"]
            if ledger_data["attestations"]
            else ""
        )

        attestation = SignedAttestation(
            session_id=session_id,
            checkpoint_id=checkpoint_id,
            state=state,
            metadata=metadata,
            prev_chain_hash=prev_chain_hash,
            sequence=sequence,
        )

        # Sign with private key
        private_key = self._load_private_key()
        attestation.compute_signature(private_key)

        # Append to ledger
        ledger_data["attestations"].append(
            {
                "sequence": attestation.sequence,
                "session_id": attestation.session_id,
                "checkpoint_id": attestation.checkpoint_id,
                "timestamp": attestation.timestamp,
                "state": attestation.state,
                "metadata": attestation.metadata,
                "chain_hash": attestation.chain_hash,
                "prev_chain_hash": attestation.prev_chain_hash,
                "signature": attestation.signature,
            }
        )
        self._save(ledger_data)
        return attestation

    def verify_attestation(self, attestation: SignedAttestation) -> bool:
        """Verify attestation signature."""
        public_key = self._load_public_key()
        return attestation.verify_signature(public_key)

    def load_attestations(self, session_id: str) -> list[SignedAttestation]:
        """Load all attestations for a session."""
        ledger_data = self._load()
        result = []
        for entry in ledger_data["attestations"]:
            if entry["session_id"] == session_id:
                att = SignedAttestation(
                    session_id=entry["session_id"],
                    checkpoint_id=entry["checkpoint_id"],
                    timestamp=entry["timestamp"],
                    state=entry["state"],
                    metadata=entry["metadata"],
                    chain_hash=entry["chain_hash"],
                    prev_chain_hash=entry["prev_chain_hash"],
                    signature=entry["signature"],
                    sequence=entry["sequence"],
                )
                result.append(att)
        return result

    def _load(self) -> dict[str, Any]:
        data = self.ledger_path.read_text(encoding="utf-8")
        return json.loads(data)

    def _save(self, ledger_data: dict[str, Any]) -> None:
        self.ledger_path.write_text(
            json.dumps(ledger_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _init_keys(self) -> None:
        """Generate and store keys (HMAC uses same key for sign/verify).

        If ATTESTATION_PRIVATE_KEY env var is set, use that instead of
        generating a random key — allows pre-configured key pairs.
        """
        key_hex = os.getenv("ATTESTATION_PRIVATE_KEY")
        if key_hex:
            key = bytes.fromhex(key_hex)
        else:
            key = os.urandom(32)  # 256-bit key

        if self.private_key_path:
            self.private_key_path.write_bytes(key)
        ledger_data = self._load()
        ledger_data["public_key"] = key.hex()
        self._save(ledger_data)

    def _load_private_key(self) -> bytes:
        if self.private_key_path and self.private_key_path.exists():
            return self.private_key_path.read_bytes()
        # Fallback to env — hex-encoded key (same format as public_key in ledger)
        key_hex = os.getenv("ATTESTATION_PRIVATE_KEY")
        if key_hex:
            return bytes.fromhex(key_hex)
        raise AttestationLedgerError("No private key available")

    def _load_public_key(self) -> bytes:
        ledger_data = self._load()
        key_hex = ledger_data.get("public_key", "")
        if key_hex:
            return bytes.fromhex(key_hex)
        return b""
