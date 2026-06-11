"""audit_log.py — Append-only audit log for Gatekeeper decisions.

Each decision is recorded as a JSONL entry with:
- timestamp: ISO 8601
- tool, target, status, reason
- entry_hash: SHA-256 of this entry
- prev_hash: SHA-256 of previous entry (chain for integrity)
"""
import hashlib
import json
import os
from datetime import datetime, timezone


class AuditLog:
    """Append-only audit log with hash-chain integrity."""

    def __init__(self, log_path: str = "gatekeeper_audit.log"):
        self._path = log_path
        self._prev_hash = self._read_last_hash() if os.path.exists(log_path) else None

    def _read_last_hash(self) -> str | None:
        """Read the hash of the last entry (for chaining)."""
        try:
            with open(self._path, "r") as f:
                lines = f.readlines()
            if lines:
                last = json.loads(lines[-1].strip())
                return last.get("entry_hash")
        except (FileNotFoundError, json.JSONDecodeError, IndexError):
            pass
        return None

    def append(self, tool: str | None, target: str, status: str, reason: str) -> dict:
        """Record a Gatekeeper decision to the audit log.

        Returns the entry dict (already written to disk).
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "target": target,
            "status": status,
            "reason": reason,
            "prev_hash": self._prev_hash,
        }

        # Compute hash of this entry (chain integrity)
        raw = json.dumps(entry, sort_keys=True, default=str)
        entry["entry_hash"] = hashlib.sha256(raw.encode()).hexdigest()

        # Append to log file
        with open(self._path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        self._prev_hash = entry["entry_hash"]
        return entry

    def verify(self) -> list[str]:
        """Verify the hash chain integrity. Returns list of errors, empty if intact."""
        errors = []
        prev = None
        try:
            with open(self._path, "r") as f:
                for i, line in enumerate(f, start=1):
                    try:
                        entry = json.loads(line.strip())
                    except json.JSONDecodeError as e:
                        errors.append(f"Line {i}: invalid JSON — {e}")
                        continue

                    # Verify prev_hash chain
                    if entry.get("prev_hash") != prev:
                        errors.append(
                            f"Line {i}: hash chain broken — expected prev_hash={prev}, "
                            f"got {entry.get('prev_hash')}"
                        )

                    # Recompute entry_hash
                    entry_no_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
                    raw = json.dumps(entry_no_hash, sort_keys=True, default=str)
                    expected_hash = hashlib.sha256(raw.encode()).hexdigest()
                    if entry.get("entry_hash") != expected_hash:
                        errors.append(
                            f"Line {i}: entry_hash mismatch — expected {expected_hash}, "
                            f"got {entry.get('entry_hash')}"
                        )

                    prev = entry.get("entry_hash")
        except FileNotFoundError:
            errors.append("Log file not found")
        except Exception as e:
            errors.append(f"Verification error: {e}")

        return errors
