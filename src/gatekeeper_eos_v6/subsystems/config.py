"""Configurable paths and settings for subsystems.

All paths can be overridden via environment variables.
Defaults to /tmp/gatekeeper/ for development.

An optional YAML config file (configs/subsystems.yaml) can provide
additional thresholds and settings beyond plain path overrides.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml


# Default paths (can be overridden via environment variables)
DEFAULT_ATTESTATION_LEDGER_PATH = Path("/tmp/gatekeeper/attestations.json")
DEFAULT_PRIVATE_KEY_PATH = Path("/tmp/gatekeeper/private_key")
DEFAULT_REPUTATION_LEDGER_PATH = Path("/tmp/gatekeeper/reputation.json")
DEFAULT_TRUST_LEDGER_PATH = Path("/tmp/gatekeeper/provider_trust.json")

# Default config values (used when YAML file is absent or partial)
DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "reputation": {
        "min_score": 0.6,
        "decay_days": 30,
        "decay_rate": 0.05,
        "prior": 0.5,
    },
    "provider_trust": {
        "min_score": 0.7,
        "min_severity": 0.1,
        "max_drift_events": 100,
    },
    "attestations": {
        "enabled": True,
        "algorithm": "sha256",
        "private_key_path": "/tmp/gatekeeper/private_key",
    },
    "ledger_paths": {
        "attestations": "/tmp/gatekeeper/attestations.json",
        "reputation": "/tmp/gatekeeper/reputation.json",
        "trust": "/tmp/gatekeeper/provider_trust.json",
    },
}


# ---------------------------------------------------------------------------
# Path-resolution helpers (env-var aware)
# ---------------------------------------------------------------------------


def get_attestation_ledger_path() -> Path:
    """Get attestation ledger path from ATTESTATION_LEDGER_PATH env or default."""
    path_str = os.getenv("ATTESTATION_LEDGER_PATH")
    if path_str:
        return Path(path_str)
    return DEFAULT_ATTESTATION_LEDGER_PATH


def get_private_key_path() -> Path:
    """Get private key path from ATTESTATION_PRIVATE_KEY_PATH env or default."""
    path_str = os.getenv("ATTESTATION_PRIVATE_KEY_PATH")
    if path_str:
        return Path(path_str)
    return DEFAULT_PRIVATE_KEY_PATH


def get_reputation_ledger_path() -> Path:
    """Get reputation ledger path from REPUTATION_LEDGER_PATH env or default."""
    path_str = os.getenv("REPUTATION_LEDGER_PATH")
    if path_str:
        return Path(path_str)
    return DEFAULT_REPUTATION_LEDGER_PATH


def get_trust_ledger_path() -> Path:
    """Get trust ledger path from TRUST_LEDGER_PATH env or default."""
    path_str = os.getenv("TRUST_LEDGER_PATH")
    if path_str:
        return Path(path_str)
    return DEFAULT_TRUST_LEDGER_PATH


def ensure_ledger_dirs() -> None:
    """Ensure all ledger directories exist."""
    for path in [
        get_attestation_ledger_path().parent,
        get_private_key_path().parent,
        get_reputation_ledger_path().parent,
        get_trust_ledger_path().parent,
    ]:
        path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# YAML config loading
# ---------------------------------------------------------------------------

_SUBSYSTEMS_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "configs" / "subsystems.yaml"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base* dict (mutates base)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_subsystems_config(
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Load subsystem configuration from YAML, merging with defaults.

    Resolution order (later wins):
      1. Hardcoded defaults (DEFAULT_CONFIG)
      2. YAML file (if found)
      3. Env-var overrides for ledger paths

    Args:
        config_path: Path to YAML config file. Defaults to
            ``configs/subsystems.yaml`` relative to the project root.
            If the file does not exist, returns defaults only.

    Returns:
        A validated config dict with all fields populated.
    """
    cfg: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)

    # Load YAML if available
    path = Path(config_path) if config_path else _SUBSYSTEMS_CONFIG_PATH
    if path.exists():
        raw = path.read_text(encoding="utf-8")
        try:
            yaml_data = yaml.safe_load(raw)
            if isinstance(yaml_data, dict):
                _deep_merge(cfg, yaml_data)
        except yaml.YAMLError:
            pass  # Malformed YAML — fall back to defaults

    # Apply env-var overrides for ledger paths
    env_overrides = {
        "ledger_paths": {
            "attestations": os.getenv("ATTESTATION_LEDGER_PATH"),
            "reputation": os.getenv("REPUTATION_LEDGER_PATH"),
            "trust": os.getenv("TRUST_LEDGER_PATH"),
        },
        "attestations": {
            "private_key_path": os.getenv("ATTESTATION_PRIVATE_KEY_PATH"),
        },
    }
    for section, keys in env_overrides.items():
        for key, value in keys.items():
            if value is not None:
                cfg.setdefault(section, {})[key] = value

    return cfg


def apply_subsystems_config(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load and apply subsystems config, returning the resolved settings.

    This is the main entry point for consumers. It loads the config,
    ensures ledger directories exist, and returns the resolved dict.

    Args:
        cfg: Optional pre-loaded config dict. If None, loads from file.

    Returns:
        Resolved configuration dict.
    """
    config = cfg if cfg is not None else load_subsystems_config()
    if config.get("enabled", True):
        ensure_ledger_dirs()
    return config
