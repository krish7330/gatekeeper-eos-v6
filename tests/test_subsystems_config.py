"""Tests for subsystems YAML config loading.

Covers:
- Default config values when no YAML file exists
- YAML file overrides deep-merged correctly
- Env-var overrides take precedence
- apply_subsystems_config ensures ledger dirs
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from gatekeeper_eos_v6.subsystems.config import (
    load_subsystems_config,
    apply_subsystems_config,
    DEFAULT_CONFIG,
    ensure_ledger_dirs,
)


# ===========================================================================
# Defaults
# ===========================================================================


class TestDefaults:
    """Default config when no YAML file is available."""

    def test_all_keys_present(self, monkeypatch):
        """Every expected top-level key is present in defaults."""
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        assert set(cfg.keys()) == {"enabled", "reputation", "provider_trust",
                                    "attestations", "ledger_paths"}
        assert cfg["enabled"] is True

    def test_reputation_defaults(self):
        """Reputation defaults are sensible."""
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        rep = cfg["reputation"]
        assert rep["min_score"] == 0.6
        assert rep["decay_days"] == 30
        assert rep["decay_rate"] == 0.05
        assert rep["prior"] == 0.5

    def test_provider_trust_defaults(self):
        """Provider trust defaults are sensible."""
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        pt = cfg["provider_trust"]
        assert pt["min_score"] == 0.7
        assert pt["min_severity"] == 0.1
        assert pt["max_drift_events"] == 100

    def test_attestation_defaults(self):
        """Attestation defaults use sha256 algorithm."""
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        att = cfg["attestations"]
        assert att["enabled"] is True
        assert att["algorithm"] == "sha256"
        assert att["private_key_path"] == "/tmp/gatekeeper/private_key"

    def test_ledger_path_defaults(self):
        """Ledger paths default to /tmp/gatekeeper/."""
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        lp = cfg["ledger_paths"]
        assert "attestations" in lp
        assert "reputation" in lp
        assert "trust" in lp
        assert all("/tmp/gatekeeper/" in v for v in lp.values())


# ===========================================================================
# YAML file loading
# ===========================================================================


class TestYamlLoading:
    """Loading from a YAML file merges correctly with defaults."""

    def test_load_valid_yaml(self, tmp_path: Path):
        """Valid YAML file overrides specific fields."""
        yaml_path = tmp_path / "subsystems.yaml"
        yaml_path.write_text(yaml.dump({
            "reputation": {"min_score": 0.8},
            "provider_trust": {"min_score": 0.9},
        }))
        cfg = load_subsystems_config(config_path=yaml_path)
        assert cfg["reputation"]["min_score"] == 0.8       # from YAML
        assert cfg["reputation"]["decay_days"] == 30        # from default
        assert cfg["provider_trust"]["min_score"] == 0.9    # from YAML
        assert cfg["provider_trust"]["max_drift_events"] == 100  # from default

    def test_load_nonexistent_yaml_returns_defaults(self):
        """Missing YAML file returns defaults."""
        cfg = load_subsystems_config(config_path="/nonexistent/config.yaml")
        assert cfg == DEFAULT_CONFIG.copy() | {"enabled": True}

    def test_malformed_yaml_falls_back_to_defaults(self, tmp_path: Path):
        """Malformed YAML silently falls back to defaults."""
        yaml_path = tmp_path / "bad.yaml"
        yaml_path.write_text("{invalid: yaml: [broken")
        cfg = load_subsystems_config(config_path=yaml_path)
        assert cfg["enabled"] is True

    def test_deep_merge_nested_dicts(self, tmp_path: Path):
        """Deep merge preserves sibling keys from defaults."""
        yaml_path = tmp_path / "partial.yaml"
        yaml_path.write_text(yaml.dump({
            "attestations": {"algorithm": "sha512"},
        }))
        cfg = load_subsystems_config(config_path=yaml_path)
        assert cfg["attestations"]["algorithm"] == "sha512"    # from YAML
        assert cfg["attestations"]["enabled"] is True           # from default
        assert cfg["attestations"]["private_key_path"] == "/tmp/gatekeeper/private_key"  # from default

    def test_enabled_flag_can_be_disabled(self, tmp_path: Path):
        """Setting enabled: false disables all subsystems."""
        yaml_path = tmp_path / "disabled.yaml"
        yaml_path.write_text(yaml.dump({"enabled": False}))
        cfg = load_subsystems_config(config_path=yaml_path)
        assert cfg["enabled"] is False


# ===========================================================================
# Env-var overrides
# ===========================================================================


class TestEnvVarOverrides:
    """Environment variables override YAML and defaults."""

    def test_env_var_overrides_ledger_path(self, monkeypatch, tmp_path: Path):
        """ATTESTATION_LEDGER_PATH env var overrides the config value."""
        monkeypatch.setenv("ATTESTATION_LEDGER_PATH", str(tmp_path / "custom.json"))
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        assert "custom.json" in cfg["ledger_paths"]["attestations"]

    def test_env_var_overrides_private_key(self, monkeypatch, tmp_path: Path):
        """ATTESTATION_PRIVATE_KEY_PATH env var overrides the config value."""
        monkeypatch.setenv("ATTESTATION_PRIVATE_KEY_PATH", str(tmp_path / "custom_key"))
        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        assert "custom_key" in cfg["attestations"]["private_key_path"]

    def test_env_var_overrides_yaml(self, monkeypatch, tmp_path: Path):
        """Env vars take precedence over YAML values."""
        yaml_path = tmp_path / "with_paths.yaml"
        yaml_path.write_text(yaml.dump({
            "ledger_paths": {"reputation": "/from/yaml/reputation.json"},
        }))
        monkeypatch.setenv("REPUTATION_LEDGER_PATH", "/from/env/reputation.json")
        cfg = load_subsystems_config(config_path=yaml_path)
        assert cfg["ledger_paths"]["reputation"] == "/from/env/reputation.json"


# ===========================================================================
# apply_subsystems_config
# ===========================================================================


class TestApplyConfig:
    """apply_subsystems_config ensures ledger directories exist."""

    def test_ensure_dirs_when_enabled(self, tmp_path: Path, monkeypatch):
        """Ledger directories are created when enabled."""
        monkeypatch.setenv("ATTESTATION_LEDGER_PATH", str(tmp_path / "ledgers" / "att.json"))
        monkeypatch.setenv("REPUTATION_LEDGER_PATH", str(tmp_path / "ledgers" / "rep.json"))
        monkeypatch.setenv("TRUST_LEDGER_PATH", str(tmp_path / "ledgers" / "trust.json"))

        cfg = load_subsystems_config(config_path="/nonexistent/path.yaml")
        result = apply_subsystems_config(cfg)

        assert result["enabled"] is True
        assert (tmp_path / "ledgers").exists()
        assert result is cfg  # returns same dict

    def test_skip_dirs_when_disabled(self, tmp_path: Path):
        """No directories are created when disabled (no crash)."""
        cfg = {"enabled": False}
        result = apply_subsystems_config(cfg)
        assert result["enabled"] is False

    def test_apply_with_explicit_config(self, tmp_path: Path):
        """apply_subsystems_config accepts an optional pre-loaded config."""
        cfg = {"enabled": False, "reputation": {"min_score": 0.9}}
        result = apply_subsystems_config(cfg)
        assert result["reputation"]["min_score"] == 0.9
