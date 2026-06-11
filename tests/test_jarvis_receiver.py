"""Tests for jarvis.receiver: webhook endpoint that wires validator, policy, queue, and audit."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from jarvis.receiver import JarvisReceiver
from jarvis.types import Command


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def receiver(tmp_path: Path) -> JarvisReceiver:
    """Create a receiver with isolated queue and audit directories."""
    from jarvis.queue import ActionQueue
    from jarvis.audit import AuditLog
    return JarvisReceiver(
        api_token="test-token-123",
        queue=ActionQueue(tmp_path / "test_receiver.db"),
        audit_log=AuditLog(hot_dir=tmp_path / "audit"),
    )


@pytest.fixture
def valid_payload() -> dict:
    return {
        "target": "PC",
        "action": "OPEN_URL",
        "parameter": "https://example.com",
        "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000001",
        "requested_at": "2026-06-11T08:00:00Z",
        "source": "web_ui",
        "priority": 5,
    }


@pytest.fixture
def auth_headers() -> dict:
    return {"Authorization": "Bearer test-token-123"}


# ===========================================================================
# Authentication
# ===========================================================================


class TestAuthentication:
    def test_no_auth_returns_401(self, receiver: JarvisReceiver, valid_payload: dict):
        status, headers, body = receiver.handle_request(valid_payload, headers={})
        assert status == 401
        data = json.loads(body)
        assert "error" in data

    def test_bad_token_returns_401(self, receiver: JarvisReceiver, valid_payload: dict):
        status, headers, body = receiver.handle_request(
            valid_payload,
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert status == 401
        data = json.loads(body)
        assert "error" in data

    def test_valid_auth_passes(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        status, headers, body = receiver.handle_request(valid_payload, headers=auth_headers)
        # Should not be 401
        assert status != 401

    def test_missing_bearer_prefix(self, receiver: JarvisReceiver, valid_payload: dict):
        status, headers, body = receiver.handle_request(
            valid_payload,
            headers={"Authorization": "test-token-123"},
        )
        assert status == 401


# ===========================================================================
# Schema validation
# ===========================================================================


class TestSchemaValidation:
    def test_invalid_json_string(self, receiver: JarvisReceiver, auth_headers: dict):
        status, headers, body = receiver.handle_request("not valid json", headers=auth_headers)
        assert status == 400
        data = json.loads(body)
        assert "error" in data

    def test_missing_required_field(self, receiver: JarvisReceiver, auth_headers: dict):
        payload = {"target": "PC"}  # missing action, parameter, etc.
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        assert status == 422
        data = json.loads(body)
        assert data["status"] == "rejected"
        assert len(data["errors"]) > 0

    def test_unknown_target(self, receiver: JarvisReceiver, auth_headers: dict, valid_payload: dict):
        payload = dict(valid_payload)
        payload["target"] = "VEHICLE"
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        assert status == 422
        data = json.loads(body)
        assert data["status"] == "rejected"

    def test_invalid_idempotency_key(self, receiver: JarvisReceiver, auth_headers: dict, valid_payload: dict):
        payload = dict(valid_payload)
        payload["idempotency_key"] = "bad-key"
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        assert status == 422
        data = json.loads(body)
        assert data["status"] == "rejected"


# ===========================================================================
# Policy classification
# ===========================================================================


class TestPolicyClassification:
    def test_auto_approve_returns_queued(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        status, headers, body = receiver.handle_request(valid_payload, headers=auth_headers)
        data = json.loads(body)
        assert data["status"] == "queued"
        assert "command_id" in data
        assert data["policy"] == "auto-approve"

    def test_always_confirm_returns_interaction(self, receiver: JarvisReceiver, auth_headers: dict):
        payload = {
            "target": "PC",
            "action": "RUN_SCRIPT",
            "parameter": "daily-backup",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000002",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        data = json.loads(body)
        assert data["status"] == "interaction"
        assert data.get("requires_approval") is True
        assert data["policy"] == "always-confirm"

    def test_blocked_returns_rejected(self, receiver: JarvisReceiver, auth_headers: dict):
        # Use an action that would be blocked (none currently in policy, so we
        # test with an unknown action which hits schema validation first.
        # For a real blocked action, we'd need a blocked entry in gate_policy.yaml.
        payload = {
            "target": "PC",
            "action": "SHUTDOWN_PC",
            "parameter": "",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000003",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        data = json.loads(body)
        # SHUTDOWN_PC is always-confirm, so it should return interaction
        assert data["status"] == "interaction"

    def test_auto_approve_audit_returns_queued(self, receiver: JarvisReceiver, auth_headers: dict):
        payload = {
            "target": "PC",
            "action": "LAUNCH_APP",
            "parameter": "Slack",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000004",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        data = json.loads(body)
        assert data["status"] == "queued"
        assert data["policy"] == "auto-approve-audit"


# ===========================================================================
# Idempotency
# ===========================================================================


class TestIdempotency:
    def test_duplicate_key_returns_idempotent(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        # First request
        status1, _, body1 = receiver.handle_request(valid_payload, headers=auth_headers)
        data1 = json.loads(body1)
        assert data1["status"] == "queued"

        # Second request with same key
        status2, _, body2 = receiver.handle_request(valid_payload, headers=auth_headers)
        data2 = json.loads(body2)
        assert data2["status"] == "idempotent"

    def test_different_keys_accepted(self, receiver: JarvisReceiver, auth_headers: dict):
        for i in range(3):
            payload = {
                "target": "PC",
                "action": "OPEN_URL",
                "parameter": f"https://example.com/{i}",
                "idempotency_key": f"IDEM-a1b2c3d4e5f6{i:020d}",
                "requested_at": "2026-06-11T08:00:00Z",
            }
            status, _, body = receiver.handle_request(payload, headers=auth_headers)
            data = json.loads(body)
            assert data["status"] == "queued"


# ===========================================================================
# Audit logging
# ===========================================================================


class TestAuditLogging:
    def test_audit_log_has_event(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        receiver.handle_request(valid_payload, headers=auth_headers)
        # The audit log should have at least one event
        count = receiver._audit.count_events()
        assert count >= 1

    def test_audit_log_rejection(self, receiver: JarvisReceiver, auth_headers: dict):
        payload = {"bad": "request"}
        receiver.handle_request(payload, headers=auth_headers)
        rejected = receiver._audit.get_by_event_type("COMMAND_REJECTED_SCHEMA")
        assert len(rejected) >= 1

    def test_audit_log_submission(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        receiver.handle_request(valid_payload, headers=auth_headers)
        submitted = receiver._audit.get_by_event_type("COMMAND_SUBMITTED")
        assert len(submitted) >= 1


# ===========================================================================
# Response format
# ===========================================================================


class TestResponseFormat:
    def test_response_has_required_fields(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        status, headers, body = receiver.handle_request(valid_payload, headers=auth_headers)
        data = json.loads(body)
        assert "status" in data
        assert "command_id" in data
        assert "target_action" in data
        assert "policy" in data
        assert "detail" in data

    def test_response_content_type(self, receiver: JarvisReceiver, valid_payload: dict, auth_headers: dict):
        status, headers, body = receiver.handle_request(valid_payload, headers=auth_headers)
        assert headers.get("Content-Type") == "application/json"


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_non_dict_body(self, receiver: JarvisReceiver, auth_headers: dict):
        status, headers, body = receiver.handle_request(["not", "a", "dict"], headers=auth_headers)
        assert status == 400

    def test_empty_body(self, receiver: JarvisReceiver, auth_headers: dict):
        status, headers, body = receiver.handle_request({}, headers=auth_headers)
        # Should fail validation (missing required fields)
        assert status == 422

    def test_string_body(self, receiver: JarvisReceiver, auth_headers: dict):
        status, headers, body = receiver.handle_request("plain string", headers=auth_headers)
        assert status == 400

    def test_very_large_parameter(self, receiver: JarvisReceiver, auth_headers: dict):
        payload = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "x" * 600,
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000005",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        assert status == 422

    def test_http_url_escalates(self, receiver: JarvisReceiver, auth_headers: dict):
        """http URL should escalate to always-confirm and return interaction."""
        payload = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "http://example.com",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000006",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = receiver.handle_request(payload, headers=auth_headers)
        data = json.loads(body)
        # http URL escalates to always-confirm
        assert data["status"] == "interaction"
        assert data["policy"] == "always-confirm"


# ===========================================================================
# No-queue mode
# ===========================================================================


class TestNoQueueMode:
    """Tests for the --no-queue flag (Phase 2A pure decision service)."""

    @pytest.fixture
    def no_queue_receiver(self, tmp_path: Path) -> JarvisReceiver:
        """Receiver with no_queue=True, no database file created."""
        from jarvis.audit import AuditLog
        return JarvisReceiver(
            api_token="test-token-123",
            audit_log=AuditLog(hot_dir=tmp_path / "audit"),
            no_queue=True,
        )

    def test_no_queue_accepts_command(self, no_queue_receiver: JarvisReceiver, auth_headers: dict):
        payload = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000007",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = no_queue_receiver.handle_request(payload, headers=auth_headers)
        data = json.loads(body)
        assert data["status"] == "queued"
        assert data["policy"] == "auto-approve"
        assert data.get("mode") == "no-queue"
        assert "queue_note" in data

    def test_no_queue_interaction_response(self, no_queue_receiver: JarvisReceiver, auth_headers: dict):
        payload = {
            "target": "PC",
            "action": "RUN_SCRIPT",
            "parameter": "daily-backup",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000008",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = no_queue_receiver.handle_request(payload, headers=auth_headers)
        data = json.loads(body)
        assert data["status"] == "interaction"
        assert data.get("mode") == "no-queue"

    def test_no_queue_still_audits(self, no_queue_receiver: JarvisReceiver, auth_headers: dict):
        payload = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "idempotency_key": "IDEM-a1b2c3d4e5f600000000000000000009",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        no_queue_receiver.handle_request(payload, headers=auth_headers)
        assert no_queue_receiver._audit.count_events() >= 1

    def test_no_queue_rejection_still_works(self, no_queue_receiver: JarvisReceiver, auth_headers: dict):
        payload = {"bad": "request"}
        status, headers, body = no_queue_receiver.handle_request(payload, headers=auth_headers)
        assert status == 422
        data = json.loads(body)
        assert data["status"] == "rejected"

    def test_no_queue_auth_still_required(self, no_queue_receiver: JarvisReceiver):
        payload = {
            "target": "PC",
            "action": "OPEN_URL",
            "parameter": "https://example.com",
            "idempotency_key": "IDEM-a1b2c3d4e5f60000000000000000000a",
            "requested_at": "2026-06-11T08:00:00Z",
        }
        status, headers, body = no_queue_receiver.handle_request(payload, headers={})
        assert status == 401
