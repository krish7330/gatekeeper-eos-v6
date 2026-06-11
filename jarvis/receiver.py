"""Webhook receiver for Jarvis v2.1.

Accepts HTTP POST requests, authenticates via bearer token, validates the
command against the JSON schema, classifies the risk policy, writes audit
events, and enqueues the command.

Response types:
  - ``queued``: Command was auto-approved and queued for execution.
  - ``interaction``: Command requires user approval (always-confirm).
  - ``rejected``: Command was blocked by schema validation or policy.

Usage::

    # As a standalone HTTP server
    python -m jarvis.receiver

    # Or as a handler for an existing server
    from jarvis.receiver import JarvisReceiver
    handler = JarvisReceiver()
    response = handler.handle_request({"target": "PC", ...}, headers)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from jarvis.audit import AuditLog
from jarvis.policy import PolicyEngine
from jarvis.queue import ActionQueue, CommandNotFoundError, DuplicateIdempotencyKeyError
from jarvis.types import AuditEventType, Command, GateOutcome, Policy
from jarvis.validator import CommandValidator


# ---------------------------------------------------------------------------
# Default config
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent.parent
DEFAULT_TOKEN = os.environ.get("JARVIS_API_TOKEN", "jarvis-dev-token")
DEFAULT_HOST = os.environ.get("JARVIS_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("JARVIS_PORT", "8080"))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ReceiverError(Exception):
    """Base error for receiver operations."""


class AuthenticationError(ReceiverError):
    """Raised when authentication fails."""


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _json_response(status_code: int, body: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
    """Create a JSON response tuple (status_code, headers_dict, body_dict)."""
    return (status_code, {"Content-Type": "application/json"}, json.dumps(body, ensure_ascii=False))


def _ok(body: dict[str, Any]) -> tuple[int, dict[str, Any], str]:
    return _json_response(200, body)


def _error(status_code: int, message: str) -> tuple[int, dict[str, Any], str]:
    return _json_response(status_code, {"error": message})


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------


class JarvisReceiver:
    """Webhook receiver that validates, classifies, and enqueues commands.

    Wires together: Authenticator → Validator → Policy → Queue → Audit.

    Use ``no_queue=True`` to run as a pure decision service (Phase 2A):
    validates, classifies, and audits without persisting to the queue.
    Decisions are returned via the response body and audit log only.
    """

    def __init__(
        self,
        api_token: str | None = None,
        policy_engine: PolicyEngine | None = None,
        validator: CommandValidator | None = None,
        queue: ActionQueue | None = None,
        audit_log: AuditLog | None = None,
        no_queue: bool = False,
    ) -> None:
        self._api_token = api_token or DEFAULT_TOKEN
        self._policy = policy_engine or PolicyEngine()
        self._validator = validator or CommandValidator(self._policy)
        self._no_queue = no_queue
        if no_queue:
            self._queue: ActionQueue | None = None  # enqueue step is skipped entirely
        else:
            self._queue = queue or ActionQueue()
        self._audit = audit_log or AuditLog()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _verify_auth(self, headers: dict[str, str]) -> None:
        """Verify the bearer token in the Authorization header.

        Raises:
            AuthenticationError: If the token is missing or invalid.
        """
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise AuthenticationError("Missing or invalid Authorization header. Expected: Bearer <token>")
        token = auth[7:]
        if token != self._api_token:
            raise AuthenticationError("Invalid API token")

    # ------------------------------------------------------------------
    # Main request handler
    # ------------------------------------------------------------------

    def handle_request(
        self,
        body: dict[str, Any] | str,
        headers: dict[str, str] | None = None,
        raw_path: str = "/webhook",
    ) -> tuple[int, dict[str, Any], str]:
        """Handle an incoming webhook request.

        Args:
            body: Parsed JSON body (dict) or raw JSON string.
            headers: Request headers dict.
            raw_path: The request path (for logging).

        Returns:
            Tuple of (status_code, headers_dict, body_string).
        """
        headers = headers or {}
        start_time = datetime.now(timezone.utc)

        # ── 1. Authenticate ─────────────────────────────────────────────
        try:
            self._verify_auth(headers)
        except AuthenticationError as e:
            return _error(401, str(e))

        # ── 2. Parse body ────────────────────────────────────────────────
        if isinstance(body, str):
            try:
                data: dict[str, Any] = json.loads(body)
            except json.JSONDecodeError as e:
                return _error(400, f"Invalid JSON: {e}")
        else:
            data = body

        if not isinstance(data, dict):
            return _error(400, "Request body must be a JSON object")

        # ── 3. Validate schema ───────────────────────────────────────────
        validation_result, cmd = self._validator.validate_and_parse(data)

        if not validation_result.valid:
            # Audit log the rejection
            self._audit.append(
                event_type=AuditEventType.COMMAND_REJECTED_SCHEMA.value,
                command_id=data.get("command_id", "unknown"),
                target_action=f"{data.get('target', '?')}:{data.get('action', '?')}",
                status="failed",
                detail=f"Schema validation failed: {'; '.join(validation_result.errors)}",
            )
            return _json_response(422, {
                "status": "rejected",
                "errors": validation_result.errors,
                "warnings": validation_result.warnings,
            })

        # ── 4. Classify policy ───────────────────────────────────────────
        policy = self._policy.classify_command(cmd)
        policy_name = policy.value

        # ── 5. Determine gate outcome ────────────────────────────────────
        if policy == Policy.BLOCKED:
            gate = "blocked"
            queue_status = "failed"
            response_status = "rejected"
            response_code = 422
            response_detail = "Action is blocked by policy"

        elif policy == Policy.ALWAYS_CONFIRM:
            gate = None  # Awaiting user confirmation
            queue_status = "queued"
            response_status = "interaction"
            response_code = 202
            response_detail = "Command requires user approval"

        else:  # AUTO_APPROVE or AUTO_APPROVE_AUDIT
            gate = "approved"
            queue_status = "queued"
            response_status = "queued"
            response_code = 202
            response_detail = "Command accepted and queued"

        # ── 6. Generate command ID ─────────────────────────────────────
        command_id = f"CMD-{uuid.uuid4().hex[:12]}"
        cmd = Command(
            target=cmd.target,
            action=cmd.action,
            parameter=cmd.parameter,
            idempotency_key=cmd.idempotency_key,
            requested_at=cmd.requested_at,
            source=cmd.source,
            priority=cmd.priority,
            command_id=command_id,
        )

        # ── 7. Enqueue (skipped in --no-queue mode) ─────────────────────
        if not self._no_queue:
            try:
                self._queue.enqueue(cmd, policy=policy_name, gate=gate)
            except DuplicateIdempotencyKeyError as e:
                existing_id = e.existing_entry["command_id"] if e.existing_entry else command_id
                return _ok({
                    "status": "idempotent",
                    "command_id": existing_id,
                    "detail": str(e),
                })

        # ── 8. Audit log ────────────────────────────────────────────────
        target_action = f"{cmd.target}:{cmd.action}"
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        mode_tag = "no-queue" if self._no_queue else "queued"
        self._audit.append(
            event_type=AuditEventType.COMMAND_SUBMITTED.value,
            command_id=command_id,
            target_action=target_action,
            status="queued",
            detail=f"source={cmd.source}, policy={policy_name}, gate={gate}, mode={mode_tag}, elapsed_ms={int(elapsed * 1000)}",
        )

        if policy == Policy.AUTO_APPROVE_AUDIT:
            self._audit.append(
                event_type=AuditEventType.COMMAND_POLICY_CLASSIFIED.value,
                command_id=command_id,
                target_action=target_action,
                status="queued",
                detail=f"policy={policy_name}, mode={mode_tag}, elevated audit trail",
            )

        if gate == "blocked":
            self._audit.append(
                event_type=AuditEventType.COMMAND_FAILED.value,
                command_id=command_id,
                target_action=target_action,
                status="failed",
                detail="Action blocked by policy",
            )

        # ── 9. Response ─────────────────────────────────────────────────
        response_body = {
            "status": response_status,
            "command_id": command_id,
            "target_action": target_action,
            "policy": policy_name,
            "detail": response_detail,
        }

        if policy == Policy.ALWAYS_CONFIRM:
            response_body["requires_approval"] = True

        if self._no_queue:
            response_body["mode"] = "no-queue"
            response_body["queue_note"] = "No queue persistence — decision logged only. Idempotency not enforced."

        return _json_response(response_code, response_body)

    # ------------------------------------------------------------------
    # Approval endpoint: approve a command awaiting user confirmation
    # ------------------------------------------------------------------

    def handle_approve(
        self,
        body: dict[str, Any] | str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        """Handle a POST /v1/interactions/approve request.

        Expects JSON body with ``command_id``. Calls ``queue.approve()``
        to set ``gate='approved'`` and ``status='queued'``, writes
        ``APPROVAL_GRANTED`` to the audit log.

        Returns:
            Tuple of (status_code, headers_dict, body_string).
        """
        headers = headers or {}

        # ── 1. Authenticate ──
        try:
            self._verify_auth(headers)
        except AuthenticationError as e:
            return _error(401, str(e))

        if self._no_queue:
            return _error(400, "Cannot approve: receiver is in --no-queue mode (no persistence)")

        # ── 2. Parse body ──
        if isinstance(body, str):
            try:
                data: dict[str, Any] = json.loads(body)
            except json.JSONDecodeError as e:
                return _error(400, f"Invalid JSON: {e}")
        else:
            data = body

        command_id = data.get("command_id", "") if isinstance(data, dict) else ""
        if not command_id:
            return _error(400, "Missing required field: command_id")

        # ── 3. Approve in queue ──
        try:
            entry = self._queue.approve(command_id)
        except CommandNotFoundError:
            return _error(404, f"Command not found: {command_id}")

        # ── 4. Audit log ──
        target_action = f"{entry['target']}:{entry['action']}"
        self._audit.append(
            event_type=AuditEventType.APPROVAL_GRANTED.value,
            command_id=command_id,
            target_action=target_action,
            status="queued",
            detail=f"gate={entry['gate']}, policy={entry['policy']}",
        )

        return _json_response(200, {
            "status": "approved",
            "command_id": command_id,
            "target_action": target_action,
            "policy": entry["policy"],
            "detail": "Command approved and queued for execution",
        })

    # ------------------------------------------------------------------
    # Rejection endpoint: reject a command awaiting user confirmation
    # ------------------------------------------------------------------

    def handle_reject(
        self,
        body: dict[str, Any] | str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        """Handle a POST /v1/interactions/reject request.

        Expects JSON body with ``command_id`` and optional ``reason``.
        Calls ``queue.reject()`` to set ``gate='rejected'`` and
        ``status='failed'``, writes ``APPROVAL_REJECTED`` to the audit log.

        Returns:
            Tuple of (status_code, headers_dict, body_string).
        """
        headers = headers or {}

        # ── 1. Authenticate ──
        try:
            self._verify_auth(headers)
        except AuthenticationError as e:
            return _error(401, str(e))

        if self._no_queue:
            return _error(400, "Cannot reject: receiver is in --no-queue mode (no persistence)")

        # ── 2. Parse body ──
        if isinstance(body, str):
            try:
                data: dict[str, Any] = json.loads(body)
            except json.JSONDecodeError as e:
                return _error(400, f"Invalid JSON: {e}")
        else:
            data = body

        command_id = data.get("command_id", "") if isinstance(data, dict) else ""
        reason = data.get("reason", "User declined") if isinstance(data, dict) else "User declined"

        if not command_id:
            return _error(400, "Missing required field: command_id")

        # ── 3. Reject in queue ──
        try:
            entry = self._queue.reject(command_id, reason=reason)
        except CommandNotFoundError:
            return _error(404, f"Command not found: {command_id}")

        # ── 4. Audit log ──
        target_action = f"{entry['target']}:{entry['action']}"
        self._audit.append(
            event_type=AuditEventType.APPROVAL_REJECTED.value,
            command_id=command_id,
            target_action=target_action,
            status="failed",
            detail=f"reason={reason}, gate={entry['gate']}",
        )

        return _json_response(200, {
            "status": "rejected",
            "command_id": command_id,
            "target_action": target_action,
            "policy": entry["policy"],
            "detail": f"Command rejected: {reason}",
        })


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------


class _RequestHandler(BaseHTTPRequestHandler):
    """HTTP handler that delegates to JarvisReceiver."""

    receiver: JarvisReceiver | None = None

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST requests with path-based routing.

        Routes:
          POST /webhook                       → receiver.handle_request()
          POST /v1/interactions/approve       → receiver.handle_approve()
          POST /v1/interactions/reject        → receiver.handle_reject()
        """
        if self.receiver is None:
            self.send_error(500, "Receiver not initialized")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length else "{}"

        headers = dict(self.headers)

        # Route based on path
        path = self.path.rstrip("/")
        if path == "/v1/interactions/approve":
            handler = lambda: self.receiver.handle_approve(body=body, headers=headers)
        elif path == "/v1/interactions/reject":
            handler = lambda: self.receiver.handle_reject(body=body, headers=headers)
        else:
            handler = lambda: self.receiver.handle_request(body=body, headers=headers, raw_path=self.path)

        status_code, resp_headers, resp_body = handler()

        self.send_response(status_code)
        for key, value in resp_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(resp_body.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default HTTP server logs (too noisy)."""
        pass


def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    api_token: str | None = None,
    no_queue: bool = False,
) -> None:
    """Run the Jarvis webhook receiver as a standalone HTTP server.

    Args:
        host: Host to bind to (default: 0.0.0.0).
        port: Port to listen on (default: 8080).
        api_token: API token for authentication. Defaults to JARVIS_API_TOKEN env var.
        no_queue: If True, run as a pure decision service (Phase 2A) —
                  validate, classify, audit, return decision, no queue persistence.
    """
    mode = "no-queue" if no_queue else "full"
    receiver = JarvisReceiver(api_token=api_token, no_queue=no_queue)
    _RequestHandler.receiver = receiver

    server = HTTPServer((host, port), _RequestHandler)
    print(f"Jarvis v2.1 receiver ({mode} mode) listening on http://{host}:{port}")
    if no_queue:
        print(f"  Mode: Pure decision service — no queue persistence")
    print(f"  Auth: Bearer token (JARVIS_API_TOKEN)")
    print(f"  Endpoint: POST /webhook")
    print(f"  Endpoints: POST /v1/interactions/approve, POST /v1/interactions/reject")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for ``python -m jarvis.receiver``."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Jarvis v2.1 Webhook Receiver — decision service for PC and home automation"
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host to bind (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--token", default=None, help="API token (default: JARVIS_API_TOKEN env)")
    parser.add_argument(
        "--no-queue", action="store_true",
        help="Run as pure decision service — validate, classify, audit, return. No queue persistence."
    )
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, api_token=args.token, no_queue=args.no_queue)


if __name__ == "__main__":
    main()
