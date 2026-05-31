"""
Comprehensive tests for the Alance n8n WhatsApp chatbot workflows.

Simulates the JS code node logic in Python to verify:
- Payload extraction and ledger_key generation
- Duplicate detection (ledger_key + message_id)
- Cancel/stop keyword detection
- Phrase-weighted keyword scoring
- 4-state machine transitions with drift detection
- Context-aware reply building
- Metrics computation
- Error formatting
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════
# Simulated JS Logic (translated to Python)
# ═══════════════════════════════════════════════════════════════════════════


def simulate_extract_payload(twilio_payload: dict, environment: str = "sandbox") -> dict:
    """Simulates the Extract Payload code node."""
    message_id = twilio_payload.get("MessageSid") or twilio_payload.get("SmsSid") or ""
    from_number = twilio_payload.get("From") or twilio_payload.get("WaId") or ""
    to_number = twilio_payload.get("To") or ""
    body = (twilio_payload.get("Body") or "").strip()
    sms_status = twilio_payload.get("SmsStatus") or twilio_payload.get("MessageStatus") or ""
    num_media = int(twilio_payload.get("NumMedia") or "0")
    account_sid = twilio_payload.get("AccountSid") or ""
    profile_name = twilio_payload.get("ProfileName") or ""
    api_version = twilio_payload.get("ApiVersion") or ""

    # Stable ledger key
    raw_key = f"{from_number}|{body.lower().strip()}"
    ledger_key = hashlib.sha256(raw_key.encode()).hexdigest()[:16]

    return {
        "message_id": message_id,
        "from_number": from_number,
        "to_number": to_number,
        "message_body": body,
        "sms_status": sms_status,
        "num_media": num_media,
        "account_sid": account_sid,
        "profile_name": profile_name,
        "api_version": api_version,
        "environment": environment,
        "is_status_callback": len(sms_status) > 0,
        "ledger_key": ledger_key,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }


def simulate_check_duplicate(payload: dict, ledger_items: list[dict]) -> dict:
    """Simulates the Check Duplicate code node."""
    msg_id = payload["message_id"]
    led_key = payload["ledger_key"]
    from_num = payload["from_number"]

    duplicate_by_ledger = any(
        item.get("ledger_key") == led_key and item.get("from_number") == from_num
        for item in ledger_items
    )
    duplicate_by_sid = any(
        item.get("message_id") == msg_id
        for item in ledger_items
    )

    return {
        **payload,
        "is_duplicate": duplicate_by_ledger or duplicate_by_sid,
        "duplicate_by_ledger": duplicate_by_ledger,
        "duplicate_by_sid": duplicate_by_sid,
        "check_timestamp": datetime.now(timezone.utc).isoformat(),
    }


def simulate_cancel_check(
    payload: dict,
    conversations: list[dict],
) -> dict:
    """Simulates the Cancel/Stop Check code node."""
    body = (payload.get("message_body") or "").lower().strip()

    cancel_keywords = [
        "cancel", "stop", "end", "quit", "unsubscribe",
        "stop all", "opt out", "optout", "pause",
        "i want to stop", "please stop", "do not send", "no more",
    ]
    menu_keywords = [
        "menu", "options", "back", "main menu", "restart", "start over", "help",
    ]

    all_keywords = cancel_keywords + menu_keywords
    is_cancel = any(k in body for k in all_keywords)

    sender_convs = sorted(
        [c for c in conversations if c.get("from_number") == payload["from_number"]],
        key=lambda c: c.get("last_message_at", "") or "",
        reverse=True,
    )
    active_conv = next(
        (c for c in sender_convs if c.get("status") == "active"),
        None,
    )

    known_sender = len(sender_convs) > 0

    return {
        **payload,
        "is_cancel_request": is_cancel,
        "existing_conversation": active_conv,
        "conversation_id": active_conv["conversation_id"] if active_conv else payload["message_id"],
        "current_state": (active_conv["state"] if active_conv
                          else ("CONSULTING" if known_sender else "NEW")),
        "has_existing_conv": active_conv is not None,
        "known_sender": known_sender,
    }


def simulate_keyword_scorer(payload: dict) -> dict:
    """Simulates the Keyword Scorer code node — phrase-weighted intent detection."""
    body = (payload.get("message_body") or "").lower().strip()

    # Phrase-weighted keywords: (phrase, weight)
    keywords = {
        "booking": [
            ("book an appointment", 3), ("schedule a meeting", 3), ("need to book", 3),
            ("i want to book", 3), ("can i book", 3),
            ("reschedule", 2), ("availability", 2), ("follow up", 2), ("make a booking", 3),
            ("book", 1), ("appointment", 1), ("schedule", 1), ("meeting", 1),
            ("consultation", 1), ("slot", 1), ("reserve", 1), ("book now", 2),
        ],
        "greeting": [
            ("hello", 1), ("hi", 1), ("hey", 1), ("good morning", 2),
            ("good evening", 2), ("namaste", 2), ("how are you", 2), ("hi there", 2),
        ],
        "pricing": [
            ("how much", 2), ("what is the price", 3), ("what are your rates", 3),
            ("price", 1), ("cost", 1), ("rate", 1), ("fee", 1), ("charge", 1),
            ("pricing", 2), ("how much does it cost", 3),
        ],
        "service": [
            ("what services", 2), ("what do you offer", 3), ("can you help", 2),
            ("service", 1), ("offer", 1), ("provide", 1), ("do you", 1),
            ("help with", 1), ("tell me about", 2),
        ],
        "time": [
            ("today", 1), ("tomorrow", 2), ("next week", 2), ("this week", 2),
            ("available", 1), ("when", 1), ("what time", 2), ("later today", 2),
        ],
        "name": [
            ("my name is", 3), ("name is", 3), ("i am", 1), ("call me", 2),
            ("i'm", 1), ("this is", 1),
        ],
        "telugu": [
            ("namaskaram", 3), ("emiti", 2), ("ela unnaru", 3), ("bagunnara", 2),
            ("kavali", 2), ("tondara", 2), ("entandi", 2), ("sarle", 1),
        ],
        "info": [
            ("what is", 1), ("tell me", 1), ("about", 1), ("information", 1),
            ("details", 1), ("more info", 2), ("i want to know", 2), ("can you tell", 1),
        ],
        "thanks": [
            ("thank you very much", 3), ("thanks a lot", 3),
            ("thank you so much", 3), ("thank you", 2), ("thanks", 2),
            ("ok", 1), ("okay", 1), ("got it", 2), ("sure", 1), ("great", 1),
        ],
    }

    scores = {}
    for category, patterns in keywords.items():
        total = 0
        for phrase, weight in patterns:
            if phrase in body:
                total += weight
        scores[category] = total

    sorted_scores = sorted(scores.items(), key=lambda x: -x[1])
    top_score = sorted_scores[0][1]
    second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0

    # Determine primary intent
    primary_intent = "unknown"
    confidence = 0

    if top_score > 0:
        primary_intent = sorted_scores[0][0]
        confidence = top_score

        # Thanks is only terminal if genuinely high confidence
        if primary_intent == "thanks" and second_score >= top_score:
            primary_intent = sorted_scores[1][0]

        # Booking gets priority on ties
        if primary_intent != "booking" and scores.get("booking", 0) > 0 and scores["booking"] >= top_score - 1:
            primary_intent = "booking"
            confidence = max(confidence, scores["booking"])

    is_booking_intent = scores.get("booking", 0) >= 2 or (scores.get("booking", 0) > 0 and scores.get("name", 0) > 0)

    return {
        **payload,
        "keyword_scores": scores,
        "primary_intent": primary_intent,
        "confidence": confidence,
        "top_intents": [s for s in sorted_scores if s[1] > 0][:3],
        "is_booking_intent": is_booking_intent,
    }


def simulate_state_machine(payload: dict) -> dict:
    """Simulates the State Machine code node — 4-state model with drift detection.

    States: NEW → CONSULTING → BOOKING → DONE
            Any → CANCELLED (on cancel)
    """
    current_state = "CANCELLED" if payload.get("is_cancel_request") else (payload.get("current_state") or "NEW")
    intent = payload.get("primary_intent") or "unknown"
    confidence = payload.get("confidence") or 0
    is_booking = payload.get("is_booking_intent") or False
    has_booking = payload.get("keyword_scores", {}).get("booking", 0) > 0

    next_state = current_state
    state_note = ""
    drift_detected = False

    if payload.get("is_cancel_request"):
        next_state = "CANCELLED"
        state_note = "CANCELLED: User requested cancellation"
    else:
        match current_state:
            case "NEW":
                if is_booking:
                    next_state = "BOOKING"
                    state_note = "NEW -> BOOKING (booking intent)"
                else:
                    next_state = "CONSULTING"
                    state_note = "NEW -> CONSULTING (general inquiry)"

            case "CONSULTING":
                if is_booking:
                    next_state = "BOOKING"
                    state_note = "CONSULTING -> BOOKING (user wants to book)"
                elif intent == "thanks" and confidence >= 2:
                    next_state = "DONE"
                    state_note = "CONSULTING -> DONE (resolved with thanks)"
                elif confidence >= 3 and intent != "unknown":
                    next_state = "DONE"
                    state_note = "CONSULTING -> DONE (high confidence resolved)"
                else:
                    state_note = "Stayed in CONSULTING (needs more info)"

            case "BOOKING":
                has_confirmation = (intent in ("thanks", "name") and confidence >= 2)
                has_name = intent == "name" or payload.get("keyword_scores", {}).get("name", 0) > 0
                if has_confirmation or (has_name and has_booking):
                    next_state = "DONE"
                    state_note = "BOOKING -> DONE (confirmed: name + thanks)"
                else:
                    state_note = "Stayed in BOOKING (awaiting confirmation)"

            case "DONE":
                state_note = "DONE: Already completed (no transition)"

            case _:
                # Unknown/corrupted state — reset with drift
                next_state = "NEW"
                state_note = f"DRIFT: {current_state} -> NEW (unknown state reset)"
                drift_detected = True

    # Drift: prevent state change on unknown intent (unless cancel)
    if not drift_detected and current_state != next_state and intent == "unknown" and not payload.get("is_cancel_request"):
        drift_detected = True
        state_note = f"DRIFT: {current_state} -> {next_state} (blocked — unknown intent)"
        next_state = current_state

    is_booking_complete = next_state == "DONE" and current_state == "BOOKING"

    return {
        **payload,
        "previous_state": current_state,
        "current_state": next_state,
        "state_note": state_note,
        "drift_detected": drift_detected,
        "is_booking_complete": is_booking_complete,
    }


def simulate_build_reply(payload: dict) -> str:
    """Simulates the Build Reply code node — returns reply text."""
    is_cancel = bool(payload.get("is_cancel_request"))
    state = (payload.get("current_state") or "NEW").upper()

    if is_cancel:
        state = "CANCELLED"

    intent = payload.get("primary_intent") or "unknown"

    match state:
        case "NEW" | "CONSULTING":
            if intent == "greeting":
                return (
                    "Hello! 👋 Welcome to Alance.\n\n"
                    "I can help with information about our services, pricing, or "
                    "booking an appointment. What would you like to know?"
                )
            elif intent == "pricing":
                return (
                    "Great question about pricing! 💰\n\n"
                    "We offer competitive rates for our services. Could you let me "
                    "know which specific service you are interested in so I can "
                    "give you accurate pricing?"
                )
            elif intent == "service":
                return (
                    "Thanks for your interest! 😊 We offer a range of professional "
                    "services. Could you tell me a bit more about what you need help with?"
                )
            elif intent == "telugu":
                return (
                    "Namaskaram! 🙏\n\n"
                    "Memu Alance lo meeku sahayam cheyadaniki siddhamga unnam. "
                    "Meeru emi kosam vethukutunnaru? "
                    "(We are happy to help you. What are you looking for?)"
                )
            else:
                return (
                    "Hi there! 👋 Welcome to Alance.\n\n"
                    "I can help with info about our services, pricing, or booking. "
                    "Just let me know what you need!"
                )

        case "BOOKING":
            return (
                "I would be happy to book an appointment for you! 📅\n\n"
                "Please share your preferred date and time, plus your name, "
                "and I will get you scheduled right away."
            )

        case "DONE":
            return (
                "Your appointment is confirmed! ✅\n\n"
                "We will send you a reminder before your scheduled time. "
                "If you need anything else, just let us know!"
            )

        case "CANCELLED":
            return (
                "No problem at all! ✅\n\n"
                "Your request has been cancelled. If you ever need our services "
                "again, just send us a message. Have a great day!"
            )

        case _:
            return "Thanks for reaching out to Alance! How can I assist you today?"


def simulate_compute_metrics(
    ledger_rows: list[dict],
    error_rows: list[dict],
    today: str | None = None,
) -> dict:
    """Simulates the Compute Metrics code node."""
    if today is None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    today_ledger = [r for r in ledger_rows if (r.get("processed_at") or "").startswith(today)]
    today_errors = [r for r in error_rows if (r.get("timestamp") or "").startswith(today)]

    total_messages = len(today_ledger)
    processed_count = sum(1 for r in today_ledger if r.get("status") in ("processed", "replied"))
    cached_count = sum(1 for r in today_ledger if r.get("status") in ("cached", "delivery_update"))
    drift_count = sum(1 for r in today_ledger if "drift" in (r.get("status") or ""))
    cancel_count = sum(1 for r in today_ledger if r.get("status") == "cancelled")
    booking_count = sum(1 for r in today_ledger if r.get("status") == "booking_done")
    error_count = len(today_errors)
    error_types = list({r.get("error_type") for r in today_errors})
    environment = (
        ledger_rows[0].get("environment") if ledger_rows
        else (error_rows[0].get("environment") if error_rows else "unknown")
    )

    return {
        "date": today,
        "total_messages": total_messages,
        "processed": processed_count,
        "cached_duplicates": cached_count,
        "cancellations": cancel_count,
        "bookings_completed": booking_count,
        "drift_events": drift_count,
        "errors_total": error_count,
        "distinct_error_types": ", ".join(error_types),
        "environment": environment,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


def simulate_format_error(error_data: dict, environment: str = "sandbox") -> dict:
    """Simulates the Format Error code node."""
    err = error_data.get("error") or {}
    wf = error_data.get("workflow") or {}
    exec_data = error_data.get("execution") or {}

    return {
        "error_message": str(err.get("message", "Unknown error"))[:1000],
        "error_type": err.get("name", "Error"),
        "workflow_id": wf.get("id", "unknown"),
        "workflow_name": wf.get("name", "unknown"),
        "execution_id": exec_data.get("id", "unknown"),
        "last_node": error_data.get("lastNodeExecuted", "unknown"),
        "severity": "error",
        "environment": environment,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Extract Payload
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractPayload:
    def test_basic_extraction(self):
        """Extract normal Twilio webhook payload."""
        twilio = {
            "MessageSid": "SM12345",
            "From": "whatsapp:+919876543210",
            "To": "whatsapp:+14155238886",
            "Body": "Hello!",
            "NumMedia": "0",
            "AccountSid": "AC123",
            "ApiVersion": "2010-04-01",
        }
        result = simulate_extract_payload(twilio)
        assert result["message_id"] == "SM12345"
        assert result["from_number"] == "whatsapp:+919876543210"
        assert result["message_body"] == "Hello!"
        assert result["is_status_callback"] is False
        assert result["sms_status"] == ""
        assert isinstance(result["ledger_key"], str)
        assert len(result["ledger_key"]) == 16

    def test_sms_status_callback(self):
        """Status callback should detect sms_status."""
        twilio = {
            "MessageSid": "SM12345",
            "SmsStatus": "delivered",
            "From": "whatsapp:+919876543210",
            "To": "whatsapp:+14155238886",
            "Body": "",
            "NumMedia": "0",
        }
        result = simulate_extract_payload(twilio)
        assert result["is_status_callback"] is True
        assert result["sms_status"] == "delivered"

    def test_message_status_callback(self):
        """Should also detect MessageStatus field."""
        twilio = {
            "MessageSid": "SM12345",
            "MessageStatus": "read",
            "From": "whatsapp:+919876543210",
            "Body": "",
        }
        result = simulate_extract_payload(twilio)
        assert result["is_status_callback"] is True
        assert result["sms_status"] == "read"

    def test_ledger_key_stability(self):
        """Same sender + body should produce same ledger_key."""
        twilio1 = {"From": "whatsapp:+919876543210", "Body": "Book an appointment", "MessageSid": "SM001"}
        twilio2 = {"From": "whatsapp:+919876543210", "Body": "  BOOK AN APPOINTMENT  ", "MessageSid": "SM002"}

        r1 = simulate_extract_payload(twilio1)
        r2 = simulate_extract_payload(twilio2)
        assert r1["ledger_key"] == r2["ledger_key"]

    def test_ledger_key_different_body(self):
        """Different bodies should produce different keys."""
        twilio1 = {"From": "whatsapp:+919876543210", "Body": "Hello", "MessageSid": "SM001"}
        twilio2 = {"From": "whatsapp:+919876543210", "Body": "Hi", "MessageSid": "SM002"}

        r1 = simulate_extract_payload(twilio1)
        r2 = simulate_extract_payload(twilio2)
        assert r1["ledger_key"] != r2["ledger_key"]

    def test_ledger_key_different_sender(self):
        """Different senders should produce different keys."""
        twilio1 = {"From": "whatsapp:+919876543210", "Body": "Hello", "MessageSid": "SM001"}
        twilio2 = {"From": "whatsapp:+919876543211", "Body": "Hello", "MessageSid": "SM002"}

        r1 = simulate_extract_payload(twilio1)
        r2 = simulate_extract_payload(twilio2)
        assert r1["ledger_key"] != r2["ledger_key"]

    def test_waid_fallback(self):
        """Should fall back to WaId when From is absent."""
        twilio = {"WaId": "whatsapp:+919876543210", "Body": "Hi", "NumMedia": "0"}
        result = simulate_extract_payload(twilio)
        assert result["from_number"] == "whatsapp:+919876543210"

    def test_environment_inherited(self):
        """Environment should be passed through."""
        twilio = {"From": "+123", "Body": "test", "MessageSid": "SM001"}
        result = simulate_extract_payload(twilio, environment="production")
        assert result["environment"] == "production"

    def test_environment_default(self):
        """When no environment is set, should default to sandbox."""
        twilio = {"From": "+123", "Body": "test", "MessageSid": "SM001"}
        result = simulate_extract_payload(twilio)
        assert result["environment"] == "sandbox"


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Check Duplicate
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckDuplicate:
    def test_no_duplicate_empty_ledger(self):
        """No duplicate when ledger is empty."""
        payload = {"message_id": "SM001", "ledger_key": "key123", "from_number": "+123"}
        result = simulate_check_duplicate(payload, [])
        assert result["is_duplicate"] is False
        assert result["duplicate_by_ledger"] is False
        assert result["duplicate_by_sid"] is False

    def test_duplicate_by_ledger_key(self):
        """Same ledger_key + from_number should be duplicate."""
        payload = {"message_id": "SM002", "ledger_key": "key123", "from_number": "+123"}
        ledger = [{"ledger_key": "key123", "from_number": "+123", "message_id": "SM001"}]
        result = simulate_check_duplicate(payload, ledger)
        assert result["is_duplicate"] is True
        assert result["duplicate_by_ledger"] is True

    def test_duplicate_by_message_id(self):
        """Same message_id should be duplicate (Twilio retry)."""
        payload = {"message_id": "SM001", "ledger_key": "key456", "from_number": "+123"}
        ledger = [{"message_id": "SM001", "ledger_key": "key123", "from_number": "+123"}]
        result = simulate_check_duplicate(payload, ledger)
        assert result["is_duplicate"] is True
        assert result["duplicate_by_sid"] is True

    def test_no_duplicate_different_sender_same_body(self):
        """Same body but different sender should NOT be duplicate."""
        payload = {"message_id": "SM002", "ledger_key": "key123", "from_number": "+456"}
        ledger = [{"ledger_key": "key123", "from_number": "+123", "message_id": "SM001"}]
        result = simulate_check_duplicate(payload, ledger)
        assert result["is_duplicate"] is False


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Cancel/Stop Check
# ═══════════════════════════════════════════════════════════════════════════


class TestCancelCheck:
    PAYLOAD = {"message_id": "SM001", "from_number": "+123", "message_body": "hello"}

    def test_not_cancel(self):
        """Normal message should not be cancel."""
        result = simulate_cancel_check(self.PAYLOAD, [])
        assert result["is_cancel_request"] is False

    def test_cancel_keyword(self):
        """'cancel' keyword should be detected."""
        payload = {**self.PAYLOAD, "message_body": "I want to cancel"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_stop_keyword(self):
        """'stop' keyword should be detected."""
        payload = {**self.PAYLOAD, "message_body": "stop"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_opt_out_keyword(self):
        """'opt out' phrase should be detected."""
        payload = {**self.PAYLOAD, "message_body": "I want to opt out"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_stop_all_keyword(self):
        """'stop all' phrase should be detected."""
        payload = {**self.PAYLOAD, "message_body": "stop all messages"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_pause_keyword(self):
        """'pause' keyword should be detected."""
        payload = {**self.PAYLOAD, "message_body": "pause my subscription"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_help_keyword(self):
        """'help' keyword should be detected."""
        payload = {**self.PAYLOAD, "message_body": "help"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_menu_keyword(self):
        """'menu' keyword should be detected."""
        payload = {**self.PAYLOAD, "message_body": "show menu"}
        result = simulate_cancel_check(payload, [])
        assert result["is_cancel_request"] is True

    def test_known_sender_no_active_conv(self):
        """Known sender without active conversation starts at CONSULTING."""
        conversations = [
            {"from_number": "+123", "conversation_id": "CONV001",
             "state": "DONE", "status": "completed", "last_message_at": "2026-05-29T12:00:00Z"},
        ]
        result = simulate_cancel_check(self.PAYLOAD, conversations)
        assert result["current_state"] == "CONSULTING"
        assert result["known_sender"] is True
        assert result["has_existing_conv"] is False

    def test_active_conversation_restored(self):
        """Active conversation state should be restored."""
        conversations = [
            {"from_number": "+123", "conversation_id": "CONV001",
             "state": "BOOKING", "status": "active", "last_message_at": "2026-05-29T12:00:00Z"},
        ]
        result = simulate_cancel_check(self.PAYLOAD, conversations)
        assert result["current_state"] == "BOOKING"
        assert result["conversation_id"] == "CONV001"
        assert result["has_existing_conv"] is True

    def test_new_sender_starts_new(self):
        """Unknown sender with no conversations starts at NEW."""
        result = simulate_cancel_check(self.PAYLOAD, [])
        assert result["current_state"] == "NEW"
        assert result["known_sender"] is False
        assert result["has_existing_conv"] is False

    def test_latest_active_wins(self):
        """When multiple active conversations exist, the latest wins."""
        conversations = [
            {"from_number": "+123", "conversation_id": "CONV001",
             "state": "CONSULTING", "status": "active", "last_message_at": "2026-05-28T12:00:00Z"},
            {"from_number": "+123", "conversation_id": "CONV002",
             "state": "BOOKING", "status": "active", "last_message_at": "2026-05-29T12:00:00Z"},
        ]
        result = simulate_cancel_check(self.PAYLOAD, conversations)
        assert result["conversation_id"] == "CONV002"
        assert result["current_state"] == "BOOKING"

    def test_no_active_conv_known_sender_resets(self):
        """No active conv + known sender → starts at CONSULTING with NEW conversation_id."""
        conversations = [
            {"from_number": "+123", "conversation_id": "CONV001",
             "state": "CONSULTING", "status": "completed", "last_message_at": "2026-05-28T12:00:00Z"},
            {"from_number": "+123", "conversation_id": "CONV002",
             "state": "DONE", "status": "completed", "last_message_at": "2026-05-29T12:00:00Z"},
        ]
        result = simulate_cancel_check(self.PAYLOAD, conversations)
        # No active conv found, so falls to knownSender → CONSULTING, new conversation_id
        assert result["conversation_id"] == self.PAYLOAD["message_id"]  # new ID
        assert result["current_state"] == "CONSULTING"  # known sender fallback
        assert result["known_sender"] is True
        assert result["has_existing_conv"] is False


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Keyword Scorer
# ═══════════════════════════════════════════════════════════════════════════


class TestKeywordScorer:
    def test_greeting(self):
        """'hi' should score as greeting."""
        result = simulate_keyword_scorer({"message_body": "Hi there!"})
        assert result["primary_intent"] == "greeting"
        assert result["confidence"] >= 1

    def test_booking_phrase(self):
        """'book an appointment' should score as booking with high confidence."""
        result = simulate_keyword_scorer({"message_body": "I want to book an appointment"})
        assert result["primary_intent"] == "booking"
        assert result["confidence"] >= 3
        assert result["is_booking_intent"] is True

    def test_booking_tie_priority(self):
        """Booking should win ties with other intents."""
        result = simulate_keyword_scorer({"message_body": "book hello"})
        assert result["primary_intent"] == "booking"

    def test_reschedule_detected(self):
        """'reschedule' should be detected."""
        result = simulate_keyword_scorer({"message_body": "I need to reschedule"})
        assert result["primary_intent"] == "booking"

    def test_availability_detected(self):
        """'availability' should be detected."""
        result = simulate_keyword_scorer({"message_body": "check availability"})
        assert result["primary_intent"] == "booking"

    def test_pricing_question(self):
        """'how much' should score as pricing."""
        result = simulate_keyword_scorer({"message_body": "How much does it cost?"})
        assert result["primary_intent"] == "pricing"
        assert result["confidence"] >= 2

    def test_service_inquiry(self):
        """'what services' should score as service."""
        result = simulate_keyword_scorer({"message_body": "What services do you offer?"})
        assert result["primary_intent"] == "service"

    def test_telugu_detected(self):
        """Telugu keywords should be detected."""
        result = simulate_keyword_scorer({"message_body": "Namaskaram, ela unnaru?"})
        assert result["primary_intent"] == "telugu"

    def test_thanks_not_terminal_with_other_intent(self):
        """'thanks' is not terminal if another intent scores equally."""
        # "thanks, how much" → thanks=2, pricing (how much)=2 → tied → pricing wins
        result = simulate_keyword_scorer({"message_body": "thanks, how much"})
        assert result["primary_intent"] == "pricing", (
            f"Expected pricing on tie, got {result['primary_intent']}"
        )

    def test_thanks_not_terminal_with_higher_other(self):
        """'thanks' is not terminal if a booking phrase is present."""
        result = simulate_keyword_scorer({"message_body": "thank you, I want to book"})
        assert result["primary_intent"] == "booking"

    def test_name_phrase(self):
        """'my name is' should detect name intent."""
        result = simulate_keyword_scorer({"message_body": "My name is Ravi"})
        assert result["primary_intent"] == "name"

    def test_unknown_intent(self):
        """Gibberish should score as unknown."""
        result = simulate_keyword_scorer({"message_body": "asdfghjkl qwerty"})
        assert result["primary_intent"] == "unknown"
        assert result["confidence"] == 0

    def test_empty_body_unknown(self):
        """Empty body should score as unknown with zero confidence."""
        result = simulate_keyword_scorer({"message_body": ""})
        assert result["primary_intent"] == "unknown"
        assert result["confidence"] == 0

    def test_whitespace_body_unknown(self):
        """Whitespace-only body should score as unknown."""
        result = simulate_keyword_scorer({"message_body": "   "})
        assert result["primary_intent"] == "unknown"
        assert result["confidence"] == 0

    def test_phrase_weighting_higher_than_word(self):
        """Phrases should score higher than single words."""
        phrase_result = simulate_keyword_scorer({"message_body": "what is the price"})
        word_result = simulate_keyword_scorer({"message_body": "price"})
        assert phrase_result["confidence"] > word_result["confidence"]

    def test_multiple_categories(self):
        """Message matching multiple categories should have correct top_intents."""
        result = simulate_keyword_scorer({"message_body": "hello, how much for booking?"})
        assert len(result["top_intents"]) >= 2

    def test_follow_up_detected(self):
        """'follow up' should contribute to booking score."""
        result = simulate_keyword_scorer({"message_body": "I want to follow up on my booking"})
        assert result["primary_intent"] == "booking"


# ═══════════════════════════════════════════════════════════════════════════
# Tests: State Machine
# ═══════════════════════════════════════════════════════════════════════════


class TestStateMachine:
    # ── NEW state ──

    def test_new_to_consulting(self):
        """NEW + greeting → CONSULTING."""
        result = simulate_state_machine({
            "current_state": "NEW",
            "primary_intent": "greeting",
            "confidence": 1,
        })
        assert result["current_state"] == "CONSULTING"
        assert result["drift_detected"] is False

    def test_new_to_booking(self):
        """NEW + booking intent → BOOKING."""
        result = simulate_state_machine({
            "current_state": "NEW",
            "is_booking_intent": True,
            "primary_intent": "booking",
            "confidence": 3,
            "keyword_scores": {"booking": 3},
        })
        assert result["current_state"] == "BOOKING"

    def test_new_unknown_intent_drift(self):
        """NEW + unknown intent + state change → drift blocked."""
        result = simulate_state_machine({
            "current_state": "NEW",
            "primary_intent": "unknown",
            "confidence": 0,
            "is_booking_intent": False,
            "keyword_scores": {},
        })
        assert result["drift_detected"] is True
        # Since NEW → CONSULTING would change state, and intent is unknown,
        # drift blocks it — rolls back to NEW
        assert result["current_state"] == "NEW"

    # ── CONSULTING state ──

    def test_consulting_to_booking(self):
        """CONSULTING + booking → BOOKING."""
        result = simulate_state_machine({
            "current_state": "CONSULTING",
            "is_booking_intent": True,
            "primary_intent": "booking",
            "confidence": 3,
            "keyword_scores": {"booking": 3},
        })
        assert result["current_state"] == "BOOKING"

    def test_consulting_to_done_thanks(self):
        """CONSULTING + thanks (confidence ≥ 2) → DONE."""
        result = simulate_state_machine({
            "current_state": "CONSULTING",
            "primary_intent": "thanks",
            "confidence": 2,
        })
        assert result["current_state"] == "DONE"

    def test_consulting_to_done_high_confidence(self):
        """CONSULTING + high confidence resolved → DONE."""
        result = simulate_state_machine({
            "current_state": "CONSULTING",
            "primary_intent": "pricing",
            "confidence": 3,
        })
        assert result["current_state"] == "DONE"

    def test_consulting_stays(self):
        """CONSULTING + low confidence → stays."""
        result = simulate_state_machine({
            "current_state": "CONSULTING",
            "primary_intent": "service",
            "confidence": 1,
        })
        assert result["current_state"] == "CONSULTING"

    # ── BOOKING state ──

    def test_booking_to_done_confirmed(self):
        """BOOKING + thanks + confidence ≥ 2 → DONE."""
        result = simulate_state_machine({
            "current_state": "BOOKING",
            "primary_intent": "thanks",
            "confidence": 2,
        })
        assert result["current_state"] == "DONE"
        assert result["is_booking_complete"] is True

    def test_booking_to_done_name(self):
        """BOOKING + name intent → DONE."""
        result = simulate_state_machine({
            "current_state": "BOOKING",
            "primary_intent": "name",
            "confidence": 3,
            "keyword_scores": {"name": 3, "booking": 2},
        })
        assert result["current_state"] == "DONE"

    def test_booking_stays_without_confirmation(self):
        """BOOKING + low confidence → stays."""
        result = simulate_state_machine({
            "current_state": "BOOKING",
            "primary_intent": "greeting",
            "confidence": 1,
        })
        assert result["current_state"] == "BOOKING"
        assert result["is_booking_complete"] is False

    # ── DONE state ──

    def test_done_stays_terminal(self):
        """DONE → stays DONE."""
        result = simulate_state_machine({
            "current_state": "DONE",
            "primary_intent": "booking",
        })
        assert result["current_state"] == "DONE"

    # ── CANCELLED ──

    def test_cancel_from_any_state(self):
        """Cancel → CANCELLED."""
        for state in ("NEW", "CONSULTING", "BOOKING", "DONE"):
            result = simulate_state_machine({
                "current_state": state,
                "is_cancel_request": True,
            })
            assert result["current_state"] == "CANCELLED", f"Failed for {state}"
            assert result["drift_detected"] is False

    # ── Unknown state ──

    def test_unknown_state_reset(self):
        """Unknown/corrupted state → reset to NEW with drift."""
        result = simulate_state_machine({
            "current_state": "INVALID",
            "primary_intent": "greeting",
            "confidence": 1,
        })
        assert result["current_state"] == "NEW"
        assert result["drift_detected"] is True

    # ── Drift detection ──

    def test_drift_logged(self):
        """Drift should set drift_detected flag."""
        result = simulate_state_machine({
            "current_state": "NEW",
            "primary_intent": "unknown",
            "confidence": 0,
            "is_booking_intent": False,
            "keyword_scores": {},
        })
        assert result["drift_detected"] is True
        assert "DRIFT" in result["state_note"]

    def test_cancel_does_not_cause_drift(self):
        """Cancel should not cause drift even with unknown intent."""
        result = simulate_state_machine({
            "current_state": "NEW",
            "primary_intent": "unknown",
            "is_cancel_request": True,
        })
        assert result["drift_detected"] is False
        assert result["current_state"] == "CANCELLED"

    def test_state_note_tracks_transition(self):
        """State note should describe the transition."""
        result = simulate_state_machine({
            "current_state": "NEW",
            "is_booking_intent": True,
            "keyword_scores": {"booking": 3},
        })
        assert "NEW" in result["state_note"]
        assert "BOOKING" in result["state_note"]

    def test_previous_state_is_set(self):
        """previous_state should equal the input current_state."""
        result = simulate_state_machine({
            "current_state": "CONSULTING",
            "is_booking_intent": True,
            "primary_intent": "booking",
            "confidence": 3,
            "keyword_scores": {"booking": 3},
        })
        assert result["previous_state"] == "CONSULTING"
        assert result["current_state"] == "BOOKING"


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Build Reply
# ═══════════════════════════════════════════════════════════════════════════


class TestBuildReply:
    def test_new_greeting_reply(self):
        """NEW state + greeting intent → welcome message."""
        reply = simulate_build_reply({"current_state": "NEW", "primary_intent": "greeting"})
        assert "Hello" in reply
        assert "Alance" in reply
        assert "👋" in reply

    def test_new_pricing_reply(self):
        """NEW state + pricing intent → pricing response."""
        reply = simulate_build_reply({"current_state": "NEW", "primary_intent": "pricing"})
        assert "pricing" in reply.lower()
        assert "💰" in reply

    def test_new_service_reply(self):
        """NEW state + service intent → service response."""
        reply = simulate_build_reply({"current_state": "NEW", "primary_intent": "service"})
        assert "services" in reply.lower()
        assert "😊" in reply

    def test_new_telugu_reply(self):
        """Telugu intent → Telugu response."""
        reply = simulate_build_reply({"current_state": "NEW", "primary_intent": "telugu"})
        assert "Namaskaram" in reply
        assert "🙏" in reply
        assert "sahayam" in reply

    def test_consulting_default_reply(self):
        """CONSULTING state + unknown intent → generic welcome."""
        reply = simulate_build_reply({"current_state": "CONSULTING", "primary_intent": "unknown"})
        assert "Alance" in reply
        assert "👋" in reply

    def test_booking_reply(self):
        """BOOKING state → scheduling prompt."""
        reply = simulate_build_reply({"current_state": "BOOKING"})
        assert "book" in reply.lower()
        assert "📅" in reply

    def test_done_reply(self):
        """DONE state → confirmation."""
        reply = simulate_build_reply({"current_state": "DONE"})
        assert "confirmed" in reply.lower()
        assert "✅" in reply

    def test_cancelled_reply(self):
        """CANCELLED state → cancellation confirmation."""
        reply = simulate_build_reply({"is_cancel_request": True, "current_state": "CANCELLED"})
        assert "cancelled" in reply.lower()
        assert "✅" in reply

    def test_cancel_is_cancelled_reply(self):
        """Cancel path forces CANCELLED state."""
        reply = simulate_build_reply({
            "is_cancel_request": True,
            "current_state": "NEW",
            "primary_intent": "greeting",
        })
        assert "cancelled" in reply.lower()

    def test_default_reply(self):
        """Unknown state → generic fallback."""
        reply = simulate_build_reply({"current_state": "INVALID"})
        assert "Alance" in reply


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Compute Metrics
# ═══════════════════════════════════════════════════════════════════════════


class TestComputeMetrics:
    TODAY = "2026-05-29"
    YESTERDAY = "2026-05-28"

    def test_empty_data(self):
        """Empty ledger and errors should produce zero counts."""
        result = simulate_compute_metrics([], [], today=self.TODAY)
        assert result["total_messages"] == 0
        assert result["errors_total"] == 0
        assert result["processed"] == 0
        assert result["cached_duplicates"] == 0

    def test_counts_messages(self):
        """Should count today's messages by status."""
        rows = [
            {"processed_at": f"{self.TODAY}T10:00:00Z", "status": "replied"},
            {"processed_at": f"{self.TODAY}T10:01:00Z", "status": "replied"},
            {"processed_at": f"{self.TODAY}T10:02:00Z", "status": "cached"},
            {"processed_at": f"{self.TODAY}T10:03:00Z", "status": "cancelled"},
            {"processed_at": f"{self.TODAY}T10:04:00Z", "status": "booking_done"},
            {"processed_at": f"{self.TODAY}T10:05:00Z", "status": "drift_sent"},
        ]
        result = simulate_compute_metrics(rows, [], today=self.TODAY)
        assert result["total_messages"] == 6
        assert result["processed"] == 2
        assert result["cached_duplicates"] == 1
        assert result["cancellations"] == 1
        assert result["bookings_completed"] == 1
        assert result["drift_events"] == 1

    def test_ignores_yesterday(self):
        """Yesterday's data should be excluded."""
        today_rows = [
            {"processed_at": f"{self.TODAY}T10:00:00Z", "status": "replied"},
        ]
        yesterday_rows = [
            {"processed_at": f"{self.YESTERDAY}T10:00:00Z", "status": "replied"},
        ]
        result = simulate_compute_metrics(today_rows + yesterday_rows, [], today=self.TODAY)
        assert result["total_messages"] == 1

    def test_counts_errors(self):
        """Should count today's errors."""
        rows = [
            {"timestamp": f"{self.TODAY}T10:00:00Z", "error_type": "Error"},
            {"timestamp": f"{self.TODAY}T10:01:00Z", "error_type": "TypeError"},
            {"timestamp": f"{self.TODAY}T10:02:00Z", "error_type": "Error"},
        ]
        result = simulate_compute_metrics([], rows, today=self.TODAY)
        assert result["errors_total"] == 3
        assert "Error" in result["distinct_error_types"]
        assert "TypeError" in result["distinct_error_types"]

    def test_environment_from_ledger(self):
        """Environment should come from ledger rows."""
        rows = [{"processed_at": f"{self.TODAY}T10:00:00Z", "status": "replied", "environment": "production"}]
        result = simulate_compute_metrics(rows, [], today=self.TODAY)
        assert result["environment"] == "production"

    def test_date_is_correct(self):
        """Date should match today."""
        result = simulate_compute_metrics([], [], today=self.TODAY)
        assert result["date"] == self.TODAY


# ═══════════════════════════════════════════════════════════════════════════
# Tests: Format Error
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatError:
    def test_basic_error_formatting(self):
        """Error should be formatted with all fields."""
        error_data = {
            "error": {"message": "Failed to send Twilio message", "name": "TwilioError"},
            "workflow": {"id": "wf_123", "name": "Alance V1"},
            "execution": {"id": "exec_456"},
            "lastNodeExecuted": "Send Reply (Production)",
        }
        result = simulate_format_error(error_data, environment="production")
        assert result["error_message"] == "Failed to send Twilio message"
        assert result["error_type"] == "TwilioError"
        assert result["workflow_id"] == "wf_123"
        assert result["workflow_name"] == "Alance V1"
        assert result["execution_id"] == "exec_456"
        assert result["last_node"] == "Send Reply (Production)"
        assert result["severity"] == "error"
        assert result["environment"] == "production"
        assert "timestamp" in result

    def test_missing_error_data(self):
        """Missing data should fall back to 'unknown'."""
        result = simulate_format_error({})
        assert result["error_message"] == "Unknown error"
        assert result["workflow_name"] == "unknown"
        assert result["environment"] == "sandbox"


# ═══════════════════════════════════════════════════════════════════════════
# Integration Tests: Full Conversation Paths
# ═══════════════════════════════════════════════════════════════════════════


def simulate_full_flow(
    twilio_payload: dict,
    ledger: list[dict] | None = None,
    conversations: list[dict] | None = None,
    environment: str = "sandbox",
) -> dict:
    """Simulate the full main workflow for a single message."""
    ledger = ledger or []
    conversations = conversations or []

    # Step 1: Extract Payload
    payload = simulate_extract_payload(twilio_payload, environment)

    # Step 2: Check Duplicate
    check = simulate_check_duplicate(payload, ledger)

    if check["is_duplicate"]:
        return {"action": "duplicate", "payload": check, "reply": None}

    # Step 3: Is Status Callback?
    if payload["is_status_callback"]:
        return {"action": "status_callback", "payload": payload, "reply": None}

    # Step 4: Cancel/Stop Check
    cancel_check = simulate_cancel_check(payload, conversations)

    # Step 5: Is Cancel?
    if cancel_check["is_cancel_request"]:
        state_machine_result = simulate_state_machine(cancel_check)
        reply = simulate_build_reply(state_machine_result)
        return {
            "action": "cancelled",
            "payload": {**state_machine_result, "reply_text": reply},
            "reply": reply,
        }

    # Step 6: Keyword Scorer
    scorer_result = simulate_keyword_scorer(cancel_check)

    # Step 7: State Machine
    state_machine_result = simulate_state_machine(scorer_result)

    # Step 8: Is Drift?
    drift_detected = state_machine_result["drift_detected"]

    # Step 9: Build Reply
    reply = simulate_build_reply(state_machine_result)

    return {
        "action": "drift" if drift_detected else "normal",
        "payload": {**state_machine_result, "reply_text": reply},
        "reply": reply,
        "state_machine": {
            "from": state_machine_result["previous_state"],
            "to": state_machine_result["current_state"],
        },
    }


class TestFullFlow:
    """Integration tests for complete conversation paths."""

    def test_duplicate_message(self):
        """Same message sent twice should be caught as duplicate."""
        # First, compute the actual ledger_key from the simulated extract
        payload = simulate_extract_payload(
            {"MessageSid": "SM001", "From": "+123", "Body": "Hello", "NumMedia": "0"}
        )
        ledger = [
            {"message_id": "SM001", "ledger_key": payload["ledger_key"], "from_number": "+123"},
        ]
        result = simulate_full_flow(
            {"MessageSid": "SM002", "From": "+123", "Body": "Hello", "NumMedia": "0"},
            ledger=ledger,
        )
        # Should be duplicate by ledger_key (same body + from_number)
        assert result["action"] == "duplicate"

    def test_status_callback(self):
        """Status callback should be identified."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123", "Body": "",
             "SmsStatus": "delivered", "NumMedia": "0"},
        )
        assert result["action"] == "status_callback"

    def test_happy_path_greeting(self):
        """New user sends greeting → CONSULTING + reply."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123", "Body": "Hi there!", "NumMedia": "0"},
        )
        assert result["action"] == "normal"
        assert result["state_machine"]["from"] == "NEW"
        assert result["state_machine"]["to"] == "CONSULTING"
        assert "Hello" in (result["reply"] or "")

    def test_booking_path(self):
        """Booking intent → BOOKING state."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123",
             "Body": "I want to book an appointment", "NumMedia": "0"},
        )
        assert result["action"] == "normal"
        assert result["state_machine"]["to"] == "BOOKING"
        assert "book" in (result["reply"] or "").lower()

    def test_cancel_path(self):
        """Cancel request → CANCELLED."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123", "Body": "cancel", "NumMedia": "0"},
        )
        assert result["action"] == "cancelled"
        assert result["payload"]["current_state"] == "CANCELLED"
        assert "cancelled" in (result["reply"] or "").lower()

    def test_unsubscribe_path(self):
        """Unsubscribe request → CANCELLED."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123",
             "Body": "unsubscribe", "NumMedia": "0"},
        )
        assert result["action"] == "cancelled"

    def test_drift_path(self):
        """Unknown intent leading to state change → drift."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123",
             "Body": "asdfghjkl qwerty", "NumMedia": "0"},
        )
        # From NEW, unknown intent with no scoring → drift blocked
        assert result["action"] == "drift"

    def test_complete_booking_journey(self):
        """Full booking journey: greeting → booking → name → done."""
        # Step 1: Greeting
        msg1 = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123", "Body": "Hi!", "NumMedia": "0"},
        )
        assert msg1["state_machine"]["to"] == "CONSULTING"

        conversations = [{
            "from_number": "+123",
            "conversation_id": "CONV001",
            "state": "CONSULTING",
            "status": "active",
        }]

        # Step 2: Booking intent
        msg2 = simulate_full_flow(
            {"MessageSid": "SM002", "From": "+123",
             "Body": "I want to book", "NumMedia": "0"},
            conversations=conversations,
        )
        assert msg2["state_machine"]["to"] == "BOOKING"

        conversations[0]["state"] = "BOOKING"

        # Step 3: Name + thanks → DONE
        msg3 = simulate_full_flow(
            {"MessageSid": "SM003", "From": "+123",
             "Body": "My name is Ravi, thank you", "NumMedia": "0"},
            conversations=conversations,
        )
        assert msg3["state_machine"]["to"] == "DONE"
        assert msg3["payload"]["is_booking_complete"] is True
        assert "confirmed" in (msg3["reply"] or "").lower()

    def test_same_body_different_sender(self):
        """Same message body from different senders → not duplicate."""
        sender_a = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+111",
             "Body": "Hello", "NumMedia": "0"},
        )
        assert sender_a["action"] == "normal"

        # Same body from different sender with no existing ledger
        sender_b = simulate_full_flow(
            {"MessageSid": "SM002", "From": "+222",
             "Body": "Hello", "NumMedia": "0"},
        )
        assert sender_b["action"] == "normal"

    def test_menu_request(self):
        """'menu' → CANCELLED path."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123",
             "Body": "menu", "NumMedia": "0"},
        )
        assert result["action"] == "cancelled"

    def test_stop_all(self):
        """'stop all' → CANCELLED path."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123",
             "Body": "stop all messages", "NumMedia": "0"},
        )
        assert result["action"] == "cancelled"

    def test_help_request(self):
        """'help' → CANCELLED path (routed as menu)."""
        result = simulate_full_flow(
            {"MessageSid": "SM001", "From": "+123",
             "Body": "help", "NumMedia": "0"},
        )
        assert result["action"] == "cancelled"

    def test_known_sender_continuation(self):
        """Known sender continues at correct state."""
        conversations = [{
            "from_number": "+123", "conversation_id": "CONV001",
            "state": "BOOKING", "status": "active",
        }]
        result = simulate_full_flow(
            {"MessageSid": "SM002", "From": "+123",
             "Body": "yes please", "NumMedia": "0"},
            conversations=conversations,
        )
        assert result["state_machine"]["from"] == "BOOKING"
