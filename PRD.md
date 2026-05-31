# Alance V1 — Product Requirements Document

> **Status:** Draft · **Last updated:** 2026-05-29  
> **Owner:** Product Team  
> **Target release:** V1

---

## 1. Executive Summary

Alance V1 is a production-hardened WhatsApp chatbot system built on n8n that automates customer conversations for a service-business (appointments, inquiries, pricing). It provides idempotent message handling, stateful conversation management, drift detection, error recovery, and nightly health metrics — all without a traditional backend.

---

## 2. Problem Statement

Service businesses receive high volumes of WhatsApp messages — booking requests, pricing questions, cancellations, and general inquiries. Manual handling leads to:

- **Slow response times** — customers wait hours for replies.
- **Lost leads** — booking intents go unanswered outside business hours.
- **Inconsistent replies** — different staff give different information.
- **No visibility** — no structured data on conversations, leads, or drift.
- **No safety net** — errors in the automation pipeline go unnoticed until a customer complains.

---

## 3. Target Users

| Persona | Description | Needs |
|---|---|---|
| **Customer** | End-user sending WhatsApp messages to the business | Fast, accurate replies; easy booking; cancellation support |
| **Business Operator** | Staff monitoring the system | Dashboard visibility; drift/error alerts; nightly health metrics; lead capture |
| **Developer** | Person deploying and maintaining the system | Clear deployment docs; error logs; testable workflows; credential management |

---

## 4. MVP Scope (V1)

### 4.1 Core Messaging

| Feature | Description | Priority |
|---|---|---|
| WhatsApp inbound | Receive messages via Twilio webhook | P0 |
| Auto-reply | Contextual reply based on conversation state | P0 |
| Idempotency | Duplicate message detection — same message_id → 200 OK skip | P0 |
| Status callbacks | Track delivery status from Twilio | P1 |

### 4.2 Conversation Management

| Feature | Description | Priority |
|---|---|---|
| State machine | 4-state conversational flow: NEW → CONSULTING → BOOKING → DONE | P0 |
| Cancellation | Cancel/stop/menu keywords → CANCELLED state | P0 |
| Keyword scoring | Intent detection via keyword matching (10 categories) | P0 |
| Drift detection | Alert on unexpected state transitions | P1 |
| LEADS capture | On booking completion, write structured lead to LEADS sheet | P1 |

### 4.3 Reliability

| Feature | Description | Priority |
|---|---|---|
| Error workflow | Error Trigger → Telegram alert → ERRORS sheet log | P0 |
| Fallback reply | If Twilio send fails, reply with safe fallback message | P0 |
| Sandbox/Production split | Environment variable routes to correct Twilio credentials | P1 |
| Silent-success detection | Track messages where Twilio 200 OK but delivery later fails | P2 |

### 4.4 Observability

| Feature | Description | Priority |
|---|---|---|
| Nightly metrics | Schedule-triggered aggregation → HEALTHMETRICS sheet | P1 |
| Telegram drift alerts | Real-time alert on unexpected state transitions | P1 |
| Telegram error alerts | Real-time alert on workflow errors | P1 |

### 4.5 Testing & Deployment

| Feature | Description | Priority |
|---|---|---|
| Webhook variant | Simpler webhook-only version for curl/Postman testing | P2 |
| Deployment guide | README with full 7-step deployment process | P0 |
| Sheet schemas | Documented schemas for all 6 Google Sheets tabs | P0 |
| Credential templates | Named credential placeholders (Twilio, Google Sheets, Telegram) | P0 |

---

## 5. Future Features (Post-V1)

| Feature | Description | Priority |
|---|---|---|
| NLP-powered intent | Replace keyword scoring with LLM-based intent classification | Future |
| Multi-language support | Detect language (Telugu, Hindi, English) and reply in-kind | Future |
| Agent handoff | Escalate to human agent when confidence is low | Future |
| Dashboard | Web dashboard for real-time conversation monitoring | Future |
| A/B reply templates | Test different reply messages | Future |
| Scheduling | Integrate calendar API for actual booking | Future |
| CRM sync | Push leads to external CRM | Future |

---

## 6. System Constraints

| Constraint | Value |
|---|---|
| Max message processing time | < 30s (Twilio webhook timeout) |
| Duplicate detection window | Based on MESSAGE_LEDGER (all rows loaded) |
| State machine states | 4 (NEW, CONSULTING, BOOKING, DONE) + 1 (CANCELLED) |
| Metrics schedule | Daily at 00:00 UTC |
| Supported keywords | 10 categories, ~50 keywords total |
| Credentials required | 4 (TwilioSandbox, TwilioProduction, GoogleSheetsAlance, TelegramAlanceBot) |

---

## 7. Acceptance Criteria

### 7.1 Inbound Path

```
GIVEN a Twilio webhook POST to /twilio-webhook
WHEN the message is new (not a duplicate)
AND it's NOT a status callback
THEN the system replies within 30 seconds
AND the interaction is logged to MESSAGE_LEDGER
```

### 7.2 Idempotency

```
GIVEN a Twilio webhook POST with message_id X
WHEN message_id X already exists in MESSAGE_LEDGER
THEN the system responds 200 OK
AND does NOT process, reply, or log again
```

### 7.3 Status Callback Handling

```
GIVEN a Twilio webhook POST
WHEN sms_status or MessageStatus is present
THEN the system updates the delivery status in MESSAGE_LEDGER
AND does NOT trigger conversation processing
```

### 7.4 State Machine

```
GIVEN a new message (no existing conversation)
WHEN the message contains booking intent
THEN state transitions from NEW → BOOKING
AND reply is booking-related

GIVEN a message in CONSULTING state
WHEN the message contains booking intent
THEN state transitions from CONSULTING → BOOKING
```

### 7.5 Cancellation

```
GIVEN any conversation state
WHEN the message contains cancel/stop/menu keywords
THEN state transitions to CANCELLED
AND cancellation is logged to CONVERSATIONS
AND reply confirms cancellation
```

### 7.6 Drift Detection

```
GIVEN a state machine transition
WHEN the intent is "unknown" AND the state changes
THEN drift_detected = true
AND a STATE_DRIFT row is appended
AND a Telegram alert is sent
AND the state stays unchanged
```

### 7.7 Error Handling

```
GIVEN an error in the main workflow
WHEN the error workflow is linked
THEN a Telegram alert is sent with workflow/node/error info
AND a structured error record is appended to ERRORS sheet
```

### 7.8 LEADS Capture

```
GIVEN a booking completion (state transitions to DONE from BOOKING)
WHEN the reply is sent and logged
THEN a lead record is appended to LEADS sheet
```

### 7.9 Nightly Metrics

```
GIVEN the Schedule Trigger fires at 00:00 UTC
WHEN both MESSAGE_LEDGER and ERRORS are read
THEN a daily-aggregated row is appended to HEALTHMETRICS
AND all metric fields are populated
```

### 7.10 Fallback Reply

```
GIVEN a Twilio send operation
WHEN the API call fails (network error, auth failure, etc.)
THEN the fallback reply is sent instead
AND the fallback_triggered flag is set
```

---

## 8. Non-Goals (V1)

- No human-agent handoff
- No calendar API integration
- No web dashboard
- No CRM sync
- No multi-language NLP (keyword-only)
- No A/B testing
- No rate limiting beyond Twilio's built-in limits
- No analytics beyond nightly metrics

---

## 9. Glossary

| Term | Definition |
|---|---|
| Drift | An unexpected state transition where intent classification doesn't match the state change |
| Idempotency | The property of processing a message only once, regardless of how many times it's received |
| MESSAGE_LEDGER | Google Sheets tab that logs every processed message and its reply |
| HEALTHMETRICS | Google Sheets tab with daily aggregated health data |
| Silent success | A message that Twilio accepted (200 OK) but later failed delivery |
| STATE_DRIFT | Google Sheets tab recording unexpected state transitions |
