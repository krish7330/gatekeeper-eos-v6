# Alance V1 — Technical Design Document

> **Status:** Draft · **Last updated:** 2026-05-29  
> **Architecture:** n8n workflow-based, no backend server

---

## 1. System Architecture

### 1.1 High-Level Overview

```
                    ┌─────────────────────────────────────────────────┐
                    │                 Twilio API                      │
                    │  (WhatsApp Sender + Status Callbacks)            │
                    └─────────────┬─────────────────────┬─────────────┘
                                  │ POST /twilio-webhook │ POST (status)
                                  ▼                      ▼
                    ┌─────────────────────────────────────────┐
                    │          n8n Instance                    │
                    │                                          │
                    │  ┌─────────────────────────────────┐     │
                    │  │  Main Workflow (27 nodes)        │     │
                    │  │  - Webhook ingress              │     │
                    │  │  - Idempotency gate             │     │
                    │  │  - State machine                │     │
                    │  │  - Twilio dual-path send        │     │
                    │  │  - LEADS capture                │     │
                    │  └─────────────────────────────────┘     │
                    │                                          │
                    │  ┌─────────────────────────────────┐     │
                    │  │  Error Workflow (5 nodes)        │     │
                    │  │  - Error Trigger                │     │
                    │  │  - Telegram + ERRORS sheet      │     │
                    │  └─────────────────────────────────┘     │
                    │                                          │
                    │  ┌─────────────────────────────────┐     │
                    │  │  Metrics Workflow (7 nodes)      │     │
                    │  │  - Schedule Trigger 00:00 UTC   │     │
                    │  │  - Aggregate → HEALTHMETRICS    │     │
                    │  └─────────────────────────────────┘     │
                    │                                          │
                    │  ┌─────────────────────────────────┐     │
                    │  │  Webhook Variant (10 nodes)      │     │
                    │  │  - Standalone test endpoint     │     │
                    │  │  - curl/Postman-friendly        │     │
                    │  └─────────────────────────────────┘     │
                    └─────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────────────┐
                    │         Google Sheets (1 doc, 6 tabs)    │
                    │  MESSAGE_LEDGER │ CONVERSATIONS │ LEADS │
                    │  STATE_DRIFT    │ ERRORS        │ HEALTH │
                    └─────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────────────┐
                    │            Telegram Bot                   │
                    │  Drift alerts │ Error alerts              │
                    └─────────────────────────────────────────┘
```

### 1.2 Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Workflow engine | n8n (self-hosted or cloud) | Orchestration, triggers, node execution |
| SMS/WhatsApp | Twilio API | Send/receive WhatsApp messages |
| Database | Google Sheets (1 doc, 6 tabs) | Message ledger, conversations, metrics, errors |
| Alerting | Telegram Bot API | Drift and error notifications |
| Environment config | n8n env vars | Switch between sandbox/production |
| Testing | n8n Webhook Variant / curl | Pre-deployment validation |

---

## 2. Main Workflow Architecture

### 2.1 Node Map

```
Webhook (POST /twilio-webhook)
  │
  ▼
Extract Payload (Code: normalise Twilio fields)
  │
  ▼
Read MESSAGE_LEDGER (Google Sheets: all rows)
  │
  ▼
Check Duplicate (Code: compare message_id against ledger)
  │
  ▼
Is Duplicate? (IF: boolean equals true)
  ├── true  → Respond 200 OK (NoOp) → Done
  │
  └── false → Is Status Callback? (IF: sms_status isNotEmpty)
                ├── true  → Update Delivery Status (GS: append)
                │             │
                │             ▼
                │          Done
                │
                └── false → Read CONVERSATIONS (GS: all rows)
                              │
                              ▼
                           Cancel/Stop Check (Code: keyword match)
                              │
                              ▼
                           Is Cancel? (IF: boolean equals true)
                              ├── true  → Build Reply
                              │             │
                              │             ▼
                              │       Append MESSAGE_LEDGER (status: cancelled)
                              │             │
                              │             ▼
                              │       Append CONVERSATIONS (state: CANCELLED)
                              │             │
                              │             ▼
                              │          Done
                              │
                              └── false ─────────────────────────────────┘
                                                                          │
                                                                          ▼
                                                                   Keyword Scorer (Code: 10-category intent)
                                                                          │
                                                                          ▼
                                                                   State Machine (Code: 4-state transitions)
                                                                          │
                                                                          ▼
                                                                   Is Drift? (IF: boolean equals true)
                                                                      ├── true  → Log STATE_DRIFT (GS: append)
                                                                      │             │
                                                                      │             ├── (parallel) Telegram Alert (Drift)
                                                                      │             │                 │
                                                                      │             ▼                 ▼
                                                                      │          Done            Build Reply
                                                                      │
                                                                      └── false → Build Reply (Code: state-based reply)
                                                                                    │
                                                                                    ▼
                                                                             Is Production? (IF: env equals production)
                                                                              ├── true  → Send Reply (Production) (Twilio send)
                                                                              │             │                   │
                                                                              │             ▼                   ▼ (error)
                                                                              │       Append MESSAGE_LEDGER  Fallback Reply
                                                                              │             │                   │
                                                                              │             ▼                   ▼
                                                                              │       Booking Complete?   Append MESSAGE_LEDGER
                                                                              │        ├── true → Append LEADS
                                                                              │        └── false → Done
                                                                              │
                                                                              └── false → Send Reply (Sandbox) (Twilio send)
                                                                                            │                   │
                                                                                            ▼                   ▼ (error)
                                                                                      Append MESSAGE_LEDGER  Fallback Reply
                                                                                            │                   │
                                                                                            ▼                   ▼
                                                                                      Booking Complete?   Append MESSAGE_LEDGER
                                                                                       ├── true → Append LEADS
                                                                                       └── false → Done
```

### 2.2 Data Flow

#### Inbound Message (Happy Path)

1. **Webhook** receives POST with Twilio fields
2. **Extract Payload** normalises: `MessageSid`, `From`, `Body`, `SmsStatus`, etc.
3. **Read MESSAGE_LEDGER** loads all ledger rows
4. **Check Duplicate** compares `message_id` against ledger using `$node["Extract Payload"]` reference (survives Google Sheets item replacement)
5. **Is Duplicate?** — false → continue
6. **Is Status Callback?** — false (no sms_status) → continue
7. **Read CONVERSATIONS** loads existing conversations
8. **Cancel/Stop Check** detects cancel keywords via `$node["Extract Payload"]`
9. **Is Cancel?** — false → continue
10. **Keyword Scorer** scores intent (10 categories, weighted)
11. **State Machine** transitions state
12. **Is Drift?** — false → continue
13. **Build Reply** generates reply text based on state
14. **Is Production?** checks environment variable
15. **Send Reply** calls Twilio API with appropriate credentials
16. **Append MESSAGE_LEDGER** logs the interaction
17. **Booking Complete?** checks if booking was just completed
18. **Append LEADS** captures lead on booking

#### Duplicate Path

1-4. Same as above
5. **Is Duplicate?** — true
6. **Respond 200 OK** — no-op, returns empty TwiML

#### Status Callback Path

1-4. Same as above
5. **Is Duplicate?** — false
6. **Is Status Callback?** — true
7. **Update Delivery Status** appends status update to MESSAGE_LEDGER

### 2.3 State Machine Specification

```
                     ┌──────────────┐
                     │     NEW      │  (initial state)
                     └──────┬───────┘
                            │
               ┌────────────┴────────────┐
               │ booking intent          │ other intent
               ▼                         ▼
       ┌──────────────┐         ┌──────────────┐
       │   BOOKING    │         │  CONSULTING  │
       └──────┬───────┘         └──────┬───────┘
              │                        │
              │ thanks/name            │ booking
              ▼                        ▼
       ┌──────────────┐         ┌──────────────┐
       │    DONE      │         │   BOOKING    │
       └──────────────┘         └──────┬───────┘
                                        │ thanks
                                        ▼
                                 ┌──────────────┐
                                 │    DONE      │
                                 └──────────────┘

                              Any state
                                  │
                          cancel/stop/menu
                                  ▼
                          ┌──────────────┐
                          │  CANCELLED   │
                          └──────────────┘

Transition rules:
  NEW → BOOKING       if booking intent detected
  NEW → CONSULTING    if any other intent
  CONSULTING → BOOKING if booking intent detected
  CONSULTING → DONE   if confidence > 2 or thanks intent
  BOOKING → DONE      if thanks, name intent, or confidence > 1
  Any → CANCELLED     if cancel/stop/menu keywords
  Any (drift)         if state changes with unknown intent
```

---

## 3. Error Workflow Architecture

### 3.1 Node Map

```
Error Trigger
  │
  ▼
Format Error (Code: normalise error → structured columns)
  │
  ▼
Telegram Alert (Telegram: send error details)
  │
  ▼
Log to ERRORS Sheet (GS: append structured error record)
```

### 3.2 Error Data Captured

| Field | Source | Example |
|---|---|---|
| `error_message` | `$json.error.message` | "Failed to send Twilio message" |
| `error_type` | `$json.error.name` | "Error" |
| `workflow_id` | `$json.workflow.id` | "abc123" |
| `workflow_name` | `$json.workflow.name` | "Alance V1 – Production Hardened" |
| `execution_id` | `$json.execution.id` | "exec_456" |
| `last_node` | `$json.lastNodeExecuted` | "Send Reply (Production)" |

---

## 4. Metrics Workflow Architecture

### 4.1 Node Map

```
Schedule Trigger (cron: 0 0 * * *)
  │
  ├── Read MESSAGE_LEDGER (GS: all rows)
  │        │
  │        └──┬── Merge Data Sources (append mode)
  │           │
  └── Read ERRORS (GS: all rows)
                 │
                 ▼
          Compute Metrics (Code: filter today, aggregate)
                 │
                 ▼
          Append HEALTHMETRICS (GS: append summary row)
```

### 4.2 Metrics Computed

| Metric | Source | Computation |
|---|---|---|
| `total_messages` | MESSAGE_LEDGER | Count of today's rows |
| `processed` | MESSAGE_LEDGER | Count where status = "replied" or "processed" |
| `cached_duplicates` | MESSAGE_LEDGER | Count where status = "cached" or "delivery_update" |
| `cancellations` | MESSAGE_LEDGER | Count where status = "cancelled" |
| `bookings_completed` | MESSAGE_LEDGER | Count where status = "booking_done" |
| `drift_events` | MESSAGE_LEDGER | Count where status contains "drift" |
| `errors_total` | ERRORS | Count of today's error rows |
| `distinct_error_types` | ERRORS | Unique error_type values joined with ", " |

---

## 5. Webhook Variant Architecture

### 5.1 Node Map

```
Webhook (POST /webhook-test)
  │
  ▼
Extract Input (Code: normalise test payload)
  │
  ▼
Keyword Scorer (Code: same logic as main)
  │
  ▼
Build Test Reply (Code: state-based reply)
  │
  ▼
Respond (Webhook Response)
```

The webhook variant is a standalone testing workflow that accepts HTTP requests from curl, Postman, or any HTTP client. It does NOT connect to Twilio, Google Sheets, or Telegram — it simply processes the input and returns a reply.

### 5.2 Request Format

```json
POST /webhook-test
Content-Type: application/json

{
  "message": "I want to book an appointment",
  "from": "whatsapp:+919876543210"
}
```

### 5.3 Response Format

```json
{
  "reply": "I would be happy to book an appointment for you! 📅...",
  "intent": "booking",
  "confidence": 2,
  "state": "BOOKING"
}
```

---

## 6. Silent Success Detection

### 6.1 Problem

A "silent success" occurs when Twilio's Send API returns HTTP 200 OK (message accepted), but the final delivery status callback reports `failed` or `undelivered`. This means the operator believes a reply was sent, but the customer never received it.

### 6.2 Detection Strategy

The main workflow already routes status callbacks to **Update Delivery Status**. Silent success detection adds a check on this path:

1. When a status callback arrives with status `failed` or `undelivered`
2. Look up the original message in MESSAGE_LEDGER
3. If the original reply_sent field is populated (meaning send returned 200)
4. Flag as `silent_success: true` in the delivery update
5. Additionally log to ERRORS sheet as a warning-level event

This is implemented as a condition node in the delivery status update branch.

---

## 7. Credential Strategy

| Credential Name | Type | Environments | Notes |
|---|---|---|---|
| `TwilioSandbox` | Twilio API | sandbox | Uses Twilio sandbox Account SID/Auth Token |
| `TwilioProduction` | Twilio API | production | Production Twilio account with WhatsApp Sender |
| `GoogleSheetsAlance` | Google Sheets OAuth2 | all | OAuth consent with sheet access |
| `TelegramAlanceBot` | Telegram Bot API | all | Bot token from @BotFather |

The `ENVIRONMENT` environment variable (values: `sandbox`, `production`) controls which Twilio credential is used.

---

## 8. Google Sheet Schema

One Google Sheet with 6 tabs:

| Tab | Purpose | Key Columns |
|---|---|---|
| `MESSAGE_LEDGER` | All processed messages | message_id, from_number, status, state, reply_sent |
| `CONVERSATIONS` | Active/concluded conversations | conversation_id, from_number, state, timestamps |
| `LEADS` | Captured leads on booking | id, from_number, name, booking_time, lead_status |
| `STATE_DRIFT` | Unexpected state transitions | timestamp, conversation_id, expected_state, actual_state |
| `ERRORS` | Workflow error records | error_message, error_type, workflow_id, last_node |
| `HEALTHMETRICS` | Daily aggregated metrics | date, total_messages, processed, errors_total |

See `n8n/README.md` for full column schemas.

---

## 9. Error Handling Strategy

| Scenario | Detection | Response |
|---|---|---|
| Twilio API error | Error output on Twilio node | Fallback Reply → logged to MESSAGE_LEDGER with status "replied" |
| Workflow execution error | Error Trigger workflow | Telegram alert + ERRORS sheet append |
| Duplicate message | Check Duplicate code node | 200 OK, no processing |
| Status callback update | Is Status Callback? IF node | Delivery status logged, no reply |
| Unexpected state transition | Is Drift? IF node | STATE_DRIFT logged, Telegram alert sent |
| Silent success (failed delivery after 200) | Delivery status check | Warning logged to MESSAGE_LEDGER + ERRORS |

---

## 10. Testing Strategy

| Test Type | Tool | What It Validates |
|---|---|---|
| Webhook variant | curl/Postman | End-to-end message processing without Twilio |
| Manual WhatsApp test | Live Twilio number | Full production path |
| Error workflow test | Intentional misconfiguration | Error capture + Telegram alert |
| Metrics manual run | n8n "Execute Workflow" | HEALTHMETRICS row written |
| Duplicate test | Send same message twice | Second message → 200 OK skip |
| Credential switching | ENVIRONMENT=sandbox/production | Send Reply routes correctly |

See `TESTING.md` for complete testing strategy.
