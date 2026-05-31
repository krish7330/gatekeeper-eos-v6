# Alance V1 — n8n Production Workflows

Three n8n workflow exports forming a production-hardened WhatsApp chatbot system for **Alance**.

| File | Purpose | Nodes |
|---|---|---|
| `alance-main.json` | Main production workflow — webhook ingress, idempotency, state machine, Twilio send, drift alerts, LEADS capture | 27 |
| `alance-error.json` | Error handler — Telegram alert + ERRORS sheet logging | 5 |
| `alance-metrics.json` | Nightly metrics — aggregates daily stats to HEALTHMETRICS | 7 |

---

## Architecture

```
                            ┌─ [duplicate] → Respond 200 OK
                            │
Twilio Webhook ──→ Extract ──┼─ [status callback] → Update Delivery Status
                            │
                            └─ [new message] → Read CONVERSATIONS ──┐
                                                                     ├─ [cancel] → Build Reply
                                                                     │
                                                                     └─ [continue] → Keyword Scorer
                                                                                      │
                                                                                   State Machine
                                                                                  ┌──┴──┐
                                                                             [drift]  [ok]
                                                                                 │     │
                                                                          Log + Alert  │
                                                                                 │     │
                                                                              Build Reply
                                                                                  │
                                                                           Is Production?
                                                                          ┌────┴────┐
                                                                   [prod creds]  [sandbox creds]
                                                                          │     │
                                                                     Twilio Send  │
                                                                          │     │
                                                                     Fallback ←──┘ (error path)
                                                                          │
                                                                   Append MESSAGE_LEDGER
                                                                          │
                                                                   Append CONVERSATIONS
                                                                          │
                                                              Booking Complete? ──[yes]→ Append LEADS
                                                                          │
                                                                        Done
```

---

## Google Sheet Setup

Create **one** Google Sheet with **six tabs**:

### Tab 1: `MESSAGE_LEDGER`

| Column | Type | Example |
|---|---|---|
| `message_id` | Text | `SMa1b2c3d4e5f6` |
| `ledger_key` | Text | `a1b2c3d4e5f6g7h8` |
| `from_number` | Text | `whatsapp:+919876543210` |
| `message_body` | Text | `Hi, I'd like to book` |
| `reply_sent` | Text | `Sure! Let me help...` |
| `environment` | Text | `production` |
| `status` | Text | `replied`, `cached`, `drift_sent`, `cancelled`, `booking_done`, `delivery_update` |
| `state` | Text | `NEW`, `CONSULTING`, `BOOKING`, `DONE`, `CANCELLED` |
| `previous_state` | Text | `CONSULTING` |
| `state_note` | Text | `NEW -> BOOKING (booking intent)` |
| `drift_detected` | Boolean | `true`, `false` |
| `primary_intent` | Text | `booking`, `pricing`, `greeting`, `telugu` |
| `confidence` | Number | `3` |
| `processed_at` | Timestamp | `2026-05-29T12:00:00Z` |
| `reply_timestamp` | Timestamp | `2026-05-29T12:00:01Z` |

### Tab 2: `CONVERSATIONS`

| Column | Type | Example |
|---|---|---|
| `conversation_id` | Text | `SMa1b2c3d4e5f6` |
| `from_number` | Text | `whatsapp:+919876543210` |
| `state` | Text | `NEW`, `CONSULTING`, `BOOKING`, `DONE`, `CANCELLED` |
| `last_message_at` | Timestamp | `2026-05-29T12:00:00Z` |
| `created_at` | Timestamp | `2026-05-28T10:00:00Z` |
| `updated_at` | Timestamp | `2026-05-29T12:00:00Z` |

### Tab 3: `LEADS`

| Column | Type | Example |
|---|---|---|
| `id` | Text | `SMa1b2c3d4e5f6` |
| `from_number` | Text | `whatsapp:+919876543210` |
| `name` | Text | `Ravi Kumar` |
| `booking_time` | Timestamp | `2026-05-29T12:00:00Z` |
| `intent` | Text | `booking` |
| `source` | Text | `whatsapp` |
| `lead_status` | Text | `new`, `contacted`, `qualified`, `converted` |
| `environment` | Text | `production` |
| `notes` | Text | `Booking completed via WhatsApp` |

### Tab 4: `STATE_DRIFT`

| Column | Type | Example |
|---|---|---|
| `timestamp` | Timestamp | `2026-05-29T12:00:00Z` |
| `conversation_id` | Text | `SMa1b2c3d4e5f6` |
| `from_number` | Text | `whatsapp:+919876543210` |
| `expected_state` | Text | `CONSULTING` |
| `actual_state` | Text | `BOOKING` |
| `trigger_message` | Text | `book now` |
| `environment` | Text | `production` |
| `state_note` | Text | `DRIFT: CONSULTING → BOOKING` |

### Tab 5: `ERRORS`

| Column | Type | Example |
|---|---|---|
| `error_message` | Text | `Failed to send Twilio message` |
| `error_type` | Text | `Error` |
| `workflow_id` | Text | `abc123` |
| `workflow_name` | Text | `Alance V1 – Production Hardened` |
| `execution_id` | Text | `exec_456` |
| `last_node` | Text | `Send Reply (Production)` |
| `severity` | Text | `error` |
| `environment` | Text | `production` |
| `timestamp` | Timestamp | `2026-05-29T12:00:00Z` |

### Tab 6: `HEALTHMETRICS`

| Column | Type | Example |
|---|---|---|
| `date` | Date | `2026-05-29` |
| `total_messages` | Number | `142` |
| `processed` | Number | `98` |
| `cached_duplicates` | Number | `32` |
| `cancellations` | Number | `5` |
| `bookings_completed` | Number | `7` |
| `drift_events` | Number | `2` |
| `errors_total` | Number | `3` |
| `distinct_error_types` | Text | `Error, TypeError` |
| `environment` | Text | `production` |
| `computed_at` | Timestamp | `2026-05-30T00:00:01Z` |

Copy the **Sheet ID** from the URL: `https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/edit`

---

## Deployment Steps

### Step 1 — Import the workflows

1. Open your n8n instance
2. Go to **Workflows** → **Add Workflow** → **Import from File**
3. Import `alance-main.json`
4. Import `alance-error.json`
5. Import `alance-metrics.json`

### Step 2 — Create credentials

Create these four credentials in n8n (**Settings** → **Credentials** → **Add Credential**):

| Credential Name | Type | What to fill |
|---|---|---|
| `TwilioSandbox` | Twilio API | Account SID + Auth Token from [Twilio Console](https://console.twilio.com) (sandbox account) |
| `TwilioProduction` | Twilio API | Account SID + Auth Token (production Twilio account with WhatsApp Sender) |
| `GoogleSheetsAlance` | Google Sheets OAuth2 | OAuth with access to the Google Sheet created above |
| `TelegramAlanceBot` | Telegram Bot API | Bot token from [@BotFather](https://t.me/botfather) |

### Step 3 — Replace placeholders

In **all three workflows**, replace:

| Placeholder | Replace with |
|---|---|
| `YOUR_GOOGLE_SHEET_ID` | The Sheet ID from step 1 (appears in multiple nodes) |
| `YOUR_TELEGRAM_CHAT_ID` | Your Telegram chat ID for alerts (get from [@userinfobot](https://t.me/userinfobot)) |
| `+14155238886` | Your actual Twilio WhatsApp-enabled number (if different) |

### Step 4 — Link the error workflow

1. Open the main workflow (`Alance V1 – Production Hardened`)
2. Click **Workflow Settings** (gear icon)
3. Under **Error Workflow**, select `Alance V1 – Error Workflow`
4. Save

### Step 5 — Set environment variable

Set the `ENVIRONMENT` environment variable in n8n:

```
ENVIRONMENT=sandbox
```

For local n8n: add to your `.env` file or docker-compose environment.
For n8n cloud: use **Settings** → **Environment Variables** in the UI.

Start in `sandbox` mode. Switch to `production` when ready for live traffic.

### Step 6 — Activate and configure Twilio

1. **Activate** the Error Workflow first
2. **Activate** the Metrics Workflow (runs at midnight UTC)
3. **Activate** the Main Workflow
4. Copy the **Production Webhook URL** from the Webhook node (e.g. `https://your-n8n.com/webhook/twilio-webhook`)
5. Go to [Twilio Console](https://console.twilio.com) → WhatsApp → Sender
6. Set the webhook URL for **incoming messages** and **status callbacks**

### Step 7 — Test

1. Send a WhatsApp message to your Twilio number
2. Confirm the reply is received
3. Send the same message again — should get a cached/duplicate response
4. Send "cancel" or "stop" — confirm cancellation reply
5. Send a booking intent — confirm booking flow
6. Intentionally trigger an error (e.g., misconfigure a Twilio credential temporarily) — confirm Telegram alert fires
7. Manually run the metrics workflow — verify a row appears in HEALTHMETRICS

---

## State Machine

```
                      ┌──────────────────┐
                      │       NEW        │
                      └────────┬─────────┘
                               │
                  ┌────────────┴────────────┐
                  │ booking intent          │ other intent
                  ▼                         ▼
          ┌──────────────┐        ┌──────────────┐
          │   BOOKING    │        │  CONSULTING  │
          └──────┬───────┘        └──────┬───────┘
                 │                       │
                 │ thanks/name           │ booking
                 ▼                       ▼
          ┌──────────────┐        ┌──────────────┐
          │    DONE      │        │   BOOKING    │
          └──────────────┘        └──────┬───────┘
                                         │ thanks
                                         ▼
                                  ┌──────────────┐
                                  │    DONE      │
                                  └──────────────┘
```

**Special transitions:**
- Cancel/stop/menu → `CANCELLED` at any state
- Unknown intent + state change → `DRIFT` (logs to STATE_DRIFT, Telegram alert, stays in current state)

---

## What Each Workflow Does

### Main Workflow (27 nodes)

| Node | Type | Function |
|---|---|---|
| **Webhook** | webhook | Receives Twilio POST at `/twilio-webhook` |
| **Extract Payload** | code | Normalises Twilio fields into structured JSON |
| **Read MESSAGE_LEDGER** | googleSheets | Reads ledger for idempotency check |
| **Check Duplicate** | code | Compares SID against ledger via `$node` reference |
| **Is Duplicate?** | if | Routes duplicates to 200 OK, new messages forward |
| **Respond 200 OK (Duplicate)** | noOp | Acknowledges duplicate without processing |
| **Is Status Callback?** | if | Checks for `SmsStatus` field presence |
| **Update Delivery Status** | googleSheets | Appends delivery status update to ledger |
| **Read CONVERSATIONS** | googleSheets | Loads existing conversations for this number |
| **Cancel/Stop Check** | code | Detects cancel/stop/menu keywords |
| **Is Cancel?** | if | Routes cancellations to log, others to keyword scoring |
| **Append CONVERSATIONS** | googleSheets | Appends updated conversation state after every message |
| **Keyword Scorer** | code | Scores intent (greeting, booking, pricing, etc.) |
| **State Machine** | code | Transitions NEW→CONSULTING→BOOKING→DONE |
| **Is Drift?** | if | Checks for unexpected state transitions |
| **Log STATE_DRIFT** | googleSheets | Appends drift event to STATE_DRIFT sheet |
| **Telegram Alert (Drift)** | telegram | Sends drift alert with context |
| **Build Reply** | code | Generates contextual reply based on state |
| **Is Production?** | if | Routes to production or sandbox Twilio credentials |
| **Send Reply (Production)** | twilio | Sends via production Twilio credentials |
| **Send Reply (Sandbox)** | twilio | Sends via sandbox Twilio credentials |
| **Fallback Reply** | set | Provides safe reply when Twilio send fails |
| **Append MESSAGE_LEDGER** | googleSheets | Logs the interaction with status |
| **Booking Complete?** | if | Checks if booking was just completed |
| **Append LEADS** | googleSheets | Captures lead on booking completion |
| **Done** | noOp | Terminal node |

### Error Workflow (4 nodes)

| Node | Type | Function |
|---|---|---|
| **Error Trigger** | errorTrigger | Fires on any error in the linked workflow |
| **Format Error** | code | Extracts error details into structured columns |
| **Telegram Alert** | telegram | Sends error alert with workflow/node/error info |
| **Log to ERRORS Sheet** | googleSheets | Appends structured error record to ERRORS sheet |

### Metrics Workflow (6 nodes)

| Node | Type | Function |
|---|---|---|
| **Schedule Trigger** | scheduleTrigger | Runs at 00:00 UTC daily (cron: `0 0 * * *`) |
| **Read MESSAGE_LEDGER** | googleSheets | Reads all ledger rows |
| **Read ERRORS** | googleSheets | Reads all error rows |
| **Merge Data Sources** | merge | Appends both data sets together |
| **Compute Metrics** | code | Filters for today, aggregates counts |
| **Append HEALTHMETRICS** | googleSheets | Writes daily summary row |

---

## Customisation Points

- **Keyword Scorer**: Update the keyword lists in the Code node for your business domain
- **State Machine**: Modify the transition rules for your conversation flow
- **Build Reply**: Change the reply templates for each state
- **State Machine drift thresholds**: Adjust the drift detection logic
- **Twilio from number**: Replace `+14155238886` with your WhatsApp-enabled number
- **Webhook path**: Change `twilio-webhook` to any path you prefer

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No reply to WhatsApp | Webhook URL not set in Twilio, or Twilio credentials wrong |
| "Duplicate" reply on first message | MESSAGE_LEDGER sheet has stale data — clear it |
| Drift alerts firing constantly | Keyword Scorer needs tuning for your domain |
| Telegram alerts not arriving | Chat ID or bot token incorrect |
| Sheet not updating | Google Sheets OAuth expired — re-authorise in n8n |
| Metrics not writing | Schedule Trigger needs activation, or sheet name typo |
