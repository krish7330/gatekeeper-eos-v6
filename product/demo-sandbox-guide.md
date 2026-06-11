# Alance WhatsApp Bot — Demo Sandbox Setup Guide

> **Goal:** Set up a working demo chatbot in under 2 hours that you can show prospects  
> **Cost:** ~$1 (Twilio phone number) + free tier of n8n  
> **Result:** A live WhatsApp number prospects can message to see the bot in action

---

## 📋 Prerequisites

Before we start, you'll need:

| Item | Cost | Time to set up |
|------|------|---------------|
| A Google account (Gmail) | Free | 2 min |
| A Twilio account | Free | 5 min |
| n8n instance (self-hosted or cloud) | Free-$20/mo | 15-30 min |
| A Telegram account (for alerts) | Free | 2 min |
| A phone that can receive SMS | Already have it | 0 min |

---

## Step 1: Create a Google Sheet for the Demo

The chatbot logs all conversations, leads, and errors into Google Sheets. You need to create a sheet with the correct tab names.

### 1.1 Create the Sheet

1. Go to [sheets.new](https://sheets.new) — this creates a new Google Sheet
2. Rename the default sheet: Double-click "Sheet1" → rename to `MESSAGE_LEDGER`
3. Add remaining tabs by clicking the **+** button at the bottom:

   **For demo purposes (Business tier):**
   - `CONVERSATIONS`
   - `LEADS`
   - `STATE_DRIFT`
   - `ERRORS`
   - `HEALTHMETRICS`

4. **Copy the Sheet ID** from the URL:
   ```
   https://docs.google.com/spreadsheets/d/⚠️THIS-IS-THE-SHEET-ID⚠️/edit#gid=0
   ```
   That long string between `/d/` and `/edit` is your Sheet ID. Save it.

### 1.2 Add Header Rows to Each Tab

> **⚠️ Tab names are case-sensitive.** `MESSAGE_LEDGER` must be exactly that — not `message_ledger` or `Message Ledger`. The n8n workflow will fail if the tab name doesn't match exactly.

Copy these headers into row 1 of each tab:

**MESSAGE_LEDGER:**
```
message_id	ledger_key	from_number	message_body	reply_sent	environment	status	state	previous_state	state_note	drift_detected	primary_intent	confidence	processed_at	reply_timestamp
```

**CONVERSATIONS:**
```
conversation_id	from_number	state	status	last_message_at	created_at	updated_at
```

**LEADS:**
```
id	from_number	name	booking_time	intent	source	lead_status	environment	notes
```

**STATE_DRIFT:**
```
timestamp	conversation_id	from_number	expected_state	actual_state	trigger_message	environment	state_note
```

**ERRORS:**
```
error_message	error_type	workflow_id	workflow_name	execution_id	last_node	severity	environment	timestamp
```

**HEALTHMETRICS:**
```
date	total_messages	processed	cached_duplicates	cancellations	bookings_completed	drift_events	errors_total	distinct_error_types	environment	computed_at
```

> 💡 **Tip:** Create a template sheet with all these headers and tabs, then use "Make a copy" for each new client instead of creating from scratch.

---

## Step 2: Set Up Twilio Sandbox

Twilio provides a free sandbox for WhatsApp that lets you test without production approval.

### 2.1 Create a Twilio Account

1. Go to [twilio.com/try-twilio](https://www.twilio.com/try-twilio)
2. Sign up with your email and phone number
3. Verify your phone via SMS code
4. Answer the questionnaire (you can say "I'm building a WhatsApp chatbot")

### 2.2 Find Your Twilio Credentials

Once logged into the Twilio Console:

1. Look at the **Account SID** at the top of the dashboard — copy it
2. Click **"View Auth Token"** and copy it (keep this secret!)
3. Save both — you'll need them in Step 4

```
Account SID: ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Auth Token:  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 2.3 Set Up WhatsApp Sandbox

1. In the Twilio Console, go to **Messaging → Try it out → Send a WhatsApp Message**
2. You'll see a sandbox number (something like `+14155238886`)
3. **Important:** Save this sandbox number — it's what you'll use for your demo
4. To activate the sandbox, send the join code (shown on the page) via WhatsApp to the sandbox number

> ⏱ **Timeline:** Sandbox setup takes 5 minutes. The sandbox number is shared (all Twilio users use the same sandbox number), but your bot filters by your configured "from" number.

### 2.4 Configure the Webhook URL

In the Twilio Sandbox configuration:

1. Under **"When a message comes in"**, set the webhook URL to:
   ```
   https://[YOUR-N8N-URL]/webhook/twilio-webhook
   ```
2. Set method to **POST**
3. Save

> You won't know your n8n URL until Step 3. Come back to this after setting up n8n.

---

## Step 3: Set Up n8n

The chatbot runs on n8n. You have two options:

### Option A: n8n Cloud (Easiest — $20/month)

1. Go to [n8n.io](https://n8n.io) and sign up
2. Choose the Starter plan ($20/month) — it includes webhook URLs
3. After setup, your n8n URL will be: `https://[your-name].app.n8n.cloud`
4. Webhook URL for Twilio: `https://[your-name].app.n8n.cloud/webhook/twilio-webhook`

### Option B: Self-hosted (Free — recommended for now)

1. Install n8n locally:
   ```bash
   # Using npm (requires Node.js installed)
   npm install n8n -g
   
   # Start n8n
   n8n start
   ```
2. n8n will open at `http://localhost:5678`
3. To expose it to the internet (required for Twilio webhooks), use ngrok:
   ```bash
   # Install ngrok
   brew install ngrok
   
   # Expose local n8n
   ngrok http 5678
   ```
4. ngrok gives you a URL like: `https://abc123.ngrok.io`
5. Your webhook URL for Twilio: `https://abc123.ngrok.io/webhook/twilio-webhook`

> **⚠️ Note:** The ngrok URL changes every time you restart ngrok. For a persistent demo, consider using the free n8n cloud trial.

### 3.1 Create n8n Credentials

Before importing workflows, create these credentials in n8n:

#### Twilio Credentials

1. In n8n, go to **Credentials → Add Credential**
2. Choose **Twilio API**
3. Credential Name: `TwilioSandbox`
4. Enter:
   - **Account SID:** From Step 2.2
   - **Auth Token:** From Step 2.2
5. Click **Save**

Also create a `TwilioProduction` credential with the same values (for now — you'll switch to production later).

#### Google Sheets Credential

1. In n8n, go to **Credentials → Add Credential**
2. Choose **Google Sheets OAuth2 API**
3. Credential Name: `GoogleSheetsAlance`
4. Click **Sign in with Google** and authorize with the Google account that owns your demo sheet
5. Click **Save**

#### Telegram Credential (Optional for Demo)

1. In n8n, go to **Credentials → Add Credential**
2. Choose **Telegram API**
3. Credential Name: `TelegramAlanceBot`
4. Create a Telegram bot:
   - Open Telegram, search for `@BotFather`
   - Send `/newbot` and follow prompts
   - Copy the bot token
5. Enter the bot token in n8n
6. Find your Chat ID: message `@userinfobot` on Telegram
7. Click **Save**

---

## Step 4: Deploy the Demo

Now use the deploy script to generate configured workflow files.

### 4.1 Run the Deploy Script

```bash
cd /Users/krishanumala/Documents/Projects/gatekeeper-eos-v6

# Interactive mode (recommended for first time)
TWILIO_TOKEN="your-auth-token-here" \
./scripts/deploy_chatbot.sh --interactive
```

When prompted, enter:

| Prompt | Your Value |
|--------|-----------|
| Client name | `Alance Demo` |
| Twilio Account SID | `AC...` from Step 2.2 |
| Twilio Auth Token | (hidden — paste from Step 2.2) |
| Twilio WhatsApp number | The sandbox number (e.g., `+14155238886`) |
| Google Sheet ID | From Step 1.1 |
| Telegram Chat ID | From Step 3.1 (optional for demo) |
| Tier | `business` (for full demo) |
| Language | `english` |

### 4.2 Check the Output

The script creates a deployment package at:
```
deployments/alance-demo-YYYYMMDD/
```

It should contain:
```
alance-main.json     → Main chatbot workflow
alance-error.json    → Error handler workflow
alance-metrics.json  → Nightly metrics workflow
sheet-config.json    → Sheet configuration
README.md            → Deployment instructions
```

---

## Step 5: Import into n8n

### 5.1 Import the Workflows

1. Open your n8n dashboard
2. Go to **Workflows → Import from File**
3. Import each file one at a time:
   - `alance-main.json`
   - `alance-error.json`
   - `alance-metrics.json`

### 5.2 Configure Each Workflow

> **⚠️ Critical:** n8n does NOT auto-link credentials when importing. You must manually select each credential. Without this, the workflow will fail silently.

**For alance-main.json:**

1. Open the workflow
2. **Manually link credentials:** Go through EVERY node that uses Twilio, Google Sheets, or Telegram:
   - Click the node
   - Find the credential dropdown (e.g., "Twilio API" or "Google Sheets OAuth2 API")
   - Select the credential you created in Step 3.1

   Nodes that need credentials:
   - `Send Reply (Production)` → TwilioProduction
   - `Send Reply (Sandbox)` → TwilioSandbox
   - `Append MESSAGE_LEDGER` → GoogleSheetsAlance
   - `Append CONVERSATIONS` → GoogleSheetsAlance
   - `Append LEADS` → GoogleSheetsAlance
   - `Log STATE_DRIFT` → GoogleSheetsAlance
   - `Read MESSAGE_LEDGER` → GoogleSheetsAlance
   - `Read CONVERSATIONS` → GoogleSheetsAlance
   - `Update Delivery Status` → GoogleSheetsAlance
   - `Telegram Alert (Drift)` → TelegramAlanceBot

3. Click **Execute Workflow** to run a manual test — it creates a temporary webhook URL. Send a WhatsApp message to trigger it.

**Link the Error Workflow:**

1. Open `alance-main.json`
2. Click **Workflow Settings** (gear icon near the top)
3. Under **Error Workflow**, select the imported error workflow
4. Save

**Activate the Metrics Workflow:**

1. Open `alance-metrics.json`
2. Manually link the `GoogleSheetsAlance` credential on all 3 Google Sheets nodes
3. Toggle it to active (green switch)

### 5.3 Set Up the Twilio Webhook

Copy your n8n webhook URL and set it in Twilio:

1. In n8n, open `alance-main.json`
2. Click the **Webhook** node
3. Copy the **Production URL** (looks like `https://your-n8n-url/webhook/twilio-webhook`)
4. Go to **Twilio Console → Messaging → Try it out → Send a WhatsApp Message**
5. Under **"When a message comes in"**, paste the webhook URL
6. Set method to **POST**
7. Save

---

## Step 6: Test the Demo

### 6.1 Send a Test Message

1. Open WhatsApp on your phone
2. Send a message to the Twilio sandbox number (you joined this in Step 2.3)
3. Try these test messages:

| You Send | Expected Bot Reply |
|----------|-------------------|
| `Hi` | Greeting with introduction |
| `What are your services?` | List of services |
| `How much does it cost?` | Pricing info |
| `I want to book an appointment` | Booking flow |
| `My name is Test User` | Confirmation |
| `Thank you` | Booking complete |
| `Stop` | Cancellation confirmation |

### 6.2 Verify the Logging

1. Open your Google Sheet
2. Check **MESSAGE_LEDGER** tab — all test messages should be logged
3. Check **LEADS** tab — if you completed a booking flow, a lead should appear

### 6.3 Test Error Handling

1. Temporarily disable the Twilio credential on one node
2. Send another WhatsApp message
3. Check that you receive a Telegram alert and the ERRORS sheet is populated
4. Re-enable the credential after testing

---

## Step 7: Show Prospects the Demo

### 7.1 Quick Demo Script (2 minutes)

> "Send 'Hi' to this WhatsApp number — watch what happens."
>
> [Prospect sends Hi, bot replies instantly]
>
> "Notice it replied in under 2 seconds. Now ask it about pricing."
>
> [Prospect asks about pricing]
>
> "See how it knows the context? Now try booking an appointment."
>
> [Prospect goes through booking flow]
>
> "And here's the dashboard — every conversation is logged in this Google Sheet, including leads captured."

### 7.2 Demo Number Setup

For a clean demo experience:

1. Create a dedicated Google Sheet just for demos
2. Keep the sheet open on your laptop during sales calls
3. Pre-send a few messages to populate the sheet so it doesn't look empty

### 7.3 What to Show in Each Tier During Demos

| Tier | Demo Focus |
|------|-----------|
| **Starter** | Auto-reply speed, FAQ handling, lead capture in Sheets |
| **Business** | Full booking flow, state machine (reply changes based on conversation), drift detection alerts |
| **Premium** | Multi-language (show Telugu/Hindi detection), nightly metrics dashboard, Telegram error alerts |

---

## 📋 Quick Reference: All Values You Need

| Item | Where to Find It |
|------|-----------------|
| Twilio Account SID | Twilio Console dashboard |
| Twilio Auth Token | Twilio Console (click reveal) |
| Twilio WhatsApp number | Twilio Console → Messaging → WhatsApp Sandbox |
| Google Sheet ID | Sheet URL — between `/d/` and `/edit` |
| n8n URL | `localhost:5678` (self-hosted) or `your-name.app.n8n.cloud` |
| Webhook URL | n8n → Webhook node → Production URL |
| Telegram Bot Token | From @BotFather on Telegram |
| Telegram Chat ID | From @userinfobot on Telegram |

---

## 🔧 Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| No reply to WhatsApp messages | Webhook not configured in Twilio | Check Twilio Sandbox "When a message comes in" URL |
| Webhook returns 404 | ngrok URL changed | Restart ngrok, update Twilio webhook URL |
| Google Sheets errors | Sheet not shared | Share sheet with n8n's Google account |
| "Invalid credential" in n8n | OAuth not completed | Re-authenticate Google Sheets credential |
| Telegram alerts not firing | Wrong Chat ID | Message @userinfobot, verify ID |
| Bot replies in wrong state | Webhook called multiple times | Check MESSAGE_LEDGER for duplicate entries |
| Bot worked, now stopped working | ngrok URL changed on restart | Restart ngrok, copy new URL, update Twilio webhook |
| ngrok URL expired | Free ngrok session timed out | Restart: `ngrok http 5678`, update Twilio webhook with new URL |

---

## ✅ Demo Sandbox Checklist

- [ ] Twilio account created and sandbox active
- [ ] Google Sheet created with all 6 tabs and headers
- [ ] n8n instance running (local or cloud)
- [ ] Credentials created in n8n (Twilio, Google Sheets, Telegram)
- [ ] Deploy script run, workflows generated
- [ ] Workflows imported into n8n
- [ ] Twilio webhook URL configured
- [ ] Test message sent → auto-reply received
- [ ] Message logged in MESSAGE_LEDGER
- [ ] Booking flow works end-to-end
- [ ] Error alert fires (Telegram + ERRORS sheet)
- [ ] Demo sheet shown to at least one prospect

---

**Once the demo is running, your first sales call is just "Send a Hi to this number" away.**
