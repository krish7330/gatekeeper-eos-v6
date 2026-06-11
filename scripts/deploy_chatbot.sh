#!/usr/bin/env bash
# =============================================================================
# Alance WhatsApp Bot — Client Deployment Script
# =============================================================================
# USAGE:
#   Interactive (recommended for first use):
#     ./scripts/deploy_chatbot.sh --interactive
#
#   Automated (for repeat deployments):
#     TWILIO_TOKEN="xxx" \
#     ./scripts/deploy_chatbot.sh \
#       --client "Sharma Dental" \
#       --twilio-sid "ACxxx" \
#       --twilio-number "+919876543210" \
#       --google-sheet-id "1abc123..." \
#       --telegram-chat-id "123456789"
#
# OPTIONS:
#   --interactive        Interactive mode (prompts for each value)
#   --client NAME        Client/business name (required)
#   --twilio-sid SID     Twilio Account SID (required)
#   --twilio-number NUM  Twilio WhatsApp number (required, format +91XXXXXXXXXX)
#   --google-sheet-id ID Google Sheets document ID (required)
#   --telegram-chat-id   Telegram chat ID for alerts (optional)
#   --tier TIER          Pricing tier: starter|business|premium (default: starter)
#   --lang LANG          Languages: english|telugu|hindi|all (default: english)
#   --n8n-url URL        n8n instance URL for auto-import (optional, e.g. http://localhost:5678)
#   --n8n-api-key KEY    n8n API key (optional, for auto-import)
#   --dry-run            Show what would be done without making changes
#   --help               Show this help message
#
# ENVIRONMENT VARIABLES:
#   TWILIO_TOKEN         Twilio Auth Token (required, use instead of --twilio-token for security)
#
# WHAT THIS SCRIPT DOES:
#   1. Generates n8n workflow files with client-specific values
#   2. Creates a deployment package with README and sheet config
#   3. Optionally imports workflows directly into n8n via API
# =============================================================================

set -euo pipefail

# ── Capture env vars BEFORE defaults override them ──────────────────────────
# This must be at the top: bash's local variable assignment shadows env vars
ORIG_TWILIO_TOKEN="${TWILIO_TOKEN:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
N8N_DIR="$PROJECT_DIR/n8n"
OUTPUT_DIR="$PROJECT_DIR/deployments"

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Defaults ────────────────────────────────────────────────────────────────
CLIENT_NAME=""
TWILIO_SID=""
TWILIO_TOKEN=""
TWILIO_NUMBER=""
GOOGLE_SHEET_ID=""
TELEGRAM_CHAT_ID=""
TIER="starter"
LANG="english"
N8N_URL=""
N8N_API_KEY=""
DRY_RUN=false
INTERACTIVE=false

# ── Help ────────────────────────────────────────────────────────────────────
show_help() {
    sed -n '3,38p' "$0"
    exit 0
}

# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interactive)     INTERACTIVE=true; shift ;;
        --client)          CLIENT_NAME="$2"; shift 2 ;;
        --twilio-sid)      TWILIO_SID="$2"; shift 2 ;;
        --twilio-number)   TWILIO_NUMBER="$2"; shift 2 ;;
        --twilio-token)
            echo -e "${YELLOW}⚠ WARNING: --twilio-token exposes credentials in process list.${NC}"
            echo -e "${YELLOW}  Use TWILIO_TOKEN env var instead for security.${NC}"
            TWILIO_TOKEN="$2"; shift 2 ;;
        --google-sheet-id) GOOGLE_SHEET_ID="$2"; shift 2 ;;
        --telegram-chat-id) TELEGRAM_CHAT_ID="$2"; shift 2 ;;
        --tier)            TIER="$2"; shift 2 ;;
        --lang)            LANG="$2"; shift 2 ;;
        --n8n-url)         N8N_URL="$2"; shift 2 ;;
        --n8n-api-key)     N8N_API_KEY="$2"; shift 2 ;;
        --dry-run)         DRY_RUN=true; shift ;;
        --help)            show_help ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; show_help ;;
    esac
done

# ── Interactive mode ────────────────────────────────────────────────────────
if $INTERACTIVE; then
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Alance Bot — Interactive Deployment${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "Enter values for each field. Press Enter to accept defaults."
    echo ""

    read -rp "$(echo -e ${BLUE}"Client name: "${NC})" CLIENT_NAME
    read -rp "$(echo -e ${BLUE}"Twilio Account SID: "${NC})" TWILIO_SID
    read -rsp "$(echo -e ${BLUE}"Twilio Auth Token (hidden): "${NC})" TWILIO_TOKEN
    echo ""
    read -rp "$(echo -e ${BLUE}"Twilio WhatsApp number (e.g. +919876543210): "${NC})" TWILIO_NUMBER
    read -rp "$(echo -e ${BLUE}"Google Sheet ID: "${NC})" GOOGLE_SHEET_ID
    read -rp "$(echo -e ${BLUE}"Telegram Chat ID (optional): "${NC})" TELEGRAM_CHAT_ID
    read -rp "$(echo -e ${BLUE}"Tier [starter/business/premium] (default: starter): "${NC})" TIER_INPUT
    TIER="${TIER_INPUT:-starter}"
    read -rp "$(echo -e ${BLUE}"Language [english/telugu/hindi/all] (default: english): "${NC})" LANG_INPUT
    LANG="${LANG_INPUT:-english}"
    echo ""
    echo -e "${GREEN}Interactive input complete.${NC}"
    echo ""
fi

# ── Read TWILIO_TOKEN from env (overrides CLI arg for security) ─────────────
# Set TWILIO_TOKEN=xxx before running the script to avoid exposing the token
# in process lists or shell history.
# Priority: CLI arg > interactive prompt > env var (env var preferred for security)
if [[ -z "$TWILIO_TOKEN" && -n "$ORIG_TWILIO_TOKEN" ]]; then
    TWILIO_TOKEN="$ORIG_TWILIO_TOKEN"
    info "Using TWILIO_TOKEN from environment variable"
fi

# ── Validation ──────────────────────────────────────────────────────────────
if [[ -z "$CLIENT_NAME" ]]; then
    echo -e "${RED}❌ Error: --client is required${NC}"
    show_help
fi

if [[ -z "$TWILIO_SID" ]]; then
    echo -e "${RED}❌ Error: --twilio-sid is required${NC}"
    show_help
fi

if [[ -z "$TWILIO_TOKEN" ]]; then
    echo -e "${RED}❌ Error: Twilio Auth Token is required.${NC}"
    echo -e "  Set TWILIO_TOKEN environment variable or use the interactive prompt."
    show_help
fi

if [[ -z "$TWILIO_NUMBER" ]]; then
    echo -e "${RED}❌ Error: --twilio-number is required${NC}"
    show_help
fi

if [[ -z "$GOOGLE_SHEET_ID" ]]; then
    echo -e "${RED}❌ Error: --google-sheet-id is required${NC}"
    show_help
fi

# ── Validate & format Twilio number ─────────────────────────────────────────
# Strip spaces
TWILIO_NUMBER=$(echo "$TWILIO_NUMBER" | tr -d ' ')

# Add + prefix if missing
if [[ "$TWILIO_NUMBER" != +* ]]; then
    TWILIO_NUMBER="+$TWILIO_NUMBER"
    echo -e "${YELLOW}⚠ Added + prefix to number: $TWILIO_NUMBER${NC}"
fi

# Basic format validation: must start with + followed by 7-15 digits
if ! [[ "$TWILIO_NUMBER" =~ ^\+[0-9]{7,15}$ ]]; then
    echo -e "${RED}❌ Invalid Twilio number format: $TWILIO_NUMBER${NC}"
    echo -e "  Expected format: +91XXXXXXXXXX (with country code)"
    exit 1
fi

# ── Validate tier ───────────────────────────────────────────────────────────
case "$TIER" in
    starter|business|premium) ;;
    *) echo -e "${RED}❌ Invalid tier: $TIER (must be starter|business|premium)${NC}"; exit 1 ;;
esac

# ── Validate language ───────────────────────────────────────────────────────
case "$LANG" in
    english|telugu|hindi|all) ;;
    *) echo -e "${RED}❌ Invalid language: $LANG (must be english|telugu|hindi|all)${NC}"; exit 1 ;;
esac

# ── Slugify client name ─────────────────────────────────────────────────────
CLIENT_SLUG=$(echo "$CLIENT_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')
DEPLOY_DIR="$OUTPUT_DIR/$CLIENT_SLUG-$(date +%Y%m%d)"

# ── Functions ───────────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}ℹ${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }

# ── Step 1: Create output directory ─────────────────────────────────────────
create_output_dir() {
    info "Creating deployment directory..."
    if $DRY_RUN; then
        info "  Would create: $DEPLOY_DIR"
    else
        mkdir -p "$DEPLOY_DIR"
        success "Created: $DEPLOY_DIR"
    fi
}

# ── Step 2: Create Google Sheets config ─────────────────────────────────────
create_sheet_config() {
    info "Generating Google Sheets configuration..."

    local SHEET_CONFIG="$DEPLOY_DIR/sheet-config.json"
    local TABS

    case "$TIER" in
        starter)
            TABS='["MESSAGE_LEDGER","CONVERSATIONS","LEADS","ERRORS"]'
            ;;
        business|premium)
            TABS='["MESSAGE_LEDGER","CONVERSATIONS","LEADS","STATE_DRIFT","ERRORS","HEALTHMETRICS"]'
            ;;
    esac

    if $DRY_RUN; then
        info "  Would create $SHEET_CONFIG with tabs: $TABS"
    else
        cat > "$SHEET_CONFIG" << EOF
{
  "client_name": "$CLIENT_NAME",
  "client_slug": "$CLIENT_SLUG",
  "tier": "$TIER",
  "language": "$LANG",
  "google_sheet_id": "$GOOGLE_SHEET_ID",
  "tabs": $TABS,
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "twilio_number": "$TWILIO_NUMBER"
}
EOF
        success "Created: $SHEET_CONFIG"
    fi
}

# ── Step 3: Generate n8n import files with placeholders replaced ────────────
generate_n8n_workflows() {
    info "Generating n8n workflow files with client-specific values..."

    local WORKFLOWS=("alance-main.json" "alance-error.json" "alance-metrics.json")
    local SOURCE_FILE TARGET_FILE WORKFLOW_CONTENT

    for WF in "${WORKFLOWS[@]}"; do
        SOURCE_FILE="$N8N_DIR/$WF"
        TARGET_FILE="$DEPLOY_DIR/$WF"

        if [[ ! -f "$SOURCE_FILE" ]]; then
            warn "Source workflow not found: $SOURCE_FILE — skipping"
            continue
        fi

        if $DRY_RUN; then
            info "  Would process: $WF → $TARGET_FILE"
            continue
        fi

        WORKFLOW_CONTENT=$(cat "$SOURCE_FILE")

        # Replace ALL placeholders
        WORKFLOW_CONTENT=$(echo "$WORKFLOW_CONTENT" | \
            sed "s/DUMMY_GOOGLE_SHEET_ID/$GOOGLE_SHEET_ID/g" | \
            sed "s/DUMMY_TELEGRAM_CHAT_ID/${TELEGRAM_CHAT_ID:-000000000}/g" | \
            sed "s/+10000000000/$TWILIO_NUMBER/g")

        # Remove errorWorkflow placeholder — user must set this manually
        # in n8n after import (n8n requires a workflow UUID, not a name)
        WORKFLOW_CONTENT=$(echo "$WORKFLOW_CONTENT" | \
            sed 's/"errorWorkflow": *"[^"]*"/"errorWorkflow": ""/g')

        # For starter tier: remove state-machine-related nodes
        if [[ "$TIER" == "starter" ]]; then
            warn "  Starter tier: removing advanced state machine nodes from $WF"

            # Remove nodes: State Machine, Is Drift?, Log STATE_DRIFT,
            # Telegram Alert (Drift), Booking Complete?, Append LEADS
            # Strategy: remove the entire node JSON objects by name
            local NODES_TO_REMOVE=(
                '"State Machine"'
                '"Is Drift?"'
                '"Log STATE_DRIFT"'
                '"Telegram Alert (Drift)"'
                '"Booking Complete?"'
                '"Append LEADS"'
            )

            for NODE_NAME in "${NODES_TO_REMOVE[@]}"; do
                # Remove node blocks that match the pattern: { "id": "...", "name": <NODE_NAME>, ... },
                WORKFLOW_CONTENT=$(echo "$WORKFLOW_CONTENT" | \
                    python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
if isinstance(data, list) and len(data) > 0:
    wf = data[0]
    nodes = [n for n in wf['nodes'] if n.get('name') != $NODE_NAME]
    wf['nodes'] = nodes
    # Also remove connections referencing these nodes
    conns = wf.get('connections', {})
    keys_to_remove = [k for k in conns if k == $NODE_NAME]
    for k in keys_to_remove:
        del conns[k]
    # Remove references to removed nodes from other connections
    for src, outputs in list(conns.items()):
        for conn_list in outputs.get('main', []):
            conns[src]['main'] = [
                [c for c in cl if c.get('node') != $NODE_NAME]
                for cl in conn_list
                if any(c.get('node') != $NODE_NAME for c in cl)
            ]
    json.dump(data, sys.stdout)
")
            done
        fi

        echo "$WORKFLOW_CONTENT" > "$TARGET_FILE"
        success "Generated: $TARGET_FILE"

        # Validate the generated JSON
        if echo "$WORKFLOW_CONTENT" | python3 -c "import json,sys; json.loads(sys.stdin.read())" 2>/dev/null; then
            success "  Valid JSON: $WF"
        else
            error "  Invalid JSON generated for $WF — check the output"
        fi
    done
}

# ── Step 4: Create deployment README ────────────────────────────────────────
create_deployment_readme() {
    info "Creating deployment instructions..."

    local README_FILE="$DEPLOY_DIR/README.md"

    if $DRY_RUN; then
        info "  Would create deployment README"
        return
    fi

    cat > "$README_FILE" << 'EOF'
# Alance WhatsApp Bot — Deployment Package

## Client: [CLIENT_NAME]
## Tier: [TIER]
## Deployed: [DATE]

---

## What's Included

| File | Purpose |
|------|---------|
| `alance-main.json` | Main production workflow — import into n8n |
| `alance-error.json` | Error handler workflow — set as Error Workflow in n8n |
| `alance-metrics.json` | Nightly metrics workflow — activate Schedule Trigger |
| `sheet-config.json` | Google Sheets configuration for this client |

---

## Deployment Steps

### Step 1: Set up Twilio WhatsApp

1. Go to [Twilio Console](https://console.twilio.com)
2. Navigate to **Messaging → Try it out → Send a WhatsApp Message**
3. Follow the sandbox setup to get a WhatsApp-approved number
4. For production: submit your business for WhatsApp approval
   - ⏱ Timeline: sandbox in 1 hour, production in 3-7 days

### Step 2: Set up Google Sheets

1. Create a new Google Sheet
2. Rename the default sheet to `MESSAGE_LEDGER`
3. Add these additional tabs:
   - `CONVERSATIONS`
   - `LEADS`
[BUSINESS/PREMIUM:   - `STATE_DRIFT`]
[BUSINESS/PREMIUM:   - `ERRORS`]
[BUSINESS/PREMIUM:   - `HEALTHMETRICS`]
4. Copy the Sheet ID from the URL (the string between `/d/` and `/edit`)

### Step 3: Import Workflows into n8n

**Option A: Manual import (recommended for first time)**
1. Open your n8n dashboard
2. Go to **Workflows** → **Import from File**
3. Import each `.json` file one at a time

**Option B: API import (if --n8n-url was provided)**
The deploy script has already attempted API import.
Verify in your n8n dashboard that the workflows appeared.

### Step 4: Configure Credentials

Create these n8n credentials before activating:

| Credential Name | Type | Notes |
|-----------------|------|-------|
| `TwilioSandbox` | Twilio API | Use sandbox credentials for initial testing |
| `TwilioProduction` | Twilio API | Production credentials (from Twilio console) |
| `GoogleSheetsAlance` | Google Sheets OAuth2 | Must have access to the client's sheet |
| `TelegramAlanceBot` | Telegram | Bot token for error/drift alerts |

To create credentials in n8n:
1. Open each workflow
2. Click the credential dropdown on relevant nodes
3. Select **Create New** and fill in the details

### Step 5: Set Error Workflow (CRITICAL)

1. Open the main workflow (`alance-main.json`)
2. Go to **Workflow Settings** (gear icon)
3. Under **Error Workflow**, select the imported error workflow
4. This must be done manually — n8n requires workflow IDs

### Step 6: Test Before Activating

1. Open the main workflow
2. Click **Execute Workflow** (manual test)
3. Send a test WhatsApp message to your Twilio number
4. Verify:
   - ✅ Auto-reply received
   - ✅ Message logged in MESSAGE_LEDGER sheet
   - ✅ Correct state transition

### Step 7: Activate

1. Toggle the main workflow to active (green)
2. Toggle the metrics workflow to active (green)
3. Monitor Telegram alerts for errors in the first 24 hours

---

## Verification Checklist

- [ ] WhatsApp message → instant auto-reply received
- [ ] Message logged in MESSAGE_LEDGER sheet
- [ ] WhatsApp message → simulated error → Telegram alert received
- [ ] ERRORS sheet populated
- [ ] Metrics workflow runs (test manually or wait for schedule)
- [ ] Error workflow linked in main workflow settings

---

## Troubleshooting

| Issue | Likely Cause | Fix |
|-------|-------------|-----|
| No reply to messages | Webhook not active | Toggle workflow on, check webhook URL |
| Telegram alerts not firing | Chat ID wrong | Verify --telegram-chat-id value |
| Google Sheets errors | Sheet access denied | Share sheet with n8n's Google account |
| Twilio send fails | Wrong credentials | Verify Twilio SID and token in n8n |

---

## Support

- Run validation: `python3 scripts/validate_n8n_import.py`
- Check Telegram alerts for error notifications
- Check ERRORS sheet in Google Sheets

EOF

    # Replace placeholders in the README
    sed -i '' "s/\[CLIENT_NAME\]/$CLIENT_NAME/g" "$README_FILE"
    sed -i '' "s/\[TIER\]/$TIER/g" "$README_FILE"
    sed -i '' "s/\[DATE\]/$(date)/g" "$README_FILE"

    # Add tier-specific lines
    if [[ "$TIER" == "starter" ]]; then
        sed -i '' '/\[BUSINESS\/PREMIUM:/d' "$README_FILE"
    fi

    success "Created: $README_FILE"
}

# ── Step 5: Auto-import into n8n via API (optional) ────────────────────────
import_to_n8n() {
    if [[ -z "$N8N_URL" ]]; then
        info "No --n8n-url provided — skipping auto-import"
        info "  Manual import: open n8n dashboard → Workflows → Import from File"
        return
    fi

    if $DRY_RUN; then
        info "  Would import workflows to n8n at: $N8N_URL"
        return
    fi

    info "Importing workflows to n8n at $N8N_URL..."

    local WORKFLOWS=("alance-main.json" "alance-error.json" "alance-metrics.json")
    local WF_FILE ENDPOINT RESPONSE

    ENDPOINT="${N8N_URL%/}/rest/workflows"

    for WF in "${WORKFLOWS[@]}"; do
        WF_FILE="$DEPLOY_DIR/$WF"
        if [[ ! -f "$WF_FILE" ]]; then
            warn "  Workflow file not found: $WF_FILE — skipping"
            continue
        fi

        # Read and reformat for n8n API (extract workflow from array wrapper)
        local IMPORT_DATA
        IMPORT_DATA=$(python3 -c "
import json, sys
data = json.load(open('$WF_FILE'))
if isinstance(data, list) and len(data) > 0:
    print(json.dumps(data[0]))
else:
    print(json.dumps(data))
")

        if [[ -n "$N8N_API_KEY" ]]; then
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST "$ENDPOINT" \
                -H "Content-Type: application/json" \
                -H "X-N8N-API-KEY: $N8N_API_KEY" \
                -d "$IMPORT_DATA" 2>/dev/null || echo "000")
        else
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST "$ENDPOINT" \
                -H "Content-Type: application/json" \
                -d "$IMPORT_DATA" 2>/dev/null || echo "000")
        fi

        if [[ "$RESPONSE" == "200" || "$RESPONSE" == "201" ]]; then
            success "  Imported: $WF (HTTP $RESPONSE)"
        else
            warn "  Import failed for $WF (HTTP $RESPONSE)"
            warn "  Import manually: open n8n → Workflows → Import from File"
        fi
    done
}

# ── Step 6: Print deployment summary ────────────────────────────────────────
print_summary() {
    echo ""
    echo "============================================"
    echo -e "  ${GREEN}Deployment Package Ready${NC}"
    echo "============================================"
    echo ""
    echo -e "  ${BLUE}Client:${NC}      $CLIENT_NAME"
    echo -e "  ${BLUE}Tier:${NC}        $TIER"
    echo -e "  ${BLUE}Language:${NC}    $LANG"
    echo -e "  ${BLUE}Twilio:${NC}      $TWILIO_NUMBER"
    echo -e "  ${BLUE}Google Sheet:${NC} $GOOGLE_SHEET_ID"
    echo ""
    echo -e "  ${GREEN}Package:${NC}     $DEPLOY_DIR/"
    echo ""
    echo "  Files:"
    ls -1 "$DEPLOY_DIR/" 2>/dev/null | sed 's/^/    /'
    echo ""

    if [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        echo -e "  ${GREEN}✓ Telegram alerts configured${NC}"
    else
        echo -e "  ${YELLOW}⚠ Telegram chat ID not set — alerts disabled${NC}"
        echo "    Pass --telegram-chat-id to enable alerts"
    fi
    echo ""

    case "$TIER" in
        starter)
            echo -e "  ${BLUE}Starter tier:${NC} Auto-reply + FAQ + lead capture"
            echo -e "  ${YELLOW}  Note:${NC} State machine, drift detection, and booking disabled"
            ;;
        business)
            echo -e "  ${BLUE}Business tier:${NC} Full state machine + booking + drift detection"
            ;;
        premium)
            echo -e "  ${BLUE}Premium tier:${NC} Multi-language + nightly metrics + priority support"
            ;;
    esac

    echo ""
    echo -e "  ${YELLOW}Next steps:${NC}"
    echo "  1. Import the n8n workflows (manual or auto-import done above)"
    echo "  2. Configure credentials in n8n (Twilio, Google Sheets, Telegram)"
    echo "  3. Link the error workflow (Workflow Settings → Error Workflow)"
    echo "  4. Test with a sample WhatsApp message"
    echo "  5. Activate the workflows"
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo -e "  ${BLUE}Alance Bot — Client Deployment${NC}"
echo "============================================"
echo ""

if $DRY_RUN; then
    warn "DRY RUN — no changes will be made"
    echo ""
fi

create_output_dir
create_sheet_config
generate_n8n_workflows
create_deployment_readme

if ! $DRY_RUN; then
    import_to_n8n
    print_summary
    success "Deployment package ready at: $DEPLOY_DIR"
else
    info "Dry run complete. Run without --dry-run to generate files."
fi

echo ""
