# Jarvis v2: Architecture & Operations Guide

> **Version:** 2.0  
> **Status:** Stable  
> **Next:** [Jarvis v2.1: Command-Control Spec](./JARVIS_V2_1_SPEC.md) — adds formal JSON schema, approval layer, action queue, and audit logging.

---

## 1. Core Architecture

Jarvis v2 is built as a strict pipeline with separate responsibilities at each layer.

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Input      │ ──► │  Cloud Layer     │ ──► │  AI Layer    │
│  Layer      │     │  (orchestration)  │     │  (LLM parse) │
└─────────────┘     └──────────────────┘     └──────┬───────┘
                                                     │
                          ┌──────────────────────────┤
                          ▼                          ▼
                   ┌──────────────┐          ┌──────────────┐
                   │  Home Layer  │          │  PC Layer    │
                   │  (HAss)      │          │  (BTT/EG)    │
                   └──────────────┘          └──────────────┘
```

| Layer | Technology | Responsibility |
|-------|-----------|----------------|
| **Input Layer** | Voice commands, phone shortcuts, widgets, web UI | Capture user intent |
| **Cloud Layer** | Make.com or n8n | Webhook routing and orchestration |
| **AI Layer** | One LLM (no chain-of-thought visible) | Translates natural language into structured JSON |
| **Home Layer** | Home Assistant | Smart devices and IoT actions |
| **PC Layer** | BetterTouchTool (macOS) or EventGhost (Windows) | Local desktop execution |

---

## 2. Command Protocol

All commands **must** be converted into one strict JSON object. No extra text, explanations, or markdown are allowed in the AI output.

```json
{
  "target": "PC",
  "action": "OPEN_URL",
  "parameter": "https://google.com"
}
```

### Allowed Targets

| Target | Description |
|--------|-------------|
| `PC` | Desktop actions (macOS / Windows) |
| `HOME` | Smart home devices via Home Assistant |

### Allowed PC Actions

| Action | Description |
|--------|-------------|
| `LAUNCH_APP` | Open a desktop application |
| `OPEN_URL` | Open a URL in the default browser |
| `EXECUTE_MACRO` | Run a pre-configured macro in BTT/EventGhost |
| `MEDIA_CONTROL` | Play, pause, skip, or adjust volume |

### Allowed HOME Actions

| Action | Description |
|--------|-------------|
| `TURN_ON` | Turn a device or light on |
| `TURN_OFF` | Turn a device or light off |
| `SET_BRIGHTNESS` | Set brightness level (0–100) |
| `SET_TEMPERATURE` | Set thermostat temperature |

---

## 3. Standard Routines

Routines are common multi-step commands that execute sequentially.

### Start My Workday

```
1. Desk lamp → ON
2. Launch Slack
3. Open browser to calendar
```

### Movie Time

```
1. Dim lights (50%)
2. Turn on TV
3. Mute PC audio
```

### I'm Leaving

```
1. All lights → OFF
2. Thermostat → Eco
3. Lock workstation
```

---

## 4. Safety Rules

These rules keep the system stable and harder to abuse.

1. **Test webhooks manually** before enabling full automation.
2. **Require a token or custom header** on every local receiver.
3. **Add a short delay** between chained PC commands (minimum 500 ms).
4. **Prefer tunnels** (Cloudflare Tunnel, Tailscale Funnel) over exposing raw local ports directly to the internet.

---

## 5. Troubleshooting Flow

When a command fails, check the path in this order:

```
1. Confirm the public endpoint is reachable.
   │
2. Confirm the destination port is open.
   │
3. Confirm the receiver app is running and listening.
   │
4. Use packet inspection only if the request reaches
   the system but the action still fails.
```

---

## 6. Expansion Notes

This version is designed to stay maintainable as you add more targets later, such as Android, NAS, or other local devices.

- **Keep the JSON schema whitelisted.** Every new target and action must be added explicitly.
- **Add approval gates for risky actions.** Not present in v2 — this is the primary motivation for v2.1.
- **Queue commands** if you want retries and better logging. Not present in v2 — deferred to v2.1.
- **Keep forensic or Wireshark material** in a separate appendix, not in the spec.

---

## 7. Upgrade Path to v2.1

The v2 architecture intentionally omits three layers that v2.1 formalizes:

| Gap | v2 Behavior | v2.1 Solution |
|-----|-------------|---------------|
| **Schema validation** | Implicit — LLM is expected to produce valid JSON | Formal JSON Schema with whitelisted enums, validated before execution |
| **Approval gating** | None — all actions execute immediately | 4-tier risk policy: auto-approve / auto-approve+audit / always-confirm / blocked |
| **Action queue** | Commands fire synchronously | SQLite-backed queue with retries, idempotency keys, and dead-letter handling |
| **Audit logging** | Manual only | Append-only hash-chained audit log with hot/cold storage tiers |

See **[Jarvis v2.1: Command-Control Spec](./JARVIS_V2_1_SPEC.md)** for the full design.

---
