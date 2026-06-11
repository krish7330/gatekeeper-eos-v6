# Alance — WhatsApp Chatbot for Indian SMBs

> **Product:** AI-powered WhatsApp customer support & booking automation  
> **Tech:** n8n + Twilio + Google Sheets  
> **Target:** Indian small & medium businesses (SMBs)  
> **Status:** ✅ Production-ready | **v1.0**

---

## 📦 Product Package Contents

| File | What it contains |
|------|-----------------|
| [`pricing-package.md`](./pricing-package.md) | 3-tier pricing, feature breakdown, value proposition, competitor comparison |
| [`sales-scripts.md`](./sales-scripts.md) | WhatsApp outreach templates, email scripts, objection handling, lead capture workflows |
| [`../scripts/deploy_chatbot.sh`](../scripts/deploy_chatbot.sh) | One-click deployment automation script for new clients |
| [`demo-sandbox-guide.md`](./demo-sandbox-guide.md) | Step-by-step guide to set up a working demo environment |

## 🧩 What's Already Built (Technical)

| Component | File | Nodes |
|-----------|------|-------|
| **Main Production Workflow** | [`../n8n/alance-main.json`](../n8n/alance-main.json) | 27 nodes |
| **Error Handler** | [`../n8n/alance-error.json`](../n8n/alance-error.json) | 5 nodes |
| **Nightly Metrics** | [`../n8n/alance-metrics.json`](../n8n/alance-metrics.json) | 7 nodes |
| **PRD** | [`../PRD.md`](../PRD.md) | Full product requirements |

## 🚀 How to Use This Package

1. **Read the pricing package** — understand what you're selling and at what price
2. **Use the sales scripts** — start prospecting Indian SMBs
3. **When you close a client** — run the deploy script to onboard them

---

*Built with n8n, Twilio, and Google Sheets. No traditional backend required.*
