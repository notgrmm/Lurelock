# Lurelock Browser Extension

AI-powered real-time phishing link detector for Chrome and Chromium-based browsers (Manifest V3).

Evaluates URL structure, character entropy, and impersonation signals on-device using a local machine learning engine.

---

## Key Features

- **⚡ Automatic Active Tab Scan**: Evaluates the safety of the current web page instantly as soon as you open the popup.
- **🛡️ Plain-English Verdicts**: Self-explanatory, color-coded safety verdicts (**Likely Legitimate**, **Suspicious Structure**, or **High Risk Phishing**) with clear, actionable advice.
- **📊 Interactive Risk Gauge**: 0% to 100% threat meter showing where the link falls across Safe, Caution, and Phishing zones.
- **🔍 Explainable AI Signals**: Inspect all 11 structural signals (domain length, subdomain nesting, special characters, entropy, protocol, keywords) with warning flags sorted to the top.
- **📋 Context Menu Scanning**: Right-click any link on any website and choose **"🛡️ Scan link with Lurelock"** to analyze it before clicking.
- **⚡ Custom Link Inspector**: Paste any URL directly into the popup to analyze suspicious links from emails or messages without navigating to them.
- **🔒 100% On-Device Privacy**: Link evaluations run strictly on your local machine via `http://127.0.0.1:8787`. No browsing data is sent to external cloud servers.

---

## Quick Start Guide

### 1. Launch the Local AI Server
From the project root:
```bash
python run_server.py
```
*(The server connects the trained XGBoost model from `models/` to `http://127.0.0.1:8787`)*.

### 2. Load the Extension into Chrome
1. Open Chrome and navigate to `chrome://extensions/`.
2. Turn on **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** (top-left).
4. Select the `Lurelock/extension` directory.
5. Pin the **Lurelock** extension to your browser toolbar.

---

## Extension Structure

```
extension/
├── manifest.json       # Manifest V3 extension configuration & permissions
├── background.js       # Background service worker (context menu, auto-scan, badges)
├── popup.html          # Sleek glassmorphism popup UI
├── popup.js            # Dynamic verdict, tabs, signals, and live scanning controller
├── ext.css             # Modern dark-mode styling system
├── options.html        # Engine configuration & connection testing page
├── options.js          # Settings & model source management
└── icons/              # Crisp multi-resolution brand icons (16, 32, 48, 128px)
```
