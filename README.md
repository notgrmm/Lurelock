# 🛡️ LureLock: Real-Time Phishing Link Detection

LureLock is an explainable machine learning security system designed to detect phishing, credential harvesting, and brand impersonation attacks in real time.

It includes:
- **Trained AI Classifier**: Fast, explainable XGBoost model with 18 lexical and structural features (< 150 KB).
- **External Reference Datasets**: Dynamic keyword, shortener, and trusted domain files (zero hardcoded links or keywords in Python code).
- **Web UI**: Interactive scanner interface served directly at `http://127.0.0.1:8787/`.
- **Browser Extension**: Real-time tab inspector and context-menu link scanner for Chrome/Chromium browsers.
- **REST API**: Unified `/predict` and `/health` JSON endpoints shared between the website and the extension.

---

## 🧭 Project Architecture & File Navigation

The codebase is organized cleanly for easy navigation and defense:

```
Lurelock/
├── main.py                     # Main entrypoint: CLI scanner, --train, --serve, --clean
├── run_server.py               # Launcher for local API server & Web UI (port 8787)
├── datasets/                   # External datasets (No hardcoded lists in Python)
│   ├── keywords.txt            # High-frequency phishing keywords (login, verify, bank...)
│   ├── shorteners.txt          # Known URL shortener domains (bit.ly, tinyurl.com...)
│   ├── trusted_domains.txt     # Trusted high-reputation domains (google.com, nytimes.com...)
│   ├── phishing_set/2.csv      # PhiUSIIL benchmark: verified phishing & legitimate URLs
│   └── apex_set/3.csv          # Top global apex domains
├── src/                        # Core Python ML package
│   ├── feature_extractor.py    # URL normalization and 18 explainable feature extractors
│   ├── domain_utils.py         # Apex domain & multi-part ccTLD extraction, trusted check
│   ├── explainer.py            # Generates human-readable indicator breakdown cards
│   ├── dataset_cleaner.py      # Dataset loading, balancing, and realistic path synthesis
│   └── trainer.py              # XGBoost training pipeline, evaluation & serialization
├── models/                     # Saved model artifacts
│   ├── model.joblib            # End-to-end inference pipeline (< 150 KB)
│   ├── url_preprocessor.joblib # URLNormalizer + URLLexicalExtractor
│   ├── xgboost_model.json      # Native cross-platform booster
│   └── phishing_model_card.json# Model card with test metrics and feature names
├── website/                    # Web UI frontend (HTML, CSS, JS)
│   ├── index.html              # Scanner webpage
│   ├── app.js                  # Frontend client communicating with /predict
│   └── style.css               # Modern dark/light styling
└── extension/                  # Chrome Browser Extension
    ├── manifest.json           # Manifest V3 configuration
    ├── background.js           # Service worker (tab auto-scan, context menu, badge)
    ├── popup.html / popup.js   # Extension popup UI with risk gauge & signals
    └── server/server.py        # Lightweight HTTP server hosting API & Web UI
```

---

## 🎓 Defense Cheatsheet: How LureLock Classifies a URL

When asked: *"How does your system classify a link as phishing or legitimate?"*, you can explain it in 4 clear, defensible steps:

```
[ Input URL ]  (from Web UI, Extension, or CLI)
      │
      ▼
1. URL Canonicalization (normalize_url)
   • Adds standard scheme, cleans host, standardizes path & query
   • Ensures "google.com", "https://google.com", and "https://google.com/" produce identical vectors
      │
      ▼
2. External Dataset Check (is_trusted_domain)
   • Resolves registered apex domain (e.g. "google.com" from "https://mail.google.com/...")
   • Checks against external reference dataset: datasets/trusted_domains.txt
   • If verified: 0% risk, skips ML to prevent false positives
      │
      ▼
3. Explainable Feature Extraction (18 Numerical Indicators)
   • Length & Structure: URL length, domain length, path depth, subdomain count
   • Obfuscation Cues: Dot count, hyphen count (brand spoofing), @ symbol (credential trick), digit counts
   • Host Identity: Bare IPv4 address check, Shannon entropy (random DGA domain detector)
   • Content & Masking: Suspicious keywords in domain vs path (from datasets/keywords.txt),
     URL shortener detection (from datasets/shorteners.txt), high-risk TLDs (.xyz, .top...)
      │
      ▼
4. XGBoost Machine Learning Classifier
   • Evaluates the 18-dimensional feature vector using trained gradient boosted decision trees
   • Outputs a calibrated threat probability from 0.0 to 1.0 (Risk Score: 0% to 100%)
   • Safe (<30% risk)  |  Warning (30% - 59% risk)  |  Phishing (>=60% risk)
   • Generates an indicator breakdown card explaining exactly WHY the verdict was given
```

---

## ❓ FAQ: Why did the Extension classify as Phishing while the Website didn't?

### The Root Cause:
1. **Input Format Difference**: On the website, users typically typed bare domain names (e.g. `nytimes.com` or `google.com`). In the Chrome extension, the browser supplies `tab.url`, which is always a fully qualified browser URL with protocol and trailing slash (e.g. `https://www.nytimes.com/`).
2. **Dataset Bias in Training**: Previously, the benign training data (`apex_set`) consisted purely of bare domain names without protocols or slashes, while phishing datasets contained full URLs with `http://` and slashes. The old model overfit on character n-grams and slashes, falsely concluding that *any URL containing `https://` or a path was 99% phishing*.
3. **Hardcoded Bypasses**: The old server had a hardcoded list that did not match between the CLI, the server, and multi-part domains (`.co.uk`).

### The Fix:
- **Canonical Normalization**: All URLs (from the website, extension, or CLI) are canonicalized before evaluation, so `nytimes.com` and `https://www.nytimes.com/` produce the exact same feature representation.
- **Realistic Benign Path Synthesis**: During training, benign apex domains are enriched with realistic benign paths and schemes so the model evaluates true phishing signals (keywords, DGA entropy, bare IPs, brand hyphens) rather than penalizing URLs for having a path.
- **External Trusted Domains**: `datasets/trusted_domains.txt` is unified across the CLI, Web UI, and Chrome Extension.

---

## 🚀 Quick Start (Local Run)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Local Server & Web App
```bash
python run_server.py
```
- Open **http://127.0.0.1:8787/** in your browser.
- The Chrome Extension automatically communicates with **http://127.0.0.1:8787/predict**.

### 3. Scan Links in Terminal
```bash
# Scan a single URL
python main.py https://example.com

# Scan and print raw JSON breakdown
python main.py http://paypal-security-update.com/login --json

# Retrain the model on external datasets
python main.py --train

# Interactive scanning shell
python main.py
```

---

## 🔌 API Reference

### Health Check
`GET http://127.0.0.1:8787/health`
```json
{
  "ok": true,
  "model_loaded": true,
  "source": ".../models/model.joblib",
  "error": null
}
```

### Predict Phishing Risk
`POST http://127.0.0.1:8787/predict`
```json
{
  "url": "http://paypal-security-update.com/login"
}
```
**Response:**
```json
{
  "url": "http://paypal-security-update.com/login",
  "probability": 0.69,
  "risk": 69,
  "level": "bad",
  "title": "High Risk Phishing Detected",
  "summary": "High probability of malicious impersonation, spoofing, or deceptive redirection.",
  "label": "phishing",
  "features": [
    { "label": "URL length", "value": "39 chars", "note": "Within typical length.", "flag": false },
    { "label": "Suspicious keywords", "value": "login, update, paypal, security", "note": "Found credential or action keywords from reference dataset.", "flag": true },
    { "label": "Character entropy", "value": "3.87 bits", "note": "High randomness suggests machine-generated domain.", "flag": true },
    { "label": "Protocol", "value": "HTTP", "note": "Unencrypted connection.", "flag": true }
  ]
}
```

---

## 🧩 Chrome Extension Installation
1. Open your browser and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the [`extension/`](extension/) directory.
4. The extension icon will appear in your browser toolbar and connect to your local server on `http://127.0.0.1:8787`.
