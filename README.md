# 🛡️ LureLock: Real-Time Phishing Link Detection

LureLock is an explainable machine learning security system designed to detect phishing and credential harvesting attacks in real time.

It includes:
- **Trained AI Classifier**: High-precision XGBoost model with character n-grams and 18 lexical/structural features (< 1 MB).
- **Web UI**: Interactive scanner interface served directly at `http://127.0.0.1:8787/`.
- **Browser Extension**: Real-time background scanning for Chrome/Chromium browsers.
- **REST API**: Fast `/predict` and `/health` JSON endpoints for integrations.

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

# Interactive scanning shell
python main.py
```

---

## 📦 Deployment Options

### Option A: Git Push (GitHub / GitLab)
All sensitive local files, `.env` files, caches, and the `env/` virtual environment are automatically excluded by `.gitignore`:
```bash
git add .
git commit -m "feat: Initial commit for LureLock Phishing AI"
git branch -M main
git remote add origin <your-git-repo-url>
git push -u origin main
```

### Option B: Clean ZIP Export
To package the whole project into a clean, lightweight zip archive ready to send or upload (skipping `env/`, `.git/`, and caches):
```bash
python main.py --zip
```
This generates `lurelock_deployment.zip` in your root folder.

### Option C: Docker Container
```bash
# Build the Docker image
docker build -t lurelock-ai .

# Run the container
docker run -d -p 8787:8787 --name lurelock lurelock-ai
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
  "probability": 0.9999,
  "label": "phishing",
  "features": [
    { "label": "URL length", "value": "39 chars", "note": "Within a typical length.", "flag": false },
    { "label": "Suspicious keywords", "value": "login, update, paypal", "note": "Sign-in or brand words found.", "flag": true },
    { "label": "Character entropy", "value": "3.87 bits", "note": "High randomness.", "flag": true }
  ]
}
```

---

## 🧩 Chrome Extension Installation
1. Open your browser and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the [`extension/`](extension/) directory.
4. The extension icon will appear in your browser toolbar and connect to your local server.

