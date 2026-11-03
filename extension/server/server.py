"""LureLock Model Server.

Serves predictions to:
  1. The Web UI at http://127.0.0.1:8787/
  2. The Chrome/Chromium Browser Extension

Unified backend ensuring identical, consistent classification between the
website and the browser extension.
No hardcoded links or keyword lists. All logic is imported from src/.
"""

import json
import mimetypes
import os
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent.parent

for p in [str(PROJECT_ROOT), str(PROJECT_ROOT / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

import joblib
import numpy as np

# Import unified ML and explainability components
from src.feature_extractor import (
    URLNormalizer,
    URLLexicalExtractor,
    normalize_url
)
from src.domain_utils import (
    is_trusted_domain,
    get_apex_domain
)
from src.explainer import (
    describe_url,
    get_prediction_details,
    VERDICTS
)

CACHE = HERE / ".cache"
STATE_FILE = HERE / "state.json"
PORT = int(os.environ.get("LURELOCK_PORT", 8787))

model = None
source = None
error = None


def resolve(src: str) -> Path:
    """Resolves local model file or downloads from remote URL / Hugging Face."""
    src = src.strip()
    if re.match(r"^https?://", src):
        url = src.replace("/blob/", "/resolve/")
    elif not Path(src).expanduser().exists() and re.match(r"^[\w.-]+/[\w.-]+/.+\.joblib$", src):
        user, repo, file = src.split("/", 2)
        url = f"https://huggingface.co/{user}/{repo}/resolve/main/{file}"
    else:
        p = Path(src).expanduser()
        if not p.is_file():
            # Try resolving relative to PROJECT_ROOT
            alt = PROJECT_ROOT / src
            if alt.is_file():
                return alt
            raise FileNotFoundError(f"No such file: {p}")
        return p

    CACHE.mkdir(exist_ok=True)
    dest = CACHE / re.sub(r"[^\w.-]", "_", url.split("//", 1)[1])
    if not dest.exists():
        req = urllib.request.Request(url, headers={"User-Agent": "lurelock"})
        token = os.environ.get("HF_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
            f.write(r.read())
    return dest


def load(src: str):
    """Loads a trained pipeline or XGBoost model from disk or cache."""
    global model, source, error
    try:
        p = resolve(src)
        loaded = None

        if str(p).lower().endswith(".json"):
            import xgboost as xgb
            clf = xgb.XGBClassifier()
            clf.load_model(str(p))
            # Wrap in Pipeline for unified raw URL handling
            from sklearn.pipeline import Pipeline
            loaded = Pipeline([
                ('norm', URLNormalizer()),
                ('features', URLLexicalExtractor()),
                ('classifier', clf)
            ])
        else:
            loaded = joblib.load(p)

        if not hasattr(loaded, "predict"):
            raise ValueError("Loaded object has no predict() method.")

        model, source, error = loaded, str(p), None
        STATE_FILE.write_text(json.dumps({"source": str(p)}))
        print(f"[INFO] Successfully loaded model from '{p.name}'")
    except Exception as e:
        model, error = None, f"{type(e).__name__}: {e}"
        print(f"[ERROR] Model load failed: {error}", file=sys.stderr)


def auto_load_default():
    """Auto-detects and loads default model artifact."""
    global model, source, error
    if model is not None:
        return

    initial = os.environ.get("LURELOCK_MODEL")
    if not initial and STATE_FILE.exists():
        try:
            initial = json.loads(STATE_FILE.read_text()).get("source")
        except Exception:
            pass

    candidates = [
        initial,
        PROJECT_ROOT / "models" / "model.joblib",
        PROJECT_ROOT / "models" / "xgboost_model.json",
        PROJECT_ROOT / "models" / "phishing_xgb_model.joblib",
        HERE / "model.joblib"
    ]

    for c in candidates:
        if c and Path(c).exists():
            load(str(c))
            if model is not None:
                return


# Auto-load on startup
auto_load_default()


def predict_url(url: str) -> dict:
    """Classifies a URL and returns standardized explainability details.
    
    Guarantees exact same prediction logic for Web UI and Chrome Extension.
    """
    clean = normalize_url(url)
    
    # Check trusted external dataset bypass
    if is_trusted_domain(clean):
        details = get_prediction_details(clean, 0.0, is_trusted=True)
        details['url'] = url
        return details

    if model is None:
        auto_load_default()

    if model is None:
        raise RuntimeError("No model is currently loaded on the server. Please run: python main.py --train")

    try:
        # Standard pipeline input (accepts raw string or list)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba([clean])[0]
            # Column 1 corresponds to phishing class
            prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            prob = float(model.predict([clean])[0])
    except Exception:
        # Fallback if raw classifier without feature transformer
        extractor = URLLexicalExtractor()
        X = extractor.transform([clean])
        if hasattr(model, "predict_proba"):
            prob = float(model.predict_proba(X)[0][1])
        else:
            prob = float(model.predict(X)[0])

    details = get_prediction_details(clean, prob, is_trusted=False)
    details['url'] = url
    return details


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Origin, Accept")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Origin, Accept")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            if model is None:
                auto_load_default()
            return self._send(200, {
                "ok": True,
                "model_loaded": model is not None,
                "source": source,
                "error": error
            })

        # Serve Web UI from website/
        site = (PROJECT_ROOT / "website").resolve()
        subpath = path.lstrip("/")
        if subpath in ("", "website"):
            target = "index.html"
        elif subpath.startswith("website/"):
            target = subpath[len("website/"):]
        else:
            target = subpath

        f = (site / target).resolve()
        if site in f.parents and f.is_file():
            body = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(f.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)

        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(content_len) or b"{}")

            if self.path == "/predict":
                url_raw = str(data.get("url", "")).strip()
                if not url_raw:
                    return self._send(400, {"error": "Please provide a 'url' parameter."})

                details = predict_url(url_raw)
                return self._send(200, details)

            if self.path == "/model":
                origin = self.headers.get("Origin") or ""
                if origin and not origin.startswith(("chrome-extension://", "moz-extension://", "http://127.0.0.1", "http://localhost")):
                    return self._send(403, {"error": "Model can only be changed locally or from extension."})

                src_req = str(data.get("source", "")).strip()
                if not src_req:
                    auto_load_default()
                else:
                    load(src_req)
                return self._send(200 if model else 400, {
                    "model_loaded": model is not None,
                    "source": source,
                    "error": error
                })

            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    if model is None:
        auto_load_default()
    print(f"Lurelock server listening at http://127.0.0.1:{PORT} · Model: {source or 'None'}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
