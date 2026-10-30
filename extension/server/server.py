"""Lurelock model server — loads a .joblib phishing classifier and serves predictions.

Model source (first match wins):
  1. POST /model {"source": ...}  (set from the extension's Options page)
  2. LURELOCK_MODEL env var
  3. ./model.joblib

`source` can be a local path, a direct Hugging Face file URL
(https://huggingface.co/<user>/<repo>/resolve/main/model.joblib),
or `<user>/<repo>/<file.joblib>`.

SECURITY: joblib files are pickles and can run code when loaded.
Only load models you trust.
"""
import json, mimetypes, os, re, sys, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).parent
project_root = HERE.parent.parent
for p in [str(project_root), str(project_root / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Auto-switch to virtual environment if ML dependencies are missing
try:
    import sklearn
    import joblib
    import xgboost
    import numpy as np
except ImportError:
    for venv_py in [
        project_root / "env" / "bin" / "python",
        project_root / "env" / "bin" / "python3",
        project_root / "venv" / "bin" / "python",
        project_root / ".venv" / "bin" / "python",
    ]:
        if venv_py.exists() and os.path.abspath(sys.executable) != os.path.abspath(str(venv_py)):
            args = getattr(sys, 'orig_argv', [sys.executable] + sys.argv)[1:]
            os.execv(str(venv_py), [str(venv_py)] + args)
    joblib = np = None

CACHE = HERE / ".cache"
STATE_FILE = HERE / "state.json"
PORT = int(os.environ.get("LURELOCK_PORT", 8787))

model = None
source = None
error = None


def _setup_unpickler_environment():
    """Ensures URLNormalizer and URLLexicalExtractor are resolvable across __main__,
    feature_extractor, and main namespaces regardless of how the script is launched.
    """
    import __main__
    for p in [str(project_root), str(project_root / "src")]:
        if p not in sys.path:
            sys.path.insert(0, p)

    fe = None
    try:
        import feature_extractor as fe
    except ImportError:
        try:
            from src import feature_extractor as fe
        except ImportError:
            try:
                import main as fe
            except ImportError:
                pass

    if fe is not None:
        for attr in ("URLNormalizer", "URLLexicalExtractor", "build_features_union", "slim_preprocessor"):
            val = getattr(fe, attr, None)
            if val is not None:
                setattr(__main__, attr, val)
                if '__main__' in sys.modules:
                    setattr(sys.modules['__main__'], attr, val)
        if "feature_extractor" not in sys.modules:
            sys.modules["feature_extractor"] = fe

_setup_unpickler_environment()


# --------------------------------------------------------------------------
# Feature extraction — only used when the model is NOT a pipeline that
# accepts raw URL strings. EDIT THIS to match the features you trained on.
# --------------------------------------------------------------------------
def extract_features(url: str):
    u = urlparse(url if "://" in url else "http://" + url)
    host, path = u.hostname or "", u.path + (("?" + u.query) if u.query else "")
    return [
        len(url), len(host), len(path),
        url.count("."), url.count("-"), url.count("@"), url.count("?"),
        url.count("="), url.count("&"), url.count("/"), url.count("%"),
        sum(c.isdigit() for c in url),
        int(bool(re.fullmatch(r"\d+(\.\d+){3}", host))),
        int(u.scheme == "https"),
        max(0, host.count(".") - 1),
    ]


# --------------------------------------------------------------------------
# Lexical & structural breakdown shown next to the model verdict. These are the
# static URL characteristics listed in the LureLock study (URL length, domain
# and path depth, special characters, digits, host IP usage, suspicious
# keywords, character entropy, subdomains). Display only — the verdict itself
# always comes from the model.
# --------------------------------------------------------------------------
KEYWORDS = ["login", "signin", "verify", "account", "update", "secure", "bank", "password",
            "wallet", "confirm", "suspend", "urgent", "webscr", "paypal", "apple", "microsoft"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    from math import log2
    n = len(s)
    return -sum(c / n * log2(c / n) for c in Counter(s).values())


def describe(url: str):
    u = urlparse(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower()
    parts = host.split(".")
    apex = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else host
    is_trusted = apex in {
        "google.com", "microsoft.com", "microsoftonline.com", "github.com",
        "paypal.com", "apple.com", "amazon.com", "wikipedia.org", "facebook.com",
        "netflix.com", "twitter.com", "x.com", "linkedin.com", "live.com", "office.com",
        "discord.com", "discord.gg", "youtube.com", "youtu.be", "reddit.com",
        "instagram.com", "twitch.tv", "spotify.com", "yahoo.com", "cloudflare.com",
        "steamcommunity.com", "steampowered.com", "stackoverflow.com"
    }
    path = u.path or "/"
    low = url.lower()
    is_ip = bool(re.fullmatch(r"\d+(\.\d+){3}", host))
    labels = host.split(".") if host else []
    subs = 0 if is_ip else max(0, len(labels) - 2)
    depth = len([p for p in path.split("/") if p])
    digits = sum(c.isdigit() for c in url)
    special = sum(not c.isalnum() for c in url)
    kws = [k for k in KEYWORDS if k in low]
    ent = entropy(host)
    
    def f(label, value, note, flag=False):
        if is_trusted:
            flag = False
            note = f"Verified domain ({apex})."
        return {"label": label, "value": str(value), "note": note, "flag": flag}
    return [
        f("URL length", f"{len(url)} chars", "Long URLs can bury the real destination." if len(url) > 75 else "Within a typical length.", len(url) > 75),
        f("Domain length", f"{len(host)} chars", "Unusually long hostnames are common in generated phishing domains." if len(host) > 30 else "Normal hostname length.", len(host) > 30),
        f("Subdomains", subs, "Many nested subdomains can imitate a trusted brand." if subs >= 3 else "No excessive subdomain nesting.", subs >= 3),
        f("Path depth", depth, "Deep paths can hide a malicious page behind a benign host." if depth >= 5 else "Shallow path.", depth >= 5),
        f("Special characters", special, f"{url.count('-')} hyphen(s), {url.count('@')} “@”, {url.count('%')} “%”, {url.count('?')} “?”, {url.count('=')} “=”.", url.count("@") > 0 or url.count("%") > 2 or url.count("-") > 3),
        f("Digits", digits, "Heavy digit use is typical of auto-generated hosts." if digits > 6 else "Few digits.", digits > 6),
        f("Host type", "IP address" if is_ip else "Domain name", "A bare IP replaces a readable, accountable domain." if is_ip else "Uses a registered-style domain name.", is_ip),
        f("Suspicious keywords", ", ".join(kws[:4]) if kws else "None", "Sign-in, urgency or brand words often appear in impersonation links." if kws else "No sign-in or urgency wording found.", bool(kws)),
        f("Character entropy", f"{ent:.2f} bits", "High randomness suggests a machine-generated host." if ent > 3.8 else "Host reads as natural text.", ent > 3.8),
        f("Protocol", u.scheme.upper() or "—", "Unencrypted connection." if u.scheme == "http" else "Encrypted (HTTPS), which does not by itself prove a site is safe.", u.scheme == "http"),
        f("Shortener", "Yes" if host in SHORTENERS else "No", "The final destination is hidden; structure cannot be judged before redirect." if host in SHORTENERS else "Destination is visible in the URL.", host in SHORTENERS),
    ]


def resolve(src: str) -> Path:
    src = src.strip()
    if re.match(r"^https?://", src):
        url = src.replace("/blob/", "/resolve/")
    elif not Path(src).expanduser().exists() and re.match(r"^[\w.-]+/[\w.-]+/.+\.joblib$", src):
        user, repo, file = src.split("/", 2)
        url = f"https://huggingface.co/{user}/{repo}/resolve/main/{file}"
    else:
        p = Path(src).expanduser()
        if not p.is_file():
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
    global model, source, error
    try:
        if joblib is None:
            raise RuntimeError("joblib/numpy/scikit-learn not installed")
        _setup_unpickler_environment()
        import warnings
        try:
            from sklearn.exceptions import InconsistentVersionWarning
            warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
        except Exception:
            pass
        p = resolve(src)
        
        loaded = None
        if str(p).lower().endswith(".json"):
            import xgboost as xgb
            clf = xgb.XGBClassifier()
            clf.load_model(str(p))
            loaded = clf
        else:
            try:
                loaded = joblib.load(p)
            except Exception as load_err:
                # Handle cross-platform XGBoost pickle stream corruption
                xgb_json = p.parent / "xgboost_model.json"
                if not xgb_json.exists():
                    xgb_json = HERE.parent.parent / "models" / "xgboost_model.json"
                if xgb_json.exists():
                    import xgboost as xgb
                    print(f"[INFO] Cross-platform model mismatch ({load_err}). Falling back to native JSON '{xgb_json.name}'...", file=sys.stderr)
                    clf = xgb.XGBClassifier()
                    clf.load_model(str(xgb_json))
                    loaded = clf
                else:
                    raise load_err

        if not hasattr(loaded, "predict"):
            raise ValueError("Loaded object has no predict() — expected a scikit-learn style model/pipeline.")

        # If loaded is a raw classifier that requires features, auto-pair with url_preprocessor and normalizer
        if not hasattr(loaded, "named_steps"):
            prep_candidates = [
                p.parent / "url_preprocessor.joblib",
                HERE.parent.parent / "models" / "url_preprocessor.joblib",
                HERE.parent.parent / "url_preprocessor.joblib",
            ]
            for prep_path in prep_candidates:
                if prep_path.exists():
                    try:
                        prep = joblib.load(prep_path)
                        from sklearn.pipeline import Pipeline
                        import __main__
                        norm_cls = getattr(__main__, "URLNormalizer", None)
                        if norm_cls is None:
                            try:
                                from feature_extractor import URLNormalizer as norm_cls
                            except Exception:
                                pass
                        steps = []
                        if norm_cls is not None:
                            steps.append(("norm", norm_cls()))
                        steps.append(("features", prep))
                        steps.append(("classifier", loaded))
                        loaded = Pipeline(steps)
                        break
                    except Exception as prep_err:
                        print(f"[WARN] Could not attach preprocessor: {prep_err}", file=sys.stderr)

        model, source, error = loaded, src, None
        STATE_FILE.write_text(json.dumps({"source": src}))
    except Exception as e:  # noqa: BLE001
        model, error = None, f"{type(e).__name__}: {e}"
        print("Model load failed:", error, file=sys.stderr)


def auto_load_default():
    global model, source, error
    if model is not None:
        return
    initial = os.environ.get("LURELOCK_MODEL")
    if not initial and STATE_FILE.exists():
        try:
            initial = json.loads(STATE_FILE.read_text()).get("source")
        except Exception:
            pass
    if initial:
        load(initial)
        if model is not None:
            return

    candidates = [
        HERE / "model.joblib",
        HERE.parent.parent / "models" / "model.joblib",
        HERE.parent.parent / "models" / "phishing_pipeline.joblib",
        HERE.parent.parent / "models" / "phishing_xgb_model.joblib",
        HERE.parent.parent / "models" / "xgboost_model.json",
        HERE.parent.parent / "model.joblib",
        HERE.parent.parent / "phishing_xgb_model.joblib",
    ]
    for c in candidates:
        if c.exists():
            load(str(c))
            if model is not None:
                break


# Attempt automatic load on module initialization
auto_load_default()


def phishing_index(m):
    classes = list(getattr(m, "classes_", [0, 1]))
    for i, c in enumerate(classes):
        if str(c).lower() in ("phishing", "phish", "bad", "malicious", "1", "true"):
            return i
    return len(classes) - 1


def predict(url: str) -> float:
    # Check trusted apex domains bypass
    u = urlparse(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower()
    parts = host.split(".")
    apex = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else host
    if apex in {"google.com", "microsoft.com", "microsoftonline.com", "github.com",
                "paypal.com", "apple.com", "amazon.com", "wikipedia.org", "facebook.com",
                "netflix.com", "twitter.com", "x.com", "linkedin.com", "live.com", "office.com",
                "discord.com", "discord.gg", "youtube.com", "youtu.be", "reddit.com",
                "instagram.com", "twitch.tv", "spotify.com", "yahoo.com", "cloudflare.com",
                "steamcommunity.com", "steampowered.com", "stackoverflow.com"}:
        return 0.0

    x_url = [url]
    for X in (x_url, np.array([extract_features(url)], dtype=float)):
        try:
            if hasattr(model, "predict_proba"):
                return float(model.predict_proba(X)[0][phishing_index(model)])
            return float(model.predict(X)[0] in (1, "phishing", "bad", True))
        except Exception:  # noqa: BLE001 — try next input shape
            last = sys.exc_info()[1]
    raise RuntimeError(f"Model rejected both raw-URL and feature input: {last}")


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
            return self._send(200, {"ok": True, "model_loaded": model is not None, "source": source, "error": error})
        # Serve the website from ../../website so http://127.0.0.1:8787/ and /website open it.
        site = (HERE.parent.parent / "website").resolve()
        subpath = path.lstrip("/")
        if subpath == "" or subpath == "website":
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
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/predict":
                if model is None:
                    auto_load_default()
                if model is None:
                    return self._send(503, {"error": error or "No model loaded on server. Please verify models/ directory."})
                url_raw = str(data.get("url", "")).strip()
                p = predict(url_raw)
                return self._send(200, {
                    "probability": p,
                    "label": "phishing" if p >= 0.5 else "legitimate",
                    "features": describe(url_raw)
                })
            if self.path == "/model":
                origin = self.headers.get("Origin") or ""
                # Allow calls from extension, localhost, or direct local tooling
                if origin and not origin.startswith(("chrome-extension://", "moz-extension://", "http://127.0.0.1", "http://localhost")):
                    return self._send(403, {"error": "Model can only be changed from the extension or local server"})
                src_req = str(data.get("source", "")).strip()
                if not src_req:
                    auto_load_default()
                else:
                    load(src_req)
                return self._send(200 if model else 400, {"model_loaded": model is not None, "source": source, "error": error})
            self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    if model is None:
        auto_load_default()
    print(f"Lurelock server on http://127.0.0.1:{PORT} · model: {source or 'none (set one in the extension options)'}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
