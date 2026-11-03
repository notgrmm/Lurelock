#!/usr/bin/env python3
"""LureLock Local Server Launcher

Starts the local API and web server at http://127.0.0.1:8787.
Connects the trained model from models/ directly to:
  1. The Web UI at http://127.0.0.1:8787/
  2. The Chrome/Chromium Browser Extension
"""
import os
import sys

# Ensure UTF-8 output on Windows consoles to prevent charmap encoding errors
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))

# Auto-switch to virtualenv if dependencies like sklearn, joblib, or xgboost are missing
try:
    import sklearn
    import joblib
    import xgboost
except ImportError:
    for venv_py in [
        os.path.join(HERE, 'env', 'bin', 'python'),
        os.path.join(HERE, 'env', 'bin', 'python3'),
        os.path.join(HERE, 'venv', 'bin', 'python'),
        os.path.join(HERE, '.venv', 'bin', 'python'),
    ]:
        if os.path.exists(venv_py) and os.path.abspath(sys.executable) != os.path.abspath(venv_py):
            args = getattr(sys, 'orig_argv', [sys.executable] + sys.argv)[1:]
            os.execv(venv_py, [venv_py] + args)

SERVER_DIR = os.path.join(HERE, 'extension', 'server')
SRC_DIR = os.path.join(HERE, 'src')

for p in [HERE, SRC_DIR, SERVER_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Ensure custom feature extractors are registered in __main__ before importing server
import __main__
try:
    import feature_extractor
    for attr in ("URLNormalizer", "URLLexicalExtractor", "build_features_union", "slim_preprocessor"):
        val = getattr(feature_extractor, attr, None)
        if val is not None:
            setattr(__main__, attr, val)
except Exception:
    pass

import server

if __name__ == '__main__':
    # Auto-resolve initial model candidate if not already loaded
    if not server.model:
        candidates = [
            os.path.join(HERE, 'models', 'model.joblib'),
            os.path.join(HERE, 'models', 'phishing_pipeline.joblib'),
            os.path.join(HERE, 'models', 'phishing_xgb_model.joblib'),
            os.path.join(HERE, 'models', 'xgboost_model.json'),
            os.path.join(HERE, 'extension', 'server', 'model.joblib'),
        ]
        for c in candidates:
            if os.path.exists(c):
                server.load(c)
                if server.model:
                    break

    print("=" * 60, flush=True)
    print(" 🚀 LureLock Local Server is running!", flush=True)
    print(" 👉 Open Website locally : http://127.0.0.1:8787", flush=True)
    print(f" 🧠 Connected Model       : {server.source or 'None'}", flush=True)
    print(" 🔌 Extension API endpoint: http://127.0.0.1:8787/predict", flush=True)
    print("=" * 60, flush=True)
    print("Press Ctrl+C to terminate.", flush=True)

    try:
        server.ThreadingHTTPServer(("127.0.0.1", server.PORT), server.Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[SYSTEM] Server stopped.")
