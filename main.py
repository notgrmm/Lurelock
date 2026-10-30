#!/usr/bin/env python3
"""Group 4 Project: Phishing URL Detector (LureLock)

Main entrypoint for model training, interactive CLI link scanning,
and automated dataset cleaning. Fully compatible with both local
environments and Google Colab / Jupyter Notebooks.

Usage:
  python main.py                  # Load model & start interactive scanner
  python main.py <url>            # Scan a single URL and print result
  python main.py --train          # Force retrain the model pipeline
  python main.py --clean          # Scan and clean all raw CSV datasets
  python main.py --serve          # Launch local web & extension API server
"""

import os
import sys
import json
import subprocess

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

# --------------------------------------------------------------------------
# Environment & Virtualenv Setup
# --------------------------------------------------------------------------
def is_in_colab() -> bool:
    """Detects whether code is running inside Google Colab."""
    return 'google.colab' in sys.modules

def is_in_notebook() -> bool:
    """Detects whether code is running inside a Jupyter notebook or ipykernel."""
    if is_in_colab() or 'ipykernel' in sys.modules:
        return True
    try:
        from IPython import get_ipython
        return get_ipython() is not None
    except Exception:
        return False

# Resolve project paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
SRC_DIR = os.path.join(ROOT_DIR, 'src')

# Ensure src/ and root are in sys.path
for p in [ROOT_DIR, SRC_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Auto-switch to local virtual environment if dependencies are not found in system Python
if not is_in_notebook() and '__file__' in globals():
    try:
        import sklearn
        import joblib
        import xgboost
        import pandas as pd
        import numpy as np
    except ImportError:
        for venv_py in [
            os.path.join(ROOT_DIR, 'env', 'bin', 'python'),
            os.path.join(ROOT_DIR, 'env', 'bin', 'python3'),
            os.path.join(ROOT_DIR, 'venv', 'bin', 'python'),
            os.path.join(ROOT_DIR, '.venv', 'bin', 'python'),
        ]:
            if os.path.exists(venv_py) and os.path.abspath(sys.executable) != os.path.abspath(venv_py):
                args = getattr(sys, 'orig_argv', [sys.executable] + sys.argv)[1:]
                os.execv(venv_py, [venv_py] + args)

# --------------------------------------------------------------------------
# Modular Component Imports
# --------------------------------------------------------------------------
from src.feature_extractor import (
    URLNormalizer,
    URLLexicalExtractor,
    build_features_union,
    slim_preprocessor,
    calculate_shannon_entropy,
    KEYWORDS,
    SHORTENERS
)
from src.domain_utils import (
    ExtractResult,
    fallback_extract,
    tld_extractor,
    get_apex_domain,
    sanitize_benign_domains,
    TRUSTED_APEX_DOMAINS
)
from src.dataset_cleaner import (
    clean_all_datasets,
    clean_and_load_csv,
    load_all_datasets,
    is_valid_url_candidate,
    is_csv_clean
)
from src.explainer import (
    describe_url,
    get_prediction_details,
    print_result_display,
    validate_url,
    VERDICTS
)
from src.trainer import (
    get_or_train_model,
    save_artifacts,
    download_models_colab,
    get_ram_usage_gb,
    MODELS_DIR,
    DATASETS_DIR,
    PIPELINE_FILE,
    PREPROCESSOR_FILE,
    MODEL_FILE,
    MODEL_CARD_FILE
)

from sklearn.pipeline import Pipeline

_global_pipeline = None


# --------------------------------------------------------------------------
# Server Launcher & Interactive Scanner
# --------------------------------------------------------------------------
def start_local_server():
    """Launches the LureLock local web and extension API server."""
    run_server_script = os.path.join(ROOT_DIR, 'run_server.py')
    if os.path.exists(run_server_script):
        subprocess.run([sys.executable, run_server_script])
    else:
        server_path = os.path.join(ROOT_DIR, 'extension', 'server', 'server.py')
        if os.path.exists(server_path):
            subprocess.run([sys.executable, server_path])
        else:
            print("[ERROR] Could not locate server launcher script.")


def scan_single_url(pipeline, url: str, as_json: bool = False):
    """Scans a single URL, checks the VIP list, and outputs the result."""
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        print(f"[ERROR] {error_msg}")
        return

    apex = get_apex_domain(url)
    if apex in TRUSTED_APEX_DOMAINS:
        details = get_prediction_details(url, 0.0, is_trusted=True)
    else:
        prob = float(pipeline.predict_proba([url])[0][1])
        details = get_prediction_details(url, prob)

    if as_json:
        print(json.dumps(details, indent=2, ensure_ascii=False))
    else:
        print_result_display(details)


def run_interactive_cli(pipeline=None, model=None):
    """Runs the terminal interactive scanner prompt loop."""
    global _global_pipeline
    if pipeline is not None and model is not None:
        # Backward compatibility if invoked as: run_interactive_cli(preprocessor, model)
        preprocessor = pipeline
        pipeline = Pipeline([
            ('norm', URLNormalizer()),
            ('features', preprocessor),
            ('classifier', model)
        ])
    elif pipeline is None:
        if _global_pipeline is not None:
            pipeline = _global_pipeline
        else:
            res = get_or_train_model()
            pipeline = res[0] if isinstance(res, tuple) else res

    _global_pipeline = pipeline
    show_json = False

    print("=" * 65)
    print(" 🛡️  LURELOCK PHISHING URL SCANNER — INTERACTIVE CONSOLE")
    print("=" * 65)
    print(" Commands:")
    print("   • Paste any link (e.g., https://example.com) to scan it")
    print("   • Type 'json'   : Toggle website/extension JSON debug payload")
    print("   • Type 'serve'  : Launch the local Web UI & Extension server")
    print("   • Type 'exit'   : Quit the application")
    print("=" * 65 + "\n")

    while True:
        try:
            prompt = "[JSON MODE] Enter link > " if show_json else "Enter link > "
            user_input = input(prompt).strip()

            if not user_input:
                continue

            if user_input.lower() in ['exit', 'quit', 'q']:
                print("[SYSTEM] Goodbye.")
                break

            if user_input.lower() == 'json':
                show_json = not show_json
                print(f"[SYSTEM] JSON format output: {'ENABLED' if show_json else 'DISABLED'}\n")
                continue

            if user_input.lower() in ['serve', 'server']:
                start_local_server()
                continue

            scan_single_url(pipeline, user_input, as_json=show_json)

        except (KeyboardInterrupt, EOFError):
            print("\n[SYSTEM] Terminating.")
            break
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}\n")


def package_clean_zip(output_filename: str = "lurelock_deployment.zip", include_datasets: bool = True) -> str:
    """Creates a clean, production-ready ZIP archive of the project,
    automatically excluding virtual environments, .git, caches, and sensitive files.
    """
    import zipfile
    zip_path = os.path.join(ROOT_DIR, output_filename)
    exclude_dirs = {'env', 'venv', '.venv', 'ENV', '__pycache__', '.git', '.cache', '.idea', '.vscode'}
    if not include_datasets:
        exclude_dirs.add('datasets')
    exclude_files = {output_filename, 'state.json', '.DS_Store', 'Thumbs.db', 'lurelock-extension.zip'}

    label = "Full" if include_datasets else "Lite (AI model & app only)"
    print(f"[INFO] Packaging {label} project into '{output_filename}'...")
    count = 0
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ROOT_DIR):
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith('.env') and not d.endswith('.cache')]
            for f in files:
                if f in exclude_files or f.endswith(('.pyc', '.pyo', '.pyd', '.log', '.zip')) or f.startswith('.env'):
                    continue
                abs_path = os.path.join(root, f)
                rel_path = os.path.relpath(abs_path, ROOT_DIR)
                zf.write(abs_path, rel_path)
                count += 1

    size_mb = round(os.path.getsize(zip_path) / (1024 * 1024), 2)
    print(f"[INFO] ✓ Clean deployment ZIP created: '{zip_path}'")
    print(f"[INFO] Packaged {count} files ({size_mb} MB total). Excluded env/, .git, and caches.\n")
    return zip_path


# --------------------------------------------------------------------------
# CLI Main Routing
# --------------------------------------------------------------------------
def main():
    args = sys.argv[1:]

    # 1. Packaging / Clean ZIP Flag
    if args and args[0] in ['--zip', '-z', 'zip', 'package', '--lite']:
        is_lite = '--lite' in args
        out_name = "lurelock_app_lite.zip" if is_lite else "lurelock_deployment.zip"
        for a in args[1:]:
            if a.endswith('.zip'):
                out_name = a
        package_clean_zip(out_name, include_datasets=(not is_lite))
        return

    # 2. Server Launcher Flag
    if args and args[0] in ['--serve', '-s', 'serve']:
        start_local_server()
        return

    # 3. Dataset Cleaner Flag
    if args and args[0] in ['--clean', '-c', 'clean']:
        clean_all_datasets(DATASETS_DIR)
        return

    # 4. Model Training / Retraining Flag
    force_retrain = bool(args and args[0] in ['--train', '--retrain', '-t'])
    res = get_or_train_model(force_retrain=force_retrain)

    if isinstance(res, tuple) and len(res) == 3:
        pipeline = res[0]
    elif isinstance(res, tuple) and len(res) == 2:
        pipeline = Pipeline([
            ('norm', URLNormalizer()),
            ('features', res[0]),
            ('classifier', res[1])
        ])
    else:
        pipeline = res

    # 4. Single URL Scan from command line argument
    remaining = [a for a in args if not a.startswith('-')]
    if remaining and not force_retrain:
        scan_single_url(pipeline, remaining[0], as_json='--json' in args)
        return

    # 5. Interactive Terminal Loop
    run_interactive_cli(pipeline)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError) as err:
        print(f"\n[FATAL ERROR] {err}")