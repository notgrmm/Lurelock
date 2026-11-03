#!/usr/bin/env python3
"""Group 4 Project: Phishing URL Detector (LureLock)

Main entrypoint for model training, interactive CLI link scanning,
and local server launching. Uses external reference datasets for keywords,
shorteners, and trusted domains (no hardcoded links in Python code).

Usage:
  python main.py                  # Load model & start interactive scanner
  python main.py <url>            # Scan a single URL and print result
  python main.py --train          # Force retrain the model pipeline
  python main.py --clean          # Validate and inspect datasets
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

ROOT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
SRC_DIR = os.path.join(ROOT_DIR, 'src')

for p in [ROOT_DIR, SRC_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Modular imports
from src.feature_extractor import (
    URLNormalizer,
    URLLexicalExtractor,
    normalize_url,
    FEATURE_NAMES
)
from src.domain_utils import (
    is_trusted_domain,
    get_apex_domain
)
from src.dataset_cleaner import (
    clean_all_datasets,
    load_all_datasets
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
    MODELS_DIR,
    DATASETS_DIR,
    PIPELINE_FILE
)

from sklearn.pipeline import Pipeline

_global_pipeline = None


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
    """Scans a single URL, checks the trusted domain list, and outputs the result."""
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        print(f"[ERROR] {error_msg}")
        return

    clean = normalize_url(url)
    if is_trusted_domain(clean):
        details = get_prediction_details(clean, 0.0, is_trusted=True)
    else:
        prob = float(pipeline.predict_proba([clean])[0][1])
        details = get_prediction_details(clean, prob, is_trusted=False)

    details['url'] = url

    if as_json:
        print(json.dumps(details, indent=2, ensure_ascii=False))
    else:
        print_result_display(details)


def run_interactive_cli(pipeline=None):
    """Runs the terminal interactive scanner prompt loop."""
    global _global_pipeline
    if pipeline is None:
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


def main():
    args = sys.argv[1:]

    # Server Launcher Flag
    if args and args[0] in ['--serve', '-s', 'serve']:
        start_local_server()
        return

    # Dataset Cleaner Flag
    if args and args[0] in ['--clean', '-c', 'clean']:
        clean_all_datasets(DATASETS_DIR)
        return

    # Model Training / Retraining Flag
    force_retrain = bool(args and args[0] in ['--train', '--retrain', '-t'])
    res = get_or_train_model(force_retrain=force_retrain)
    pipeline = res[0] if isinstance(res, tuple) else res

    # Single URL Scan from CLI argument
    remaining = [a for a in args if not a.startswith('-')]
    if remaining and not force_retrain:
        scan_single_url(pipeline, remaining[0], as_json='--json' in args)
        return

    # Interactive Terminal Loop
    run_interactive_cli(pipeline)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError) as err:
        print(f"\n[FATAL ERROR] {err}")
