"""Automated Dataset Cleaning & Loading Engine.

Prepares balanced, high-quality training datasets from:
  - datasets/phishing_set/2.csv (PhiUSIIL benchmark: verified phishing & legitimate URLs)
  - datasets/apex_set/3.csv (Top global apex domains)

Features realistic path synthesis for benign domains so the model learns
genuine phishing patterns (credential keywords, brand impersonation, high entropy)
rather than falsely penalizing legitimate links for having a path.
"""

import os
import re
import glob
import gc
import random
import pandas as pd
from .domain_utils import sanitize_benign_domains

# Common realistic benign paths used to ensure dataset structural diversity
BENIGN_PATHS = [
    '', '/', '/index.html', '/about', '/about-us', '/contact', '/privacy-policy',
    '/terms', '/help', '/faq', '/docs', '/docs/overview', '/blog', '/blog/post',
    '/news', '/articles/technology', '/category/all', '/search?q=info',
    '/products', '/services', '/pricing', '/download', '/wiki/Main_Page',
    '/en-us/support', '/explore', '/community', '/gallery', '/team'
]


def is_valid_url_candidate(val: str) -> bool:
    """Verifies that a cell value represents a realistic URL or domain name."""
    s = str(val).strip()
    if not s or len(s) < 3 or len(s) > 2048 or ' ' in s:
        return False
    if re.match(r'^-?\d+(\.\d+)?$', s):
        return False
    return bool('.' in s or '://' in s)


def load_all_datasets(
    datasets_dir: str,
    max_samples_per_class: int = 75_000
) -> pd.DataFrame:
    """Loads, cleans, balances, and structurally enriches training datasets.
    
    Args:
        datasets_dir: Directory containing 'phishing_set' and 'apex_set'.
        max_samples_per_class: Balanced sampling budget per class.
        
    Returns:
        Balanced DataFrame with standardized columns ['url', 'label'].
    """
    phishing_set_dir = os.path.join(datasets_dir, 'phishing_set')
    apex_set_dir = os.path.join(datasets_dir, 'apex_set')

    print(f"[INFO] Scanning datasets in '{phishing_set_dir}/' and '{apex_set_dir}/'...")

    phish_csv = os.path.join(phishing_set_dir, '2.csv')
    if not os.path.exists(phish_csv):
        # Look for any available csv
        found = glob.glob(os.path.join(phishing_set_dir, "*.csv"))
        phish_csv = found[0] if found else None

    if not phish_csv or not os.path.exists(phish_csv):
        raise FileNotFoundError(f"No valid dataset found in '{phishing_set_dir}/'.")

    # Load verified phishing and legitimate URLs from benchmark dataset
    raw_df = pd.read_csv(phish_csv, low_memory=False)
    if 'url' not in raw_df.columns or 'label' not in raw_df.columns:
        raise ValueError(f"Dataset '{phish_csv}' must contain 'url' and 'label' columns.")

    raw_df = raw_df.dropna(subset=['url', 'label'])
    raw_df['url'] = raw_df['url'].astype(str).str.strip()
    raw_df['label'] = raw_df['label'].astype(int)
    raw_df = raw_df[raw_df['url'].apply(is_valid_url_candidate)]

    phishing_samples = raw_df[raw_df['label'] == 1].copy()
    legit_samples = raw_df[raw_df['label'] == 0].copy()

    # Load apex domains from apex_set
    apex_csvs = sorted(glob.glob(os.path.join(apex_set_dir, "*.csv")))
    apex_list = []
    if apex_csvs:
        target_apex = apex_csvs[0]
        try:
            apex_preview = pd.read_csv(target_apex, nrows=max_samples_per_class, header=0)
            url_col = apex_preview.columns[0]
            apex_list = apex_preview[url_col].dropna().astype(str).str.strip().tolist()
        except Exception as e:
            print(f"[WARN] Could not load apex domains from {target_apex}: {e}")

    # Synthesize realistic benign URLs with diverse paths and schemes
    if apex_list:
        random.seed(42)
        schemes = ['https://', 'http://', 'https://www.']
        synthesized = []
        for domain in apex_list:
            if is_valid_url_candidate(domain):
                clean_d = re.sub(r'^https?://(www\.)?', '', domain).split('/')[0]
                sch = random.choice(schemes)
                p = random.choice(BENIGN_PATHS)
                synthesized.append(f"{sch}{clean_d}{p}")
        if synthesized:
            extra_legit_df = pd.DataFrame({'url': synthesized, 'label': 0})
            legit_samples = pd.concat([legit_samples, extra_legit_df], ignore_index=True)

    # Sanitize benign domains against phishing dataset
    phishing_urls_set = set(phishing_samples['url'].tolist())
    legit_samples = sanitize_benign_domains(legit_samples, phishing_urls_set)

    # Stratified balance to avoid class skew
    target_count = min(len(phishing_samples), len(legit_samples), max_samples_per_class)
    phishing_balanced = phishing_samples.sample(n=target_count, random_state=42)
    legit_balanced = legit_samples.sample(n=target_count, random_state=42)

    full_df = pd.concat([phishing_balanced, legit_balanced], ignore_index=True)
    full_df = full_df.drop_duplicates(subset=['url']).sample(frac=1, random_state=42).reset_index(drop=True)

    counts = full_df['label'].value_counts().to_dict()
    print(f"[INFO] Training set prepared: {len(full_df):,} total URLs.")
    print(f"[INFO] Class balance -> Legitimate (0): {counts.get(0, 0):,} | Phishing (1): {counts.get(1, 0):,}\n")

    return full_df


def clean_all_datasets(datasets_dir: str):
    """Scans and validates dataset files."""
    print(f"[INFO] Scanning datasets in '{datasets_dir}'...")
    for root, _, files in os.walk(datasets_dir):
        for f in sorted(files):
            if f.endswith('.csv'):
                fp = os.path.join(root, f)
                sz_mb = round(os.path.getsize(fp) / (1024 * 1024), 2)
                print(f"       • {f} ({sz_mb} MB)")
    print("[INFO] Dataset check complete.\n")
