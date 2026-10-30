"""Automated Dataset Cleaning & Loading Engine.

Handles raw, dirty, or malformed CSV datasets:
  - Automatically identifies URL and label columns across diverse schemas.
  - Automatically handles PhiUSIIL label inversions (1 -> 0 legitimate, 0 -> 1 phishing).
  - Rejects corrupted/numeric float records (e.g., '0.207316').
  - Normalizes and overwrites cleaned files on disk to permanently reduce RAM and disk usage.
  - Balances classes to ensure training runs comfortably within Google Colab RAM limits (< 1.5 GB).
"""

import os
import re
import glob
import gc
import pandas as pd
from .domain_utils import sanitize_benign_domains

# Valid label identifiers across common public security benchmarks
KNOWN_LABEL_SET = {
    0, 1, -1, '0', '1', '-1', '0.0', '1.0', '-1.0',
    'phishing', 'legitimate', 'benign', 'good', 'bad', 'safe', 'malicious',
    'definement', 'defacement', 'malware'
}

# Column header aliases commonly used for URL addresses
URL_ALIASES = {'url', 'urls', 'domain', 'link', 'address', 'site', 'hostname'}

# Column header aliases commonly used for class labels
LABEL_ALIASES = {'label', 'class', 'target', 'phishing', 'type', 'status', 'result', 'is_phishing'}


def is_valid_url_candidate(val: str) -> bool:
    """Verifies that a cell value represents a realistic URL or domain name
    rather than a numerical feature or empty string.
    
    Args:
        val: Raw string value from CSV cell.
        
    Returns:
        True if string contains domain/URL patterns, False otherwise.
    """
    s = str(val).strip()
    if not s or len(s) < 3 or len(s) > 2048:
        return False
    if ' ' in s:
        return False
    # Reject pure numbers/floats (e.g., '0.207316' or '-1.5')
    if re.match(r'^-?\d+(\.\d+)?$', s):
        return False
    # Must contain domain-like characters (e.g. dot or protocol)
    return bool('.' in s or '://' in s)


def is_csv_clean(filepath: str) -> bool:
    """Checks whether a CSV file is already in the standardized clean format:
    columns ['url', 'label'] with binary 0/1 integer labels and valid URL records.
    """
    try:
        preview = pd.read_csv(filepath, nrows=20)
        if list(preview.columns) != ['url', 'label']:
            return False
        uniques = set(preview['label'].dropna().unique())
        if not uniques.issubset({0, 1}):
            return False
        sample = preview['url'].dropna().astype(str).tolist()
        if not sample:
            return False
        valid_count = sum(is_valid_url_candidate(u) for u in sample)
        return valid_count >= max(1, int(len(sample) * 0.7))
    except Exception:
        return False


def detect_csv_schema(filepath: str):
    """Inspects an uncleaned CSV file to detect header existence, URL column,
    and Label column automatically.
    
    Returns:
        Tuple of (has_header: bool, url_col: str|int, label_col: str|int)
    """
    preview = pd.read_csv(filepath, nrows=30)
    has_header = True

    # If first column name is a plain integer rank (e.g. '1', '2'), file is headerless
    if all(re.match(r'^\d+$', str(c).strip()) for c in preview.columns[:1]):
        preview = pd.read_csv(filepath, header=None, nrows=30)
        has_header = False

    cols = list(preview.columns)
    url_col = None
    label_col = None

    # Step 1: Detect URL column by name
    if has_header:
        for c in cols:
            if str(c).lower().strip() in URL_ALIASES:
                url_col = c
                break

    # Step 2: Detect URL column by value content inspection if name is not standard
    if url_col is None:
        best_col = None
        best_valid_ratio = 0.0
        for c in cols:
            sample = preview[c].dropna().astype(str).tolist()
            if not sample:
                continue
            valid_ratio = sum(is_valid_url_candidate(s) for s in sample) / len(sample)
            if valid_ratio > best_valid_ratio and valid_ratio >= 0.5:
                best_valid_ratio = valid_ratio
                best_col = c
        url_col = best_col

    # Step 3: Detect Label column by name
    if has_header:
        for c in cols:
            if c != url_col and str(c).lower().strip() in LABEL_ALIASES:
                label_col = c
                break

    # Step 4: Detect Label column by inspecting unique value sets
    if label_col is None:
        for c in cols:
            if c != url_col:
                uniques = set(preview[c].dropna().unique())
                if uniques and uniques.issubset(KNOWN_LABEL_SET):
                    label_col = c
                    break

    return has_header, url_col, label_col


def clean_and_load_csv(
    filepath: str,
    default_label: int = 0,
    max_rows: int = None,
    overwrite_clean: bool = True
) -> pd.DataFrame:
    """Loads a CSV dataset, automatically normalizing and cleaning it:
      - If already clean, loads instantly via column projection.
      - If uncleaned, decodes schema, fixes label mappings (including PhiUSIIL inversion),
        drops corrupted/numeric rows, and overwrites the file on disk to save future time and RAM.
    """
    filename = os.path.basename(filepath)
    if not os.path.exists(filepath):
        return pd.DataFrame(columns=['url', 'label'])

    # Fast-path: Already clean and normalized
    if is_csv_clean(filepath):
        try:
            df = pd.read_csv(filepath, nrows=max_rows, dtype={'url': str, 'label': int})
            df['url'] = df['url'].astype(str).str.strip()
            df = df.dropna(subset=['url', 'label'])
            print(f"[INFO] Loaded clean dataset '{filename}' (Rows: {len(df):,})")
            return df
        except Exception as e:
            print(f"[WARN] Could not fast-load '{filename}': {e}. Re-cleaning...")

    print(f"[INFO] Uncleaned dataset detected: '{filename}'. Auto-cleaning into standardized format...")
    has_header, url_col, label_col = detect_csv_schema(filepath)

    if url_col is None:
        print(f"[WARN] Skipped '{filename}': No valid URL or domain column found.")
        return pd.DataFrame(columns=['url', 'label'])

    try:
        # Memory optimization: Read ONLY the needed columns from disk
        header_arg = 0 if has_header else None
        usecols = [url_col] if label_col is None else [url_col, label_col]

        raw_df = pd.read_csv(
            filepath,
            header=header_arg,
            usecols=usecols,
            nrows=max_rows,
            low_memory=False
        )

        clean_df = pd.DataFrame()
        clean_df['url'] = raw_df[url_col].astype(str).str.strip()

        # Map labels
        if label_col is not None:
            # Check for PhiUSIIL inverted labels (where 1 = legitimate, 0 = phishing)
            is_phiusiil = 'phiusiil' in filename.lower() or filename == '2.csv'
            if is_phiusiil:
                phiusiil_map = {1: 0, '1': 0, '1.0': 0, 0: 1, '0': 1, '0.0': 1}
                clean_df['label'] = raw_df[label_col].map(lambda x: phiusiil_map.get(x, phiusiil_map.get(str(x).strip(), None)))
            else:
                standard_map = {
                    0: 0, '0': 0, '0.0': 0, -1: 0, '-1': 0, '-1.0': 0,
                    'legitimate': 0, 'benign': 0, 'good': 0, 'safe': 0,
                    1: 1, '1': 1, '1.0': 1,
                    'phishing': 1, 'bad': 1, 'malicious': 1, 'definement': 1, 'defacement': 1, 'malware': 1
                }
                clean_df['label'] = raw_df[label_col].map(lambda x: standard_map.get(x, standard_map.get(str(x).lower().strip(), None)))
        else:
            clean_df['label'] = default_label

        # Filter out invalid rows (must have domain/protocol characters and valid non-null label)
        valid_mask = clean_df['url'].apply(is_valid_url_candidate) & clean_df['label'].notna()
        clean_df = clean_df[valid_mask].copy()
        clean_df['label'] = clean_df['label'].astype(int)
        clean_df = clean_df.drop_duplicates(subset=['url']).reset_index(drop=True)

        if clean_df.empty:
            print(f"[WARN] Skipped '{filename}': Zero valid URL records remained after cleaning.")
            return clean_df

        # Save clean version back to disk to permanently save disk space and RAM
        if overwrite_clean:
            try:
                clean_df.to_csv(filepath, index=False)
                new_size_mb = round(os.path.getsize(filepath) / (1024 * 1024), 2)
                print(f"[INFO] ✓ Cleaned & normalized '{filename}' -> saved ({len(clean_df):,} rows, {new_size_mb} MB on disk).")
            except Exception as e:
                print(f"[WARN] Could not overwrite '{filename}': {e}. Continuing with in-memory cleaned data.")

        return clean_df

    except Exception as e:
        print(f"[ERROR] Failed to clean '{filename}': {e}")
        return pd.DataFrame(columns=['url', 'label'])


def clean_all_datasets(datasets_dir: str):
    """Scans and cleans all CSV datasets across all folders in datasets_dir."""
    print(f"[INFO] Scanning '{datasets_dir}' to detect and clean uncleaned datasets...")
    for root, _, files in os.walk(datasets_dir):
        for f in sorted(files):
            if f.endswith('.csv'):
                fp = os.path.join(root, f)
                d_label = 0 if ('apex' in fp.lower() or 'benign' in fp.lower()) else 1
                clean_and_load_csv(fp, default_label=d_label, overwrite_clean=True)
    print("[INFO] Dataset cleaning sweep completed.\n")


def load_directory_csvs(directory: str, default_label: int, max_per_file: int = None) -> pd.DataFrame:
    """Loads and concatenates all CSV files in a specific directory."""
    if not os.path.exists(directory):
        return pd.DataFrame(columns=['url', 'label'])

    csv_files = sorted(glob.glob(os.path.join(directory, "*.csv")))
    dfs = []
    for filepath in csv_files:
        df = clean_and_load_csv(filepath, default_label=default_label, max_rows=max_per_file)
        if not df.empty:
            dfs.append(df)

    if dfs:
        return pd.concat(dfs, ignore_index=True)
    return pd.DataFrame(columns=['url', 'label'])


def load_all_datasets(
    datasets_dir: str,
    max_samples_per_class: int = 150_000
) -> pd.DataFrame:
    """Loads, cleans, balances, and sanitizes all dataset files across
    phishing_set and apex_set subdirectories.
    
    Args:
        datasets_dir: Base directory containing 'phishing_set' and 'apex_set'.
        max_samples_per_class: Cap per class to keep training RAM < 1.5 GB.
        
    Returns:
        Balanced, deduplicated DataFrame with columns ['url', 'label'].
    """
    phishing_set_dir = os.path.join(datasets_dir, 'phishing_set')
    apex_set_dir = os.path.join(datasets_dir, 'apex_set')

    print(f"[INFO] Scanning for datasets in '{phishing_set_dir}/' and '{apex_set_dir}/'...")

    apex_files = sorted(glob.glob(os.path.join(apex_set_dir, "*.csv")))
    num_apex_files = max(1, len(apex_files))
    max_per_apex = (max_samples_per_class // num_apex_files) + 10_000 if max_samples_per_class else None

    phishing_df = load_directory_csvs(phishing_set_dir, default_label=1, max_per_file=max_samples_per_class)
    apex_df = load_directory_csvs(apex_set_dir, default_label=0, max_per_file=max_per_apex)

    # Fallback search if subdirectories are empty
    if phishing_df.empty and apex_df.empty:
        fallback_df = load_directory_csvs(datasets_dir, default_label=0, max_per_file=max_samples_per_class)
        if not fallback_df.empty and 'label' in fallback_df.columns:
            phishing_df = fallback_df[fallback_df['label'] == 1].copy()
            apex_df = fallback_df[fallback_df['label'] == 0].copy()

    if phishing_df.empty and apex_df.empty:
        raise FileNotFoundError(
            f"No CSV datasets found in '{phishing_set_dir}/' or '{apex_set_dir}/'.\n"
            "Please ensure dataset files are placed in these folders."
        )

    # Separate any legitimate URLs found within the phishing folder
    if not phishing_df.empty:
        actual_phish = phishing_df[phishing_df['label'] == 1].copy()
        extra_legit = phishing_df[phishing_df['label'] == 0].copy()
        if not extra_legit.empty:
            apex_df = pd.concat([apex_df, extra_legit], ignore_index=True)
            phishing_df = actual_phish

    # Stratified balance capping to prevent out-of-memory crashes
    if max_samples_per_class is not None:
        if len(phishing_df) > max_samples_per_class:
            phishing_df = phishing_df.sample(n=max_samples_per_class, random_state=42)
        if len(apex_df) > max_samples_per_class:
            apex_df = apex_df.sample(n=max_samples_per_class, random_state=42)

    # Sanitize benign domains
    if not apex_df.empty and not phishing_df.empty:
        phishing_urls_set = set(phishing_df['url'].tolist())
        apex_df = sanitize_benign_domains(apex_df, phishing_urls_set)

    dfs_to_concat = []
    if not phishing_df.empty:
        dfs_to_concat.append(phishing_df)
    if not apex_df.empty:
        dfs_to_concat.append(apex_df)

    del phishing_df, apex_df
    gc.collect()

    full_df = pd.concat(dfs_to_concat, ignore_index=True)
    full_df['url'] = full_df['url'].astype(str).str.strip()
    full_df = full_df.drop_duplicates(subset=['url']).reset_index(drop=True)

    total_counts = full_df['label'].value_counts().to_dict()
    print(f"[INFO] Dataset merge complete. Total unique records: {len(full_df):,}")
    print(f"[INFO] Target Balance -> Legitimate: {total_counts.get(0, 0):,} | Phishing: {total_counts.get(1, 0):,}\n")

    return full_df

