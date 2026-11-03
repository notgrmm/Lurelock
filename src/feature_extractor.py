"""Feature Extraction Module for Phishing URL Detection.

Defines URL canonicalization and human-explainable lexical/structural feature extraction.
All keywords, shorteners, and trusted domains are loaded from external datasets:
  - datasets/keywords.txt
  - datasets/shorteners.txt
  - datasets/trusted_domains.txt

No hardcoded links, keywords, or shorteners exist in Python code.
Features are designed to be intuitive, transparent, and easy to defend.
"""

import math
import os
import re
import sys
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')
KEYWORDS_FILE = os.path.join(DATASETS_DIR, 'keywords.txt')
SHORTENERS_FILE = os.path.join(DATASETS_DIR, 'shorteners.txt')

_cached_keywords = None
_cached_shorteners = None


def load_keywords(filepath: str = None) -> list[str]:
    """Loads suspicious phishing keywords from an external dataset file."""
    global _cached_keywords
    if filepath is None and _cached_keywords is not None:
        return _cached_keywords

    target_file = filepath or KEYWORDS_FILE
    kws = []
    if os.path.exists(target_file):
        with open(target_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    kws.append(line.lower())

    # If external file was missing or empty, ensure set/list is initialized
    if filepath is None:
        _cached_keywords = kws
    return kws


def load_shorteners(filepath: str = None) -> set[str]:
    """Loads known URL shortener service domains from an external dataset file."""
    global _cached_shorteners
    if filepath is None and _cached_shorteners is not None:
        return _cached_shorteners

    target_file = filepath or SHORTENERS_FILE
    shorteners = set()
    if os.path.exists(target_file):
        with open(target_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    shorteners.add(line.lower())

    if filepath is None:
        _cached_shorteners = shorteners
    return shorteners


# Dynamic references loaded from external datasets
KEYWORDS = load_keywords()
SHORTENERS = load_shorteners()

# High-risk TLDs frequently abused in automated phishing campaigns
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.fit', '.buzz', '.work', '.gq', '.ga', '.cf',
    '.ml', '.icu', '.club', '.online', '.site', '.monster', '.rest', '.cam'
}

# The 18 explainable features extracted from each URL
FEATURE_NAMES = [
    "url_length",              # 0: Total character length of URL
    "domain_length",           # 1: Character length of domain/host
    "path_depth",              # 2: Directory nesting depth in path
    "dot_count_domain",        # 3: Dot count in domain
    "hyphen_count_domain",     # 4: Hyphen count in domain (brand spoofing)
    "special_chars_domain",    # 5: Special characters in domain
    "at_symbol",               # 6: @ symbol count (credential embedding indicator)
    "digits_domain",           # 7: Digits in domain name
    "digits_url",              # 8: Total digits across URL
    "domain_entropy",          # 9: Shannon entropy of domain (randomness/DGA indicator)
    "is_https",                # 10: HTTPS protocol indicator (1 = https, 0 = http)
    "is_ip_address",           # 11: Bare IPv4 address indicator
    "subdomain_count",         # 12: Nested subdomain count
    "keyword_in_domain",       # 13: Suspicious keyword in domain (from external dataset)
    "keyword_in_path",         # 14: Suspicious keyword in path/query (from external dataset)
    "is_shortener",            # 15: URL shortener service (from external dataset)
    "suspicious_tld",          # 16: High-risk TLD (.xyz, .top, .buzz, etc.)
    "excessive_length",        # 17: Unusually long URL indicator (> 75 chars)
]


def normalize_url(raw_url: str) -> str:
    """Canonicalizes a raw URL into a uniform format for training and inference.
    
    Ensures consistent treatment across the Web UI, Chrome Extension, and CLI:
      - Trims whitespace and surrounding quotes.
      - Adds 'https://' if no scheme is specified (standard for modern web).
      - Converts hostname to lowercase.
      - Normalizes empty path to '/'.
    """
    s = str(raw_url).strip().strip("'\"")
    if not s:
        return ""

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', s):
        s = 'https://' + s

    try:
        parsed = urlparse(s)
        scheme = parsed.scheme.lower() or 'https'
        netloc = parsed.netloc.lower()
        if netloc.endswith(':80') and scheme == 'http':
            netloc = netloc[:-3]
        elif netloc.endswith(':443') and scheme == 'https':
            netloc = netloc[:-4]

        path = parsed.path
        if not path:
            path = '/'
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return s


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy (randomness score) of a given string.
    
    Phishing and algorithmically-generated domains (DGAs) tend to have high
    entropy compared to human-readable domain names.
    """
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


class URLNormalizer(BaseEstimator, TransformerMixin):
    """Transformer that canonicalizes URL strings into a uniform structure."""

    def fit(self, X, y=None):
        self.fitted_ = True
        return self

    def transform(self, X):
        if hasattr(X, "columns") and "url" in X.columns:
            urls = X["url"].astype(str).tolist()
        elif hasattr(X, "values"):
            urls = [str(x) for x in X.values.ravel()]
        elif isinstance(X, str):
            urls = [X]
        else:
            urls = [str(x) for x in X]
        return [normalize_url(u) for u in urls]


class URLLexicalExtractor(BaseEstimator, TransformerMixin):
    """Transformer that extracts 18 explainable lexical and structural features.
    
    Uses external datasets for suspicious keywords and URL shorteners.
    Features directly correspond to the explainability breakdown shown to users.
    """

    def __init__(self, keywords=None, shorteners=None):
        self.keywords = list(keywords) if keywords is not None else list(load_keywords())
        self.shorteners = set(shorteners) if shorteners is not None else set(load_shorteners())

    def fit(self, X, y=None):
        self.fitted_ = True
        return self

    def transform(self, X):
        if isinstance(X, (pd.DataFrame, pd.Series)):
            X_vals = X.values.ravel()
        else:
            X_vals = np.array(X).ravel()

        n_samples = len(X_vals)
        features = np.zeros((n_samples, 18), dtype=np.float32)

        kws = self.keywords or load_keywords()
        shorts = self.shorteners or load_shorteners()

        for i, raw_url in enumerate(X_vals):
            url = normalize_url(raw_url)
            try:
                parsed = urlparse(url)
                host = (parsed.hostname or parsed.netloc.split(':')[0] or "").lower()
                path = parsed.path or "/"
                query = parsed.query or ""
                scheme = parsed.scheme.lower()
            except Exception:
                host, path, query, scheme = "", "/", "", "https"

            path_and_query = (path + ('?' + query if query else '')).lower()
            path_segments = [p for p in path.split('/') if p]

            # 0: Total URL length
            features[i, 0] = len(url)
            # 1: Domain length
            features[i, 1] = len(host)
            # 2: Path depth
            features[i, 2] = len(path_segments)
            # 3: Dot count in domain
            features[i, 3] = host.count('.')
            # 4: Hyphen count in domain
            features[i, 4] = host.count('-')
            # 5: Special characters in domain
            features[i, 5] = sum(not c.isalnum() and c not in '.-' for c in host)
            # 6: At-sign (@) count
            features[i, 6] = url.count('@')
            # 7: Digits in domain
            features[i, 7] = sum(c.isdigit() for c in host)
            # 8: Digits in full URL
            features[i, 8] = sum(c.isdigit() for c in url)
            # 9: Shannon entropy of domain
            features[i, 9] = calculate_shannon_entropy(host)
            # 10: Is HTTPS
            features[i, 10] = 1.0 if scheme == 'https' else 0.0
            # 11: Is IPv4 address
            features[i, 11] = 1.0 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else 0.0
            # 12: Subdomain nesting count
            features[i, 12] = float(max(0, len(host.split('.')) - 2)) if not features[i, 11] else 0.0
            # 13: Keyword in domain
            features[i, 13] = 1.0 if any(kw in host for kw in kws) else 0.0
            # 14: Keyword in path/query
            features[i, 14] = 1.0 if any(kw in path_and_query for kw in kws) else 0.0
            # 15: Known shortener
            features[i, 15] = 1.0 if host in shorts else 0.0
            # 16: Suspicious TLD
            features[i, 16] = 1.0 if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
            # 17: Excessive length flag (>75 chars)
            features[i, 17] = 1.0 if len(url) > 75 else 0.0

        return features


def build_features_union(max_tfidf_features: int = 1000):
    """Backward compatibility helper returning the lexical feature extractor."""
    return URLLexicalExtractor()


def slim_preprocessor(pipeline_or_features):
    """Compatibility stub for preprocessor compression."""
    pass


# Compatibility registrations for cross-module unpickling
URLNormalizer.__module__ = 'feature_extractor'
URLLexicalExtractor.__module__ = 'feature_extractor'

if 'feature_extractor' not in sys.modules:
    sys.modules['feature_extractor'] = sys.modules[__name__]

import __main__
setattr(__main__, 'URLNormalizer', URLNormalizer)
setattr(__main__, 'URLLexicalExtractor', URLLexicalExtractor)
if '__main__' in sys.modules:
    setattr(sys.modules['__main__'], 'URLNormalizer', URLNormalizer)
    setattr(sys.modules['__main__'], 'URLLexicalExtractor', URLLexicalExtractor)
