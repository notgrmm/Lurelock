"""Feature Extraction Module for Phishing URL Detection.

Defines custom scikit-learn transformers used across model training, prediction,
and serialization. Built for high performance and low RAM (< 1.5 GB) during training
and real-time inference.
"""

import math
import re
import sys
import types
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion

# Suspicious keywords frequently used in phishing attack URLs
KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "bank", "password",
    "wallet", "confirm", "suspend", "urgent", "webscr", "paypal", "apple", "microsoft",
    "banking", "admin", "service"
]

# Known URL shortener services that mask final destination domains
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy (randomness score) of a given text string.
    
    Phishing and algorithmically-generated domains (DGAs) tend to have high
    entropy compared to natural human-readable domain names.
    
    Args:
        text: Input domain or URL string.
        
    Returns:
        Entropy float value (bits). Higher indicates greater randomness.
    """
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


class URLNormalizer(BaseEstimator, TransformerMixin):
    """Scikit-learn compatible transformer that normalizes arbitrary inputs
    into a flat list of clean URL strings.
    
    Accepts:
      - Single URL string
      - List/tuple of URL strings
      - Pandas DataFrame or Series
      - NumPy 1D array
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if hasattr(X, "columns") and "url" in X.columns:
            return X["url"].astype(str).tolist()
        if hasattr(X, "values"):
            return [str(x) for x in X.values.ravel()]
        if isinstance(X, str):
            return [X]
        return [str(x) for x in X]


class URLLexicalExtractor(BaseEstimator, TransformerMixin):
    """Scikit-learn compatible transformer that extracts 18 numerical lexical
    and structural features from a sequence of raw URL strings.
    
    Uses pre-allocated 2D float32 NumPy arrays to keep memory usage below 1.5 GB RAM
    even when processing hundreds of thousands of samples in Google Colab.
    
    Features extracted:
      0: Total URL character length
      1: Domain character length
      2: Path character length
      3: Total dot count in URL
      4: Dot count in domain
      5: Total hyphen count in URL
      6: Hyphen count in domain
      7: At-sign (@) symbol count (phishing credential embedding indicator)
      8: Question mark (?) count
      9: Equal sign (=) count (parameter heavy)
     10: Slash (/) count (URL depth)
     11: Total digits count
     12: Shannon entropy of the domain name
     13: HTTPS scheme indicator (1.0 = https, 0.0 = http/other)
     14: IPv4 host indicator (1.0 = IP address used as host)
     15: Subdomain depth count
     16: Suspicious keyword presence in domain (1.0 or 0.0)
     17: Suspicious keyword presence in path/query (1.0 or 0.0)
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if isinstance(X, (pd.DataFrame, pd.Series)):
            X_vals = X.values.ravel()
        else:
            X_vals = np.array(X).ravel()

        n_samples = len(X_vals)
        # Pre-allocate contiguous float32 array to minimize memory fragmentation
        features = np.empty((n_samples, 18), dtype=np.float32)

        for i, raw_url in enumerate(X_vals):
            url = str(raw_url).strip()
            try:
                formatted = url if url.startswith(("http://", "https://")) else f"http://{url}"
                parsed = urlparse(formatted)
                domain = parsed.netloc or parsed.path.split("/")[0]
                path = parsed.path
            except Exception:
                domain, path = "", ""

            domain_lower = domain.lower()
            path_lower = path.lower()

            # Assign feature columns
            features[i, 0] = len(url)
            features[i, 1] = len(domain)
            features[i, 2] = len(path)
            features[i, 3] = url.count('.')
            features[i, 4] = domain.count('.')
            features[i, 5] = url.count('-')
            features[i, 6] = domain.count('-')
            features[i, 7] = url.count('@')
            features[i, 8] = url.count('?')
            features[i, 9] = url.count('=')
            features[i, 10] = url.count('/')
            features[i, 11] = sum(c.isdigit() for c in url)
            features[i, 12] = calculate_shannon_entropy(domain_lower)
            features[i, 13] = 1.0 if url.startswith('https://') else 0.0
            features[i, 14] = 1.0 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain) else 0.0
            features[i, 15] = float(max(0, len(domain.split('.')) - 2))
            features[i, 16] = 1.0 if any(kw in domain_lower for kw in KEYWORDS) else 0.0
            features[i, 17] = 1.0 if any(kw in path_lower for kw in KEYWORDS) else 0.0

        return features


def build_features_union(max_tfidf_features: int = 1000) -> FeatureUnion:
    """Builds a scikit-learn FeatureUnion combining 18 lexical URL features
    with character n-gram (3 to 5 chars) TF-IDF representations.
    
    Args:
        max_tfidf_features: Maximum vocabulary size for character n-grams.
        
    Returns:
        FeatureUnion transformer ready for pipeline integration.
    """
    return FeatureUnion(
        transformer_list=[
            ('lexical', URLLexicalExtractor()),
            ('tfidf', TfidfVectorizer(
                analyzer='char',
                ngram_range=(3, 5),
                max_features=max_tfidf_features,
                dtype=np.float32,
                sublinear_tf=True
            ))
        ]
    )


def slim_preprocessor(pipeline_or_features):
    """Strips stop_words_ and non-essential cached metadata from TfidfVectorizer
    instances to drastically compress pickled .joblib file sizes (from ~10 MB down to < 100 KB).
    """
    transformers = []
    if hasattr(pipeline_or_features, "named_steps"):
        for step in pipeline_or_features.named_steps.values():
            if hasattr(step, "transformer_list"):
                transformers.extend([t for _, t in step.transformer_list])
            else:
                transformers.append(step)
    elif hasattr(pipeline_or_features, "transformer_list"):
        transformers.extend([t for _, t in pipeline_or_features.transformer_list])
    elif hasattr(pipeline_or_features, "transformers_"):
        transformers.extend([t for _, t, _ in pipeline_or_features.transformers_])
    else:
        transformers = [pipeline_or_features]

    for t in transformers:
        if hasattr(t, "stop_words_"):
            t.stop_words_ = None


# Explicitly bind class module identities to 'feature_extractor' so pickled
# joblib models are universally portable across scripts, servers, and notebooks.
URLNormalizer.__module__ = 'feature_extractor'
URLLexicalExtractor.__module__ = 'feature_extractor'

# Register in sys.modules and __main__ for complete backward and forward compatibility
if 'feature_extractor' not in sys.modules:
    sys.modules['feature_extractor'] = sys.modules[__name__]

import __main__
setattr(__main__, 'URLNormalizer', URLNormalizer)
setattr(__main__, 'URLLexicalExtractor', URLLexicalExtractor)
if '__main__' in sys.modules:
    setattr(sys.modules['__main__'], 'URLNormalizer', URLNormalizer)
    setattr(sys.modules['__main__'], 'URLLexicalExtractor', URLLexicalExtractor)

