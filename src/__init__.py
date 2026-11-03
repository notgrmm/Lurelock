"""LureLock Machine Learning Core Package.

Provides high-performance, modular components for phishing link detection:
  - feature_extractor: URL canonicalization and explainable feature extraction
  - domain_utils: Domain parsing, ccTLD handling, and external trusted domain resolution
  - dataset_cleaner: Automated dataset loading and realistic path synthesis
  - explainer: Human-readable indicators and user-friendly CLI/Web displays
  - trainer: XGBoost training pipeline, evaluation, and artifact serialization
"""

from .feature_extractor import (
    URLNormalizer,
    URLLexicalExtractor,
    normalize_url,
    calculate_shannon_entropy,
    load_keywords,
    load_shorteners,
    KEYWORDS,
    SHORTENERS,
    FEATURE_NAMES
)
from .domain_utils import (
    ExtractResult,
    fallback_extract,
    tld_extractor,
    get_apex_domain,
    is_trusted_domain,
    load_trusted_domains,
    sanitize_benign_domains
)
from .dataset_cleaner import (
    clean_all_datasets,
    load_all_datasets,
    is_valid_url_candidate
)
from .explainer import (
    describe_url,
    get_prediction_details,
    print_result_display,
    validate_url,
    VERDICTS
)
from .trainer import (
    get_or_train_model,
    save_artifacts,
    MODELS_DIR,
    DATASETS_DIR,
    PIPELINE_FILE,
    PREPROCESSOR_FILE,
    MODEL_FILE,
    MODEL_CARD_FILE
)

__all__ = [
    'URLNormalizer',
    'URLLexicalExtractor',
    'normalize_url',
    'calculate_shannon_entropy',
    'load_keywords',
    'load_shorteners',
    'KEYWORDS',
    'SHORTENERS',
    'FEATURE_NAMES',
    'ExtractResult',
    'fallback_extract',
    'tld_extractor',
    'get_apex_domain',
    'is_trusted_domain',
    'load_trusted_domains',
    'sanitize_benign_domains',
    'clean_all_datasets',
    'load_all_datasets',
    'is_valid_url_candidate',
    'describe_url',
    'get_prediction_details',
    'print_result_display',
    'validate_url',
    'VERDICTS',
    'get_or_train_model',
    'save_artifacts',
    'MODELS_DIR',
    'DATASETS_DIR',
    'PIPELINE_FILE',
    'PREPROCESSOR_FILE',
    'MODEL_FILE',
    'MODEL_CARD_FILE'
]
