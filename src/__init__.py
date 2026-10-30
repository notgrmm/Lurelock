"""LureLock Machine Learning Core Package.

Provides high-performance, modular components for phishing link detection:
  - feature_extractor: Custom Scikit-learn transformers (URLNormalizer, URLLexicalExtractor)
  - domain_utils: Domain parsing, multi-part ccTLD handling, and benign domain sanitization
  - dataset_cleaner: Automated schema detection and dataset normalization
  - explainer: Explainable URL indicators and user-friendly CLI/Web displays
  - trainer: XGBoost training pipeline, evaluation, and artifact serialization
"""

import sys
from .feature_extractor import (
    URLNormalizer,
    URLLexicalExtractor,
    build_features_union,
    slim_preprocessor,
    calculate_shannon_entropy,
    KEYWORDS,
    SHORTENERS
)
from .domain_utils import (
    ExtractResult,
    fallback_extract,
    tld_extractor,
    get_apex_domain,
    sanitize_benign_domains,
    TRUSTED_APEX_DOMAINS
)
from .dataset_cleaner import (
    clean_all_datasets,
    clean_and_load_csv,
    load_all_datasets,
    load_directory_csvs,
    is_valid_url_candidate,
    is_csv_clean,
    detect_csv_schema
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
    download_models_colab,
    get_ram_usage_gb,
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
    'build_features_union',
    'slim_preprocessor',
    'calculate_shannon_entropy',
    'KEYWORDS',
    'SHORTENERS',
    'ExtractResult',
    'fallback_extract',
    'tld_extractor',
    'get_apex_domain',
    'sanitize_benign_domains',
    'TRUSTED_APEX_DOMAINS',
    'clean_all_datasets',
    'clean_and_load_csv',
    'load_all_datasets',
    'load_directory_csvs',
    'is_valid_url_candidate',
    'is_csv_clean',
    'detect_csv_schema',
    'describe_url',
    'get_prediction_details',
    'print_result_display',
    'validate_url',
    'VERDICTS',
    'get_or_train_model',
    'save_artifacts',
    'download_models_colab',
    'get_ram_usage_gb',
    'MODELS_DIR',
    'DATASETS_DIR',
    'PIPELINE_FILE',
    'PREPROCESSOR_FILE',
    'MODEL_FILE',
    'MODEL_CARD_FILE'
]

