"""Model Training, Evaluation & Serialization Module.

Orchestrates training of the XGBoost classifier and scikit-learn FeatureUnion pipeline.
Includes early stopping, memory tracking, and artifact persistence.
"""

import os
import sys
import gc
import json
import dis
import warnings
from datetime import datetime, timezone
import numpy as np
import joblib
import sklearn
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import xgboost
from xgboost import XGBClassifier

from .feature_extractor import (
    URLNormalizer,
    build_features_union,
    slim_preprocessor
)
from .dataset_cleaner import load_all_datasets

# Safe directory resolution relative to project root
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')

# Standardized model artifact paths
PIPELINE_FILE = os.path.join(MODELS_DIR, 'model.joblib')
PREPROCESSOR_FILE = os.path.join(MODELS_DIR, 'url_preprocessor.joblib')
MODEL_FILE = os.path.join(MODELS_DIR, 'phishing_xgb_model.joblib')
MODEL_CARD_FILE = os.path.join(MODELS_DIR, 'phishing_model_card.json')
TREE_DUMP_FILE = os.path.join(MODELS_DIR, 'xgboost_tree_dump.txt')
XGB_JSON_FILE = os.path.join(MODELS_DIR, 'xgboost_model.json')


def get_ram_usage_gb() -> float:
    """Returns the peak RSS RAM usage of the current Python process in GB."""
    try:
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024), 2)
    except Exception:
        return 0.0


def save_artifacts(pipeline, preprocessor, model, card: dict):
    """Saves compressed .joblib pipelines, readable model cards, and raw booster files."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Compress artifacts with level 6 gzip compression
    joblib.dump(pipeline, PIPELINE_FILE, compress=6)
    joblib.dump(preprocessor, PREPROCESSOR_FILE, compress=6)
    joblib.dump(model, MODEL_FILE, compress=6)

    sizes = {
        os.path.basename(f): round(os.path.getsize(f) / 1024, 1)
        for f in (PIPELINE_FILE, PREPROCESSOR_FILE, MODEL_FILE)
        if os.path.exists(f)
    }
    card['files_kb'] = sizes

    with open(MODEL_CARD_FILE, 'w', encoding='utf-8') as f:
        json.dump(card, f, indent=2)

    try:
        model.get_booster().dump_model(TREE_DUMP_FILE)
        model.save_model(XGB_JSON_FILE)
    except Exception as e:
        print(f"[WARN] Could not export raw model dumps: {e}")

    print(f"[INFO] Artifacts neatly saved in '{MODELS_DIR}/':")
    for fname, sz in sizes.items():
        print(f"       • {fname} ({sz} KB)")
    print(f"[INFO] Readable model card and tree dumps saved to '{MODELS_DIR}/'.\n")


def _detect_expected_unpacks() -> int:
    """Detects caller sequence unpack count for backwards compatibility
    (e.g., if existing Colab notebook calls `preprocessor, model = get_or_train_model()`).
    """
    try:
        frame = sys._getframe(2)
        instructions = list(dis.get_instructions(frame.f_code))
        for inst in instructions:
            if inst.offset > frame.f_lasti:
                if inst.opname == 'UNPACK_SEQUENCE':
                    return inst.argval
                break
    except Exception:
        pass
    return 3


def get_or_train_model(
    force_retrain: bool = False,
    max_samples_per_class: int = 150_000,
    datasets_dir: str = None
):
    """Retrieves the pre-trained pipeline or initiates retraining if missing.
    
    Args:
        force_retrain: Set True to re-scan datasets and retrain XGBoost.
        max_samples_per_class: Per-class sampling budget for Colab RAM safety.
        datasets_dir: Custom datasets directory path (defaults to datasets/).
        
    Returns:
        Pipeline instance (or tuple for legacy unpack callers).
    """
    expected_unpacks = _detect_expected_unpacks()
    d_dir = datasets_dir or DATASETS_DIR

    # Load pre-trained artifacts if already available
    has_artifacts = (
        os.path.exists(PIPELINE_FILE) or 
        (os.path.exists(PREPROCESSOR_FILE) and (os.path.exists(MODEL_FILE) or os.path.exists(XGB_JSON_FILE)))
    )
    if has_artifacts and not force_retrain:
        print(f"[INFO] Pre-trained model found in '{MODELS_DIR}/'. Loading artifacts...\n")
        try:
            from sklearn.exceptions import InconsistentVersionWarning
            warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
        except Exception:
            pass

        pipeline = None
        preprocessor = None
        model = None

        if os.path.exists(PIPELINE_FILE):
            try:
                pipeline = joblib.load(PIPELINE_FILE)
                preprocessor = pipeline.named_steps.get('features')
                model = pipeline.named_steps.get('classifier')
            except Exception as e:
                print(f"[WARN] Could not load {os.path.basename(PIPELINE_FILE)} directly ({e}). Trying fallback artifacts...")
                pipeline = None

        if pipeline is None and os.path.exists(PREPROCESSOR_FILE) and os.path.exists(MODEL_FILE):
            try:
                preprocessor = joblib.load(PREPROCESSOR_FILE)
                model = joblib.load(MODEL_FILE)
                pipeline = Pipeline([
                    ('norm', URLNormalizer()),
                    ('features', preprocessor),
                    ('classifier', model)
                ])
            except Exception as e:
                print(f"[WARN] Could not load {os.path.basename(MODEL_FILE)} directly ({e}). Trying XGBoost JSON fallback...")
                pipeline = None

        # Cross-platform fallback: reconstruct pipeline from native JSON booster and preprocessor
        if pipeline is None and os.path.exists(PREPROCESSOR_FILE) and os.path.exists(XGB_JSON_FILE):
            try:
                print(f"[INFO] Loading model from native cross-platform '{os.path.basename(XGB_JSON_FILE)}'...")
                preprocessor = joblib.load(PREPROCESSOR_FILE)
                model = XGBClassifier()
                model.load_model(XGB_JSON_FILE)
                pipeline = Pipeline([
                    ('norm', URLNormalizer()),
                    ('features', preprocessor),
                    ('classifier', model)
                ])
                # Re-save artifacts for local OS/platform so future loads are instantaneous
                try:
                    joblib.dump(pipeline, PIPELINE_FILE, compress=6)
                    joblib.dump(model, MODEL_FILE, compress=6)
                    print(f"[INFO] Successfully reserialized model artifacts for current platform.")
                except Exception as save_err:
                    print(f"[WARN] Could not re-cache local joblib files: {save_err}")
            except Exception as json_err:
                print(f"[WARN] Native JSON fallback failed: {json_err}")
                pipeline = None

        if pipeline is not None:
            if expected_unpacks == 2:
                return preprocessor, model
            return pipeline, preprocessor, model

    print("[INFO] Retraining pipeline initiated...")
    df = load_all_datasets(d_dir, max_samples_per_class=max_samples_per_class)
    total_urls = int(len(df))

    # Stratified 80/10/10 split (train, validation, test)
    X_rest, X_test_raw, y_rest, y_test = train_test_split(
        df['url'], df['label'], test_size=0.20, random_state=42, stratify=df['label']
    )
    X_train_raw, X_val_raw, y_train, y_val = train_test_split(
        X_rest, y_rest, test_size=0.125, random_state=42, stratify=y_rest
    )
    train_len = int(len(y_train))
    val_len = int(len(y_val))
    test_len = int(len(y_test))
    del df, X_rest, y_rest
    gc.collect()

    normalizer = URLNormalizer()
    features = build_features_union(max_tfidf_features=1000)

    print(f"[INFO] Extracting features and training XGBoost model... (RAM: {get_ram_usage_gb()} GB)")
    X_train_norm = normalizer.transform(X_train_raw)
    X_val_norm = normalizer.transform(X_val_raw)
    X_test_norm = normalizer.transform(X_test_raw)
    del X_train_raw, X_val_raw, X_test_raw
    gc.collect()

    X_train_feat = features.fit_transform(X_train_norm)
    X_val_feat = features.transform(X_val_norm)
    X_test_feat = features.transform(X_test_norm)
    del X_train_norm, X_val_norm, X_test_norm
    gc.collect()
    slim_preprocessor(features)

    # Class imbalance weighting
    num_neg = (y_train == 0).sum()
    num_pos = (y_train == 1).sum()
    scale_weight = num_neg / num_pos if num_pos > 0 else 1.0

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=2,
        scale_pos_weight=scale_weight,
        eval_metric='logloss',
        tree_method='hist',
        n_jobs=-1,
        early_stopping_rounds=20,
        random_state=42
    )

    model.fit(X_train_feat, y_train, eval_set=[(X_val_feat, y_val)], verbose=False)
    del X_val_feat, y_val
    gc.collect()

    try:
        best_iteration = model.best_iteration
    except Exception:
        best_iteration = None

    num_trees = (best_iteration + 1) if (best_iteration is not None and best_iteration >= 0) else getattr(model, 'n_estimators', 300)

    y_pred = model.predict(X_test_feat)
    y_proba = model.predict_proba(X_test_feat)[:, 1]

    print("\n--- MODEL TRAINING COMPLETE ---")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    auc = roc_auc_score(y_test, y_proba)
    print(f"ROC-AUC Score: {auc:.4f}  |  Trees: {num_trees}")
    print(f"[INFO] Peak RAM consumed: {get_ram_usage_gb()} GB / 12.7 GB (Colab Safe)\n")

    pipeline = Pipeline([
        ('norm', normalizer),
        ('features', features),
        ('classifier', model)
    ])

    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], output_dict=True)
    card = {
        'trained_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'versions': {
            'python': sys.version.split()[0],
            'scikit-learn': sklearn.__version__,
            'xgboost': xgboost.__version__,
            'numpy': np.__version__
        },
        'data': {
            'total_urls': total_urls,
            'train': train_len,
            'validation': val_len,
            'test': test_len
        },
        'metrics_on_test_set': {
            'roc_auc': round(float(auc), 4),
            'accuracy': round(report['accuracy'], 4),
            'phishing_precision': round(report['Phishing']['precision'], 4),
            'phishing_recall': round(report['Phishing']['recall'], 4),
            'phishing_f1': round(report['Phishing']['f1-score'], 4),
        },
        'model': {
            'trees': int(num_trees),
            'max_depth': 6,
            'learning_rate': 0.08,
            'tfidf_features': 1000,
            'lexical_features': 18
        },
    }

    save_artifacts(pipeline, features, model, card)

    if expected_unpacks == 2:
        return features, model
    return pipeline, features, model


def download_models_colab():
    """Helper for Google Colab to download saved model artifacts to local machine."""
    try:
        from google.colab import files
        for f in [PIPELINE_FILE, PREPROCESSOR_FILE, MODEL_FILE, MODEL_CARD_FILE]:
            if os.path.exists(f):
                files.download(f)
    except Exception as e:
        print(f"[ERROR] Could not trigger download: {e}")

