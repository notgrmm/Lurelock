"""Model Training, Evaluation & Serialization Module.

Orchestrates training of the XGBoost phishing classifier using 18 explainable
lexical and structural features and external datasets (keywords, shorteners, trusted domains).
No hardcoded links or keywords exist in the code.
Outputs compact, portable .joblib and .json artifacts.
"""

import os
import sys
import gc
import json
import warnings
from datetime import datetime, timezone
import numpy as np
import joblib
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from xgboost import XGBClassifier

from .feature_extractor import (
    URLNormalizer,
    URLLexicalExtractor,
    load_keywords,
    load_shorteners,
    FEATURE_NAMES
)
from .dataset_cleaner import load_all_datasets

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')

PIPELINE_FILE = os.path.join(MODELS_DIR, 'model.joblib')
PREPROCESSOR_FILE = os.path.join(MODELS_DIR, 'url_preprocessor.joblib')
MODEL_FILE = os.path.join(MODELS_DIR, 'phishing_xgb_model.joblib')
MODEL_CARD_FILE = os.path.join(MODELS_DIR, 'phishing_model_card.json')
XGB_JSON_FILE = os.path.join(MODELS_DIR, 'xgboost_model.json')


def save_artifacts(pipeline, preprocessor, classifier, card: dict):
    """Saves compressed .joblib pipelines, model card, and native JSON booster."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(pipeline, PIPELINE_FILE, compress=6)
    joblib.dump(preprocessor, PREPROCESSOR_FILE, compress=6)
    joblib.dump(classifier, MODEL_FILE, compress=6)

    try:
        classifier.save_model(XGB_JSON_FILE)
    except Exception as e:
        print(f"[WARN] Could not export XGBoost JSON booster: {e}")

    sizes = {
        os.path.basename(f): round(os.path.getsize(f) / 1024, 1)
        for f in (PIPELINE_FILE, PREPROCESSOR_FILE, MODEL_FILE, XGB_JSON_FILE)
        if os.path.exists(f)
    }
    card['files_kb'] = sizes

    with open(MODEL_CARD_FILE, 'w', encoding='utf-8') as f:
        json.dump(card, f, indent=2)

    print(f"[INFO] Saved artifacts in '{MODELS_DIR}/':")
    for fname, sz in sizes.items():
        print(f"       • {fname} ({sz} KB)")
    print(f"[INFO] Model card written to '{MODEL_CARD_FILE}'.\n")


def get_or_train_model(
    force_retrain: bool = False,
    max_samples_per_class: int = 75_000,
    datasets_dir: str = None
):
    """Retrieves the pre-trained pipeline or initiates retraining if missing.
    
    Args:
        force_retrain: Set True to force retrain on datasets.
        max_samples_per_class: Per-class sampling budget.
        datasets_dir: Custom datasets directory path.
        
    Returns:
        Pipeline instance (or tuple for legacy callers).
    """
    d_dir = datasets_dir or DATASETS_DIR

    if os.path.exists(PIPELINE_FILE) and not force_retrain:
        print(f"[INFO] Loading pre-trained model from '{PIPELINE_FILE}'...")
        try:
            pipeline = joblib.load(PIPELINE_FILE)
            preprocessor = pipeline.named_steps.get('features')
            classifier = pipeline.named_steps.get('classifier')
            return pipeline, preprocessor, classifier
        except Exception as e:
            print(f"[WARN] Could not load {PIPELINE_FILE} directly ({e}). Retraining...")

    print("=" * 65)
    print(" 🚀 LURELOCK MODEL TRAINING & OPTIMIZATION")
    print("=" * 65)
    print(" Training with explainable lexical/structural features & external datasets...")

    kws = load_keywords()
    shorts = load_shorteners()
    print(f"[INFO] Loaded external reference datasets: {len(kws)} keywords, {len(shorts)} shorteners.")

    df = load_all_datasets(d_dir, max_samples_per_class=max_samples_per_class)

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df['url'], df['label'], test_size=0.20, random_state=42, stratify=df['label']
    )
    X_train_sub, X_val_raw, y_train_sub, y_val = train_test_split(
        X_train_raw, y_train, test_size=0.15, random_state=42, stratify=y_train
    )

    del df, X_train_raw, y_train
    gc.collect()

    preprocessor = Pipeline([
        ('norm', URLNormalizer()),
        ('extractor', URLLexicalExtractor(keywords=kws, shorteners=shorts))
    ])

    print("[INFO] Transforming feature matrices...")
    X_train_feat = preprocessor.fit_transform(X_train_sub)
    X_val_feat = preprocessor.transform(X_val_raw)
    X_test_feat = preprocessor.transform(X_test_raw)

    classifier = XGBClassifier(
        n_estimators=250,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        eval_metric='logloss',
        tree_method='hist',
        n_jobs=-1,
        early_stopping_rounds=20,
        random_state=42
    )

    print("[INFO] Fitting XGBoost classifier with early stopping...")
    classifier.fit(X_train_feat, y_train_sub, eval_set=[(X_val_feat, y_val)], verbose=False)

    # Evaluate on held-out test set
    y_pred = classifier.predict(X_test_feat)
    y_prob = classifier.predict_proba(X_test_feat)[:, 1]

    auc_score = float(roc_auc_score(y_test, y_prob))
    report_dict = classification_report(y_test, y_pred, output_dict=True)

    print("-" * 65)
    print(" 📊 EVALUATION ON HELD-OUT TEST DATASET:")
    print(classification_report(y_test, y_pred, digits=4))
    print(f" Area Under ROC Curve (ROC-AUC): {auc_score:.4f}")
    print("-" * 65)

    # Assemble complete end-to-end inference pipeline
    pipeline = Pipeline([
        ('norm', preprocessor.named_steps['norm']),
        ('features', preprocessor.named_steps['extractor']),
        ('classifier', classifier)
    ])

    model_card = {
        'model_name': 'LureLock Explainable Phishing Detector',
        'framework': 'XGBoost + Scikit-Learn',
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'feature_count': len(FEATURE_NAMES),
        'features': FEATURE_NAMES,
        'external_datasets': {
            'keywords': 'datasets/keywords.txt',
            'shorteners': 'datasets/shorteners.txt',
            'trusted_domains': 'datasets/trusted_domains.txt'
        },
        'test_metrics': {
            'accuracy': round(report_dict['accuracy'], 4),
            'roc_auc': round(auc_score, 4),
            'phishing_precision': round(report_dict['1']['precision'], 4),
            'phishing_recall': round(report_dict['1']['recall'], 4),
            'phishing_f1': round(report_dict['1']['f1-score'], 4),
            'test_samples': len(y_test)
        }
    }

    save_artifacts(pipeline, preprocessor, classifier, model_card)

    return pipeline, preprocessor, classifier
