"""
CyberSentinel – Isolation Forest Model Training
Supports two training modes:
  1. Real data mode (default): Uses preprocessed NSL-KDD + UNSW-NB15 CSVs
  2. Simulated mode: Generates synthetic training logs (fallback)
"""

import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, precision_score, recall_score, f1_score,
)

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    MODEL_PATH, SCALER_PATH, CONTAMINATION, N_ESTIMATORS,
    TRAINING_SAMPLES, ATTACK_RATIO, MODEL_DIR,
    FEATURE_COLUMNS_EXPANDED, USE_REAL_DATA,
    REAL_TRAIN_PATH, REAL_TEST_PATH,
)


def load_real_data(max_samples: int = 0):
    """
    Load preprocessed real-world dataset CSVs.

    IMPORTANT: For proper unsupervised anomaly detection, we train the Isolation
    Forest on NORMAL traffic only. This teaches the model what "normal" looks like,
    so any deviation from this learned distribution is flagged as anomalous.

    Returns: (X_train_normal, y_train_dummy, X_test, y_test, feature_cols)
    """
    if not REAL_TRAIN_PATH.exists():
        print(f"❌ Real training data not found at {REAL_TRAIN_PATH}")
        print("   Run: python data/preprocess.py first")
        return None

    print(f"📂 Loading real dataset from {REAL_TRAIN_PATH.parent}/...")
    df_train = pd.read_csv(REAL_TRAIN_PATH)
    df_test = pd.read_csv(REAL_TEST_PATH)

    print(f"   Raw train: {len(df_train)} rows | Raw test: {len(df_test)} rows")

    feature_cols = FEATURE_COLUMNS_EXPANDED

    # Verify columns exist
    missing = [c for c in feature_cols if c not in df_train.columns]
    if missing:
        print(f"   ⚠️ Missing columns: {missing}")
        feature_cols = [c for c in feature_cols if c not in missing]

    # ── CRITICAL: Train on NORMAL traffic only ──
    # This is the correct approach for Isolation Forest anomaly detection:
    # 1. Train on clean/normal data → model learns the normal distribution
    # 2. At inference, anything deviating from normal is flagged as anomaly
    df_normal_train = df_train[df_train["label"] == 0]
    n_normal = len(df_normal_train)
    n_total = len(df_train)
    n_attack = n_total - n_normal

    # Subsample if requested (for faster experimentation)
    if max_samples > 0 and max_samples < n_normal:
        df_normal_train = df_normal_train.sample(n=max_samples, random_state=42).reset_index(drop=True)
        print(f"   Subsampled normal training data to {max_samples} rows")

    X_train = df_normal_train[feature_cols].values.astype(np.float64)
    y_train = np.zeros(len(X_train), dtype=int)  # all normal = 0

    X_test = df_test[feature_cols].values.astype(np.float64)
    y_test = df_test["label"].values.astype(int)

    # Handle NaN/inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=1e6, neginf=-1e6)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=1e6, neginf=-1e6)

    # Print dataset statistics
    n_attack_test = y_test.sum()
    datasets_train = df_train["dataset"].value_counts().to_dict() if "dataset" in df_train.columns else {}
    print(f"\n📊 Full Training Dataset:")
    print(f"   Total:   {n_total} rows")
    print(f"   Normal:  {n_normal} ({n_normal/n_total*100:.1f}%)")
    print(f"   Attack:  {n_attack} ({n_attack/n_total*100:.1f}%) [excluded from training]")
    if datasets_train:
        print(f"   Sources: {datasets_train}")

    print(f"\n📊 Training Set (Normal-Only for Anomaly Detection):")
    print(f"   Samples:  {len(X_train)}")
    print(f"   Features: {X_train.shape[1]}")
    print(f"   Strategy: Train on normal → detect anomalies as deviations")

    print(f"\n📊 Test Set (Mixed – for evaluation):")
    print(f"   Samples: {len(X_test)}")
    print(f"   Normal:  {len(X_test) - n_attack_test} ({(1 - n_attack_test/len(X_test))*100:.1f}%)")
    print(f"   Attack:  {n_attack_test} ({n_attack_test/len(X_test)*100:.1f}%)")

    return X_train, y_train, X_test, y_test, feature_cols


def load_simulated_data(n_samples: int):
    """Fallback: generate synthetic training data."""
    from simulator.log_generator import generate_batch
    from ingestion.log_parser import parse_batch
    from ml.features import extract_features_batch

    print(f"🔧 Generating {n_samples} simulated training logs (attack_ratio={ATTACK_RATIO})...")
    raw_logs = generate_batch(n_samples, attack_ratio=ATTACK_RATIO)
    parsed_logs = parse_batch(raw_logs)
    X = extract_features_batch(parsed_logs)
    y = None  # No labels for simulated unsupervised training
    print(f"   Feature matrix: {X.shape}")
    return X, y


def evaluate_model(model, scaler, X_test, y_test, feature_cols):
    """Evaluate the trained model on labeled test data."""
    print(f"\n{'=' * 60}")
    print(f"  Model Evaluation on Test Set ({len(X_test)} samples)")
    print(f"{'=' * 60}")

    X_test_scaled = scaler.transform(X_test)
    predictions = model.predict(X_test_scaled)
    scores = model.decision_function(X_test_scaled)

    # In Isolation Forest: -1 = anomaly, 1 = normal
    # In our labels: 1 = attack, 0 = normal
    y_pred = (predictions == -1).astype(int)

    # Classification metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"\n📈 Classification Metrics:")
    print(f"   Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"   Precision: {prec:.4f} ({prec*100:.2f}%)")
    print(f"   Recall:    {rec:.4f} ({rec*100:.2f}%)")
    print(f"   F1-Score:  {f1:.4f} ({f1*100:.2f}%)")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\n📊 Confusion Matrix:")
    print(f"   True Negatives:  {tn}")
    print(f"   False Positives: {fp}")
    print(f"   False Negatives: {fn}")
    print(f"   True Positives:  {tp}")
    fpr = fp / max(fp + tn, 1)
    print(f"   False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")

    # Detailed report
    print(f"\n📋 Detailed Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Normal", "Attack"],
        digits=4,
    ))

    # Score distribution
    normal_scores = scores[y_test == 0]
    attack_scores = scores[y_test == 1]
    print(f"📊 Anomaly Score Distribution:")
    print(f"   Normal traffic: mean={normal_scores.mean():.4f}, std={normal_scores.std():.4f}")
    print(f"   Attack traffic: mean={attack_scores.mean():.4f}, std={attack_scores.std():.4f}")
    print(f"   Score separation: {normal_scores.mean() - attack_scores.mean():.4f}")

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "false_positive_rate": round(fpr, 4),
    }


def train_model(
    n_samples: int = TRAINING_SAMPLES,
    contamination: float = CONTAMINATION,
    n_estimators: int = N_ESTIMATORS,
    use_real: bool = USE_REAL_DATA,
    save: bool = True,
):
    """
    Full training pipeline:
    1. Load real or simulated training data
    2. Scale features
    3. Train Isolation Forest
    4. Evaluate on test set (if labels available)
    5. Save model + scaler

    Returns: (model, scaler, metrics_dict)
    """
    t0 = time.time()

    X_test, y_test, feature_cols = None, None, None

    # ── Data Loading ──
    if use_real and REAL_TRAIN_PATH.exists():
        result = load_real_data(max_samples=0)
        if result is not None:
            X_train, y_train, X_test, y_test, feature_cols = result
        else:
            print("⚠️ Falling back to simulated data...")
            X_train, y_train = load_simulated_data(n_samples)
    else:
        if use_real:
            print(f"⚠️ Real data not found at {REAL_TRAIN_PATH}")
            print(f"   Run: python data/preprocess.py first")
            print(f"   Falling back to simulated data...\n")
        X_train, y_train = load_simulated_data(n_samples)

    gen_time = time.time() - t0
    print(f"\n   Data loading time: {gen_time:.2f}s")

    # ── Feature Scaling ──
    print("⚙️  Scaling features with StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # ── Compute contamination ──
    if y_train is not None and use_real and REAL_TRAIN_PATH.exists():
        # Training on normal-only data: use small contamination for noise tolerance
        # (accounts for any mislabeled samples or borderline traffic)
        contamination = 0.10
        n_estimators = 200  # more trees for better detection on real data
        print(f"   Training on normal-only data → contamination={contamination} (noise tolerance)")

    # ── Train Isolation Forest ──
    print(f"\n🧠 Training Isolation Forest:")
    print(f"   n_estimators = {n_estimators}")
    print(f"   contamination = {contamination}")
    print(f"   n_features = {X_scaled.shape[1]}")
    print(f"   n_samples = {X_scaled.shape[0]}")

    t1 = time.time()
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples='auto',
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )
    model.fit(X_scaled)
    train_time = time.time() - t1
    print(f"   Training time: {train_time:.2f}s")

    # ── Training Set Quick Metrics ──
    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    n_anomalies = int((predictions == -1).sum())
    anomaly_pct = n_anomalies / len(predictions) * 100

    metrics = {
        "data_source": "real" if (use_real and REAL_TRAIN_PATH.exists()) else "simulated",
        "n_samples": X_scaled.shape[0],
        "n_features": X_scaled.shape[1],
        "n_estimators": n_estimators,
        "contamination": contamination,
        "n_anomalies_detected": n_anomalies,
        "anomaly_percentage": round(anomaly_pct, 2),
        "mean_score": round(float(scores.mean()), 4),
        "std_score": round(float(scores.std()), 4),
        "min_score": round(float(scores.min()), 4),
        "max_score": round(float(scores.max()), 4),
        "train_time_seconds": round(train_time, 2),
    }

    print(f"\n📈 Training Summary:")
    for key, val in metrics.items():
        print(f"   {key}: {val}")

    # ── Evaluate on Test Set ──
    eval_metrics = None
    if X_test is not None and y_test is not None:
        eval_metrics = evaluate_model(model, scaler, X_test, y_test, feature_cols)
        metrics["test_metrics"] = eval_metrics

    # ── Save Artifacts ──
    if save:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)

        # Save feature columns list for predict-time consistency
        import json
        meta_path = MODEL_DIR / "model_meta.json"
        meta = {
            "feature_columns": feature_cols if feature_cols else [],
            "n_features": X_scaled.shape[1],
            "data_source": metrics["data_source"],
            "contamination": contamination,
            "n_estimators": n_estimators,
            "n_training_samples": X_scaled.shape[0],
        }
        if eval_metrics:
            meta["test_metrics"] = eval_metrics
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        print(f"\n💾 Model saved to: {MODEL_PATH}")
        print(f"💾 Scaler saved to: {SCALER_PATH}")
        print(f"💾 Metadata saved to: {meta_path}")

    return model, scaler, metrics


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  CyberSentinel – Model Training Pipeline")
    print("=" * 60)
    model, scaler, metrics = train_model()
    print("\n✅ Training complete!")
