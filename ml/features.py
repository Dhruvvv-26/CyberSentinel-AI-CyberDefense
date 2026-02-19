"""
CyberSentinel – Feature Engineering Pipeline
Extracts numerical feature vectors from parsed/enriched log entries.

Supports two modes:
  1. Core 11 features (for live log prediction from simulator/parsed logs)
  2. Expanded 19 features (when trained on real datasets with extra columns)

The predict module auto-selects the right feature set based on model metadata.
"""

import json
import numpy as np
from typing import Optional
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    FEATURE_COLUMNS, FEATURE_COLUMNS_EXPANDED,
    PROTOCOL_MAP, EVENT_TYPE_MAP,
    LOG_LEVEL_MAP, RISK_KEYWORDS, MODEL_DIR,
)


def compute_message_risk_score(message: str) -> int:
    """Score a log message based on presence of threat-related keywords."""
    if not message:
        return 0
    message_lower = message.lower()
    score = 0
    for keyword, weight in RISK_KEYWORDS.items():
        if keyword in message_lower:
            score += weight
    return min(score, 25)  # cap at 25


def get_model_n_features() -> int:
    """Read model metadata to determine expected feature count."""
    meta_path = MODEL_DIR / "model_meta.json"
    if meta_path.exists():
        try:
            with open(meta_path) as f:
                meta = json.load(f)
            return meta.get("n_features", 11)
        except Exception:
            pass
    return 11  # default


def extract_features_single(log: dict) -> Optional[np.ndarray]:
    """
    Extract a feature vector from a single enriched log entry.
    Auto-adapts to the feature count the model was trained with.
    Returns a 1D numpy array with the right number of features.
    """
    try:
        n_model_features = get_model_n_features()

        # Compute message risk score if not already present
        msg_score = log.get("message_risk_score")
        if msg_score is None:
            msg_score = compute_message_risk_score(log.get("message", ""))

        # Core 11 features (always present)
        features = [
            float(log.get("src_port", 0)),
            float(log.get("dst_port", 0)),
            float(log.get("bytes_sent", 0)),
            float(log.get("bytes_recv", 0)),
            float(log.get("duration", 0)),
            float(log.get("protocol_code", PROTOCOL_MAP.get(log.get("protocol", "TCP"), 0))),
            float(log.get("event_type_code", EVENT_TYPE_MAP.get(log.get("event_type", "connection"), 0))),
            float(log.get("log_level_code", LOG_LEVEL_MAP.get(log.get("log_level", "INFO"), 1))),
            float(msg_score),
            float(log.get("hour_of_day", 12)),
            float(log.get("is_weekend", 0)),
        ]

        # If model was trained with expanded features (19), pad with defaults
        if n_model_features > 11:
            extra_features = [
                float(log.get("count", 1)),                    # connection count
                float(log.get("srv_count", 1)),                # service count
                float(log.get("serror_rate", 0.0)),            # SYN error rate
                float(log.get("same_srv_rate", 1.0)),          # same service rate
                float(log.get("dst_host_count", 1)),           # dest host count
                float(log.get("dst_host_srv_count", 1)),       # dest host service count
                float(log.get("dst_host_same_srv_rate", 0.5)), # dest host same srv rate
                float(log.get("dst_host_serror_rate", 0.0)),   # dest host SYN error rate
            ]
            features.extend(extra_features)

            # Ensure we have exactly the right number
            while len(features) < n_model_features:
                features.append(0.0)
            features = features[:n_model_features]

        return np.array(features, dtype=np.float64)
    except (KeyError, ValueError, TypeError) as e:
        return None


def extract_features_batch(logs: list[dict]) -> np.ndarray:
    """
    Extract feature matrix from a list of enriched log entries.
    Returns a 2D numpy array of shape (n_valid_logs, n_features).
    """
    feature_vectors = []
    for log in logs:
        vec = extract_features_single(log)
        if vec is not None:
            feature_vectors.append(vec)

    if not feature_vectors:
        n_features = get_model_n_features()
        return np.empty((0, n_features))

    return np.vstack(feature_vectors)


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    from simulator.log_generator import generate_batch
    from ingestion.log_parser import parse_batch

    print("🔄 Feature extraction test...\n")
    raw = generate_batch(5, attack_ratio=0.4)
    parsed = parse_batch(raw)
    matrix = extract_features_batch(parsed)

    n_feat = get_model_n_features()
    print(f"  Model expects: {n_feat} features")
    print(f"  Logs parsed:    {len(parsed)}")
    print(f"  Feature matrix: {matrix.shape}")
    print(f"  Feature names:  {FEATURE_COLUMNS if n_feat == 11 else FEATURE_COLUMNS_EXPANDED}")
    print(f"\n  Sample vector:  {matrix[0]}")
    print("\n✅ Feature extraction working correctly.")
