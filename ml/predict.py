"""
CyberSentinel – Real-Time Anomaly Prediction
Loads trained model + scaler and provides prediction for individual logs.
"""

import joblib
import numpy as np
from pathlib import Path
from typing import Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_PATH, SCALER_PATH
from ml.features import extract_features_single


class AnomalyDetector:
    """Wraps the trained Isolation Forest for real-time prediction."""

    def __init__(self, model_path: Path = MODEL_PATH, scaler_path: Path = SCALER_PATH):
        self.model = None
        self.scaler = None
        self.is_loaded = False
        self._load(model_path, scaler_path)

    def _load(self, model_path: Path, scaler_path: Path):
        """Load the trained model and scaler from disk."""
        try:
            if model_path.exists() and scaler_path.exists():
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.is_loaded = True
                print(f"✅ Model loaded from {model_path}")
            else:
                print(f"⚠️  Model not found at {model_path}. Run ml.train first.")
        except Exception as e:
            print(f"❌ Error loading model: {e}")

    def predict(self, log: dict) -> dict:
        """
        Predict whether a log entry is anomalous.

        Returns:
            {
                "is_anomaly": bool,
                "prediction": int,       # -1 = anomaly, 1 = normal
                "anomaly_score": float,   # lower = more anomalous
                "confidence": float,      # 0-1 confidence score
            }
        """
        if not self.is_loaded:
            return {
                "is_anomaly": False,
                "prediction": 1,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "error": "Model not loaded",
            }

        features = extract_features_single(log)
        if features is None:
            return {
                "is_anomaly": False,
                "prediction": 1,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "error": "Feature extraction failed",
            }

        # Reshape and scale
        X = features.reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        # Predict
        prediction = int(self.model.predict(X_scaled)[0])
        score = float(self.model.decision_function(X_scaled)[0])

        # Convert score to confidence (0-1 range)
        # More negative score = higher anomaly confidence
        confidence = min(1.0, max(0.0, -score / 0.5)) if prediction == -1 else 0.0

        return {
            "is_anomaly": prediction == -1,
            "prediction": prediction,
            "anomaly_score": round(score, 4),
            "confidence": round(confidence, 4),
        }

    def predict_batch(self, logs: list[dict]) -> list[dict]:
        """Predict anomalies for a batch of logs."""
        return [self.predict(log) for log in logs]


# Singleton instance for reuse
_detector: Optional[AnomalyDetector] = None


def get_detector() -> AnomalyDetector:
    """Get or create the singleton AnomalyDetector."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    from simulator.log_generator import generate_batch
    from ingestion.log_parser import parse_batch

    detector = AnomalyDetector()
    if not detector.is_loaded:
        print("❌ Train the model first: python -m ml.train")
        exit(1)

    print("🔍 Testing predictions on 10 sample logs...\n")
    raw = generate_batch(10, attack_ratio=0.4)
    parsed = parse_batch(raw)

    for log in parsed:
        result = detector.predict(log)
        status = "🔴 ANOMALY" if result["is_anomaly"] else "🟢 NORMAL "
        print(f"  {status} | score={result['anomaly_score']:+.4f} | "
              f"conf={result['confidence']:.2f} | {log['event_type']}")

    print("\n✅ Prediction engine working correctly.")
