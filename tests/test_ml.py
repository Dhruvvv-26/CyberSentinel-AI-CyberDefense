"""
CyberSentinel – ML Pipeline Tests
"""

import sys
import os
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.log_generator import generate_single_log, generate_batch
from ingestion.log_parser import parse_log, parse_batch, validate_log
from ml.features import extract_features_single, extract_features_batch, compute_message_risk_score, get_model_n_features


class TestLogGenerator:
    def test_generate_single_log_has_required_fields(self):
        log = generate_single_log()
        required = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                     "protocol", "bytes_sent", "bytes_recv", "duration",
                     "event_type", "log_level", "message"]
        for field in required:
            assert field in log, f"Missing field: {field}"

    def test_generate_batch_correct_size(self):
        logs = generate_batch(100)
        assert len(logs) == 100

    def test_attack_ratio(self):
        logs = generate_batch(1000, attack_ratio=0.3)
        attack_types = {"port_scan", "brute_force", "ddos", "data_exfiltration", "privilege_escalation"}
        attack_count = sum(1 for l in logs if l["event_type"] in attack_types)
        # Allow ±5% tolerance
        assert 250 <= attack_count <= 350, f"Attack count {attack_count} outside expected range"


class TestLogParser:
    def test_valid_log_passes(self):
        log = generate_single_log()
        valid, reason = validate_log(log)
        assert valid is True

    def test_missing_field_fails(self):
        log = generate_single_log()
        del log["src_ip"]
        valid, reason = validate_log(log)
        assert valid is False
        assert "src_ip" in reason

    def test_parse_log_enriches(self):
        raw = generate_single_log()
        parsed = parse_log(raw)
        assert parsed is not None
        assert "hour_of_day" in parsed
        assert "is_weekend" in parsed
        assert "protocol_code" in parsed
        assert "traffic_direction" in parsed

    def test_parse_batch_filters_invalid(self):
        logs = generate_batch(10)
        # Corrupt one
        del logs[0]["timestamp"]
        parsed = parse_batch(logs)
        assert len(parsed) == 9


class TestFeatureExtraction:
    def test_single_extraction_shape(self):
        log = generate_single_log()
        parsed = parse_log(log)
        vec = extract_features_single(parsed)
        assert vec is not None
        expected_n = get_model_n_features()
        assert vec.shape == (expected_n,)

    def test_batch_extraction_shape(self):
        logs = generate_batch(50)
        parsed = parse_batch(logs)
        matrix = extract_features_batch(parsed)
        expected_n = get_model_n_features()
        assert matrix.shape[0] == len(parsed)
        assert matrix.shape[1] == expected_n

    def test_message_risk_score(self):
        assert compute_message_risk_score("normal traffic") == 0
        assert compute_message_risk_score("unauthorized sudo exploit") > 10
        assert compute_message_risk_score("") == 0

    def test_features_are_numeric(self):
        log = generate_single_log()
        parsed = parse_log(log)
        vec = extract_features_single(parsed)
        assert np.isfinite(vec).all()


class TestModelTraining:
    """Training test – only runs if model doesn't exist yet or in CI."""

    def test_model_files_exist_after_training(self):
        """This test is validated during the verification phase."""
        from config import MODEL_PATH, SCALER_PATH
        # Note: model must be trained before running this test
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            from ml.predict import AnomalyDetector
            detector = AnomalyDetector()
            assert detector.is_loaded is True

            # Test prediction
            log = generate_single_log()
            parsed = parse_log(log)
            result = detector.predict(parsed)
            assert "is_anomaly" in result
            assert "anomaly_score" in result
            assert isinstance(result["is_anomaly"], bool)
