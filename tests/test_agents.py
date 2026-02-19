"""
CyberSentinel – Intelligence Agent Tests
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.context_agent import ContextAgent
from agents.threat_scorer import ThreatScorer
from agents.response_agent import ResponseAgent


class TestContextAgent:
    def setup_method(self):
        self.agent = ContextAgent()

    def test_normal_log_not_suppressed(self):
        log = {"hour_of_day": 10, "src_ip": "10.0.0.50", "dst_ip": "203.0.113.50",
               "bytes_sent": 500, "event_type": "connection", "traffic_direction": "outbound"}
        anomaly = {"is_anomaly": False, "anomaly_score": 0.1, "confidence": 0.0}
        result = self.agent.evaluate(log, anomaly)
        assert result["suppress"] is False

    def test_maintenance_window_suppresses_low_confidence(self):
        log = {"hour_of_day": 3, "src_ip": "10.0.0.50", "dst_ip": "203.0.113.50",
               "bytes_sent": 500, "event_type": "connection", "traffic_direction": "outbound"}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.2, "confidence": 0.3}
        result = self.agent.evaluate(log, anomaly)
        assert result["suppress"] is True
        assert "maintenance" in result["reason"].lower()

    def test_whitelisted_ip_suppresses_low_confidence(self):
        log = {"hour_of_day": 10, "src_ip": "10.0.0.1", "dst_ip": "10.0.1.50",
               "bytes_sent": 500, "event_type": "connection", "traffic_direction": "internal"}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.15, "confidence": 0.4}
        result = self.agent.evaluate(log, anomaly)
        assert result["suppress"] is True

    def test_peak_hours_adjusts_score(self):
        log = {"hour_of_day": 12, "src_ip": "203.0.113.50", "dst_ip": "10.0.1.50",
               "bytes_sent": 500, "event_type": "port_scan", "traffic_direction": "inbound"}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.5, "confidence": 0.8}
        result = self.agent.evaluate(log, anomaly)
        assert "peak_hours" in result["context_flags"]

    def test_stats_tracking(self):
        log = {"hour_of_day": 10, "src_ip": "10.0.0.50", "dst_ip": "203.0.113.50",
               "bytes_sent": 500, "event_type": "connection", "traffic_direction": "outbound"}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.5, "confidence": 0.8}
        self.agent.evaluate(log, anomaly)
        stats = self.agent.get_stats()
        assert stats["total_evaluated"] == 1


class TestThreatScorer:
    def setup_method(self):
        self.scorer = ThreatScorer()

    def test_normal_log_scores_zero(self):
        anomaly = {"is_anomaly": False}
        context = {"suppress": False, "context_flags": []}
        result = self.scorer.score({}, anomaly, context)
        assert result["threat_score"] == 0
        assert result["severity"] == "NORMAL"

    def test_suppressed_scores_zero(self):
        anomaly = {"is_anomaly": True}
        context = {"suppress": True, "reason": "test", "context_flags": []}
        result = self.scorer.score({}, anomaly, context)
        assert result["severity"] == "SUPPRESSED"

    def test_high_threat_scores_high(self):
        log = {"src_ip": "203.0.113.50", "dst_port": 4444, "bytes_sent": 200000,
               "duration": 0.005, "log_level": "CRITICAL", "event_type": "data_exfiltration",
               "message": "unauthorized exfiltration exploit"}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.7, "confidence": 0.9}
        context = {"suppress": False, "context_flags": []}
        result = self.scorer.score(log, anomaly, context)
        assert result["threat_score"] >= 50
        assert result["severity"] in ("HIGH", "CRITICAL")

    def test_event_correlation_increases_score(self):
        log = {"src_ip": "1.2.3.4", "dst_port": 80, "bytes_sent": 100,
               "duration": 1.0, "log_level": "WARNING", "event_type": "port_scan",
               "message": "scan detected"}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.3, "confidence": 0.5}
        context = {"suppress": False, "context_flags": []}

        score1 = self.scorer.score(log, anomaly, context)["threat_score"]
        score2 = self.scorer.score(log, anomaly, context)["threat_score"]
        assert score2 >= score1  # correlation should increase score


class TestResponseAgent:
    def setup_method(self):
        self.agent = ResponseAgent()

    def test_normal_returns_none(self):
        score = {"severity": "NORMAL", "threat_score": 0}
        result = self.agent.respond({}, score, {})
        assert result is None

    def test_critical_generates_alert_with_actions(self):
        log = {"src_ip": "203.0.113.50", "dst_ip": "10.0.1.100",
               "event_type": "ddos", "message": "DDoS attack"}
        score = {"severity": "CRITICAL", "threat_score": 90, "factors": {}}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.8, "confidence": 0.95}

        alert = self.agent.respond(log, score, anomaly)
        assert alert is not None
        assert alert["severity"] == "CRITICAL"
        assert len(alert["actions"]) >= 3
        action_types = {a["type"] for a in alert["actions"]}
        assert "block_ip" in action_types
        assert "escalate" in action_types

    def test_cooldown_prevents_duplicate(self):
        log = {"src_ip": "100.0.0.1", "dst_ip": "10.0.1.1",
               "event_type": "port_scan", "message": "test"}
        score = {"severity": "HIGH", "threat_score": 60, "factors": {}}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.5, "confidence": 0.7}

        alert1 = self.agent.respond(log, score, anomaly)
        alert2 = self.agent.respond(log, score, anomaly)
        assert alert1 is not None
        assert alert2 is None  # cooldown active

    def test_stats_tracking(self):
        log = {"src_ip": "200.0.0.1", "dst_ip": "10.0.1.1",
               "event_type": "brute_force", "message": "test"}
        score = {"severity": "MEDIUM", "threat_score": 40, "factors": {}}
        anomaly = {"is_anomaly": True, "anomaly_score": -0.3, "confidence": 0.5}

        self.agent.respond(log, score, anomaly)
        stats = self.agent.get_stats()
        assert stats["total_alerts"] == 1
        assert stats["by_severity"]["MEDIUM"] == 1
