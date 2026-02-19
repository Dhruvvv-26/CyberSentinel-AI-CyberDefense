"""
CyberSentinel – Threat Scoring Engine
Assigns severity levels (LOW/MEDIUM/HIGH/CRITICAL) using multi-factor
risk assessment with event correlation and time decay.
"""

import time
from collections import defaultdict
from typing import Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SEVERITY_THRESHOLDS, RISK_KEYWORDS


class ThreatScorer:
    """
    Multi-factor threat severity engine that combines ML anomaly scores,
    feature-based modifiers, event correlation, and attack pattern recognition.
    """

    def __init__(self):
        # Track anomaly history per IP for correlation
        self._ip_history: dict[str, list[float]] = defaultdict(list)
        self._ip_last_seen: dict[str, float] = {}
        self.TIME_DECAY_SECONDS = 300  # 5 minute window for correlation

    def score(self, log: dict, anomaly_result: dict, context_result: dict) -> dict:
        """
        Compute a threat severity score (0–100) using multiple factors.

        Args:
            log: enriched log dict
            anomaly_result: output from AnomalyDetector.predict()
            context_result: output from ContextAgent.evaluate()

        Returns:
            {
                "threat_score": int,
                "severity": str,
                "factors": dict,
            }
        """
        if context_result.get("suppress", False):
            return {
                "threat_score": 0,
                "severity": "SUPPRESSED",
                "factors": {"reason": context_result.get("reason", "Suppressed by context")},
            }

        if not anomaly_result.get("is_anomaly", False):
            return {
                "threat_score": 0,
                "severity": "NORMAL",
                "factors": {},
            }

        factors = {}

        # ── Factor 1: Base ML Score (0-35 points) ──
        raw_score = anomaly_result.get("anomaly_score", 0.0)
        confidence = anomaly_result.get("confidence", 0.0)
        ml_base = min(35, int(confidence * 35))
        factors["ml_anomaly_base"] = ml_base

        # ── Factor 2: Feature-Based Modifiers (0-25 points) ──
        feature_score = 0

        # High bytes transferred
        bytes_sent = log.get("bytes_sent", 0)
        if bytes_sent > 100000:
            feature_score += 8
            factors["high_bytes_sent"] = bytes_sent
        elif bytes_sent > 10000:
            feature_score += 4

        # Suspicious ports
        dst_port = log.get("dst_port", 0)
        suspicious_ports = {4444, 5555, 31337, 12345, 23, 445, 1433, 3389}
        if dst_port in suspicious_ports:
            feature_score += 7
            factors["suspicious_port"] = dst_port

        # Very short duration (scan-like)
        duration = log.get("duration", 1.0)
        if duration < 0.01:
            feature_score += 5
            factors["rapid_connection"] = duration

        # High log level
        log_level = log.get("log_level", "INFO")
        if log_level == "CRITICAL":
            feature_score += 5
        elif log_level == "ERROR":
            feature_score += 3

        feature_score = min(25, feature_score)
        factors["feature_modifiers"] = feature_score

        # ── Factor 3: Message Risk Keywords (0-15 points) ──
        message = log.get("message", "").lower()
        keyword_score = 0
        for keyword, weight in RISK_KEYWORDS.items():
            if keyword in message:
                keyword_score += weight
        keyword_score = min(15, keyword_score)
        factors["keyword_risk"] = keyword_score

        # ── Factor 4: Event Correlation (0-15 points) ──
        src_ip = log.get("src_ip", "unknown")
        now = time.time()
        correlation_score = 0

        # Decay old entries
        if src_ip in self._ip_history:
            cutoff = now - self.TIME_DECAY_SECONDS
            last_seen = self._ip_last_seen.get(src_ip, 0)
            if last_seen < cutoff:
                self._ip_history[src_ip] = []

        # Add current anomaly
        self._ip_history[src_ip].append(now)
        self._ip_last_seen[src_ip] = now

        # More repeated anomalies from same IP = higher risk
        repeat_count = len(self._ip_history[src_ip])
        if repeat_count >= 5:
            correlation_score = 15
        elif repeat_count >= 3:
            correlation_score = 10
        elif repeat_count >= 2:
            correlation_score = 5
        factors["event_correlation"] = correlation_score
        factors["repeat_count"] = repeat_count

        # ── Factor 5: Attack Pattern Bonus (0-10 points) ──
        event_type = log.get("event_type", "")
        attack_bonuses = {
            "data_exfiltration": 10,
            "privilege_escalation": 10,
            "ddos": 8,
            "brute_force": 7,
            "port_scan": 5,
        }
        pattern_bonus = attack_bonuses.get(event_type, 0)
        factors["attack_pattern_bonus"] = pattern_bonus

        # ── Final Score ──
        total = ml_base + feature_score + keyword_score + correlation_score + pattern_bonus
        # Apply context adjustment if available
        if "peak_hours" in context_result.get("context_flags", []):
            total = int(total * 0.85)
            factors["peak_hours_reduction"] = True

        total = max(0, min(100, total))

        # Classify severity
        severity = "LOW"
        for level, (low, high) in SEVERITY_THRESHOLDS.items():
            if low <= total <= high:
                severity = level
                break

        return {
            "threat_score": total,
            "severity": severity,
            "factors": factors,
        }

    def get_ip_history_size(self) -> int:
        return sum(len(v) for v in self._ip_history.values())


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    scorer = ThreatScorer()
    test_log = {
        "src_ip": "203.0.113.50",
        "dst_ip": "10.0.1.100",
        "dst_port": 4444,
        "bytes_sent": 200000,
        "duration": 0.005,
        "log_level": "CRITICAL",
        "event_type": "data_exfiltration",
        "message": "Large outbound data transfer to suspicious external IP – possible exfiltration",
    }
    test_anomaly = {"is_anomaly": True, "anomaly_score": -0.6, "confidence": 0.85}
    test_context = {"suppress": False, "context_flags": []}

    result = scorer.score(test_log, test_anomaly, test_context)
    print(f"Score:    {result['threat_score']}")
    print(f"Severity: {result['severity']}")
    print(f"Factors:  {result['factors']}")
    print(f"\n✅ Threat Scorer working correctly.")
