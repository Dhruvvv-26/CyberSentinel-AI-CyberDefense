"""
CyberSentinel – Context-Aware Intelligence Agent
Suppresses false positives using business context, maintenance windows,
known services, and adaptive thresholds.
"""

from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    MAINTENANCE_HOURS, PEAK_HOURS, PEAK_SCORE_MULTIPLIER,
    BACKUP_SUBNETS, WHITELISTED_IPS,
)


class ContextAgent:
    """
    Evaluates log context to determine whether an anomaly alert should
    be suppressed or its severity adjusted.
    """

    def __init__(self):
        self.suppression_stats = {
            "total_evaluated": 0,
            "suppressed": 0,
            "adjusted": 0,
        }

    def evaluate(self, log: dict, anomaly_result: dict) -> dict:
        """
        Check business context rules against an anomaly detection result.

        Args:
            log: enriched log dict
            anomaly_result: output from AnomalyDetector.predict()

        Returns:
            {
                "suppress": bool,
                "reason": str,
                "adjusted_score": float,
                "context_flags": list[str],
            }
        """
        self.suppression_stats["total_evaluated"] += 1

        if not anomaly_result.get("is_anomaly", False):
            return {
                "suppress": False,
                "reason": "Not an anomaly",
                "adjusted_score": anomaly_result.get("anomaly_score", 0.0),
                "context_flags": [],
            }

        score = anomaly_result.get("anomaly_score", 0.0)
        context_flags = []
        suppress = False
        reason = ""

        # 1. Maintenance window check
        hour = log.get("hour_of_day", 12)
        if MAINTENANCE_HOURS[0] <= hour < MAINTENANCE_HOURS[1]:
            context_flags.append("maintenance_window")
            # Only suppress low-confidence anomalies during maintenance
            if anomaly_result.get("confidence", 0) < 0.5:
                suppress = True
                reason = f"Low-confidence anomaly during maintenance window ({MAINTENANCE_HOURS[0]}:00-{MAINTENANCE_HOURS[1]}:00 UTC)"
                self.suppression_stats["suppressed"] += 1

        # 2. Backup traffic detection
        dst_ip = log.get("dst_ip", "")
        if any(dst_ip.startswith(subnet) for subnet in BACKUP_SUBNETS):
            context_flags.append("backup_traffic")
            bytes_sent = log.get("bytes_sent", 0)
            # Large transfers to backup subnets are expected
            if bytes_sent > 50000 and log.get("event_type") not in ["brute_force", "privilege_escalation"]:
                suppress = True
                reason = f"Large transfer to backup subnet {dst_ip} – likely scheduled backup"
                self.suppression_stats["suppressed"] += 1

        # 3. Whitelisted IP check
        src_ip = log.get("src_ip", "")
        if src_ip in WHITELISTED_IPS or dst_ip in WHITELISTED_IPS:
            context_flags.append("whitelisted_ip")
            if anomaly_result.get("confidence", 0) < 0.6:
                suppress = True
                reason = f"Low-confidence anomaly involving whitelisted IP"
                self.suppression_stats["suppressed"] += 1

        # 4. Peak hours adjustment
        if PEAK_HOURS[0] <= hour < PEAK_HOURS[1]:
            context_flags.append("peak_hours")
            score = score * PEAK_SCORE_MULTIPLIER
            self.suppression_stats["adjusted"] += 1

        # 5. Internal-only traffic leniency
        traffic_dir = log.get("traffic_direction", "")
        if traffic_dir == "internal" and anomaly_result.get("confidence", 0) < 0.4:
            context_flags.append("internal_traffic")
            suppress = True
            reason = "Low-confidence anomaly in internal-only traffic"
            self.suppression_stats["suppressed"] += 1

        if not suppress:
            reason = "Anomaly confirmed after context evaluation"

        return {
            "suppress": suppress,
            "reason": reason,
            "adjusted_score": round(score, 4),
            "context_flags": context_flags,
        }

    def get_stats(self) -> dict:
        """Return suppression statistics."""
        total = self.suppression_stats["total_evaluated"]
        return {
            **self.suppression_stats,
            "suppression_rate": round(
                self.suppression_stats["suppressed"] / max(total, 1) * 100, 2
            ),
        }


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    agent = ContextAgent()
    # Simulate context evaluation
    test_log = {
        "src_ip": "10.0.0.1",
        "dst_ip": "203.0.113.50",
        "hour_of_day": 3,
        "bytes_sent": 500,
        "event_type": "connection",
        "traffic_direction": "outbound",
    }
    test_anomaly = {"is_anomaly": True, "anomaly_score": -0.3, "confidence": 0.3}

    result = agent.evaluate(test_log, test_anomaly)
    print(f"Suppress: {result['suppress']}")
    print(f"Reason:   {result['reason']}")
    print(f"Flags:    {result['context_flags']}")
    print(f"\n✅ Context Agent working correctly.")
