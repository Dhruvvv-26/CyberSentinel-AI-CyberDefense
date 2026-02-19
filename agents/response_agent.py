"""
CyberSentinel – Autonomous Response Agent
Generates alerts, triggers automated actions, handles deduplication
and cooldown logic, and logs all response actions.
"""

import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import COOLDOWN_SECONDS, MAX_ALERTS_STORED


class ResponseAgent:
    """
    Autonomous response system that generates alerts, deduplicates,
    and triggers severity-based automated actions.
    """

    def __init__(self):
        self.alerts: list[dict] = []
        self.response_log: list[dict] = []
        self._cooldowns: dict[str, float] = {}  # ip -> last_alert_time
        self.stats = {
            "total_alerts": 0,
            "by_severity": defaultdict(int),
            "actions_taken": defaultdict(int),
            "suppressed_by_cooldown": 0,
        }

    def respond(self, log: dict, score_result: dict, anomaly_result: dict) -> Optional[dict]:
        """
        Process a scored anomaly and generate response actions.

        Args:
            log: enriched log dict
            score_result: output from ThreatScorer.score()
            anomaly_result: output from AnomalyDetector.predict()

        Returns:
            Alert dict or None if no action needed
        """
        severity = score_result.get("severity", "NORMAL")
        threat_score = score_result.get("threat_score", 0)

        # Skip normal / suppressed
        if severity in ("NORMAL", "SUPPRESSED"):
            return None

        src_ip = log.get("src_ip", "unknown")

        # Cooldown check – prevent alert flooding from same IP
        if self._is_in_cooldown(src_ip, severity):
            self.stats["suppressed_by_cooldown"] += 1
            return None

        # Generate alert
        alert = self._create_alert(log, score_result, anomaly_result)

        # Determine actions based on severity
        actions = self._determine_actions(severity, src_ip, log)
        alert["actions"] = actions

        # Store alert
        self.alerts.append(alert)
        if len(self.alerts) > MAX_ALERTS_STORED:
            self.alerts = self.alerts[-MAX_ALERTS_STORED:]

        # Update cooldown
        self._cooldowns[src_ip] = time.time()

        # Update stats
        self.stats["total_alerts"] += 1
        self.stats["by_severity"][severity] += 1

        # Log response actions
        for action in actions:
            self.response_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert["id"],
                "action": action["type"],
                "target": action.get("target", ""),
                "severity": severity,
            })
            self.stats["actions_taken"][action["type"]] += 1

        return alert

    def _is_in_cooldown(self, ip: str, severity: str) -> bool:
        """Check if IP is within cooldown window for this severity."""
        last_time = self._cooldowns.get(ip, 0)
        cooldown = COOLDOWN_SECONDS.get(severity, 120)
        return (time.time() - last_time) < cooldown

    def _create_alert(self, log: dict, score_result: dict, anomaly_result: dict) -> dict:
        """Create a structured alert object."""
        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": score_result["severity"],
            "threat_score": score_result["threat_score"],
            "src_ip": log.get("src_ip", "unknown"),
            "dst_ip": log.get("dst_ip", "unknown"),
            "event_type": log.get("event_type", "unknown"),
            "message": log.get("message", ""),
            "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
            "confidence": anomaly_result.get("confidence", 0.0),
            "factors": score_result.get("factors", {}),
            "actions": [],
        }

    def _determine_actions(self, severity: str, src_ip: str, log: dict) -> list[dict]:
        """
        Determine response actions based on severity level.
        All actions are simulated (no real network changes).
        """
        actions = []

        if severity == "LOW":
            actions.append({
                "type": "log_event",
                "description": f"Low-severity anomaly logged for {src_ip}",
                "target": src_ip,
            })

        elif severity == "MEDIUM":
            actions.append({
                "type": "generate_alert",
                "description": f"Alert generated for medium-severity threat from {src_ip}",
                "target": src_ip,
            })
            actions.append({
                "type": "increase_monitoring",
                "description": f"Monitoring level increased for {src_ip}",
                "target": src_ip,
            })

        elif severity == "HIGH":
            actions.append({
                "type": "generate_alert",
                "description": f"HIGH severity alert for {src_ip}",
                "target": src_ip,
            })
            actions.append({
                "type": "block_ip",
                "description": f"[SIMULATED] Firewall rule added to block {src_ip}",
                "target": src_ip,
            })
            actions.append({
                "type": "notify_soc",
                "description": f"SOC team notified of high-severity threat from {src_ip}",
                "target": "SOC_TEAM",
            })

        elif severity == "CRITICAL":
            actions.append({
                "type": "generate_alert",
                "description": f"🚨 CRITICAL alert for {src_ip}",
                "target": src_ip,
            })
            actions.append({
                "type": "block_ip",
                "description": f"[SIMULATED] Emergency firewall block for {src_ip}",
                "target": src_ip,
            })
            actions.append({
                "type": "isolate_node",
                "description": f"[SIMULATED] Network isolation for target {log.get('dst_ip', 'unknown')}",
                "target": log.get("dst_ip", "unknown"),
            })
            actions.append({
                "type": "escalate",
                "description": f"Incident escalated to SOC Lead – CRITICAL threat",
                "target": "SOC_LEAD",
            })

        return actions

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        """Get the most recent alerts."""
        return self.alerts[-limit:]

    def get_stats(self) -> dict:
        """Return response statistics."""
        return {
            "total_alerts": self.stats["total_alerts"],
            "by_severity": dict(self.stats["by_severity"]),
            "actions_taken": dict(self.stats["actions_taken"]),
            "suppressed_by_cooldown": self.stats["suppressed_by_cooldown"],
        }


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    agent = ResponseAgent()

    # Test critical alert
    test_log = {
        "src_ip": "203.0.113.50",
        "dst_ip": "10.0.1.100",
        "event_type": "data_exfiltration",
        "message": "Large outbound data transfer detected",
    }
    test_score = {"threat_score": 85, "severity": "CRITICAL", "factors": {}}
    test_anomaly = {"is_anomaly": True, "anomaly_score": -0.7, "confidence": 0.9}

    alert = agent.respond(test_log, test_score, test_anomaly)
    if alert:
        print(f"Alert ID:  {alert['id']}")
        print(f"Severity:  {alert['severity']}")
        print(f"Score:     {alert['threat_score']}")
        print(f"Actions:")
        for action in alert['actions']:
            print(f"  → {action['type']}: {action['description']}")

    print(f"\nStats: {agent.get_stats()}")
    print(f"\n✅ Response Agent working correctly.")
