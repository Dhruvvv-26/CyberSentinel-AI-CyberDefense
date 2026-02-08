"""
CyberSentinel - Autonomous Response Agent
Triggers response actions for detected anomalies.
"""

from datetime import datetime, timezone

ACTIONS_LOG = "data/response_actions.log"


def block_ip(ip: str):
    action = f"[{datetime.now(timezone.utc).isoformat()}] BLOCKED IP: {ip}"
    _log_action(action)
    print(action)


def isolate_node(node: str):
    action = f"[{datetime.now(timezone.utc).isoformat()}] ISOLATED NODE: {node}"
    _log_action(action)
    print(action)


def alert_soc(message: str):
    action = f"[{datetime.now(timezone.utc).isoformat()}] ALERT SENT: {message}"
    _log_action(action)
    print(action)


def _log_action(action: str):
    with open(ACTIONS_LOG, "a") as f:
        f.write(action + "\n")


if __name__ == "__main__":
    block_ip("192.168.1.23")
    isolate_node("sd-wan-edge-2")
    alert_soc("Multiple failed login attempts detected")
