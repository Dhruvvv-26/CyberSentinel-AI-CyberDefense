"""
CyberSentinel - Context Agent
Applies contextual reasoning to filter false alarms.
"""

MAINTENANCE_WINDOWS = [
    ("02:00", "03:00"),  # simulated maintenance window
]

def is_within_maintenance(timestamp_utc: str) -> bool:
    # Simple placeholder logic for demo purposes
    hour = int(timestamp_utc[11:13])
    return hour == 2  # simulate maintenance hour

def should_alert(log):
    """
    Decide whether to escalate an anomaly based on context.
    """
    if is_within_maintenance(log["timestamp"]):
        return False  # suppress alert during maintenance

    if "backup" in log["message"].lower():
        return False  # suppress backup-related spikes

    return True
