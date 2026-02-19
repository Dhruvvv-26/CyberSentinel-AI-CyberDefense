"""
CyberSentinel – Log Parser & Normalizer
Parses raw JSON logs, normalizes timestamps, validates fields,
and enriches with derived features for the ML pipeline.
"""

from datetime import datetime, timezone
from typing import Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import PROTOCOL_MAP, EVENT_TYPE_MAP, LOG_LEVEL_MAP

REQUIRED_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes_sent", "bytes_recv", "duration",
    "event_type", "log_level", "message",
]


def validate_log(log: dict) -> tuple[bool, str]:
    """Check that all required fields are present and valid."""
    for field in REQUIRED_FIELDS:
        if field not in log:
            return False, f"Missing required field: {field}"

    # Type checks
    if not isinstance(log["bytes_sent"], (int, float)):
        return False, "bytes_sent must be numeric"
    if not isinstance(log["bytes_recv"], (int, float)):
        return False, "bytes_recv must be numeric"
    if not isinstance(log["duration"], (int, float)):
        return False, "duration must be numeric"
    if not isinstance(log["src_port"], int):
        return False, "src_port must be integer"
    if not isinstance(log["dst_port"], int):
        return False, "dst_port must be integer"

    return True, "OK"


def normalize_timestamp(ts: str) -> datetime:
    """Parse ISO timestamp string to UTC datetime."""
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def enrich_log(log: dict) -> dict:
    """Add derived features to a validated log entry."""
    dt = normalize_timestamp(log["timestamp"])

    enriched = dict(log)
    enriched["timestamp_utc"] = dt.isoformat()
    enriched["hour_of_day"] = dt.hour
    enriched["is_weekend"] = 1 if dt.weekday() >= 5 else 0

    # Encode categoricals
    enriched["protocol_code"] = PROTOCOL_MAP.get(log["protocol"], 0)
    enriched["event_type_code"] = EVENT_TYPE_MAP.get(log["event_type"], 0)
    enriched["log_level_code"] = LOG_LEVEL_MAP.get(log["log_level"], 1)

    # Traffic direction
    src = log["src_ip"]
    is_internal_src = any(src.startswith(s) for s in ["10.", "192.168.", "172.16."])
    dst = log["dst_ip"]
    is_internal_dst = any(dst.startswith(s) for s in ["10.", "192.168.", "172.16."])

    if is_internal_src and not is_internal_dst:
        enriched["traffic_direction"] = "outbound"
    elif not is_internal_src and is_internal_dst:
        enriched["traffic_direction"] = "inbound"
    else:
        enriched["traffic_direction"] = "internal"

    return enriched


def parse_log(raw_log: dict) -> Optional[dict]:
    """
    Full parsing pipeline: validate → normalize → enrich.
    Returns enriched log dict or None if invalid.
    """
    valid, reason = validate_log(raw_log)
    if not valid:
        return None

    return enrich_log(raw_log)


def parse_batch(logs: list[dict]) -> list[dict]:
    """Parse a batch of logs, skipping invalid entries."""
    parsed = []
    for log in logs:
        result = parse_log(log)
        if result is not None:
            parsed.append(result)
    return parsed


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    from simulator.log_generator import generate_batch

    print("🔄 Parsing 5 sample logs...\n")
    raw_logs = generate_batch(5, attack_ratio=0.4)
    parsed = parse_batch(raw_logs)

    for p in parsed:
        print(f"  [{p['event_type']:>22s}] dir={p['traffic_direction']:<8s} "
              f"hour={p['hour_of_day']:2d} proto_code={p['protocol_code']} "
              f"level_code={p['log_level_code']}")

    print(f"\n✅ Parsed {len(parsed)}/{len(raw_logs)} logs successfully.")
