"""
CyberSentinel - Log Ingestor
Collects and normalizes network/system logs for downstream ML processing.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("data/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

def ingest_log(source: str, message: str, level: str = "INFO"):
    """
    Save a normalized log entry to disk.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "level": level,
        "message": message
    }

    file_path = LOG_DIR / "logs.jsonl"
    with open(file_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return entry

if __name__ == "__main__":
    # Demo log
    print(ingest_log("sd-wan-edge-1", "Packet drop detected on interface eth0", "WARN"))
