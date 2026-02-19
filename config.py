"""
CyberSentinel – Central Configuration
All system-wide constants, paths, and tuning parameters.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────── Paths ────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = DATA_DIR / "models"
LOG_DIR = DATA_DIR / "logs"
PROCESSED_DIR = DATA_DIR / "processed"

# Ensure directories exist
MODEL_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ──────────────────────────── Server ───────────────────────────
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DEMO_LOG_INTERVAL = float(os.getenv("DEMO_LOG_INTERVAL", "1.5"))  # seconds

# ──────────────────────────── ML Model ─────────────────────────
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
CONTAMINATION = float(os.getenv("CONTAMINATION", "0.15"))
N_ESTIMATORS = int(os.getenv("N_ESTIMATORS", "150"))
TRAINING_SAMPLES = int(os.getenv("TRAINING_SAMPLES", "10000"))
ATTACK_RATIO = 0.15  # 15% of training data is anomalous

# ──────────────────────────── Feature Config ───────────────────
# Core 11 features (used for live log prediction)
FEATURE_COLUMNS = [
    "src_port", "dst_port", "bytes_sent", "bytes_recv",
    "duration", "protocol_code", "event_type_code",
    "log_level_code", "message_risk_score",
    "hour_of_day", "is_weekend",
]

# Expanded 19 features (used when training on real datasets)
FEATURE_COLUMNS_EXPANDED = [
    "src_port", "dst_port", "log_bytes_sent", "log_bytes_recv",
    "norm_duration", "protocol_code", "event_type_code",
    "log_level_code", "message_risk_score",
    "hour_of_day", "is_weekend",
    # Extra features from real datasets
    "count", "srv_count", "serror_rate", "same_srv_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_serror_rate",
]

# Use real data if available
USE_REAL_DATA = os.getenv("USE_REAL_DATA", "true").lower() == "true"
REAL_TRAIN_PATH = PROCESSED_DIR / "combined_train.csv"
REAL_TEST_PATH = PROCESSED_DIR / "combined_test.csv"

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "DNS": 4}
EVENT_TYPE_MAP = {
    "connection": 0, "authentication": 1, "file_access": 2,
    "dns_query": 3, "http_request": 4, "port_scan": 5,
    "brute_force": 6, "ddos": 7, "data_exfiltration": 8,
    "privilege_escalation": 9,
}
LOG_LEVEL_MAP = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}

RISK_KEYWORDS = {
    "failed": 3, "denied": 3, "unauthorized": 5, "root": 4,
    "admin": 3, "sudo": 4, "password": 3, "exploit": 5,
    "malware": 5, "suspicious": 4, "blocked": 2, "timeout": 1,
    "flood": 4, "scan": 3, "exfiltration": 5, "escalation": 5,
    "brute": 4, "injection": 5, "overflow": 5, "payload": 4,
}

# ──────────────────────────── Threat Scoring ───────────────────
SEVERITY_THRESHOLDS = {
    "LOW":      (0, 25),
    "MEDIUM":   (26, 50),
    "HIGH":     (51, 75),
    "CRITICAL": (76, 100),
}

SEVERITY_COLORS = {
    "LOW":      "#22c55e",
    "MEDIUM":   "#f59e0b",
    "HIGH":     "#f97316",
    "CRITICAL": "#ef4444",
}

# ──────────────────────────── Context Agent ────────────────────
MAINTENANCE_HOURS = (2, 5)      # 2 AM – 5 AM UTC  (suppress alerts)
PEAK_HOURS = (9, 17)            # 9 AM – 5 PM UTC  (higher thresholds)
PEAK_SCORE_MULTIPLIER = 0.7     # reduce score by 30% during peak

BACKUP_SUBNETS = ["10.0.100.", "172.16.200."]  # known backup targets
WHITELISTED_IPS = ["10.0.0.1", "10.0.0.2", "192.168.1.1"]  # known services

# ──────────────────────────── Response Agent ───────────────────
COOLDOWN_SECONDS = {
    "LOW":      300,    # 5 min
    "MEDIUM":   120,    # 2 min
    "HIGH":     60,     # 1 min
    "CRITICAL": 30,     # 30 sec
}

MAX_ALERTS_STORED = 500
MAX_LOGS_STORED = 1000

# ──────────────────────────── Simulator ────────────────────────
INTERNAL_SUBNETS = ["10.0.0.", "10.0.1.", "192.168.1."]
EXTERNAL_IPS = [
    "203.0.113.50", "198.51.100.23", "185.220.101.42",
    "91.240.118.172", "45.33.32.156", "104.18.32.7",
]
COMMON_PORTS = [22, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]
ATTACK_PORTS = [4444, 5555, 31337, 12345, 23, 445, 1433, 3389]
