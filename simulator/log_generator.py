"""
CyberSentinel – Synthetic Log Generator
Produces realistic network/system logs with configurable attack injection.
Supports batch mode (for training) and streaming mode (for real-time demo).
"""

import random
import time
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Generator

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    INTERNAL_SUBNETS, EXTERNAL_IPS, COMMON_PORTS, ATTACK_PORTS,
    ATTACK_RATIO,
)

# ─────────────────────── Helpers ───────────────────────────────

def _random_internal_ip() -> str:
    subnet = random.choice(INTERNAL_SUBNETS)
    return f"{subnet}{random.randint(2, 254)}"


def _random_external_ip() -> str:
    return random.choice(EXTERNAL_IPS)


def _random_port(attack: bool = False) -> int:
    if attack:
        return random.choice(ATTACK_PORTS + COMMON_PORTS)
    return random.choice(COMMON_PORTS)


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp_random_recent(hours: int = 24) -> str:
    delta = timedelta(seconds=random.randint(0, hours * 3600))
    return (datetime.now(timezone.utc) - delta).isoformat()


# ─────────────────────── Normal Log Generators ─────────────────

def _gen_connection_log() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_external_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([80, 443, 8080]),
        "protocol": random.choice(["TCP", "HTTP"]),
        "bytes_sent": random.randint(100, 5000),
        "bytes_recv": random.randint(200, 15000),
        "duration": round(random.uniform(0.01, 5.0), 3),
        "event_type": "connection",
        "log_level": "INFO",
        "message": random.choice([
            "Outbound connection established",
            "HTTP GET request completed",
            "TLS handshake successful",
            "Connection to CDN established",
        ]),
    }


def _gen_auth_log() -> dict:
    success = random.random() > 0.1
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": 22,
        "protocol": "TCP",
        "bytes_sent": random.randint(50, 500),
        "bytes_recv": random.randint(50, 500),
        "duration": round(random.uniform(0.5, 3.0), 3),
        "event_type": "authentication",
        "log_level": "INFO" if success else "WARNING",
        "message": "User login successful" if success else "Authentication failed: invalid credentials",
    }


def _gen_dns_log() -> dict:
    domains = ["google.com", "github.com", "aws.amazon.com", "cdn.jsdelivr.net", "api.internal.local"]
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_internal_ip(),
        "dst_ip": "10.0.0.1",
        "src_port": random.randint(49152, 65535),
        "dst_port": 53,
        "protocol": "DNS",
        "bytes_sent": random.randint(30, 100),
        "bytes_recv": random.randint(50, 300),
        "duration": round(random.uniform(0.001, 0.1), 4),
        "event_type": "dns_query",
        "log_level": "DEBUG",
        "message": f"DNS query for {random.choice(domains)}",
    }


def _gen_file_access_log() -> dict:
    paths = ["/var/log/syslog", "/home/user/docs/report.pdf", "/etc/hosts", "/tmp/cache.dat"]
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": 445,
        "protocol": "TCP",
        "bytes_sent": random.randint(100, 2000),
        "bytes_recv": random.randint(500, 10000),
        "duration": round(random.uniform(0.01, 2.0), 3),
        "event_type": "file_access",
        "log_level": "INFO",
        "message": f"File read: {random.choice(paths)}",
    }


# ─────────────────────── Attack Log Generators ─────────────────

def _gen_port_scan() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_external_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice(ATTACK_PORTS + COMMON_PORTS),
        "protocol": "TCP",
        "bytes_sent": random.randint(40, 120),
        "bytes_recv": random.randint(0, 60),
        "duration": round(random.uniform(0.001, 0.05), 4),
        "event_type": "port_scan",
        "log_level": "WARNING",
        "message": "SYN scan detected – rapid sequential port probing",
    }


def _gen_brute_force() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_external_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([22, 3389, 23]),
        "protocol": "TCP",
        "bytes_sent": random.randint(100, 400),
        "bytes_recv": random.randint(50, 200),
        "duration": round(random.uniform(0.1, 1.5), 3),
        "event_type": "brute_force",
        "log_level": "ERROR",
        "message": random.choice([
            "Multiple failed SSH login attempts from external IP",
            "Brute force password attack detected",
            "Repeated authentication failures – possible credential stuffing",
        ]),
    }


def _gen_ddos() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_external_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 53]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "bytes_sent": random.randint(10000, 500000),
        "bytes_recv": random.randint(0, 500),
        "duration": round(random.uniform(0.001, 0.1), 4),
        "event_type": "ddos",
        "log_level": "CRITICAL",
        "message": random.choice([
            "SYN flood detected – abnormal packet volume",
            "UDP flood – massive traffic spike from single source",
            "DDoS amplification attack in progress",
        ]),
    }


def _gen_data_exfiltration() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_external_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([443, 8443, 4444]),
        "protocol": "TCP",
        "bytes_sent": random.randint(100000, 5000000),
        "bytes_recv": random.randint(100, 1000),
        "duration": round(random.uniform(5.0, 60.0), 2),
        "event_type": "data_exfiltration",
        "log_level": "CRITICAL",
        "message": random.choice([
            "Large outbound data transfer to suspicious external IP",
            "Possible data exfiltration – encrypted tunnel detected",
            "Abnormal data upload volume exceeding baseline",
        ]),
    }


def _gen_privilege_escalation() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "timestamp": _timestamp_now(),
        "src_ip": _random_internal_ip(),
        "dst_ip": _random_internal_ip(),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([22, 445, 135]),
        "protocol": "TCP",
        "bytes_sent": random.randint(200, 2000),
        "bytes_recv": random.randint(100, 1500),
        "duration": round(random.uniform(0.1, 5.0), 3),
        "event_type": "privilege_escalation",
        "log_level": "CRITICAL",
        "message": random.choice([
            "Unauthorized sudo access attempt detected",
            "Privilege escalation – user gained root access",
            "Suspicious admin command execution from non-admin user",
        ]),
    }


# ─────────────────────── Generator Methods ─────────────────────

NORMAL_GENERATORS = [_gen_connection_log, _gen_auth_log, _gen_dns_log, _gen_file_access_log]
ATTACK_GENERATORS = [_gen_port_scan, _gen_brute_force, _gen_ddos, _gen_data_exfiltration, _gen_privilege_escalation]


def generate_single_log(attack_probability: float = ATTACK_RATIO) -> dict:
    """Generate a single random log entry."""
    if random.random() < attack_probability:
        return random.choice(ATTACK_GENERATORS)()
    return random.choice(NORMAL_GENERATORS)()


def generate_batch(n: int = 10000, attack_ratio: float = ATTACK_RATIO) -> list[dict]:
    """Generate a batch of n log entries for training."""
    logs = []
    n_attacks = int(n * attack_ratio)
    n_normal = n - n_attacks

    for _ in range(n_normal):
        logs.append(random.choice(NORMAL_GENERATORS)())
    for _ in range(n_attacks):
        logs.append(random.choice(ATTACK_GENERATORS)())

    random.shuffle(logs)
    return logs


def stream_logs(interval: float = 1.5, attack_ratio: float = ATTACK_RATIO) -> Generator[dict, None, None]:
    """Yield logs one at a time with a delay (for real-time demo)."""
    while True:
        yield generate_single_log(attack_ratio)
        time.sleep(interval)


# ─────────────────────── CLI Entry Point ───────────────────────

if __name__ == "__main__":
    print("🔄 Generating 10 sample logs...\n")
    for i, log in enumerate(generate_batch(10, attack_ratio=0.3)):
        print(f"[{i+1}] {log['event_type']:>22s} | {log['log_level']:<8s} | {log['message']}")
    print("\n✅ Log generator working correctly.")
