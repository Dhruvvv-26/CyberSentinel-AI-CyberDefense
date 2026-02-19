"""
CyberSentinel – Real Dataset Preprocessing Pipeline
=====================================================
Downloads, cleans, and preprocesses two real-world cybersecurity datasets:
  1. NSL-KDD (125,973 train + 22,544 test)
  2. UNSW-NB15 (175,342 train + 82,333 test)

Produces a unified preprocessed CSV with standardized columns that map
directly to CyberSentinel's feature extraction pipeline.

Output: data/processed/combined_train.csv, data/processed/combined_test.csv
"""

import sys
import os
import time
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

warnings.filterwarnings("ignore")

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# NSL-KDD Column Names (dataset has no header row)
# ═══════════════════════════════════════════════════════════════
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_type", "difficulty_level"
]

# NSL-KDD Attack type mapping to categories
NSL_KDD_ATTACK_MAP = {
    "normal": "Normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS",
    "mailbomb": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    # Probe
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    # R2L (Remote to Local)
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L",
    "multihop": "R2L", "phf": "R2L", "spy": "R2L", "warezclient": "R2L",
    "warezmaster": "R2L", "xlock": "R2L", "xsnoop": "R2L",
    "snmpgetattack": "R2L", "httptunnel": "R2L", "snmpguess": "R2L",
    "sendmail": "R2L", "named": "R2L", "worm": "R2L",
    # U2R (User to Root)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R",
    "rootkit": "U2R", "xterm": "U2R", "ps": "U2R", "sqlattack": "U2R",
}

# NSL-KDD service to port mapping (approximate)
NSL_KDD_SERVICE_PORT_MAP = {
    "http": 80, "http_443": 443, "smtp": 25, "ftp": 21, "ftp_data": 20,
    "ssh": 22, "telnet": 23, "domain_u": 53, "domain": 53,
    "pop_3": 110, "imap4": 143, "ldap": 389, "finger": 79,
    "private": 0, "other": 0, "eco_i": 0, "ecr_i": 0,
    "tim_i": 0, "urp_i": 0, "red_i": 0,
}


def preprocess_nslkdd():
    """Preprocess NSL-KDD dataset into standardized format."""
    print("\n" + "=" * 60)
    print("  Preprocessing NSL-KDD Dataset")
    print("=" * 60)

    train_path = RAW_DIR / "nslkdd" / "KDDTrain+.txt"
    test_path = RAW_DIR / "nslkdd" / "KDDTest+.txt"

    if not train_path.exists() or not test_path.exists():
        print("❌ NSL-KDD files not found. Skipping.")
        return None, None

    # Load
    df_train = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    df_test = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS)
    print(f"📦 Loaded: train={len(df_train)}, test={len(df_test)}")

    dfs = {}
    for name, df in [("train", df_train), ("test", df_test)]:
        # Map attack types to categories
        df["attack_category"] = df["attack_type"].map(
            lambda x: NSL_KDD_ATTACK_MAP.get(x, "Unknown")
        )
        df["label"] = (df["attack_category"] != "Normal").astype(int)

        # Encode protocol
        protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
        df["protocol_code"] = df["protocol_type"].map(protocol_map).fillna(3).astype(int)

        # Map service to approximate port
        df["dst_port"] = df["service"].map(
            lambda x: NSL_KDD_SERVICE_PORT_MAP.get(x, 0)
        )
        df["src_port"] = np.random.randint(1024, 65535, size=len(df))

        # Log-scale bytes
        df["log_src_bytes"] = np.log2(1 + df["src_bytes"].clip(lower=0))
        df["log_dst_bytes"] = np.log2(1 + df["dst_bytes"].clip(lower=0))

        # Normalize duration
        df["norm_duration"] = df["duration"].clip(0, 300) / 300.0

        # Encode flag (connection state) as severity indicator
        flag_severity = {
            "SF": 0, "S0": 3, "REJ": 4, "RSTR": 3, "RSTO": 3,
            "SH": 2, "S1": 2, "S2": 2, "S3": 2, "OTH": 1
        }
        df["flag_code"] = df["flag"].map(flag_severity).fillna(1).astype(int)

        # Map attack_category to event_type code for compatibility
        event_map = {
            "Normal": 0, "DoS": 1, "Probe": 2, "R2L": 3, "U2R": 4, "Unknown": 5
        }
        df["event_type_code"] = df["attack_category"].map(event_map).fillna(0).astype(int)

        # Create standardized output columns
        df_out = pd.DataFrame({
            "src_port": df["src_port"] / 65535.0,
            "dst_port": df["dst_port"] / 65535.0,
            "log_bytes_sent": df["log_src_bytes"],
            "log_bytes_recv": df["log_dst_bytes"],
            "norm_duration": df["norm_duration"],
            "protocol_code": df["protocol_code"],
            "event_type_code": df["event_type_code"],
            "log_level_code": df["flag_code"],
            "hour_of_day": np.random.uniform(0, 1, size=len(df)),  # simulated
            "is_weekend": np.random.choice([0, 1], size=len(df), p=[0.72, 0.28]),
            "message_risk_score": (
                df["hot"] * 5 +
                df["num_failed_logins"] * 10 +
                df["num_compromised"] * 8 +
                df["root_shell"] * 25 +
                df["su_attempted"] * 20 +
                df["num_root"] * 10
            ).clip(0, 50),
            # Metadata (not used as features, but useful for evaluation)
            "label": df["label"],
            "attack_category": df["attack_category"],
            "attack_type": df["attack_type"],
            "dataset": "NSL-KDD",
            # Extra useful features from NSL-KDD
            "count": df["count"],
            "srv_count": df["srv_count"],
            "serror_rate": df["serror_rate"],
            "same_srv_rate": df["same_srv_rate"],
            "dst_host_count": df["dst_host_count"],
            "dst_host_srv_count": df["dst_host_srv_count"],
            "dst_host_same_srv_rate": df["dst_host_same_srv_rate"],
            "dst_host_serror_rate": df["dst_host_serror_rate"],
        })

        dfs[name] = df_out
        print(f"   {name}: {len(df_out)} rows, attacks={df_out['label'].sum()} ({df_out['label'].mean()*100:.1f}%)")
        print(f"   Attack types: {dict(df['attack_category'].value_counts())}")

    return dfs["train"], dfs["test"]


# ═══════════════════════════════════════════════════════════════
# UNSW-NB15 Preprocessing
# ═══════════════════════════════════════════════════════════════

# UNSW-NB15 attack category mapping
UNSW_ATTACK_MAP = {
    "Normal": "Normal",
    "Fuzzers": "Probe",
    "Analysis": "Probe",
    "Backdoor": "U2R",
    "Backdoors": "U2R",
    "DoS": "DoS",
    "Exploits": "R2L",
    "Generic": "DoS",
    "Reconnaissance": "Probe",
    "Shellcode": "U2R",
    "Worms": "U2R",
}

# UNSW-NB15 service to port mapping
UNSW_SERVICE_PORT_MAP = {
    "http": 80, "ftp": 21, "ftp-data": 20, "smtp": 25,
    "ssh": 22, "dns": 53, "pop3": 110, "snmp": 161,
    "ssl": 443, "dhcp": 67, "irc": 6667, "radius": 1812,
}


def preprocess_unsw():
    """Preprocess UNSW-NB15 dataset into standardized format."""
    print("\n" + "=" * 60)
    print("  Preprocessing UNSW-NB15 Dataset")
    print("=" * 60)

    train_path = RAW_DIR / "unsw" / "UNSW_NB15_training-set.csv"
    test_path = RAW_DIR / "unsw" / "UNSW_NB15_testing-set.csv"

    if not train_path.exists() or not test_path.exists():
        print("❌ UNSW-NB15 files not found. Skipping.")
        return None, None

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    print(f"📦 Loaded: train={len(df_train)}, test={len(df_test)}")

    dfs = {}
    for name, df in [("train", df_train), ("test", df_test)]:
        # Clean attack_cat column
        df["attack_cat"] = df["attack_cat"].fillna("Normal").str.strip()
        df["attack_cat"] = df["attack_cat"].replace("", "Normal")
        df["attack_cat"] = df["attack_cat"].replace(" ", "Normal")

        # Map to unified categories
        df["attack_category"] = df["attack_cat"].map(
            lambda x: UNSW_ATTACK_MAP.get(x, "Unknown")
        )

        # Label
        df["label_clean"] = df["label"].astype(int)

        # Encode protocol
        protocol_map = {"tcp": 0, "udp": 1, "icmp": 2, "arp": 3}
        df["proto_clean"] = df["proto"].str.lower().str.strip()
        df["protocol_code"] = df["proto_clean"].map(protocol_map).fillna(3).astype(int)

        # Map service to port
        df["service_clean"] = df["service"].fillna("-").str.lower().str.strip()
        df["dst_port_approx"] = df["service_clean"].map(
            lambda x: UNSW_SERVICE_PORT_MAP.get(x, np.random.randint(1024, 65535))
        )

        # Event type code from attack category
        event_map = {"Normal": 0, "DoS": 1, "Probe": 2, "R2L": 3, "U2R": 4, "Unknown": 5}
        df["event_type_code"] = df["attack_category"].map(event_map).fillna(0).astype(int)

        # State to severity
        state_severity = {
            "FIN": 0, "CON": 0, "INT": 1, "ACC": 0,
            "REQ": 1, "RST": 3, "CLO": 0, "no": 2, "ECO": 1,
        }
        df["state_clean"] = df["state"].fillna("no").str.strip()
        df["state_code"] = df["state_clean"].map(state_severity).fillna(1).astype(int)

        # Log-scale bytes
        df["log_sbytes"] = np.log2(1 + df["sbytes"].clip(lower=0))
        df["log_dbytes"] = np.log2(1 + df["dbytes"].clip(lower=0))

        # Duration normalization
        df["norm_dur"] = df["dur"].clip(0, 300) / 300.0

        # Risk score from features
        df["risk_score"] = (
            df["ct_state_ttl"].clip(0, 10) * 2 +
            (df["sttl"] < 32).astype(int) * 10 +
            (df["is_ftp_login"] == 1).astype(int) * 15 +
            df["ct_flw_http_mthd"].clip(0, 5) * 3 +
            (df["is_sm_ips_ports"] == 1).astype(int) * 5
        ).clip(0, 50)

        # Create standardized output
        df_out = pd.DataFrame({
            "src_port": np.random.randint(1024, 65535, size=len(df)) / 65535.0,
            "dst_port": df["dst_port_approx"] / 65535.0,
            "log_bytes_sent": df["log_sbytes"],
            "log_bytes_recv": df["log_dbytes"],
            "norm_duration": df["norm_dur"],
            "protocol_code": df["protocol_code"],
            "event_type_code": df["event_type_code"],
            "log_level_code": df["state_code"],
            "hour_of_day": np.random.uniform(0, 1, size=len(df)),
            "is_weekend": np.random.choice([0, 1], size=len(df), p=[0.72, 0.28]),
            "message_risk_score": df["risk_score"],
            # Metadata
            "label": df["label_clean"],
            "attack_category": df["attack_category"],
            "attack_type": df["attack_cat"],
            "dataset": "UNSW-NB15",
            # Extra informative features from UNSW-NB15
            "count": df["spkts"] + df["dpkts"],
            "srv_count": df["ct_srv_src"],
            "serror_rate": df["sload"].clip(0, 1000000) / 1000000.0,
            "same_srv_rate": df["rate"].clip(0, 1000) / 1000.0,
            "dst_host_count": df["ct_dst_ltm"],
            "dst_host_srv_count": df["ct_srv_dst"],
            "dst_host_same_srv_rate": df["ct_dst_src_ltm"].clip(0, 100) / 100.0,
            "dst_host_serror_rate": df["dttl"].clip(0, 255) / 255.0,
        })

        dfs[name] = df_out
        print(f"   {name}: {len(df_out)} rows, attacks={df_out['label'].sum()} ({df_out['label'].mean()*100:.1f}%)")
        print(f"   Attack types: {dict(df['attack_cat'].value_counts().head(10))}")

    return dfs["train"], dfs["test"]


# ═══════════════════════════════════════════════════════════════
# Combine and Save
# ═══════════════════════════════════════════════════════════════

def combine_datasets(nsl_train, nsl_test, unsw_train, unsw_test):
    """Combine all datasets into unified train/test sets."""
    print("\n" + "=" * 60)
    print("  Combining Datasets")
    print("=" * 60)

    train_parts = [df for df in [nsl_train, unsw_train] if df is not None]
    test_parts = [df for df in [nsl_test, unsw_test] if df is not None]

    if not train_parts:
        print("❌ No training data available!")
        return None, None

    combined_train = pd.concat(train_parts, ignore_index=True)
    combined_test = pd.concat(test_parts, ignore_index=True)

    # Shuffle
    combined_train = combined_train.sample(frac=1, random_state=42).reset_index(drop=True)
    combined_test = combined_test.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n📊 Combined Training Set:")
    print(f"   Total samples: {len(combined_train)}")
    print(f"   Normal: {(combined_train['label'] == 0).sum()} ({(combined_train['label'] == 0).mean()*100:.1f}%)")
    print(f"   Attack: {(combined_train['label'] == 1).sum()} ({(combined_train['label'] == 1).mean()*100:.1f}%)")
    if "dataset" in combined_train.columns:
        print(f"   By dataset: {dict(combined_train['dataset'].value_counts())}")
    print(f"\n📊 Combined Test Set:")
    print(f"   Total samples: {len(combined_test)}")
    print(f"   Normal: {(combined_test['label'] == 0).sum()} ({(combined_test['label'] == 0).mean()*100:.1f}%)")
    print(f"   Attack: {(combined_test['label'] == 1).sum()} ({(combined_test['label'] == 1).mean()*100:.1f}%)")

    return combined_train, combined_test


def main():
    print("=" * 60)
    print("  CyberSentinel – Real Dataset Preprocessing Pipeline")
    print("=" * 60)
    t0 = time.time()

    # Preprocess each dataset
    nsl_train, nsl_test = preprocess_nslkdd()
    unsw_train, unsw_test = preprocess_unsw()

    # Combine
    combined_train, combined_test = combine_datasets(
        nsl_train, nsl_test, unsw_train, unsw_test
    )

    if combined_train is None:
        print("\n❌ No datasets were processed. Exiting.")
        sys.exit(1)

    # Save
    train_path = PROCESSED_DIR / "combined_train.csv"
    test_path = PROCESSED_DIR / "combined_test.csv"

    combined_train.to_csv(train_path, index=False)
    combined_test.to_csv(test_path, index=False)

    elapsed = time.time() - t0

    print(f"\n💾 Saved:")
    print(f"   Training: {train_path} ({len(combined_train)} rows)")
    print(f"   Testing:  {test_path} ({len(combined_test)} rows)")
    print(f"   Total preprocessing time: {elapsed:.1f}s")

    # Print feature summary
    feature_cols = [
        "src_port", "dst_port", "log_bytes_sent", "log_bytes_recv",
        "norm_duration", "protocol_code", "event_type_code",
        "log_level_code", "hour_of_day", "is_weekend", "message_risk_score"
    ]
    print(f"\n📈 Feature Statistics (Training):")
    print(combined_train[feature_cols].describe().to_string())

    # Print extra features
    extra_cols = ["count", "srv_count", "serror_rate", "same_srv_rate",
                  "dst_host_count", "dst_host_srv_count",
                  "dst_host_same_srv_rate", "dst_host_serror_rate"]
    print(f"\n📈 Extra Feature Statistics (Training):")
    print(combined_train[extra_cols].describe().to_string())

    print(f"\n✅ Preprocessing complete!")
    return combined_train, combined_test


if __name__ == "__main__":
    main()
