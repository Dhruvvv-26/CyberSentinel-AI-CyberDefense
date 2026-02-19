"""
CyberSentinel – Generate evaluation graphs for the IEEE research paper.
Produces: confusion matrix, anomaly score distribution, severity breakdown,
detection rates per attack type, latency analysis, and ROC-like curve.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
import time

from simulator.log_generator import generate_batch
from ingestion.log_parser import parse_batch
from ml.features import extract_features_batch
from ml.predict import AnomalyDetector
from agents.context_agent import ContextAgent
from agents.threat_scorer import ThreatScorer
from agents.response_agent import ResponseAgent

# Config
sns.set_theme(style="darkgrid")
plt.rcParams.update({
    'figure.facecolor': 'white',
    'axes.facecolor': '#f8f9fa',
    'font.size': 11,
    'font.family': 'serif',
})
OUT_DIR = "docs/figures"
os.makedirs(OUT_DIR, exist_ok=True)

# ─────────────── Generate Test Data ───────────────
print("📊 Generating 2000 test logs...")
ATTACK_TYPES = {"port_scan", "brute_force", "ddos", "data_exfiltration", "privilege_escalation"}
raw_logs = generate_batch(2000, attack_ratio=0.20)
parsed_logs = parse_batch(raw_logs)

detector = AnomalyDetector()
context_agent = ContextAgent()
threat_scorer = ThreatScorer()
response_agent = ResponseAgent()

# Run full pipeline
results = []
latencies = []
for log in parsed_logs:
    t0 = time.perf_counter()
    anomaly_result = detector.predict(log)
    context_result = context_agent.evaluate(log, anomaly_result)
    score_result = threat_scorer.score(log, anomaly_result, context_result)
    alert = response_agent.respond(log, score_result, anomaly_result)
    latency = (time.perf_counter() - t0) * 1000  # ms
    latencies.append(latency)

    is_actual_attack = log.get("event_type", "") in ATTACK_TYPES
    results.append({
        "is_actual_attack": is_actual_attack,
        "is_predicted_anomaly": anomaly_result.get("is_anomaly", False),
        "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
        "confidence": anomaly_result.get("confidence", 0.0),
        "severity": score_result.get("severity", "NORMAL"),
        "threat_score": score_result.get("threat_score", 0),
        "event_type": log.get("event_type", ""),
        "suppressed": context_result.get("suppress", False),
    })

print(f"✅ Processed {len(results)} logs, mean latency: {np.mean(latencies):.2f}ms")

# ─────────────── Fig 1: Confusion Matrix ───────────────
y_true = [1 if r["is_actual_attack"] else 0 for r in results]
y_pred = [1 if r["is_predicted_anomaly"] else 0 for r in results]

TP = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
FP = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
FN = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
TN = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

cm = np.array([[TN, FP], [FN, TP]])
fig, ax = plt.subplots(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Anomaly'],
            yticklabels=['Normal', 'Attack'], ax=ax, linewidths=1, linecolor='white',
            annot_kws={"size": 16, "weight": "bold"})
ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
ax.set_ylabel('Actual Label', fontsize=12, fontweight='bold')
ax.set_title('Confusion Matrix – Isolation Forest', fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/confusion_matrix.png", dpi=200, bbox_inches='tight')
plt.close()
print(f"  TP={TP}, FP={FP}, FN={FN}, TN={TN}")
precision = TP / max(TP + FP, 1)
recall = TP / max(TP + FN, 1)
f1 = 2 * precision * recall / max(precision + recall, 0.001)
accuracy = (TP + TN) / max(len(y_true), 1)
print(f"  Accuracy={accuracy:.4f}, Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}")

# ─────────────── Fig 2: Anomaly Score Distribution ───────────────
normal_scores = [r["anomaly_score"] for r in results if not r["is_actual_attack"]]
attack_scores = [r["anomaly_score"] for r in results if r["is_actual_attack"]]

fig, ax = plt.subplots(figsize=(7, 4))
ax.hist(normal_scores, bins=50, alpha=0.7, label='Normal Traffic', color='#3b82f6', edgecolor='white')
ax.hist(attack_scores, bins=50, alpha=0.7, label='Attack Traffic', color='#ef4444', edgecolor='white')
ax.axvline(x=0, color='#f59e0b', linestyle='--', linewidth=2, label='Decision Boundary')
ax.set_xlabel('Anomaly Score (Decision Function)', fontsize=12, fontweight='bold')
ax.set_ylabel('Frequency', fontsize=12, fontweight='bold')
ax.set_title('Anomaly Score Distribution by Traffic Type', fontsize=13, fontweight='bold')
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/score_distribution.png", dpi=200, bbox_inches='tight')
plt.close()

# ─────────────── Fig 3: Detection Rate per Attack Type ───────────────
attack_types_list = ["port_scan", "brute_force", "ddos", "data_exfiltration", "privilege_escalation"]
detection_rates = []
for at in attack_types_list:
    total = sum(1 for r in results if r["event_type"] == at)
    detected = sum(1 for r in results if r["event_type"] == at and r["is_predicted_anomaly"])
    rate = detected / max(total, 1) * 100
    detection_rates.append(rate)
    print(f"  {at}: {detected}/{total} = {rate:.1f}%")

fig, ax = plt.subplots(figsize=(7, 4))
colors = ['#f97316', '#ef4444', '#dc2626', '#b91c1c', '#991b1b']
bars = ax.barh([at.replace("_", " ").title() for at in attack_types_list],
               detection_rates, color=colors, edgecolor='white', height=0.6)
ax.set_xlabel('Detection Rate (%)', fontsize=12, fontweight='bold')
ax.set_title('Detection Rate by Attack Type', fontsize=13, fontweight='bold')
ax.set_xlim(0, 105)
for bar, rate in zip(bars, detection_rates):
    ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
            f'{rate:.1f}%', va='center', fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/detection_rates.png", dpi=200, bbox_inches='tight')
plt.close()

# ─────────────── Fig 4: Severity Distribution ───────────────
severity_order = ["NORMAL", "SUPPRESSED", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
severity_counts = {s: 0 for s in severity_order}
for r in results:
    s = r["severity"]
    if s in severity_counts:
        severity_counts[s] += 1

fig, ax = plt.subplots(figsize=(7, 4))
scolors = ['#64748b', '#94a3b8', '#22c55e', '#f59e0b', '#f97316', '#ef4444']
ax.bar(severity_order, [severity_counts[s] for s in severity_order],
       color=scolors, edgecolor='white', width=0.6)
ax.set_xlabel('Severity Level', fontsize=12, fontweight='bold')
ax.set_ylabel('Count', fontsize=12, fontweight='bold')
ax.set_title('Threat Severity Distribution', fontsize=13, fontweight='bold')
for i, (s, c) in enumerate(severity_counts.items()):
    ax.text(i, c + 5, str(c), ha='center', fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/severity_distribution.png", dpi=200, bbox_inches='tight')
plt.close()

# ─────────────── Fig 5: Latency Distribution ───────────────
fig, ax = plt.subplots(figsize=(7, 4))
ax.hist(latencies, bins=60, color='#8b5cf6', edgecolor='white', alpha=0.85)
ax.axvline(x=np.mean(latencies), color='#ef4444', linestyle='--', linewidth=2,
           label=f'Mean: {np.mean(latencies):.2f}ms')
ax.axvline(x=np.percentile(latencies, 95), color='#f59e0b', linestyle='--', linewidth=2,
           label=f'P95: {np.percentile(latencies, 95):.2f}ms')
ax.set_xlabel('Processing Latency (ms)', fontsize=12, fontweight='bold')
ax.set_ylabel('Frequency', fontsize=12, fontweight='bold')
ax.set_title('End-to-End Pipeline Latency Distribution', fontsize=13, fontweight='bold')
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/latency_distribution.png", dpi=200, bbox_inches='tight')
plt.close()

# ─────────────── Fig 6: False Positive Reduction ───────────────
fp_before = FP
fp_after = sum(1 for r in results if not r["is_actual_attack"] and r["is_predicted_anomaly"] and not r["suppressed"])
suppressed_fps = fp_before - fp_after

fig, ax = plt.subplots(figsize=(5, 4))
categories = ['Before\nContext Agent', 'After\nContext Agent']
values = [fp_before, fp_after]
bars = ax.bar(categories, values, color=['#ef4444', '#22c55e'], edgecolor='white', width=0.5)
ax.set_ylabel('False Positives', fontsize=12, fontweight='bold')
ax.set_title('False Positive Reduction via Context Agent', fontsize=13, fontweight='bold')
for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 3,
            str(val), ha='center', fontsize=14, fontweight='bold')
reduction = (fp_before - fp_after) / max(fp_before, 1) * 100
ax.text(0.5, max(values) * 0.5, f'↓ {reduction:.1f}% reduction',
        ha='center', fontsize=13, fontweight='bold', color='#16a34a',
        transform=ax.transData)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fp_reduction.png", dpi=200, bbox_inches='tight')
plt.close()

# ─────────────── Fig 7: Threat Score vs. Confidence Scatter ───────────────
anomaly_results = [r for r in results if r["is_predicted_anomaly"]]
fig, ax = plt.subplots(figsize=(7, 5))
attacks = [r for r in anomaly_results if r["is_actual_attack"]]
normals = [r for r in anomaly_results if not r["is_actual_attack"]]
ax.scatter([r["confidence"] for r in normals], [r["threat_score"] for r in normals],
           alpha=0.5, c='#3b82f6', s=30, label='False Positive', edgecolors='white', linewidth=0.3)
ax.scatter([r["confidence"] for r in attacks], [r["threat_score"] for r in attacks],
           alpha=0.5, c='#ef4444', s=30, label='True Attack', edgecolors='white', linewidth=0.3)
ax.set_xlabel('ML Confidence', fontsize=12, fontweight='bold')
ax.set_ylabel('Threat Score (0–100)', fontsize=12, fontweight='bold')
ax.set_title('Threat Score vs. ML Confidence', fontsize=13, fontweight='bold')
ax.axhline(y=25, color='#22c55e', linestyle=':', alpha=0.7, label='LOW threshold')
ax.axhline(y=50, color='#f59e0b', linestyle=':', alpha=0.7, label='MEDIUM threshold')
ax.axhline(y=75, color='#f97316', linestyle=':', alpha=0.7, label='HIGH threshold')
ax.legend(fontsize=9, loc='upper left')
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/score_vs_confidence.png", dpi=200, bbox_inches='tight')
plt.close()

print(f"\n✅ All 7 figures saved to {OUT_DIR}/")
print(f"   Metrics: Acc={accuracy:.4f}, Prec={precision:.4f}, Rec={recall:.4f}, F1={f1:.4f}")
print(f"   Mean latency: {np.mean(latencies):.2f}ms, P95: {np.percentile(latencies, 95):.2f}ms")
print(f"   FP reduction: {reduction:.1f}%")
