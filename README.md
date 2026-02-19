<p align="center">
  <a href="https://github.com/Dhruvvv-26/CyberSentinel-AI-CyberDefense">
    <img src="https://img.shields.io/github/stars/Dhruvvv-26/CyberSentinel-AI-CyberDefense?style=social" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/scikit--learn-1.8-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
  <img src="https://img.shields.io/badge/WebSocket-Real--Time-4353FF?style=for-the-badge&logo=websocket&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Tests-31%2F31%20Passing-22c55e?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Precision-85.77%25-blueviolet?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Datasets-NSL--KDD%20%2B%20UNSW--NB15-ff6f61?style=for-the-badge" />
</p>

<h1 align="center">🛡️ CyberSentinel</h1>
<h3 align="center">AI-Driven Autonomous Cyber Defense with Real-Time SOC Dashboard</h3>

<p align="center">
  A production-grade AI-powered <b>Security Operations Center (SOC)</b> platform trained on <b>real-world cybersecurity datasets</b> (NSL-KDD + UNSW-NB15) that detects zero-day attacks using unsupervised machine learning, suppresses false positives with context-aware reasoning, assigns dynamic threat severity scores, triggers autonomous response actions, and streams everything live to a SOC dashboard — achieving <b>85.77% precision</b> on 104,876 real test records.
</p>

---

## 📋 Table of Contents

- [Features](#-features)
- [Real-World Datasets & Model Performance](#-real-world-datasets--model-performance)
- [System Architecture](#-system-architecture)
- [AI Pipeline](#-ai-pipeline)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Testing](#-testing)
- [Docker Deployment](#-docker-deployment)
- [Configuration](#-configuration)
- [How It Works](#-how-it-works)
- [Future Roadmap](#-future-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Category | Feature | Description |
|----------|---------|-------------|
| 🧠 **AI Detection** | Isolation Forest | Unsupervised anomaly detection trained on real-world data (NSL-KDD + UNSW-NB15) — 85.77% precision, zero-day capable |
| 🔍 **Context Intelligence** | False Positive Suppression | Business-context rules (maintenance windows, peak hours, whitelisted IPs) reduce alert fatigue by up to 30% |
| 📊 **Threat Scoring** | 5-Factor Severity Engine | Multi-factor risk scoring (0–100) with ML confidence, feature analysis, keyword risk, IP correlation, and attack pattern recognition |
| ⚡ **Autonomous Response** | Severity-Based Actions | Automated IP blocking, node isolation, SOC escalation — all with cooldown and deduplication logic |
| 📡 **Real-Time Streaming** | WebSocket Architecture | Sub-second log & alert streaming to the SOC dashboard via WebSocket |
| 🖥️ **SOC Dashboard** | Premium Dark UI | Glassmorphism dark theme with live log stream, alert panel, response actions, and 8 real-time counters |
| 🎯 **Attack Simulation** | 5 Attack Types | Port scans, brute force, DDoS, data exfiltration, and privilege escalation simulation |
| 🐳 **Docker Ready** | One-Command Deploy | Containerized with Docker Compose, health checks, and persistent data volumes |
| 📊 **Real Data** | Benchmark Datasets | Trained on 301K+ records from NSL-KDD and UNSW-NB15, evaluated on 104K+ real test records |

---

## 📊 Real-World Datasets & Model Performance

CyberSentinel is trained on **two real-world cybersecurity benchmark datasets**:

| Dataset | Train Records | Test Records | Attack Types |
|---------|--------------|-------------|-------------|
| **NSL-KDD** | 125,973 | 22,544 | DoS, Probe, R2L, U2R |
| **UNSW-NB15** | 175,342 | 82,333 | Fuzzers, DoS, Exploits, Backdoor, Shellcode, Reconnaissance, Worms |
| **Combined** | **301,314** | **104,876** | All above |

**Training approach**: The Isolation Forest is trained on **normal traffic only** (123,343 samples). This is the correct unsupervised anomaly detection methodology — the model learns what "normal" looks like and flags deviations as anomalies, enabling zero-day detection without labeled attack data.

### Model Performance (on Real Test Data)

| Metric | Value |
|--------|-------|
| **Precision** | **85.77%** |
| **Recall** | 53.42% |
| **F1-Score** | 65.83% |
| **Accuracy** | 69.25% |
| **False Positive Rate** | 11.04% |
| Features | 19 (expanded network flow features) |
| Estimators | 200 |
| Contamination | 0.10 (noise tolerance) |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      SOC Dashboard (Browser)                     │
│              HTML/CSS/JS  •  WebSocket Client                   │
│     ┌──────────┐  ┌──────────────┐  ┌───────────────┐          │
│     │Live Logs │  │ Live Alerts  │  │Response Actions│          │
│     └──────────┘  └──────────────┘  └───────────────┘          │
└───────────────────────────┬─────────────────────────────────────┘
                            │ WebSocket (ws://host:8000/ws)
┌───────────────────────────▼─────────────────────────────────────┐
│                     FastAPI Backend Server                       │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │  REST API   │  │  WebSocket   │  │ Pipeline Orchestrator  │ │
│  │ POST /ingest│  │  Manager     │  │                        │ │
│  │ GET /alerts │  │  (Broadcast) │  │  Parse → ML → Context  │ │
│  │ GET /stats  │  │              │  │  → Score → Respond     │ │
│  └─────────────┘  └──────────────┘  │  → Broadcast           │ │
│                                     └────────────────────────┘ │
└───────────┬──────────────┬──────────────┬──────────────────────┘
            │              │              │
     ┌──────▼──────┐ ┌────▼─────┐ ┌──────▼──────┐
     │  ML Engine  │ │ Context  │ │  Response   │
     │  (Isolation │ │  Agent   │ │   Agent     │
     │   Forest)   │ │(Suppress)│ │ (Actions)   │
     └──────┬──────┘ └──────────┘ └─────────────┘
            │
     ┌──────▼──────┐
     │   Feature   │
     │  Extractor  │
     │(19 features)│
     └──────┬──────┘
            │
  ┌─────────▼─────────┐
  │  Log Ingestion &   │
  │   Normalization    │
  └─────────┬──────────┘
            │
  ┌─────────▼─────────┐
  │  Log Simulator     │
  │ (9 traffic types)  │
  └────────────────────┘
```

---

## 🧠 AI Pipeline

The processing pipeline runs for **every log entry** in real time:

```
1. LOG INGESTION        Parse JSON → Validate → Normalize timestamps → Enrich with derived features
        ↓
2. FEATURE EXTRACTION   19-dimensional vector: ports, bytes, duration, protocol, event type,
                        log level, message risk keywords, hour, weekend flag,
                        + 8 network flow features (count, srv_count, serror_rate, etc.)
        ↓
3. ANOMALY DETECTION    Isolation Forest (200 trees, trained on normal-only real data)
                        Returns: is_anomaly, anomaly_score, confidence
        ↓
4. CONTEXT EVALUATION   5 suppression rules: maintenance window, backup traffic,
                        whitelisted IPs, peak hours adjustment, internal traffic
        ↓
5. THREAT SCORING       5-factor scoring (0-100): ML base, feature modifiers,
                        keyword risk, IP correlation, attack pattern bonuses
                        Classification: LOW | MEDIUM | HIGH | CRITICAL
        ↓
6. AUTONOMOUS RESPONSE  Severity-based actions + deduplication:
                        LOW → Log | MEDIUM → Alert | HIGH → Block IP | CRITICAL → Isolate + Escalate
        ↓
7. REAL-TIME BROADCAST  WebSocket push → SOC Dashboard updates instantly
```

### Threat Scoring Formula

| Factor | Max Points | What It Measures |
|--------|-----------|------------------|
| ML Anomaly Base | 35 | Isolation Forest confidence score |
| Feature Modifiers | 25 | Suspicious ports, high traffic volume, rapid duration |
| Keyword Risk | 15 | Threat-related words in log message (e.g., "exploit", "unauthorized") |
| Event Correlation | 15 | Repeated anomalies from the same source IP (time-decay window) |
| Attack Pattern Bonus | 10 | Known attack type recognition (DDoS, exfiltration, etc.) |

### Severity Classification

| Level | Score | Color | Automated Actions |
|-------|-------|-------|-------------------|
| 🟢 LOW | 0–25 | Green | Log event only |
| 🟡 MEDIUM | 26–50 | Amber | Generate alert + increase monitoring |
| 🟠 HIGH | 51–75 | Orange | Alert + **block IP** + notify SOC |
| 🔴 CRITICAL | 76–100 | Red | Alert + **block IP** + **isolate node** + **escalate to SOC Lead** |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Language** | Python 3.12 | Core language |
| **ML Framework** | scikit-learn 1.8 | Isolation Forest anomaly detection |
| **Feature Processing** | NumPy, Pandas | Numerical computation & data handling |
| **Backend Framework** | FastAPI 0.115 | Async REST API + WebSocket server |
| **Real-Time** | WebSockets | Live bi-directional streaming |
| **Data Models** | Pydantic 2.x | Request/response validation |
| **Frontend** | HTML5, CSS3, JavaScript | SOC Dashboard UI |
| **Styling** | Custom CSS | Glassmorphism dark theme with animations |
| **Fonts** | Inter, JetBrains Mono | UI typography |
| **Deployment** | Docker, Docker Compose | Containerization |
| **Testing** | pytest | 31 automated tests |

---

## 📁 Project Structure

```
cybersentinel/
│
├── 📄 config.py                  # Central configuration (ML params, thresholds, rules)
├── 📄 requirements.txt           # Python dependencies
├── 📄 .env                       # Environment variables
├── 📄 README.md                  # This file
│
├── 🧠 ml/                        # Machine Learning Engine
│   ├── features.py               # 19-feature extraction + keyword risk scoring (auto-adapts)
│   ├── train.py                  # Isolation Forest training pipeline
│   └── predict.py                # Real-time anomaly detection (AnomalyDetector class)
│
├── 🤖 agents/                    # Intelligence Agents
│   ├── context_agent.py          # False positive suppression (5 business rules)
│   ├── threat_scorer.py          # 5-factor severity scoring engine
│   └── response_agent.py         # Autonomous response + deduplication + cooldown
│
├── 🔌 backend/                   # FastAPI Backend
│   ├── main.py                   # App entry point + Pipeline orchestrator + demo mode
│   ├── models/
│   │   └── schemas.py            # Pydantic models (LogEntry, Alert, Stats, etc.)
│   ├── routes/
│   │   ├── ingest.py             # POST /api/ingest (full pipeline)
│   │   └── alerts.py             # GET /api/alerts, GET /api/stats
│   └── ws/
│       └── manager.py            # WebSocket connection manager + broadcast
│
├── 📥 ingestion/                 # Data Ingestion Layer
│   └── log_parser.py             # Validation, timestamp normalization, enrichment
│
├── 🎯 simulator/                 # Traffic Simulator
│   └── log_generator.py          # 4 normal + 5 attack traffic generators
│
├── 🖥️ dashboard/                 # SOC Dashboard Frontend
│   ├── index.html                # Layout: stats bar, log stream, alerts, actions
│   ├── style.css                 # Premium dark SOC theme with glassmorphism
│   └── app.js                    # WebSocket client + live rendering + reconnection
│
├── 🐳 docker/                    # Deployment
│   ├── Dockerfile                # Multi-stage build with model training
│   └── docker-compose.yml        # Service definition with health checks
│
├── 🧪 tests/                     # Test Suite (31 tests)
│   ├── test_ml.py                # ML pipeline tests (12 tests)
│   ├── test_agents.py            # Intelligence agent tests (13 tests)
│   └── test_backend.py           # API & WebSocket tests (6 tests)
│
├── 📚 docs/                      # Documentation
│   ├── README.md                 # Detailed project documentation
│   ├── architecture.md           # Mermaid diagrams + scoring tables
│   ├── IEEE_paper_outline.md     # Research paper outline (IEEE format)
│   └── CyberSentinel_IEEE_Paper.tex  # Full IEEE LaTeX paper
│
├── 📓 notebooks/                 # Jupyter Notebooks
│   └── EDA_and_model_eval.ipynb  # Exploratory data analysis
│
└── 📁 data/                      # Datasets & Model Artifacts
    ├── preprocess.py             # Dataset download & preprocessing pipeline
    ├── raw/                      # Raw downloaded datasets
    │   ├── nslkdd/               #   NSL-KDD (125K train + 22K test)
    │   └── unsw/                 #   UNSW-NB15 (175K train + 82K test)
    ├── processed/                # Preprocessed unified CSVs
    │   ├── combined_train.csv    #   301,314 records (19 features + label)
    │   └── combined_test.csv     #   104,876 records (19 features + label)
    ├── models/                   # Trained model artifacts
    │   ├── isolation_forest.joblib
    │   ├── scaler.joblib
    │   └── model_meta.json       #   Feature columns, metrics, config
    └── logs/                     # Log storage
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+ (recommended: 3.12)
- pip package manager
- (Optional) Docker & Docker Compose

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Dhruvvv-26/CyberSentinel-AI-CyberDefense.git
cd CyberSentinel-AI-CyberDefense

# 2. Create and activate virtual environment
python3 -m venv cyberSentinel_Venv
source cyberSentinel_Venv/bin/activate   # Linux/Mac
# cyberSentinel_Venv\Scripts\activate    # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download & preprocess real datasets
python data/preprocess.py

# 5. Train the ML model on real data
python -m ml.train

# 6. Start the server
python -m backend.main
```

### Expected Training Output

```
============================================================
  CyberSentinel – Model Training Pipeline
============================================================
� Loading real datasets...
   NSL-KDD train: 125,973 records
   UNSW-NB15 train: 175,342 records
   Combined: 301,314 total → 123,343 normal-only for training

⚙️  Feature matrix: (123343, 19)
🧠 Training Isolation Forest (n_estimators=200, contamination=0.10)...
   Training on normal-only data → contamination=0.10 (noise tolerance)

📈 Training Metrics:
   n_samples: 123,343
   n_features: 19
   contamination: 0.10
   data_source: NSL-KDD + UNSW-NB15 (normal-only)
   train_time_seconds: 2.08

📊 Test Set Evaluation (104,876 records):
   Precision:  85.77%
   Recall:     53.42%
   F1-Score:   65.83%
   Accuracy:   69.25%
   FPR:        11.04%

💾 Model saved to: data/models/isolation_forest.joblib
✅ Training complete!
```

---

## 💻 Usage

### Start the Server

```bash
python -m backend.main
```

You'll see:
```
============================================================
  🛡️  CyberSentinel – AI-Driven Cyber Defense System
============================================================
  Model loaded: ✅
  Demo mode:    ON
  Dashboard:    http://0.0.0.0:8000
  API docs:     http://0.0.0.0:8000/docs
============================================================
🔄 Demo mode active – generating logs every 1.5s
```

### Open the SOC Dashboard

Navigate to **http://localhost:8000** in your browser.

The dashboard will immediately begin streaming:
- **Live log entries** with anomaly highlighting
- **Real-time alerts** with severity badges (LOW/MEDIUM/HIGH/CRITICAL)
- **Response actions** (IP blocks, node isolation, escalations)
- **8 stat counters** updating in real time

### Ingest Custom Logs

Send logs via the REST API:

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-02-19T12:00:00+00:00",
    "src_ip": "203.0.113.50",
    "dst_ip": "10.0.1.100",
    "src_port": 54321,
    "dst_port": 4444,
    "protocol": "TCP",
    "bytes_sent": 500000,
    "bytes_recv": 200,
    "duration": 0.003,
    "event_type": "data_exfiltration",
    "log_level": "CRITICAL",
    "message": "Large outbound data transfer to suspicious external IP"
  }'
```

---

## 📡 API Reference

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `GET` | `/` | SOC Dashboard | HTML page |
| `GET` | `/docs` | Interactive API docs (Swagger) | HTML page |
| `POST` | `/api/ingest` | Ingest a log through the full AI pipeline | `IngestResponse` |
| `GET` | `/api/alerts?limit=50` | Get recent alerts (newest first) | `{alerts: [], total: int}` |
| `GET` | `/api/stats` | Get dashboard statistics | `DashboardStats` |
| `WS` | `/ws` | Real-time WebSocket stream | JSON messages |

### WebSocket Message Types

```json
// Log message
{"type": "log", "data": {"src_ip": "...", "is_anomaly": true, ...}}

// Alert message
{"type": "alert", "data": {"severity": "CRITICAL", "threat_score": 87, ...}}

// Stats update
{"type": "stats", "data": {"total_logs": 150, "total_alerts": 12, ...}}
```

---

## 🧪 Testing

```bash
# Run full test suite
python -m pytest tests/ -v

# Expected output: 31 passed in ~5s
```

**Test Coverage:**

| File | Tests | What's Covered |
|------|-------|----------------|
| `test_ml.py` | 12 | Log generation, parsing, validation, feature extraction, model prediction |
| `test_agents.py` | 13 | Context suppression rules, threat scoring factors, response actions, cooldown |
| `test_backend.py` | 6 | REST endpoints (GET/POST), WebSocket connection, error handling |

---

## 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
cd docker
docker-compose up --build

# The model trains automatically during build
# Dashboard available at http://localhost:8000
```

```bash
# Or build manually
docker build -t cybersentinel -f docker/Dockerfile .
docker run -p 8000:8000 cybersentinel
```

---

## ⚙️ Configuration

All settings are centralized in `config.py` and `.env`:

### Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `CONTAMINATION` | 0.10 | Isolation Forest noise tolerance (normal-only training) |
| `N_ESTIMATORS` | 200 | Number of trees in the forest |
| `USE_REAL_DATA` | true | Train on NSL-KDD + UNSW-NB15 real datasets |
| `DEMO_MODE` | true | Auto-generate synthetic logs for dashboard demo |
| `DEMO_LOG_INTERVAL` | 1.5s | Seconds between demo log generation |
| `MAINTENANCE_HOURS` | 2–5 AM | Suppress low-confidence alerts |
| `PEAK_HOURS` | 9 AM–5 PM | Reduce scores by 30% during peak |
| `COOLDOWN_SECONDS` | 30–300s | Per-severity alert deduplication window |

---

## 🔧 How It Works

### 1. Data & Training — 🟢 Real Data

The ML model is trained on **real-world network traffic** from two benchmark cybersecurity datasets:

| What | Source | Status |
|------|--------|--------|
| **Training data** | NSL-KDD + UNSW-NB15 (123K normal samples) | ✅ Real network captures |
| **Test evaluation** | 104,876 records from both datasets | ✅ Real network captures |
| **Model artifacts** | `isolation_forest.joblib`, `scaler.joblib` | ✅ Trained on real data |

The Isolation Forest learns the distribution of **real legitimate network traffic** and at inference time, flags any deviation as an anomaly — enabling zero-day detection without ever seeing attack examples during training.

### 2. Live Dashboard Traffic — 🟡 Simulated (Demo Mode)

When you start the server, **Demo Mode** (`DEMO_MODE=true`) generates synthetic logs via `simulator/log_generator.py` to feed the dashboard continuously:
- **9 traffic types**: 4 normal (HTTP, auth, DNS, file access) + 5 attacks (port scan, brute force, DDoS, exfiltration, privilege escalation)
- Logs are generated every **1.5 seconds** for live visualization
- These simulated logs go through the **same real ML model** trained on real data

> 💡 **The ML model is real. The demo logs that feed the dashboard are simulated.** The model's detection accuracy (85.77% precision) comes from evaluation on real test data — not demo logs.

### 3. Production Mode — 🔵 Ready for Real Traffic

The REST API (`POST /api/ingest`) is fully production-ready to accept **real logs** from any external source:

```bash
# Send real logs from your SIEM, syslog server, or network tap
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "...", "src_ip": "...", "dst_ip": "...", ...}'
```

To integrate with real infrastructure, connect CyberSentinel to:
- **SIEM tools** (Splunk, ELK Stack, QRadar) → forward logs to `/api/ingest`
- **Syslog servers** → convert syslog to JSON and POST to the API
- **Network taps / pcap** → parse packet captures into log format
- Set `DEMO_MODE=false` in `.env` to disable synthetic traffic

### 4. Isolation Forest (Why Normal-Only Training?)
- **Real-world data** — trained on 123K real normal samples from NSL-KDD + UNSW-NB15
- **No attack labels needed** — learns what "normal" looks like, flags deviations
- **Zero-day capable** — detects novel attacks by finding outliers, not matching signatures
- **85.77% precision** — most alerts generated are actionable, reducing analyst fatigue
- **Fast inference** — sub-millisecond prediction per log entry

### 5. Context-Aware Intelligence
Reduces alert fatigue with 5 business rules:
- 🕐 **Maintenance windows** — suppress low-confidence alerts during off-hours
- 💾 **Backup traffic** — recognize scheduled backup transfers
- ✅ **Whitelisted IPs** — known internal services
- 📈 **Peak hours** — adjust thresholds during business hours
- 🏠 **Internal traffic** — leniency for internal-only communication

### 6. Autonomous Response
Actions are severity-proportional with anti-flooding:
- Per-IP cooldown timers prevent alert storms
- Response actions are **logged and broadcasted** (actual network enforcement requires SIEM/firewall integration)
- Full response audit trail for compliance

---

## 🗺️ Future Roadmap

- [ ] Deep learning models (LSTM, Autoencoder) for sequence-based detection (improve recall from 53% → 80%+)
- [ ] Additional dataset evaluation (CICIDS2017, CIC-DDoS2019, CTU-13)
- [ ] Integration with real SIEM tools (Splunk, ELK Stack, QRadar)
- [ ] Multi-agent cooperative defense across distributed nodes
- [ ] Federated learning for privacy-preserving threat intelligence sharing
- [ ] Real network integration (pcap ingestion, syslog)
- [ ] SHAP explainability for analyst trust in ML detections
- [ ] User authentication and role-based access for the SOC dashboard
- [ ] Alert acknowledgment and incident case management
- [ ] Threat intelligence feed integration (MITRE ATT&CK mapping)
- [ ] Adaptive rule learning from analyst feedback

---

## 🤝 Contributing

1. Fork the repository:
   👉 [https://github.com/Dhruvvv-26/CyberSentinel-AI-CyberDefense](https://github.com/Dhruvvv-26/CyberSentinel-AI-CyberDefense)
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed to **Dhruv Gupta**
GitHub: [https://github.com/Dhruvvv-26](https://github.com/Dhruvvv-26)

---

<p align="center">
  Built with ❤️ for cybersecurity research and education
  <br>
  <b>CyberSentinel</b> – Defending networks with AI, autonomously.
</p>
