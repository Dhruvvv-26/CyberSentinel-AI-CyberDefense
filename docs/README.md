# CyberSentinel – AI-Driven Autonomous Cyber Defense

> **Real-time AI-powered Security Operations Center (SOC) platform** with anomaly detection, context-aware intelligence, autonomous response, and a live streaming SOC dashboard — trained on real-world cybersecurity datasets (NSL-KDD + UNSW-NB15).

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SOC Dashboard                        │
│           (HTML/CSS/JS + WebSocket Client)              │
└──────────────────┬──────────────────────────────────────┘
                   │ WebSocket
┌──────────────────▼──────────────────────────────────────┐
│                FastAPI Backend                          │
│  ┌──────────┐ ┌──────────┐ ┌─────────────────────────┐ │
│  │ REST API │ │WebSocket │ │ Pipeline Orchestrator    │ │
│  │ /ingest  │ │  /ws     │ │  Parse → ML → Context   │ │
│  │ /alerts  │ │          │ │  → Score → Respond       │ │
│  │ /stats   │ │          │ │  → Broadcast             │ │
│  └──────────┘ └──────────┘ └─────────────────────────┘ │
└──────────────────┬──────────────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│ ML     │  │ Context  │  │ Response │
│ Engine │  │ Agent    │  │ Agent    │
│(IsoFor)│  │(Suppress)│  │(Actions) │
└────────┘  └──────────┘  └──────────┘
```

## 📊 Real-World Datasets

CyberSentinel is trained on **two real-world cybersecurity benchmark datasets**:

| Dataset | Train Records | Test Records | Attack Types |
|---------|--------------|-------------|-------------|
| **NSL-KDD** | 125,973 | 22,544 | DoS, Probe, R2L, U2R |
| **UNSW-NB15** | 175,342 | 82,333 | Fuzzers, DoS, Exploits, Backdoor, Shellcode, Reconnaissance, Worms |
| **Combined** | **301,314** | **104,876** | All above |

**Training approach**: The Isolation Forest is trained on **normal traffic only** (123,343 samples). This is the correct unsupervised anomaly detection methodology — the model learns the "normal" distribution and flags deviations as anomalies, enabling zero-day detection.

## 🧠 Model Performance (on Real Test Data)

| Metric | Value |
|--------|-------|
| **Precision** | 85.77% |
| **Recall** | 53.42% |
| **F1-Score** | 65.83% |
| **Accuracy** | 69.25% |
| **False Positive Rate** | 11.04% |
| Features | 19 (expanded network flow features) |
| Estimators | 200 |
| Contamination | 0.10 |

## 🚀 Quick Start

### 1. Setup Virtual Environment
```bash
cd cybersentinel
python3 -m venv cyberSentinel_Venv
source cyberSentinel_Venv/bin/activate
pip install -r requirements.txt
```

### 2. Download & Preprocess Real Datasets
```bash
python data/preprocess.py
```
This downloads and preprocesses NSL-KDD + UNSW-NB15 into unified training/test CSVs.

### 3. Train the ML Model
```bash
python -m ml.train
```
Trains on **normal-only** traffic with automatic evaluation on the test set.

### 4. Launch the Server
```bash
python -m backend.main
```

### 5. Open the Dashboard
Navigate to **http://localhost:8000** in your browser.

## 📁 Project Structure

```
cybersentinel/
├── agents/                  # Intelligence Agents
│   ├── context_agent.py     # False positive suppression (5 rules)
│   ├── threat_scorer.py     # 5-factor severity scoring engine
│   └── response_agent.py    # Autonomous response with cooldown
├── backend/                 # FastAPI Backend
│   ├── main.py              # App + pipeline orchestrator
│   ├── models/schemas.py    # Pydantic models
│   ├── routes/ingest.py     # Log ingestion endpoint
│   ├── routes/alerts.py     # Alerts & stats endpoints
│   └── ws/manager.py        # WebSocket manager
├── dashboard/               # SOC Dashboard Frontend
│   ├── index.html
│   ├── style.css
│   └── app.js
├── data/                    # Datasets & Models
│   ├── preprocess.py        # Real dataset preprocessing pipeline
│   ├── raw/                 # Raw downloaded datasets
│   │   ├── nslkdd/          #   NSL-KDD (125K train + 22K test)
│   │   └── unsw/            #   UNSW-NB15 (175K train + 82K test)
│   ├── processed/           # Preprocessed combined CSVs
│   │   ├── combined_train.csv  # 301,314 records
│   │   └── combined_test.csv   # 104,876 records
│   └── models/              # Trained model artifacts
│       ├── isolation_forest.joblib
│       ├── scaler.joblib
│       └── model_meta.json
├── ml/                      # Machine Learning Engine
│   ├── features.py          # 19-feature engineering (auto-adapts)
│   ├── train.py             # Training (real data + evaluation)
│   └── predict.py           # Real-time anomaly detection
├── ingestion/               # Data Ingestion
│   └── log_parser.py        # Log parsing & normalization
├── simulator/               # Log Simulator (for demo mode)
│   └── log_generator.py     # Synthetic traffic generator
├── docker/                  # Deployment
│   ├── Dockerfile
│   └── docker-compose.yml
├── tests/                   # Test Suite (31 tests)
├── docs/                    # Documentation + IEEE Paper
├── config.py                # Central configuration
├── requirements.txt         # Dependencies
└── .env                     # Environment variables
```

## 🔬 AI Pipeline (19-Feature)

1. **Log Ingestion** → Parse and normalize JSON logs
2. **Feature Extraction** → 19-dimension vector: ports, bytes (log-scaled), duration, protocol, event type, severity, message risk, time features + 8 network flow features (count, srv_count, serror_rate, same_srv_rate, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_serror_rate)
3. **Anomaly Detection** → Isolation Forest trained on real normal traffic (200 estimators)
4. **Context Analysis** → Suppress false positives via 5 business rules
5. **Threat Scoring** → 5-factor severity engine (0–100 score)
6. **Autonomous Response** → Severity-based automated actions with cooldown

## 🔧 Configuration

All settings in `config.py` and `.env`. Key parameters:
- `CONTAMINATION`: Anomaly detection sensitivity (default: 0.10)
- `USE_REAL_DATA`: Use real datasets for training (default: true)
- `DEMO_MODE`: Auto-generate synthetic logs for dashboard demo (default: true)
- `MAINTENANCE_HOURS`: Hours to suppress low-confidence alerts
- `COOLDOWN_SECONDS`: Per-severity alert deduplication windows

## 🐳 Docker Deployment

```bash
cd docker
docker-compose up --build
```

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | SOC Dashboard |
| POST | `/api/ingest` | Ingest a log entry |
| GET | `/api/alerts` | Get recent alerts |
| GET | `/api/stats` | Dashboard statistics |
| WS | `/ws` | Real-time WebSocket |

## 📄 License

MIT License
