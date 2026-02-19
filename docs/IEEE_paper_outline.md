# CyberSentinel: AI-Driven Autonomous Cyber Defense with Real-Time SOC Dashboard

## IEEE Research Paper Outline

---

### I. Abstract
- Problem: Rising zero-day attacks, alert fatigue, manual SOC limitations
- Solution: CyberSentinel – unsupervised ML (Isolation Forest) trained on real-world datasets (NSL-KDD + UNSW-NB15), context-aware intelligence, autonomous response
- Key Results: 85.77% precision, 53.42% recall, 65.83% F1, 11.04% FPR on 104,876 real test records
- Dashboard: Live SOC streaming via WebSocket

### II. Introduction
- Cybersecurity threat landscape evolution
- Limitations of signature-based detection (cannot detect zero-day)
- Alert fatigue in traditional SOC environments (70–99% false positive rates)
- Motivation for AI-driven autonomous defense
- Research contributions:
  1. Unsupervised anomaly detection trained on real normal traffic for zero-day detection
  2. Context-aware intelligence for false positive reduction
  3. Multi-factor threat scoring engine (5 factors, 0–100 scale)
  4. Autonomous response with severity-based actions and cooldown
  5. Real-time SOC dashboard with WebSocket streaming

### III. Related Work
- Intrusion Detection Systems (IDS) – Snort, Suricata, signature-based limitations
- ML-based anomaly detection – Isolation Forest, Extended IF, Autoencoders, LSTM
- Deep learning approaches – CNN-IDS, CNN-LSTM, attention mechanisms
- Benchmark datasets – NSL-KDD, UNSW-NB15, CICIDS2017
- False positive reduction – context-aware filtering, SOAR platforms
- SOC Automation – multi-agent frameworks, automated incident response
- Research gap: no integrated end-to-end system combining all capabilities

### IV. System Architecture
- A. Overall architecture (7-stage pipeline)
- B. Log ingestion and normalization pipeline
- C. Feature engineering (19-dimension vector from real datasets)
  - 11 core features + 8 network flow features
- D. Isolation Forest anomaly detection (200 estimators, trained on normal-only)
- E. Context-aware intelligence agent (5 suppression rules)
- F. Multi-factor threat scoring engine (5 weighted factors)
- G. Autonomous response agent (cooldown + deduplication)
- H. Real-time WebSocket streaming architecture

### V. Methodology
- A. Real Dataset Acquisition and Preprocessing
  - NSL-KDD: 125,973 train + 22,544 test (41 features → 19 standardized)
  - UNSW-NB15: 175,342 train + 82,333 test (49 features → 19 standardized)
  - Unified preprocessing: protocol encoding, port mapping, byte log-scaling, attack category unification
- B. Normal-Only Training Strategy
  - Train on 123,343 normal-only samples (correct IF methodology)
  - Contamination = 0.10 (noise tolerance for mislabeled samples)
  - Model learns normal distribution → deviations = anomalies
- C. Feature Extraction and Scaling (StandardScaler)
- D. Context Rules Design (maintenance windows, peak hours, whitelists, internal traffic)
- E. Threat Score Computation (5-factor weighted formula, 0–100)
- F. Response Action Mapping (LOG → ALERT → BLOCK → ISOLATE → ESCALATE)

### VI. Implementation
- Technology stack: Python 3.12, FastAPI, scikit-learn, WebSocket
- ~3,000+ lines of code across 20+ files
- Frontend: HTML5/CSS3/JavaScript, premium dark SOC theme
- Deployment: Docker containerization with health checks
- Demo mode with continuous traffic simulation for dashboard

### VII. Evaluation
- A. Training on real normal-only data (123K samples, 19 features, 200 estimators)
- B. Classification metrics on 104,876 real test records:
  - Precision: 85.77%, Recall: 53.42%, F1: 65.83%, Accuracy: 69.25%
  - False Positive Rate: 11.04%
  - Confusion Matrix: TP=31,071, FP=5,155, FN=27,094, TN=41,556
- C. Score distribution analysis (normal mean=0.0612, attack mean=-0.0039)
- D. Latency measurement (~31ms per log end-to-end)
- E. Comparison: precision advantage over synthetic-trained models (85.77% vs 74.09%)
- F. Test suite validation: 31/31 tests pass

### VIII. Results and Discussion
- Strengths: high precision (low alert fatigue), zero-day capability, real-time
- Normal-only training produces superior precision vs. mixed training
- Recall trade-off: 53.42% — expected for pure IF without sequence analysis
- Score separation: 0.0651 (clear distinction between normal and attack traffic)
- Comparison with supervised approaches (higher accuracy but require labels)
- Limitations: low detection for stealthy attacks (port scan, brute force)
- Scalability: ~1,000 events/sec on single server

### IX. Conclusion and Future Work
- Summary: first integrated system with ML + context + scoring + response + dashboard on real data
- Future: LSTM/Autoencoder for sequence-based detection (improve recall for stealthy attacks)
- Future: CICIDS2017 and CIC-DDoS2019 evaluation
- Future: integration with SIEM tools (Splunk, Elastic, QRadar)
- Future: federated learning for distributed deployment
- Future: SHAP explainability for analyst trust
- Future: adaptive rule learning from analyst feedback

### X. References (20 citations, 2019–2024)
- Liu et al. (2008) – Isolation Forest
- Khraisat et al. (2019) – Survey of IDS
- Ahmad et al. (2021) – Network IDS with ML/DL
- Omar et al. (2024) – ML anomaly detection in IoT
- Hariri et al. (2021) – Extended Isolation Forest
- Alahmadi et al. (2022) – False positive reduction
- Vinayakumar et al. (2020) – Deep learning IDS
- Husák et al. (2022) – Automated incident response
- + 12 additional references
