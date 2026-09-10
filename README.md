[README.md](https://github.com/user-attachments/files/32050204/README.md)
# TLP2LDP: A Policy-Aware Local Differential Privacy Middleware for Real-Time Cyber Threat Intelligence Anonymization

[![IEEE ICTAS 2026](https://img.shields.io/badge/IEEE%20ICTAS%202026-Accepted-blue)](https://www.ictas.org)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-green)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![diffprivlib](https://img.shields.io/badge/IBM%20diffprivlib-v0.6.6-orange)](https://github.com/IBM/differential-privacy-library)

---

> **Paper:** *TLP2LDP: A Policy-Aware Local Differential Privacy Middleware for Real-Time Cyber Threat Intelligence Anonymization*
> **Authors:** Adeyemo Iseoluwa Samuel, Dr. Atanda Oladayo Gbenga
> **Institution:** Department of Cybersecurity, Bowen University, Iwo, Osun State, Nigeria
> **Venue:** 10th IEEE International Conference on Information Communication Technology and Society (ICTAS 2026), Durban, South Africa, October 14–16 2026
> **Conference ID:** 1571333706

---

## Overview

TLP2LDP is a real-time privacy-preserving middleware that automatically translates **Traffic Light Protocol (TLP 2.0)** governance labels into calibrated **Local Differential Privacy (LDP)** epsilon budgets, anonymizing network logs at the edge before they are shared or stored.

The core contribution is a deterministic mapping function:

```
g(TLP) = ε  →  { 0.05   if TLP = RED
                { 0.25   if TLP = AMBER / AMBER+STRICT
                { 1.00   if TLP = GREEN
                { 10.00  if TLP = CLEAR
```

This eliminates the manual redaction bottleneck that currently prevents Security Operations Centres (SOCs) from safely sharing Cyber Threat Intelligence (CTI) while complying with the Nigeria Data Protection Act (NDPA) 2023 and GDPR.

### Key Results (Bowen WNET Live Capture — 90,172 records)

| Metric | Value |
|--------|-------|
| Mean processing latency | **0.158 ms/record** |
| SOC operational threshold | 500 ms |
| Throughput | **2,269.33 records/second** |
| Re-identification risk reduction (TLP:RED) | **96.24%** |
| Global accuracy degradation | **1.34%** (75.94% → 74.60%) |
| PortScan F1 improvement under TLP:RED | **+42.7%** |
| DDoS F1 improvement under TLP:RED | **+48.0%** |

---

## Repository Structure

```
TLP2LDP/
│
├── core/                          # Core pipeline modules
│   ├── tlp_resolver.py            # g(TLP) = ε deterministic mapping function
│   ├── anonymizer.py              # Field-aware anonymization engine
│   ├── tlp_anonymizer.py          # TLPAnonymizerMiddleware (main orchestrator)
│   ├── pii_detector.py            # Two-tier PII detection (Regex + NLP/NER)
│   ├── text_redactor.py           # Free-text payload redaction layer
│   └── kafka_pipeline.py          # Stream transport infrastructure
│
├── pipeline/                      # End-to-end pipeline runners
│   └── run_realtime_anonymizer.py # Parquet / pcapng ingestion and streaming
│
├── evaluation/                    # Chapter 4 evaluation framework
│   └── evaluation_harness.py      # Three-axis evaluation (Privacy, Utility, Latency)
│
├── dashboard/                     # Streamlit research dashboard
│   └── app.py                     # Interactive evaluation and visualization UI
│
├── data/                          # Evaluation outputs
│   └── secure_logs.ndjson         # Anonymized Bowen WNET output (90,172 records)
│
├── requirements.txt               # Python dependencies
├── LICENSE                        # MIT License
└── README.md                      # This file
```

---

## System Architecture

The framework is implemented as a decoupled three-tier pipeline:

```
Raw Capture              Tier 2: Anonymization             Output
(pcapng/parquet)         ┌─────────────────────────┐
       │                 │  TLPAnonymizerMiddleware  │
       ▼                 │  ┌─────────────────────┐  │
┌─────────────┐          │  │   tlp_resolver.py   │  │       ┌──────────────┐
│tlp_injector │──raw─────►  │   g(TLP) = ε        │  ├──────►│ secure-logs  │
│   .py       │  logs    │  └─────────┬───────────┘  │       │ (SIEM/SOC)   │
└─────────────┘          │            ▼               │       └──────────────┘
                         │  ┌─────────────────────┐  │
                         │  │   anonymizer.py     │  │
                         │  │  IP  → SHA-256 hash │  │
                         │  │  Port → Laplace(ε)  │  │
                         │  │  TS  → adaptive DP  │  │
                         │  │  Cat → SHA-256 hash │  │
                         │  └─────────┬───────────┘  │
                         │            ▼               │
                         │  ┌─────────────────────┐  │
                         │  │   pii_detector.py   │  │
                         │  │  Regex + NLP/NER    │  │
                         │  └─────────────────────┘  │
                         └─────────────────────────────┘
```

All processing is performed **entirely in-memory**. Unperturbed records never touch persistent storage.

---

## Installation

### Prerequisites

- Python 3.13
- pip

### Clone and install

```bash
git clone https://github.com/[YOUR-USERNAME]/TLP2LDP.git
cd TLP2LDP
pip install -r requirements.txt
```

### Optional: NLP/NER support (for unstructured payload detection)

```bash
python -m spacy download en_core_web_lg
```

> Without this, the PII detector falls back to the heuristic regex recognizer automatically. The pipeline will still run correctly.

---

## Quick Start

### 1. Run the anonymizer on your own parquet or pcapng file

Open `pipeline/run_realtime_anonymizer.py` and set the three configuration values at the top of the file:

```python
# Your file path — use a raw string on Windows
PARQUET_FILE_PATH = r"C:\Users\you\data\capture.parquet"

# The column that holds your traffic label
LABEL_COLUMN = "Label"

# Start with a small number for a first test run
MAX_ROWS = 1_000
```

Then run:

```bash
python pipeline/run_realtime_anonymizer.py
```

Output is written to `secure_logs.ndjson` — one anonymized JSON record per line, with the traffic label preserved for downstream ML evaluation.

### 2. Run the evaluation harness

```bash
python evaluation/evaluation_harness.py
```

This produces three outputs in `evaluation_results/`:
- `evaluation_report.txt` — structured three-section report
- `evaluation_metrics.csv` — full numeric table (RAW baseline + 4 TLP levels)
- `report_TLP_*.txt` — per-class precision/recall/F1 breakdown per TLP level

### 3. Launch the Streamlit dashboard

```bash
streamlit run dashboard/app.py
```

Upload a `.parquet` or `.pcapng` file through the browser UI. The dashboard runs the full pipeline, displays the evaluation results, and provides a single ZIP download of all research deliverables.

---

## Module Reference

### `tlp_resolver.py` — The g(TLP) = ε Function

The core mapping engine. Accepts any raw TLP string (e.g. `"TLP:RED"`, `"amber"`, `"TLP:AMBER+STRICT"`) and returns the corresponding epsilon value and policy context.

```python
from core.tlp_resolver import resolve_epsilon, resolve_policy

resolve_epsilon("TLP:RED")       # → 0.05
resolve_epsilon("TLP:AMBER")     # → 0.25
resolve_epsilon("garbage")       # → 0.05  (fail-safe: defaults to RED)

resolve_policy("TLP:GREEN")
# → {'tlp': 'GREEN', 'epsilon': 1.0, 'sensitivity': 1, 'noise_level': 'LOW'}
```

Unrecognized or missing TLP tags default to `TLP:RED` (ε=0.05) — the highest-noise, most protective setting — consistent with the process flow diagram's fail-safe branch.

---

### `anonymizer.py` — Field-Aware Anonymization Engine

Implements four perturbation strategies:

| Field type | Strategy | Properties |
|---|---|---|
| IP addresses | Salted per-octet SHA-256 | Irreversible; preserves subnet relationships |
| Ports / numeric | Laplace mechanism (diffprivlib) | Noise scales with ε; domain-clamped |
| Timestamps | Adaptive Laplace + monotonicity guard | Obfuscates exact time; preserves event ordering |
| Categorical (MACs, usernames, hostnames) | Salted full SHA-256 | Deterministic pseudonym; consistent across logs |

```python
from core.anonymizer import FieldAnonymizer

fa = FieldAnonymizer()

fa.anonymize_ip("192.168.1.50")
# → "219.241.246.128"  (same /24 prefix as 192.168.1.51)

fa.anonymize_ip("192.168.1.51")
# → "219.241.246.212"  (different host, same anonymized /24)

fa.anonymize_numeric(443, epsilon=0.05, lower=0, upper=65535)
# → 459  (noisy; varies each call)

fa.anonymize_categorical("jdoe")
# → "350eba1ba33714dd"  (deterministic across all calls)
```

The static system salt is `BowenCyberSec2026`.

---

### `tlp_anonymizer.py` — Middleware Orchestrator

`TLPAnonymizerMiddleware` is the main class that ties TLP resolution to field-aware anonymization. It accepts a field schema mapping column names to their anonymization type, with auto-detection for any unlisted fields.

```python
from core.tlp_anonymizer import TLPAnonymizerMiddleware

middleware = TLPAnonymizerMiddleware()

log_entry = {
    "tlp":      "TLP:AMBER",
    "src_ip":   "192.168.1.50",
    "dst_port": 443,
    "user_id":  "jdoe",
    "timestamp": 1718000000.123,
    "message":  "Failed login from 192.168.1.50 port 51422",
}

result = middleware.anonymize(log_entry)
# result["policy"]    → {'tlp': 'AMBER', 'epsilon': 0.25, ...}
# result["anonymized"] → {'src_ip': '219.241.246.128', 'dst_port': 441, ...}
```

Set `unknown_field_strategy="passthrough"` to leave statistical flow features untouched (recommended for feature-extracted parquet files).

---

### `pii_detector.py` — Two-Tier PII Detection

Implements the hybrid detection strategy for unstructured log payloads:

- **Tier 1 — Regex:** Fast, deterministic detection of IPv4 addresses, MAC addresses, email addresses, port references, and ISO-8601 timestamps in structured fields
- **Tier 2 — NLP/NER:** Microsoft Presidio AnalyzerEngine (spaCy-backed) for person names, usernames, hostnames, and entities embedded in free-text payloads. Falls back to `HeuristicNERRecognizer` if no spaCy model is installed.

```python
from core.pii_detector import PIIDetector

detector = PIIDetector()

matches = detector.analyze(
    "Failed password for user jdoe from 192.168.1.50 port 51422 ssh2"
)
# [PIIMatch(IP_ADDRESS, '192.168.1.50', source=regex),
#  PIIMatch(PORT, '51422', source=regex),
#  PIIMatch(USERNAME, 'jdoe', source=ner)]
```

---

### `kafka_pipeline.py` — Stream Transport Infrastructure

Provides two interchangeable runner backends:

- **`KafkaStreamRunner`** — connects to a live Apache Kafka broker (`raw-logs` → anonymize → `secure-logs`). Use this in production with Docker Compose.
- **`InMemoryStreamRunner`** — in-process pub/sub broker with identical interface. No infrastructure required. Used for all evaluation runs in the paper.

Both backends instrument per-record latency via `LatencyTracker`, reporting mean, max, and p95 millisecond values against the 500 ms SOC threshold.

---

### `evaluation_harness.py` — Three-Axis Evaluation

Implements the full evaluation framework from Section 3.7 of the dissertation:

- **Axis 1 (Privacy):** Adversary Guessing Advantage (A_adv) — normalised mean absolute difference between raw and anonymized PII field values per TLP level
- **Axis 2 (Utility):** Random Forest classifier (100 estimators, 70/30 split) trained once on raw data, tested against anonymized outputs at each of the four TLP levels
- **Axis 3 (Latency):** End-to-end Δt = t_export − t_ingest per record, reported as mean, max, and p95

Accepts any parquet file: CIC-IDS2017, NF-UNSW-NB15-v2, or live pcapng-derived captures.

---

## Reproducing the Paper Results

The `data/secure_logs.ndjson` file contains the anonymized output of the Bowen WNET evaluation — 90,172 records processed through the full TLP2LDP pipeline. The `label` field in each record preserves the original traffic classification for downstream ML evaluation.

> **Note on raw data:** The raw pcapng capture file is not published to protect the privacy of network users on Bowen University's wireless network, consistent with the NDPA 2023 obligations this framework is designed to enforce. The anonymized output and all evaluation metrics are fully reproducible using any comparable live network capture and the pipeline described above.

To reproduce the evaluation metrics reported in the paper:

```bash
# 1. Configure your parquet path in evaluation_harness.py
# 2. Run the harness
python evaluation/evaluation_harness.py

# Expected output (Bowen WNET):
# Mean latency:       0.185 ms (overall)
# Global accuracy:    75.94% (RAW) → 74.60% (TLP:RED)
# A_adv at TLP:RED:   0.0376
# PortScan F1 change: +42.7% under TLP:RED
```

---

## Citation

If you use TLP2LDP in your research, please cite:

```bibtex
@inproceedings{adeyemo2026tlp2ldp,
  title     = {TLP2LDP: A Policy-Aware Local Differential Privacy Middleware
               for Real-Time Cyber Threat Intelligence Anonymization},
  author    = {Adeyemo, Iseoluwa Samuel and Atanda, Oladayo Gbenga},
  booktitle = {Proceedings of the 10th IEEE International Conference on
               Information Communication Technology and Society (ICTAS 2026)},
  year      = {2026},
  address   = {Durban, South Africa},
  publisher = {IEEE},
  note      = {ISBN: 979-8-3195-1782-1}
}
```

---

## Dependencies

```
diffprivlib>=0.6.6
presidio-analyzer>=2.2.35
scikit-learn>=1.3.0
pandas>=2.1.0
numpy>=1.26.0
pyarrow>=14.0.0
kafka-python>=2.0.2
scapy>=2.5.0
streamlit>=1.35.0
```

Full dependency list with exact versions: see `requirements.txt`.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

**Adeyemo Iseoluwa Samuel**
Department of Cybersecurity, Bowen University
bu22cyb1002@bowenuniversity.edu.ng

**Dr. Atanda Oladayo Gbenga** (Supervisor)
Department of Cybersecurity, Bowen University

For questions about the research, conference presentation, or collaboration on Paper 2 (NDPA compliance engineering) and Paper 3 (anomaly regularization), please open an issue or contact via email.
