# LogSentinel: Behavioral Network Anomaly Monitoring

LogSentinel is a Python pipeline that ingests CIC-IDS2017 flow CSVs, builds a baseline of normal traffic, and emits SOC-ready anomaly alerts. It is batch/offline by design for deterministic, reproducible analysis.

## Features
- End-to-end pipeline from one entrypoint (`main.py`)
- Encoding-tolerant CSV loading and schema validation
- Window-level feature engineering (10,000-flow snapshots)
- Baseline modeling from Monday (benign) traffic
- Z-score scoring + anomaly index severity buckets
- SOC-focused alert context: severity, pattern guess, confidence, trend, top indicators, blast radius, action hint
- Hybrid detection: Isolation Forest layer (trained on Monday) alongside Z-score

## Repository Layout
```
.
|-- main.py                   # CLI entrypoint
|-- logsentinel/              # pipeline code
|   |-- config.py             # paths, window size, thresholds, schema
|   |-- preprocessing.py      # cleaning and numeric coercion
|   |-- windowing.py          # 10k-flow windows + features
|   |-- baseline.py           # baseline mean/std from Monday
|   `-- monitor.py            # z-scores, severity, alerts CSV
|-- Data/
|   |-- raw/                  # input CSVs (CIC-IDS2017)
|   |-- processed/            # cleaned CSVs (generated)
|   `-- windowed/             # windowed CSVs (generated)
|-- Models/
|   |-- baseline_model.json   # baseline stats (generated)
|   `-- alerts_output.csv     # SOC alerts (generated)
`-- docs/                     # static site
```

## Requirements
- Python 3.10+
- Pip
- Dependencies: `pandas` (>=2.0), `numpy` (>=1.24)
  ```bash
  python -m venv .venv
  .venv\Scripts\activate
  pip install -r requirements.txt
  ```

## Dataset Setup (CIC-IDS2017)
1. Download the "MachineLearningCSV" archive from https://www.unb.ca/cic/datasets/ids-2017.html
2. Extract all CSVs into `Data/raw/` so you have:
   - `Monday-WorkingHours.pcap_ISCX.csv`
   - `Tuesday-WorkingHours.pcap_ISCX.csv`
   - `Wednesday-workingHours.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
   - `Friday-WorkingHours-Morning.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`

## Quick Start
Run everything:
```bash
python main.py
```
Run a specific stage:
```bash
python main.py --step preprocess   # Data/raw -> Data/processed
python main.py --step window       # Data/processed -> Data/windowed
python main.py --step baseline     # builds Models/baseline_model.json from Monday
python main.py --step monitor      # scores Tue-Fri, writes Models/alerts_output.csv
```
Execution time is printed on exit.

Isolation Forest is trained automatically after baseline (uses Monday windowed data) and loaded during monitoring; no new CLI flags required.

## Configuration (`logsentinel/config.py`)
- `WINDOW_SIZE`: default `10000` flows per window
- `ANOMALY_INDEX_THRESHOLDS`: LOW <3, MEDIUM 3-<6, HIGH 6-<10, CRITICAL >=10
- Paths: `RAW_DIR`, `PROCESSED_DIR`, `WINDOWED_DIR`, `MODELS_DIR`
- Monday reference file: `MONDAY_WINDOWED_FILE`
- Model paths: `BASELINE_PATH`, `ALERTS_OUTPUT_PATH`, `isolation_forest_model.pkl`

Change values in `config.py` and rerun the relevant stages.

## Outputs
- Cleaned CSVs -> `Data/processed/cleaned_*.csv`
- Windowed feature CSVs -> `Data/windowed/windowed_*.csv`
- Baseline model -> `Models/baseline_model.json`
- Alerts -> `Models/alerts_output.csv` (also printed to terminal) with extra columns: `iforest_prediction`, `iforest_score`, `final_decision`

Example alert row (truncated):
```
file=windowed_cleaned_Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
window_id=2 severity=CRITICAL likely_pattern=Possible DDoS confidence=High
anomaly_index=15.69 max_z_score=-5.85 top_indicators=unique_destination_ips:-5.85 || avg_flow_packets_per_sec:-3.13 || unique_destination_ports:-2.44
trend=Up (prev: 7.23 -> current: 15.69)
```

## How Detection Works
- Z-score per metric using the Monday baseline (mean/std); std guarded to 1.0 if zero.
- Anomaly Index = sum(|z_i|) across metrics.
- Alert triggers when:
  - >=2 metrics have |z| >= 3, **or**
  - any metric has |z| >= 5.
- Severity from Anomaly Index using configured thresholds.
- Pattern heuristic:
  - PortScan: very low `unique_destination_ips` with high `unique_destination_ports`.
  - DDoS: very low `unique_destination_ips` with high packet volume/rate deviation.
  - Infiltration: drop in `unique_destination_ips` with spike in packet rate.
  - Web Attack: high `unique_source_ips` with high packet rate.
  - Else: Unknown (review indicators).

## Performance Notes
- CIC-IDS2017 CSVs are large (hundreds of MB). Ensure >8 GB RAM for smooth pandas reads.
- Windowing is O(rows); window size 10k balances fidelity vs compute. Increase cautiously.
- Baseline/monitoring reuse intermediate files; rerun only needed stages to save time.

## Troubleshooting
- Missing required columns -> file is skipped in preprocessing; check column names exactly.
- Baseline missing -> ensure `Data/windowed/windowed_cleaned_Monday-WorkingHours.pcap_ISCX.csv` exists, then rerun `--step baseline`.
- Encoding errors -> preprocessing falls back from utf-8 to cp1252 to latin1 automatically.
- Empty alerts -> verify non-Monday windowed files exist and baseline is present.

## Roadmap Ideas
- Add unit tests and CI workflow.
- Dockerfile for reproducible runtime.
- Streaming/online windowing option.
- Configurable CLI flags for thresholds and window size.
