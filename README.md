# LogSentinel

LogSentinel is a hybrid network anomaly detection project built on CIC-IDS2017 flow CSV files.
It uses:

- statistical deviation detection (Z-score + anomaly index), and
- machine learning detection (Isolation Forest)

The goal is to generate SOC-style, explainable alerts from batch network flow data.

## What this project does

LogSentinel runs a full offline pipeline:

1. Preprocess raw CSV files
2. Convert traffic into fixed-size behavior windows
3. Build a baseline from Monday traffic
4. Train an Isolation Forest model on Monday windows
5. Monitor Tuesday-Friday windows and generate alerts

Each alert includes severity, likely attack pattern, top indicators, trend, and action hint.

## Why this project exists

Signature and rule-only detection often misses unknown behavior.
LogSentinel adds behavioral detection by combining:

- transparent statistical scoring (easy to explain/tune), and
- unsupervised ML (captures non-linear patterns)

This gives more context than a single method alone.

## Core features

- One entry point: `main.py`
- Encoding-tolerant CSV loading (`utf-8`, then `cp1252`, then `latin1`)
- Schema validation and numeric coercion
- Window-level feature engineering (default: 10,000 flows/window)
- Monday baseline model (`mean`/`std`)
- Z-score alerting with severity buckets
- Isolation Forest training + inference
- Hybrid final decision field in alerts
- SOC-friendly terminal alert output + CSV export

## Repository structure

```text
.
|-- main.py
|-- requirements.txt
|-- logsentinel/
|   |-- __init__.py
|   |-- config.py
|   |-- preprocessing.py
|   |-- windowing.py
|   |-- baseline.py
|   |-- isolation_forest_model.py
|   |-- monitor.py
|   `-- pipeline.py
|-- Data/
|   |-- raw/          # input CIC-IDS2017 CSV files
|   |-- processed/    # generated cleaned CSV files
|   `-- windowed/     # generated window feature CSV files
|-- Models/
|   |-- baseline_model.json         # generated baseline model
|   |-- isolation_forest_model.pkl  # generated IF model
|   `-- alerts_output.csv           # generated alerts
`-- docs/              # static documentation website
```

## Requirements

- Python 3.10+
- pip

Install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Dataset setup (CIC-IDS2017)

1. Download the `MachineLearningCSV` archive from:
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Extract all CSV files into `Data/raw/`.
3. Ensure these files exist:

- `Monday-WorkingHours.pcap_ISCX.csv`
- `Tuesday-WorkingHours.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
- `Friday-WorkingHours-Morning.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`

## How to run

Run full pipeline:

```bash
python main.py
```

Run individual stages:

```bash
python main.py --step preprocess
python main.py --step window
python main.py --step baseline
python main.py --step monitor
```

## Pipeline stages in detail

### 1) Preprocessing (`logsentinel/preprocessing.py`)

- Reads `Data/raw/*.csv`
- Strips column whitespace
- Validates required schema
- Keeps required fields only
- Converts numeric columns with coercion
- Drops rows with invalid values
- Writes cleaned files to `Data/processed/cleaned_*.csv`

### 2) Windowing (`logsentinel/windowing.py`)

- Reads `Data/processed/*.csv`
- Splits rows into fixed windows (`WINDOW_SIZE`, default `10000`)
- Computes behavior features per window:
  - `total_flows`
  - `total_bytes`
  - `total_packets`
  - `unique_source_ips`
  - `unique_destination_ips`
  - `unique_destination_ports`
  - `avg_flow_bytes_per_sec`
  - `avg_flow_packets_per_sec`
  - `avg_packets_per_flow`
  - `attack_ratio`
- Writes window files to `Data/windowed/windowed_*.csv`

### 3) Baseline (`logsentinel/baseline.py`)

- Uses Monday windowed file:
  `Data/windowed/windowed_cleaned_Monday-WorkingHours.pcap_ISCX.csv`
- Excludes `window_id` and `attack_ratio`
- Computes `mean` and `std` for each feature
- Saves baseline to `Models/baseline_model.json`

### 4) Isolation Forest training (`logsentinel/isolation_forest_model.py`)

- Runs after baseline stage in pipeline
- Trains on Monday windowed features
- Excludes `window_id` and `attack_ratio`
- Model params:
  - `n_estimators=100`
  - `contamination=0.05`
  - `random_state=42`
- Saves model to `Models/isolation_forest_model.pkl`

### 5) Monitoring (`logsentinel/monitor.py`)

- Loads baseline and non-Monday windowed files
- Computes per-window Z-scores per feature:
  - `z = (value - mean) / std`
- Computes anomaly index:
  - `sum(abs(z_i))`
- Triggers alert when:
  - at least 2 metrics have `|z| >= 3`, or
  - any metric has `|z| >= 5`
- Classifies severity by anomaly index:
  - `<3` -> `LOW`
  - `3 to <6` -> `MEDIUM`
  - `6 to <10` -> `HIGH`
  - `>=10` -> `CRITICAL`
- Runs Isolation Forest inference for each window
- Emits SOC-style alert details to terminal
- Writes alert rows to `Models/alerts_output.csv`

## Hybrid decision logic

For each alerted window:

- Z-score trigger is active (alert condition met)
- Isolation Forest gives prediction:
  - `-1` = anomaly
  - `1` = normal

Final decision in output:

- `CONFIRMED ANOMALY` when Z-score trigger and IF anomaly agree
- `SUSPICIOUS` when only one side indicates anomaly

## Pattern labeling heuristics

The monitor adds a likely pattern label with confidence and action hint:

- `Possible PortScan`
- `Possible DDoS`
- `Possible Infiltration`
- `Possible Web Attack`
- `Unknown`

These are heuristic labels based on feature deviations, not supervised attack classification.

## Output files

- Cleaned data: `Data/processed/cleaned_*.csv`
- Windowed features: `Data/windowed/windowed_*.csv`
- Baseline model: `Models/baseline_model.json`
- Isolation Forest model: `Models/isolation_forest_model.pkl`
- Alerts: `Models/alerts_output.csv`

Main alert CSV columns include:

- `file`
- `window_id`
- `severity`
- `likely_pattern`
- `confidence`
- `anomaly_index`
- `max_z_score`
- `top_indicators`
- `trend`
- `unique_source_ips`
- `unique_destination_ips`
- `unique_destination_ports`
- `attack_ratio`
- `soc_action_hint`
- `iforest_prediction`
- `iforest_score`
- `final_decision`

## Configuration

Edit `logsentinel/config.py` to tune behavior:

- `WINDOW_SIZE`
- `ANOMALY_INDEX_THRESHOLDS`
- `RAW_DIR`, `PROCESSED_DIR`, `WINDOWED_DIR`, `MODELS_DIR`
- `MONDAY_WINDOWED_FILE`
- `BASELINE_PATH`, `ALERTS_OUTPUT_PATH`

After config changes:

- window size change -> rerun `window`, `baseline`, `monitor`
- threshold change -> rerun `monitor`
- baseline source change -> rerun `baseline`, `monitor`

## Practical notes

- CIC-IDS2017 files are large; 8+ GB RAM recommended.
- This is an offline batch pipeline (not real-time streaming).
- Baseline quality depends on Monday traffic being representative.

## Troubleshooting

- Missing required columns:
  - file is skipped during preprocessing
- Baseline missing:
  - ensure Monday windowed file exists, then rerun `--step baseline`
- Encoding issues:
  - loader tries `utf-8`, then `cp1252`, then `latin1`
- No alerts:
  - check non-Monday windowed files and baseline presence
- Isolation Forest missing at monitor time:
  - rerun `--step baseline` to retrain IF model

## Limitations

- Static baseline can drift over time
- Low-and-slow attacks may evade threshold detection
- No live ingestion/stream processing
- No external enrichment (threat intel, asset context)
- Heuristic pattern naming is not ground-truth classification

## License

MIT License. See `LICENSE`.
