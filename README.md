# LogSentinel: Behavioral Network Anomaly Monitoring

LogSentinel is a Python pipeline for behavioral anomaly detection on network flow data.
It preprocesses raw flow CSVs, aggregates them into windows, builds a baseline from normal traffic,
and monitors for anomalous behavioral patterns with SOC-friendly alert output.

## Features
- End-to-end pipeline from one entrypoint (`main.py`)
- Data preprocessing with schema filtering and numeric coercion
- Window-level feature engineering
- Baseline modeling using statistical profile (mean/std)
- Anomaly scoring with configurable Anomaly Index thresholds
- SOC-focused alert context:
  - severity
  - likely pattern
  - confidence
  - top indicators
  - trend
  - blast radius
  - action hint

## Repository Structure

```text
.
|-- main.py
|-- logsentinel/
|   |-- __init__.py
|   |-- config.py
|   |-- preprocessing.py
|   |-- windowing.py
|   |-- baseline.py
|   |-- monitor.py
|   `-- pipeline.py
|-- Data/
|   |-- raw/        # input CSVs
|   |-- processed/  # generated cleaned files
|   `-- windowed/   # generated windowed files
`-- Models/
    |-- baseline_model.json  # generated baseline model
    `-- alerts_output.csv    # generated alerts
```

## Requirements
- Python 3.10+
- pip

Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start
Run the full pipeline:

```bash
python main.py
```

Run specific stages:

```bash
python main.py --step preprocess
python main.py --step window
python main.py --step baseline
python main.py --step monitor
```

## Pipeline Order
1. `preprocess`: Reads `Data/raw/*.csv`, cleans and writes `Data/processed/cleaned_*.csv`
2. `window`: Builds fixed-size windows and writes `Data/windowed/windowed_cleaned_*.csv`
3. `baseline`: Trains baseline statistics from Monday windowed data
4. `monitor`: Scores deviations and writes SOC-ready alerts to `Models/alerts_output.csv`

## Data Download
Raw data is **not** stored in the repository. To run the pipeline:

1. Download the CIC-IDS2017 flow CSVs from the official dataset page: https://www.unb.ca/cic/datasets/ids-2017.html (grab the `MachineLearningCSV.zip` archive).
2. Extract all CSVs into `Data/raw/` so files look like `Data/raw/Monday-WorkingHours.pcap_ISCX.csv`, `Data/raw/Tuesday-WorkingHours.pcap_ISCX.csv`, etc.
3. Leave `Data/processed`, `Data/windowed`, and `Models` empty; the pipeline will fill them.

Example (bash):

```bash
mkdir -p Data/raw
unzip ~/Downloads/MachineLearningCSV.zip -d Data/raw
```

## Severity and Anomaly Index
Anomaly Index is computed per window:

```text
anomaly_index = sum(abs(z_score(metric_i)))
```

Default thresholds (`logsentinel/config.py`):
- `< 3` -> `LOW`
- `3 to <6` -> `MEDIUM`
- `6 to <10` -> `HIGH`
- `>=10` -> `CRITICAL`

## Input Data Expectations
Each raw CSV must include these columns:
- `Source IP`
- `Destination IP`
- `Source Port`
- `Destination Port`
- `Protocol`
- `Flow Duration`
- `Total Fwd Packets`
- `Total Backward Packets`
- `Total Length of Fwd Packets`
- `Total Length of Bwd Packets`
- `Flow Bytes/s`
- `Flow Packets/s`
- `Label`

## Configuration
Edit settings in `logsentinel/config.py`:
- `WINDOW_SIZE`
- `ANOMALY_INDEX_THRESHOLDS`
- Paths (`RAW_DIR`, `PROCESSED_DIR`, `WINDOWED_DIR`, `MODELS_DIR`)

## Typical Output
During monitoring, terminal alerts show:
- severity and anomaly snapshot
- likely pattern and confidence
- top 3 indicators
- blast radius metrics
- SOC action hint

## Notes
- `Data/raw`, `Data/processed`, `Data/windowed`, and `Models` are **gitignored** to keep the repo lightweight.
- After downloading raw CSVs, rerun the pipeline steps as needed to regenerate processed/windowed data and models locally.

## Troubleshooting
- If baseline is missing: run `python main.py --step baseline`
- If no alerts are produced: confirm `Data/windowed` contains non-Monday files
- If schema errors occur: verify required column names exactly match expected names

## Future Improvements
- Add unit tests with `pytest`
- Add CI workflow (lint + tests)
- Add Dockerfile for reproducible runtime
