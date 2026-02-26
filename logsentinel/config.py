from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "Data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
WINDOWED_DIR = DATA_DIR / "windowed"
MODELS_DIR = BASE_DIR / "Models"

MONDAY_WINDOWED_FILE = "windowed_cleaned_Monday-WorkingHours.pcap_ISCX.csv"
BASELINE_PATH = MODELS_DIR / "baseline_model.json"
ALERTS_OUTPUT_PATH = MODELS_DIR / "alerts_output.csv"

WINDOW_SIZE = 10000

# Severity thresholds based on anomaly index (sum of absolute Z-scores).
# Buckets:
#   anomaly_index < LOW       -> LOW
#   LOW <= anomaly_index < MEDIUM -> MEDIUM
#   MEDIUM <= anomaly_index < HIGH -> HIGH
#   anomaly_index >= HIGH     -> CRITICAL
ANOMALY_INDEX_THRESHOLDS = {
    "LOW": 3.0,
    "MEDIUM": 6.0,
    "HIGH": 10.0,
}

REQUIRED_COLUMNS = [
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Label",
]

NUMERIC_COLUMNS = [
    "Source Port",
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
]
