import json

import numpy as np
import pandas as pd

from .config import BASELINE_PATH, MONDAY_WINDOWED_FILE, WINDOWED_DIR


def build_baseline() -> None:
    file_path = WINDOWED_DIR / MONDAY_WINDOWED_FILE

    if not file_path.exists():
        print("Monday windowed file not found.")
        return

    print("\nLoading Monday windowed data...")
    try:
        df = pd.read_csv(file_path)
        print(f"[INFO] Loaded baseline dataset: {file_path} (rows: {len(df)})")
    except Exception as exc:
        print(f"[ERROR] Failed to process file: {exc}")
        print("Baseline build aborted.")
        return

    columns_to_exclude = ["window_id", "attack_ratio"]
    feature_columns = [col for col in df.columns if col not in columns_to_exclude]

    baseline = {}

    print("\nComputing baseline statistics...\n")

    for col in feature_columns:
        mean, std = _mean_and_std(df[col])
        baseline[col] = {"mean": mean, "std": std}

        print(f"{col}")
        print(f"   Mean: {round(mean, 4)}")
        print(f"   Std : {round(std, 4)}\n")

    print("[INFO] Feature extraction completed for baseline model.")

    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_PATH, "w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=4)

    print(f"Baseline model saved to: {BASELINE_PATH}")
    print("\nBaseline training completed successfully.")


def _mean_and_std(values: pd.Series) -> tuple[float, float]:
    series = pd.to_numeric(values, errors="coerce")
    series = series.replace([np.inf, -np.inf], np.nan).dropna()

    if series.empty:
        return 0.0, 1.0

    mean = float(series.mean())
    std = float(np.std(series))
    if std == 0:
        std = 1.0

    return mean, std
