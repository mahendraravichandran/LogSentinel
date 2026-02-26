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
    df = pd.read_csv(file_path)

    columns_to_exclude = ["window_id", "attack_ratio"]
    feature_columns = [col for col in df.columns if col not in columns_to_exclude]

    baseline_model = {}

    print("\nComputing baseline statistics...\n")

    for col in feature_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        clean_series = df[col].replace([np.inf, -np.inf], np.nan).dropna()

        if len(clean_series) == 0:
            mean = 0.0
            std = 1.0
        else:
            mean = float(clean_series.mean())
            std = float(clean_series.std())
            if std == 0:
                std = 1.0

        baseline_model[col] = {"mean": mean, "std": std}

        print(f"{col}")
        print(f"   Mean: {round(mean, 4)}")
        print(f"   Std : {round(std, 4)}\n")

    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_PATH, "w", encoding="utf-8") as file:
        json.dump(baseline_model, file, indent=4)

    print(f"Baseline model saved to: {BASELINE_PATH}")
    print("\nBaseline training completed successfully.")
