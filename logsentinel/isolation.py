from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import (
    ANOMALY_INDEX_THRESHOLDS,
    IFOREST_ALERTS_PATH,
    IFOREST_MODEL_PATH,
    MONDAY_WINDOWED_FILE,
    WINDOWED_DIR,
)

FEATURE_EXCLUDE = {"window_id", "attack_ratio"}


@dataclass
class IFModelBundle:
    model: IsolationForest
    score_mean: float
    score_std: float


def _classify_severity(value: float, thresholds: Dict[str, float]) -> str:
    low = thresholds["LOW"]
    med = thresholds["MEDIUM"]
    high = thresholds["HIGH"]
    if value < low:
        return "LOW"
    if value < med:
        return "MEDIUM"
    if value < high:
        return "HIGH"
    return "CRITICAL"


def _load_features(file_path: Path) -> pd.DataFrame:
    df = pd.read_csv(file_path)
    df = df.drop(columns=list(FEATURE_EXCLUDE), errors="ignore")
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    return df


def train_iforest() -> IFModelBundle | None:
    source = WINDOWED_DIR / MONDAY_WINDOWED_FILE
    if not source.exists():
        print(f"[IFOREST] Monday windowed file missing: {source}")
        return None

    print(f"[IFOREST] Loading training data from {source}")
    df = _load_features(source)
    if df.empty:
        print("[IFOREST] Training data empty; aborting.")
        return None

    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination="auto",
        random_state=42,
    )
    model.fit(df)

    train_scores = -model.decision_function(df)
    score_mean = float(train_scores.mean())
    score_std = float(train_scores.std() or 1.0)

    bundle = IFModelBundle(model=model, score_mean=score_mean, score_std=score_std)
    IFOREST_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "score_mean": score_mean, "score_std": score_std}, IFOREST_MODEL_PATH)

    print(f"[IFOREST] Model saved to {IFOREST_MODEL_PATH}")
    print(f"[IFOREST] Score mean: {score_mean:.4f} | std: {score_std:.4f}")
    return bundle


def _load_model() -> IFModelBundle | None:
    if not IFOREST_MODEL_PATH.exists():
        print(f"[IFOREST] Model not found at {IFOREST_MODEL_PATH}")
        return None
    data = joblib.load(IFOREST_MODEL_PATH)
    model: IsolationForest = data["model"]
    return IFModelBundle(model=model, score_mean=float(data["score_mean"]), score_std=float(data["score_std"]))


def _score_to_severity(score: float, bundle: IFModelBundle) -> Tuple[str, float]:
    z = (score - bundle.score_mean) / bundle.score_std if bundle.score_std else score
    sev = _classify_severity(abs(z), ANOMALY_INDEX_THRESHOLDS)
    return sev, z


def run_iforest_monitor(save_alerts: bool = True) -> pd.DataFrame:
    bundle = _load_model()
    if bundle is None:
        print("[IFOREST] No model available; run iforest-train first.")
        return pd.DataFrame()

    files = sorted([f for f in WINDOWED_DIR.glob("*.csv") if "Monday" not in f.name])
    if not files:
        print("[IFOREST] No non-Monday windowed files found.")
        return pd.DataFrame()

    alert_rows = []
    total_windows = 0
    total_alerts = 0

    for file_path in files:
        print(f"[IFOREST] Scoring file: {file_path.name}")
        df_raw = pd.read_csv(file_path)
        features = _load_features(file_path)

        if features.empty:
            print(f"[IFOREST] Skipping {file_path.name}; no rows.")
            continue

        scores = -bundle.model.decision_function(features)
        preds = bundle.model.predict(features)  # -1 anomaly, 1 normal

        for idx, score in enumerate(scores):
            total_windows += 1
            severity, z = _score_to_severity(score, bundle)
            is_alert = preds[idx] == -1 or severity in {"HIGH", "CRITICAL"}

            if is_alert:
                total_alerts += 1
                alert_rows.append(
                    {
                        "file": file_path.name,
                        "window_id": int(df_raw.iloc[idx]["window_id"]) if "window_id" in df_raw.columns else idx,
                        "severity": severity,
                        "anomaly_score": float(score),
                        "z_score": float(z),
                        "iforest_prediction": int(preds[idx]),
                    }
                )

    print("[IFOREST] Summary")
    print(f"  Windows scored : {total_windows}")
    print(f"  Alerts raised  : {total_alerts}")

    alerts_df = pd.DataFrame(alert_rows)
    if save_alerts:
        IFOREST_ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        alerts_df.to_csv(IFOREST_ALERTS_PATH, index=False)
        print(f"[IFOREST] Alerts saved to {IFOREST_ALERTS_PATH}")

    return alerts_df
