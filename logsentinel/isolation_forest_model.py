from __future__ import annotations

from pathlib import Path
from typing import Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import MODELS_DIR

MODEL_PATH = MODELS_DIR / "isolation_forest_model.pkl"
EXCLUDE_COLUMNS = ["window_id", "attack_ratio"]


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    features = df.drop(columns=EXCLUDE_COLUMNS, errors="ignore").copy()

    for col in features.columns:
        features[col] = pd.to_numeric(features[col], errors="coerce")

    features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
    return features


def _validate_feature_columns(
    features: pd.DataFrame,
    expected_columns: Sequence[str],
) -> pd.DataFrame:
    missing_columns = [col for col in expected_columns if col not in features.columns]
    extra_columns = [col for col in features.columns if col not in expected_columns]

    if missing_columns or extra_columns:
        details = []
        if missing_columns:
            details.append(f"missing={missing_columns}")
        if extra_columns:
            details.append(f"extra={extra_columns}")
        raise ValueError(
            "Isolation Forest feature mismatch between training and inference: "
            + ", ".join(details)
        )

    return features.loc[:, list(expected_columns)]


def train_isolation_forest(df: pd.DataFrame) -> Path:
    features = _prepare_features(df)

    if features.shape[1] == 0:
        raise ValueError("No features available for Isolation Forest.")
    if features.empty:
        raise ValueError("Training data is empty after feature prep.")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(features)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(
        f"[IFOREST] Model trained on {len(features)} samples using "
        f"{features.shape[1]} features."
    )
    print(f"[IFOREST] Model trained and saved to: {MODEL_PATH}")
    return MODEL_PATH


def load_isolation_forest() -> IsolationForest | None:
    if not MODEL_PATH.exists():
        print(f"[IFOREST] Model not found at {MODEL_PATH}")
        return None

    try:
        return joblib.load(MODEL_PATH)
    except Exception as exc:
        print(f"[IFOREST] Failed to load model at {MODEL_PATH}: {exc}")
        return None


def predict_isolation_forest(
    df: pd.DataFrame,
    model: IsolationForest,
) -> tuple[np.ndarray, np.ndarray]:
    features = _prepare_features(df)

    if features.shape[1] == 0:
        raise ValueError("No features available for Isolation Forest.")

    expected_columns = getattr(model, "feature_names_in_", None)
    if expected_columns is not None:
        features = _validate_feature_columns(features, expected_columns.tolist())

    preds = model.predict(features)
    scores = model.decision_function(features)
    return preds, scores
