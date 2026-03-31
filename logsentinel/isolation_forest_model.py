"""
Isolation Forest training and inference utilities.
This layer complements the existing statistical baseline without changing its logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import MODELS_DIR

MODEL_PATH = MODELS_DIR / "isolation_forest_model.pkl"
EXCLUDE_COLUMNS = ["window_id", "attack_ratio"]


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """Drop non-feature columns, replace inf, and fill NaN."""
    features = df.drop(columns=EXCLUDE_COLUMNS, errors="ignore").copy()
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
    return features


def train_isolation_forest(df: pd.DataFrame) -> Path:
    """
    Train IsolationForest on provided windowed DataFrame (expected Monday data).
    Saves the model to MODELS_DIR and returns the path.
    """
    features = _prepare_features(df)
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
    print(f"[IFOREST] Model trained and saved to: {MODEL_PATH}")
    return MODEL_PATH


def load_isolation_forest():
    """Load a previously trained IsolationForest model."""
    if not MODEL_PATH.exists():
        print(f"[IFOREST] Model not found at {MODEL_PATH}")
        return None
    return joblib.load(MODEL_PATH)


def predict_isolation_forest(df: pd.DataFrame, model) -> Tuple[np.ndarray, np.ndarray]:
    """
    Run IsolationForest predictions.
    Returns:
      predictions: -1 for anomaly, 1 for normal
      scores: decision_function values (higher is more normal)
    """
    features = _prepare_features(df)
    preds = model.predict(features)
    scores = model.decision_function(features)
    return preds, scores
