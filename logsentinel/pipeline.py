from .baseline import build_baseline
from .monitor import run_monitoring
from .preprocessing import run_preprocessing
from .windowing import run_windowing
from .isolation_forest_model import train_isolation_forest
from .config import WINDOWED_DIR, MONDAY_WINDOWED_FILE


def run_pipeline(step: str = "all") -> None:
    step = step.lower()

    if step == "preprocess":
        run_preprocessing()
        return

    if step == "window":
        run_windowing()
        return

    if step == "baseline":
        build_baseline()
        _maybe_train_iforest()
        return

    if step == "monitor":
        run_monitoring()
        return

    if step == "all":
        run_preprocessing()
        run_windowing()
        build_baseline()
        _maybe_train_iforest()
        run_monitoring()
        return

    raise ValueError(f"Unsupported step: {step}")


def _maybe_train_iforest() -> None:
    """Train IsolationForest on Monday windowed data if available."""
    monday_path = WINDOWED_DIR / MONDAY_WINDOWED_FILE
    if not monday_path.exists():
        print(f"[IFOREST] Skipping training; missing {monday_path}")
        return
    try:
        import pandas as pd
        df = pd.read_csv(monday_path)
        train_isolation_forest(df)
    except Exception as exc:
        print(f"[IFOREST] Training failed: {exc}")
