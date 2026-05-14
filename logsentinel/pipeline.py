from .baseline import build_baseline
from .config import WINDOWED_DIR, MONDAY_WINDOWED_FILE
from .isolation_forest_model import train_isolation_forest
from .monitor import run_monitoring
from .preprocessing import run_preprocessing
from .windowing import run_windowing


def _log_stage(stage: str) -> None:
    print(f"[PIPELINE] Running stage: {stage}")


def run_pipeline(step: str = "all") -> None:
    step = step.lower()

    steps = {
        "preprocess": _run_preprocess,
        "window": _run_windowing,
        "baseline": _run_baseline,
        "monitor": _run_monitoring,
    }

    if step == "all":
        for stage in steps.values():
            stage()
    elif step in steps:
        steps[step]()
    else:
        raise ValueError(f"Unsupported step: {step}")


def _run_preprocess() -> None:
    _log_stage("preprocess")
    run_preprocessing()


def _run_windowing() -> None:
    _log_stage("window")
    run_windowing()


def _run_baseline() -> None:
    _log_stage("baseline")
    build_baseline()
    _maybe_train_iforest()


def _run_monitoring() -> None:
    _log_stage("monitor")
    run_monitoring()


def _maybe_train_iforest() -> None:
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
