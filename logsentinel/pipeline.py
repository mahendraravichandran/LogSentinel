from .baseline import build_baseline
from .monitor import run_monitoring
from .preprocessing import run_preprocessing
from .windowing import run_windowing


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
        return

    if step == "monitor":
        run_monitoring()
        return

    if step == "all":
        run_preprocessing()
        run_windowing()
        build_baseline()
        run_monitoring()
        return

    raise ValueError(f"Unsupported step: {step}")
