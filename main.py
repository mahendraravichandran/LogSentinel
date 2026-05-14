import argparse
import time

from logsentinel.pipeline import run_pipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the LogSentinel pipeline")
    parser.add_argument(
        "--step",
        choices=["all", "preprocess", "window", "baseline", "monitor"],
        default="all",
        help="Pipeline stage to run. Defaults to all.",
    )
    return parser.parse_args()


def main() -> None:
    start_time = time.time()
    try:
        args = parse_args()
        run_pipeline(args.step)
    except Exception as exc:
        print(f"[ERROR] Failed to process pipeline: {exc}")
        raise SystemExit(1) from exc
    finally:
        elapsed = time.time() - start_time
        print(f"[PERFORMANCE] Execution Time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
