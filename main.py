import argparse

from logsentinel.pipeline import run_pipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LogSentinel pipeline runner"
    )
    parser.add_argument(
        "--step",
        choices=["all", "preprocess", "window", "baseline", "monitor"],
        default="all",
        help="Pipeline stage to execute (default: all).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_pipeline(args.step)


if __name__ == "__main__":
    main()
