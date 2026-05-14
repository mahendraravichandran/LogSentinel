from pathlib import Path

import pandas as pd

from .config import NUMERIC_COLUMNS, PROCESSED_DIR, RAW_DIR, REQUIRED_COLUMNS


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip()
    return df


def convert_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def read_csv_safely(file_path: Path) -> pd.DataFrame:
    encodings = ["utf-8", "cp1252", "latin1"]

    for encoding in encodings:
        try:
            return pd.read_csv(file_path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError:
            print(f"{encoding} failed. Trying next encoding...")

    raise UnicodeDecodeError("csv", b"", 0, 1, "Unable to read with known encodings")


def preprocess_file(file_path: Path, output_path: Path) -> None:
    print(f"\nProcessing: {file_path}")

    try:
        df = read_csv_safely(file_path)
        print(f"[INFO] Loaded dataset: {file_path} (rows: {len(df)})")
        df = clean_column_names(df)

        missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing:
            print(f"Skipping file - missing columns: {missing}")
            return

        df = convert_numeric_columns(df[REQUIRED_COLUMNS].copy())
        df = df.dropna()
        print(f"[INFO] Rows processed (after cleaning): {len(df)}")

        df.to_csv(output_path, index=False)

        print(f"Saved cleaned file to: {output_path}")
        print(f"Rows after cleaning: {len(df)}")
        print("-" * 60)

    except Exception as exc:
        print(f"[ERROR] Failed to process file: {exc}")
        print(f"Skipping file due to error: {exc}")
        print("-" * 60)


def run_preprocessing() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    for file_path in sorted(RAW_DIR.glob("*.csv")):
        output_path = PROCESSED_DIR / f"cleaned_{file_path.name}"
        preprocess_file(file_path, output_path)
