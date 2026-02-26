import numpy as np
import pandas as pd

from .config import PROCESSED_DIR, WINDOW_SIZE, WINDOWED_DIR


def create_windows(df: pd.DataFrame) -> pd.DataFrame:
    windows = []

    total_rows = len(df)
    num_windows = total_rows // WINDOW_SIZE

    for i in range(num_windows):
        start = i * WINDOW_SIZE
        end = start + WINDOW_SIZE

        window_df = df.iloc[start:end].copy()
        window_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        window_df.fillna(0, inplace=True)

        total_flows = len(window_df)
        total_bytes = (
            window_df["Total Length of Fwd Packets"].sum()
            + window_df["Total Length of Bwd Packets"].sum()
        )
        total_packets = (
            window_df["Total Fwd Packets"].sum()
            + window_df["Total Backward Packets"].sum()
        )

        unique_src = window_df["Source IP"].nunique()
        unique_dst = window_df["Destination IP"].nunique()
        unique_ports = window_df["Destination Port"].nunique()

        avg_flow_bytes_per_sec = window_df["Flow Bytes/s"].mean()
        avg_flow_packets_per_sec = window_df["Flow Packets/s"].mean()
        avg_packets_per_flow = total_packets / total_flows if total_flows > 0 else 0

        attack_ratio = (
            window_df["Label"].apply(lambda x: 0 if "BENIGN" in str(x).upper() else 1).mean()
        )

        windows.append(
            {
                "window_id": i,
                "total_flows": total_flows,
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "unique_source_ips": unique_src,
                "unique_destination_ips": unique_dst,
                "unique_destination_ports": unique_ports,
                "avg_flow_bytes_per_sec": avg_flow_bytes_per_sec,
                "avg_flow_packets_per_sec": avg_flow_packets_per_sec,
                "avg_packets_per_flow": avg_packets_per_flow,
                "attack_ratio": attack_ratio,
            }
        )

    return pd.DataFrame(windows)


def process_file(file_path, output_path) -> None:
    print(f"\nProcessing window aggregation for: {file_path}")
    df = pd.read_csv(file_path)
    window_df = create_windows(df)
    window_df.to_csv(output_path, index=False)
    print(f"Saved windowed file to: {output_path}")
    print("-" * 60)


def run_windowing() -> None:
    WINDOWED_DIR.mkdir(parents=True, exist_ok=True)

    for file_path in sorted(PROCESSED_DIR.glob("*.csv")):
        output_path = WINDOWED_DIR / f"windowed_{file_path.name}"
        process_file(file_path, output_path)
