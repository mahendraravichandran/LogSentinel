import json

import pandas as pd

from .config import (
    ALERTS_OUTPUT_PATH,
    ANOMALY_INDEX_THRESHOLDS,
    BASELINE_PATH,
    WINDOWED_DIR,
)
from .isolation_forest_model import load_isolation_forest, predict_isolation_forest

Z_MEDIUM = 3
Z_HIGH = 5


def load_baseline():
    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
            print(f"[INFO] Loaded baseline model: {BASELINE_PATH}")
            return data
    except Exception as exc:
        print(f"[ERROR] Failed to process file: {exc}")
        return None


def compute_z(value, mean, std):
    if pd.isna(value) or std == 0:
        return 0
    return (value - mean) / std


def classify_severity(anomaly_index: float, thresholds: dict) -> str:
    low_threshold = thresholds["LOW"]
    medium_threshold = thresholds["MEDIUM"]
    high_threshold = thresholds["HIGH"]

    if anomaly_index < low_threshold:
        return "LOW"
    if anomaly_index < medium_threshold:
        return "MEDIUM"
    if anomaly_index < high_threshold:
        return "HIGH"
    return "CRITICAL"


def top_indicators(metric_z_scores: dict, limit: int = 3) -> list:
    ranked = sorted(
        metric_z_scores.items(),
        key=lambda item: abs(item[1]),
        reverse=True,
    )
    return ranked[:limit]


def anomaly_trend(previous_index: float | None, current_index: float) -> str:
    if previous_index is None:
        return "N/A"
    diff = current_index - previous_index
    if abs(diff) < 0.5:
        return f"Stable (prev: {previous_index:.2f} -> current: {current_index:.2f})"
    if diff > 0:
        return f"Up (prev: {previous_index:.2f} -> current: {current_index:.2f})"
    return f"Down (prev: {previous_index:.2f} -> current: {current_index:.2f})"


def infer_pattern(metric_z_scores: dict) -> tuple[str, str, str]:
    z_unique_dst_ips = metric_z_scores.get("unique_destination_ips", 0.0)
    z_unique_dst_ports = metric_z_scores.get("unique_destination_ports", 0.0)
    z_packets_rate = metric_z_scores.get("avg_flow_packets_per_sec", 0.0)
    z_total_packets = metric_z_scores.get("total_packets", 0.0)
    z_unique_src_ips = metric_z_scores.get("unique_source_ips", 0.0)

    # PortScan signal: sharp drop in destination IP diversity and elevated destination ports.
    if z_unique_dst_ips <= -5 and z_unique_dst_ports >= 2:
        return (
            "Possible PortScan",
            "High",
            "Investigate top source IPs for horizontal scan behavior and block repeated probes.",
        )

    # DDoS signal: strong destination concentration with packet-rate/volume anomalies.
    if z_unique_dst_ips <= -5 and (z_packets_rate <= -3 or abs(z_total_packets) >= 3):
        return (
            "Possible DDoS",
            "High",
            "Validate volumetric flood on constrained targets; apply rate-limit and upstream filtering.",
        )

    # Infiltration-like signal: destination diversity drops while packet rate rises.
    if z_unique_dst_ips <= -3 and z_packets_rate >= 4:
        return (
            "Possible Infiltration",
            "Medium",
            "Correlate destination hosts with endpoint telemetry and unusual outbound sessions.",
        )

    # Web attack-like signal: source diversity grows with increased packet rate.
    if z_unique_src_ips >= 3 and z_packets_rate >= 3:
        return (
            "Possible Web Attack",
            "Medium",
            "Review web server logs for bursty request patterns and exploit signatures.",
        )

    return (
        "Unknown",
        "Low",
        "Review top deviating metrics and correlate with firewall, DNS, and endpoint logs.",
    )


def print_alert(
    file_name,
    window_id,
    severity,
    max_z_score,
    anomaly_index,
    top_three,
    trend_label,
    likely_pattern,
    confidence,
    action_hint,
    unique_source_ips,
    unique_destination_ips,
    unique_destination_ports,
    attack_ratio,
    iforest_flag,
    iforest_score,
    final_decision,
    final_confidence,
):
    print("\n" + "=" * 80)
    print("LogSentinel Behavioral Anomaly Alert")
    print("=" * 80)
    print(f"File          : {file_name}")
    print(f"Window ID     : {window_id}")
    print(f"Severity      : {severity}")
    print(f"Likely Pattern: {likely_pattern}")
    print(f"Confidence    : {confidence}")
    print(f"IsolationForest   : {iforest_flag}")
    if iforest_score is not None:
        print(f"IF Score          : {iforest_score:.4f}")
    print(f"Final Decision    : {final_decision} ({final_confidence})")
    print("")
    print("Anomaly Snapshot:")
    print(f"  Anomaly Index : {round(anomaly_index, 2)}")
    print(f"  Max Z-Score   : {round(max_z_score, 2)}")
    print(f"  Trend         : {trend_label}")
    print("-" * 80)
    print("Top 3 Indicators:")
    for idx, (metric, z_value) in enumerate(top_three, start=1):
        print(f"  {idx}) {metric:<26} z={z_value:+.2f}")
    print("")
    print("Blast Radius:")
    print(f"  Unique Source IPs       : {unique_source_ips}")
    print(f"  Unique Destination IPs  : {unique_destination_ips}")
    print(f"  Unique DestinationPorts : {unique_destination_ports}")
    if pd.notna(attack_ratio):
        print("")
        print("Ground-Truth Context:")
        print(f"  Window Attack Ratio     : {float(attack_ratio):.2f}")
    print("")
    print("SOC Action Hint:")
    print(f"  {action_hint}")
    print("=" * 80)


def run_monitoring(save_alerts: bool = True) -> pd.DataFrame:
    print("\n=== BEHAVIORAL DEVIATION MONITOR STARTED ===")

    baseline = load_baseline()
    if baseline is None:
        print("[ERROR] Failed to process file: Baseline model could not be loaded.")
        return pd.DataFrame()

    iforest_model = load_isolation_forest()
    if iforest_model is None:
        print("[IFOREST] Proceeding without IsolationForest model.")

    total_windows = 0
    total_alerts = 0
    alert_rows = []
    file_alert_counts: dict[str, int] = {}

    files = sorted(
        [f for f in WINDOWED_DIR.glob("*.csv") if "Monday" not in f.name]
    )

    for file_path in files:
        print(f"\nProcessing file: {file_path.name}")
        file_alert_counts[file_path.name] = 0
        try:
            df = pd.read_csv(file_path)
            print(f"[INFO] Loaded windowed dataset: {file_path} (windows: {len(df)})")
            previous_anomaly_index = None

            # Pre-compute IsolationForest predictions if model available
            if iforest_model is not None:
                if_preds, if_scores = predict_isolation_forest(df, iforest_model)
            else:
                if_preds, if_scores = None, None

            for idx, row in df.iterrows():
                total_windows += 1
                window_id = int(row["window_id"])
                deviating_metrics = []
                max_z = 0
                metric_z_scores = {}

                for metric in baseline.keys():
                    if metric not in row:
                        continue

                    value = row[metric]
                    mean = baseline[metric]["mean"]
                    std = baseline[metric]["std"]
                    z = compute_z(value, mean, std)
                    metric_z_scores[metric] = z

                    if abs(z) >= Z_MEDIUM:
                        deviating_metrics.append(
                            f"{metric} | value={round(value, 2)} | baseline={round(mean, 2)} | z={round(z, 2)}"
                        )

                    if abs(z) > abs(max_z):
                        max_z = z

                anomaly_index = sum(abs(z) for z in metric_z_scores.values())
                trend_label = anomaly_trend(previous_anomaly_index, anomaly_index)
                previous_anomaly_index = anomaly_index
                top_three = top_indicators(metric_z_scores, limit=3)
                likely_pattern, confidence, action_hint = infer_pattern(metric_z_scores)

                if len(deviating_metrics) >= 2 or abs(max_z) >= Z_HIGH:
                    severity = classify_severity(
                        anomaly_index,
                        ANOMALY_INDEX_THRESHOLDS,
                    )
                    total_alerts += 1
                    file_alert_counts[file_path.name] += 1

                    # IsolationForest inference for this window
                    if_pred = if_preds[idx] if if_preds is not None else None
                    if_score = float(if_scores[idx]) if if_scores is not None else None
                    if_flag = (
                        "Anomaly" if if_pred == -1 else "Normal"
                        if if_pred is not None
                        else "N/A"
                    )

                    # Hybrid decision
                    z_trigger = True
                    if_trigger = if_pred == -1 if if_pred is not None else False

                    if z_trigger and if_trigger:
                        final_decision = "CONFIRMED ANOMALY"
                        final_confidence = "High"
                    elif z_trigger or if_trigger:
                        final_decision = "SUSPICIOUS"
                        final_confidence = "Medium"
                    else:
                        final_decision = "NORMAL"
                        final_confidence = "Low"

                    # Keep existing confidence but augment final decision context
                    print_alert(
                        file_path.name,
                        window_id,
                        severity,
                        max_z,
                        anomaly_index,
                        top_three,
                        trend_label,
                        likely_pattern,
                        confidence,
                        action_hint,
                        int(row.get("unique_source_ips", 0)),
                        int(row.get("unique_destination_ips", 0)),
                        int(row.get("unique_destination_ports", 0)),
                        row.get("attack_ratio", float("nan")),
                        if_flag,
                        if_score,
                        final_decision,
                        final_confidence,
                    )

                    alert_rows.append(
                        {
                            "file": file_path.name,
                            "window_id": window_id,
                            "severity": severity,
                            "likely_pattern": likely_pattern,
                            "confidence": confidence,
                            "anomaly_index": round(float(anomaly_index), 4),
                            "max_z_score": round(float(max_z), 4),
                            "top_indicators": " || ".join(
                                [f"{metric}:{z_value:.2f}" for metric, z_value in top_three]
                            ),
                            "trend": trend_label,
                            "unique_source_ips": int(row.get("unique_source_ips", 0)),
                            "unique_destination_ips": int(row.get("unique_destination_ips", 0)),
                            "unique_destination_ports": int(
                                row.get("unique_destination_ports", 0)
                            ),
                            "attack_ratio": (
                                round(float(row.get("attack_ratio")), 4)
                                if pd.notna(row.get("attack_ratio", float("nan")))
                                else None
                            ),
                            "soc_action_hint": action_hint,
                            "iforest_prediction": if_pred,
                            "iforest_score": if_score,
                            "final_decision": final_decision,
                        }
                    )
        except Exception as exc:
            print(f"[ERROR] Failed to process file: {exc}")
            print(f"Skipping monitoring for file due to error: {exc}")
            continue

    print("\n" + "=" * 80)
    print("MONITORING SUMMARY")
    print("=" * 80)
    print(f"Total Windows Processed : {total_windows}")
    print(f"Total Alerts Detected   : {total_alerts}")
    print("=" * 80)

    alerts_df = pd.DataFrame(alert_rows)

    if save_alerts:
        ALERTS_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        alerts_df.to_csv(ALERTS_OUTPUT_PATH, index=False)
        print(f"\nSaved alerts to: {ALERTS_OUTPUT_PATH}")

    day_alert_counts = {
        "monday": 0,
        "tuesday": 0,
        "wednesday": 0,
        "thursday": 0,
        "friday": 0,
    }

    for file_name, count in file_alert_counts.items():
        lower_name = file_name.lower()
        for day in day_alert_counts:
            if day in lower_name:
                day_alert_counts[day] += count
                break

    print("\n[COMPARISON SUMMARY]")
    print(f"{'Monday (benign)':<20} -> {day_alert_counts['monday']} alerts")
    print(f"{'Tuesday':<20} -> {day_alert_counts['tuesday']} alerts")
    print(f"{'Wednesday':<20} -> {day_alert_counts['wednesday']} alerts")
    print(f"{'Thursday':<20} -> {day_alert_counts['thursday']} alerts")
    print(f"{'Friday (attack)':<20} -> {day_alert_counts['friday']} alerts")

    print("\n=== Monitoring Completed ===")
    return alerts_df
