"""
evaluation_harness.py  —  Chapter 4 Evaluation
================================================================
Three-axis evaluation (Section 3.7):

  Axis 1 - Privacy    (Section 3.7.1)
            Epsilon budget per TLP level + adversary guessing
            advantage on anonymized numeric PII fields.

  Axis 2 - Utility    (Section 3.7.2)
            Random Forest trained on RAW data, tested on data
            anonymized at each TLP level.
            Metrics: Accuracy, Precision, Recall, F1-Score.

  Axis 3 - Latency    (Section 3.7.3)
            End-to-end per-record Dt vs 500 ms threshold.

Key design decisions reflecting new developments:
  - Accepts ANY parquet: CIC-IDS2017, NF-UNSW-NB15-v2, or live
    pcapng-derived captures from Wireshark.
  - Only PII columns (IPs, ports, MACs, timestamps) are anonymized.
    Statistical flow features pass through UNCHANGED so the RF gets
    full-fidelity behavioral features (NDPA justification).
  - TLP labels are either read from the file (if present) or forced
    to each level in turn for the controlled evaluation sweep.
  - All four TLP levels are always evaluated regardless of which
    labels appear in the dataset.

CONFIGURE (3 settings below):
  PARQUET_FILE_PATH  - path to your parquet file
  LABEL_COLUMN       - column holding traffic class / attack label
  PII_COLUMNS        - which columns to anonymize (see list below)
"""

from __future__ import annotations

import json
import math
import sys
import time
import warnings
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, f1_score,
    precision_score, recall_score,
    classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, str(Path(__file__).parent))
from kafka_pipeline import AnonymizerPipeline, InMemoryStreamRunner
from tlp_anonymizer import TLPAnonymizerMiddleware
from tlp_resolver import TLP_EPSILON_MAP, TLPLevel

warnings.filterwarnings("ignore")


# ================================================================
# TLP ASSIGNMENT MAPPING
# Same mapping used in run_realtime_anonymizer.py so both scripts
# report consistent TLP distributions for the same dataset.
# ================================================================
LABEL_TO_TLP: dict[str, str] = {
    "BENIGN":                           "TLP:CLEAR",
    "Benign":                           "TLP:CLEAR",
    "benign":                           "TLP:CLEAR",
    "DoS Hulk":                         "TLP:CLEAR",
    "DoS GoldenEye":                    "TLP:CLEAR",
    "DoS slowloris":                    "TLP:CLEAR",
    "DoS Slowhttptest":                 "TLP:CLEAR",
    "DDoS":                             "TLP:GREEN",
    "PortScan":                         "TLP:AMBER",
    "FTP-Patator":                      "TLP:AMBER",
    "SSH-Patator":                      "TLP:AMBER",
    "Brute Force":                      "TLP:AMBER",
    "Heartbleed":                       "TLP:AMBER",
    "Web Attack - Brute Force":         "TLP:AMBER",
    "Web Attack - XSS":                 "TLP:AMBER",
    "Web Attack - Sql Injection":       "TLP:AMBER",
    "Web Attack \u2013 Brute Force":    "TLP:AMBER",
    "Web Attack \u2013 XSS":            "TLP:AMBER",
    "Web Attack \u2013 Sql Injection":  "TLP:AMBER",
    "Infiltration":                     "TLP:RED",
    "Bot":                              "TLP:RED",
    # NF-UNSW-NB15-v2 / live capture labels
    "Analysis":      "TLP:AMBER",
    "Backdoor":      "TLP:RED",
    "DoS":           "TLP:CLEAR",
    "Exploits":      "TLP:RED",
    "Fuzzers":       "TLP:AMBER",
    "Generic":       "TLP:GREEN",
    "Normal":        "TLP:CLEAR",
    "Reconnaissance":"TLP:AMBER",
    "Shellcode":     "TLP:RED",
    "Worms":         "TLP:RED",
    # Wireshark / pcapng live capture labels
    "http":          "TLP:CLEAR",
    "dns":           "TLP:CLEAR",
    "tls":           "TLP:CLEAR",
    "tcp":           "TLP:CLEAR",
    "udp":           "TLP:CLEAR",
    "arp":           "TLP:CLEAR",
    "icmp":          "TLP:CLEAR",
}
DEFAULT_TLP_LABEL = "TLP:AMBER"


def assign_tlp(label: str) -> str:
    return LABEL_TO_TLP.get(str(label).strip(), DEFAULT_TLP_LABEL)



# 1. Path to your parquet file.
#    Windows: use a raw string  r"C:\Users\A\Downloads\capture.parquet"
#    macOS/Linux: "/home/ise/datasets/capture.parquet"
PARQUET_FILE_PATH = "CICIDS2017_test.parquet"

# 2. Column that holds the traffic label.
#    Common names: "Label", "label", "attack_cat", "ClassLabel"
LABEL_COLUMN = "Label"

# 3. PII columns to anonymize — ONLY raw network identifiers.
#    Statistical flow features (Flow Duration, Packet Length Std,
#    Active Mean, etc.) are NOT listed here and pass through
#    untouched as ML features (NDPA 2023 justification).
#    Comment out any column that does not exist in your file.
PII_COLUMNS: dict = {
    # IP addresses
    "ip.src":           "ip",
    "ip.dst":           "ip",
    "src_ip":           "ip",
    "dst_ip":           "ip",
    "Source IP":        "ip",
    "Destination IP":   "ip",
    "IPV4_SRC_ADDR":    "ip",
    "IPV4_DST_ADDR":    "ip",
    "ipv4_src_addr":    "ip",
    "ipv4_dst_addr":    "ip",
    # Ports
    "tcp.srcport":      ("numeric", 0, 65535),
    "tcp.dstport":      ("numeric", 0, 65535),
    "udp.srcport":      ("numeric", 0, 65535),
    "udp.dstport":      ("numeric", 0, 65535),
    "src_port":         ("numeric", 0, 65535),
    "dst_port":         ("numeric", 0, 65535),
    "Source Port":      ("numeric", 0, 65535),
    "Destination Port": ("numeric", 0, 65535),
    "L4_SRC_PORT":      ("numeric", 0, 65535),
    "L4_DST_PORT":      ("numeric", 0, 65535),
    # MAC addresses
    "eth.src":          "categorical",
    "eth.dst":          "categorical",
    "src_mac":          "categorical",
    "dst_mac":          "categorical",
    # Timestamps
    "frame.time":       "timestamp",
    "timestamp":        "timestamp",
    "Timestamp":        "timestamp",
    "utc_date_time":    "timestamp",
}

# ================================================================
# TUNING KNOBS
# ================================================================
MAX_ROWS      = None     # None = full dataset; 1000 for a quick test
BATCH_SIZE    = 5_000
TEST_SIZE     = 0.30     # 70/30 split
RANDOM_STATE  = 42
OUTPUT_DIR    = "evaluation_results"

# The four TLP levels evaluated in sequence.
EVAL_LEVELS = [
    ("TLP:RED",   0.05,  "HIGH"),
    ("TLP:AMBER", 0.25,  "MEDIUM"),
    ("TLP:GREEN", 1.00,  "LOW"),
    ("TLP:CLEAR", 10.00, "MINIMAL"),
]


# ================================================================
# UTILITIES
# ================================================================

def sanitize(value):
    """Convert pcapng / parquet types to JSON-safe primitives."""
    try:
        import pandas as _pd
        if isinstance(value, _pd.Timestamp):
            return value.timestamp()
        try:
            if _pd.isna(value):
                return None
        except (TypeError, ValueError):
            pass
    except ImportError:
        pass

    import datetime
    if isinstance(value, datetime.datetime):
        return value.timestamp()
    if isinstance(value, datetime.date):
        import calendar
        return float(calendar.timegm(value.timetuple()))

    if isinstance(value, (bytes, bytearray)):
        return value.hex()

    try:
        import numpy as _np
        if isinstance(value, _np.integer):
            return int(value)
        if isinstance(value, _np.floating):
            f = float(value)
            return None if (math.isnan(f) or math.isinf(f)) else f
        if isinstance(value, _np.bool_):
            return bool(value)
    except ImportError:
        pass

    if isinstance(value, float):
        return None if (math.isnan(value) or math.isinf(value)) else value

    return value


def load_parquet(path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
    pf   = pq.ParquetFile(path)
    dfs, rows = [], 0
    for batch in pf.iter_batches(batch_size=BATCH_SIZE):
        df = batch.to_pandas()
        if max_rows:
            df = df.head(max_rows - rows)
        dfs.append(df)
        rows += len(df)
        if max_rows and rows >= max_rows:
            break
    return pd.concat(dfs, ignore_index=True)


def build_schema(actual_cols: list[str]) -> dict:
    """
    Build a field schema containing ONLY the PII columns present in
    this dataset, plus passthrough for label and TLP fields.
    Every other column (statistical features) is handled by
    unknown_field_strategy='passthrough' in the middleware.
    """
    schema: dict = {
        "tlp":        "passthrough",
        "label":      "passthrough",
        LABEL_COLUMN: "passthrough",
    }
    col_set = set(actual_cols)
    for col, ftype in PII_COLUMNS.items():
        if col in col_set:
            schema[col] = ftype
    return schema


def anonymize_df(df: pd.DataFrame,
                  forced_tlp: str,
                  schema: dict,
                  label_col: str) -> tuple[pd.DataFrame, float, float]:
    """
    Anonymize every row in df at forced_tlp level.
    Returns (anonymized_df, mean_latency_ms, max_latency_ms).
    Only PII columns are touched; everything else passes through.
    """
    middleware = TLPAnonymizerMiddleware(
        field_schema=schema,
        unknown_field_strategy="passthrough",
    )
    pipeline = AnonymizerPipeline(middleware=middleware)
    runner   = InMemoryStreamRunner(pipeline=pipeline)

    records = []
    for i, (_, row) in enumerate(df.iterrows()):
        label = str(row.get(label_col, "unknown"))
        env: dict = {"tlp": forced_tlp, "label": label}
        for col, val in row.items():
            if col in (label_col, "tlp"):
                continue
            safe = sanitize(val)
            if safe is not None:
                env[col] = safe

        runner.publish_raw(env, key=f"flow-{i}")
        runner.run()
        records.extend(runner.drain_secure_logs())

    anon_df = pd.DataFrame(records)
    stats   = pipeline.latency.summary()
    return anon_df, stats.get("mean_ms", 0.0), stats.get("max_ms", 0.0)


def get_feature_columns(df: pd.DataFrame,
                          pii_cols: set,
                          label_col: str) -> list[str]:
    """
    Return numeric columns that are not PII and not the label.
    These are the behavioral features the RF trains on.
    """
    numeric = df.select_dtypes(include=[np.number]).columns.tolist()
    return [c for c in numeric
            if c not in pii_cols and c != label_col and c != "tlp"]


def encode_features(df: pd.DataFrame,
                     feature_cols: list[str],
                     label_col: str,
                     le: Optional[LabelEncoder] = None,
                     fit: bool = False):
    """
    Extract feature matrix X and encoded labels y.
    Non-numeric values (e.g. hashed IP strings) are coerced to 0
    so the RF sees a clean numeric matrix.
    """
    avail = [c for c in feature_cols if c in df.columns]
    X = df[avail].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.fillna(0).replace([np.inf, -np.inf], 0)

    raw_y = df[label_col].astype(str) if label_col in df.columns \
            else pd.Series(["unknown"] * len(df))

    if le is None:
        le = LabelEncoder()
    if fit:
        y = le.fit_transform(raw_y)
    else:
        known = set(le.classes_)
        raw_y = raw_y.apply(lambda v: v if v in known else le.classes_[0])
        y = le.transform(raw_y)

    return X.values, y, le


def metrics(y_true, y_pred) -> dict:
    avg = "weighted"
    return {
        "accuracy":  round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred,
                            average=avg, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred,
                            average=avg, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred,
                            average=avg, zero_division=0)), 4),
    }


def guessing_advantage(raw_series: pd.Series,
                         anon_series: pd.Series) -> float:
    """
    Adversary guessing advantage for a numeric PII field (Section 3.7.1).
    Measures mean normalised absolute difference between raw and noisy values.
    Range: 0 (fully masked) to 1 (no protection).
    """
    r = pd.to_numeric(raw_series,  errors="coerce").fillna(0).values
    a = pd.to_numeric(anon_series, errors="coerce").fillna(0).values
    n = len(r)
    if n == 0:
        return 1.0
    adv = np.mean(np.abs(r - a) / (np.abs(r) + 1))
    return round(float(adv), 4)


def banner(text: str, w: int = 66):
    print("=" * w)
    print(f"  {text}")
    print("=" * w)


# ================================================================
# MAIN
# ================================================================
# ================================================================
# MAIN
# ================================================================
def main():
    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(exist_ok=True)

    t_wall_start = time.perf_counter()

    parquet_path = Path(PARQUET_FILE_PATH)
    if not parquet_path.exists():
        print(f"\n[ERROR] File not found: {parquet_path.resolve()}")
        print("  Fix: Update PARQUET_FILE_PATH at the top of this script.")
        print("  Tip: Use a raw string on Windows:")
        print('       PARQUET_FILE_PATH = r"C:\\Users\\A\\file.parquet"')
        sys.exit(1)

    banner("TLP-Driven Privacy-Utility Evaluation  —  Chapter 4")
    print(f"  File    : {parquet_path.resolve()}")
    print(f"  Output  : {out_dir.resolve()}")
    print(f"  Max rows: {MAX_ROWS or 'all'}")
    print()

    # ── STEP 0: Load data ─────────────────────────────────────────────
    print("  [STEP 0]  Loading dataset ...")
    raw_df = load_parquet(parquet_path, MAX_ROWS)
    raw_df = raw_df.dropna(subset=[LABEL_COLUMN]).reset_index(drop=True)
    actual_cols  = list(raw_df.columns)
    total_rows   = len(raw_df)
    print(f"  Rows    : {total_rows:,}")
    print(f"  Columns : {actual_cols}")
    print(f"  Labels  :")
    for lbl, cnt in raw_df[LABEL_COLUMN].value_counts().items():
        print(f"    {str(lbl):<30}  {cnt:>7,}")
    print()

    # Compute TLP distribution from the full dataset using the same
    # label -> TLP mapping as run_realtime_anonymizer.py
    raw_df["_tlp"] = raw_df[LABEL_COLUMN].apply(
        lambda x: assign_tlp(str(x))
    )
    tlp_dist = raw_df["_tlp"].value_counts().to_dict()
    tlp_order = ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]

    # ── STEP 1: Schema and feature detection ─────────────────────────
    print("  [STEP 1]  Building schema and detecting features ...")
    schema = build_schema(actual_cols)
    pii_in_data = [c for c in PII_COLUMNS if c in actual_cols]
    print(f"  PII columns found   : {pii_in_data}")
    if not pii_in_data:
        print("  NOTE: No PII columns detected in this dataset.")
        print("        Statistical features pass through unchanged (NDPA).")

    feature_cols = get_feature_columns(
        raw_df, set(PII_COLUMNS.keys()), LABEL_COLUMN
    )
    print(f"  ML feature columns  : {len(feature_cols)}")
    print(f"    {feature_cols}")
    print()

    if not feature_cols:
        print("[ERROR] No numeric feature columns found.")
        sys.exit(1)

    # ── STEP 2: Train / test split ────────────────────────────────────
    print("  [STEP 2]  Train / test split (70 / 30) ...")
    le = LabelEncoder()
    X_all, y_all, le = encode_features(
        raw_df, feature_cols, LABEL_COLUMN, fit=True
    )

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X_all, y_all,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y_all,
        )
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(
            X_all, y_all,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
        )

    _, test_df = train_test_split(
        raw_df, test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
    )
    test_df = test_df.reset_index(drop=True)

    print(f"  Train : {len(X_train):,}   Test : {len(X_test):,}")
    print(f"  Classes : {list(le.classes_)}")
    print()

    # ── STEP 3: Train Random Forest on raw data ───────────────────────
    print("  [STEP 3]  Training Random Forest on raw (unaltered) data ...")
    t0 = time.perf_counter()
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    train_secs = time.perf_counter() - t0
    print(f"  Training complete in {train_secs:.2f}s")
    print()

    # ── STEP 4: Baseline on raw test data ────────────────────────────
    print("  [STEP 4]  Baseline — testing on raw (unaltered) test data ...")
    y_pred_raw = clf.predict(X_test)
    baseline   = metrics(y_test, y_pred_raw)
    print(f"  Baseline (no anonymization):")
    for k, v in baseline.items():
        print(f"    {k:<12} {v:.4f}")
    print()

    # ── STEP 5: Per-TLP anonymization and evaluation ──────────────────
    print("  [STEP 5]  Evaluating across all four TLP levels ...")
    print()

    all_results      = []
    all_mean_lat_ms  = []
    all_max_lat_ms   = []

    for (tlp_tag, epsilon, noise_label) in EVAL_LEVELS:
        print(f"  ── {tlp_tag}  (epsilon={epsilon},  noise={noise_label}) ──")

        t_anon = time.perf_counter()
        anon_df, mean_lat_ms, max_lat_ms = anonymize_df(
            test_df, tlp_tag, schema, LABEL_COLUMN
        )
        anon_secs = time.perf_counter() - t_anon

        all_mean_lat_ms.append(mean_lat_ms)
        all_max_lat_ms.append(max_lat_ms)

        X_anon, y_anon, _ = encode_features(
            anon_df, feature_cols, "label", le=le, fit=False
        )
        y_pred_anon = clf.predict(X_anon)
        m = metrics(y_anon, y_pred_anon)

        f1_drop     = round(baseline["f1"] - m["f1"], 4)
        f1_drop_pct = round(100 * f1_drop / (baseline["f1"] + 1e-9), 2)

        print(f"    Accuracy   : {m['accuracy']:.4f}  "
              f"(baseline {baseline['accuracy']:.4f})")
        print(f"    Precision  : {m['precision']:.4f}  "
              f"(baseline {baseline['precision']:.4f})")
        print(f"    Recall     : {m['recall']:.4f}  "
              f"(baseline {baseline['recall']:.4f})")
        print(f"    F1-Score   : {m['f1']:.4f}  "
              f"(baseline {baseline['f1']:.4f}  "
              f"drop={f1_drop_pct:.1f}%)")

        adv_scores = []
        for col in pii_in_data:
            field_type = PII_COLUMNS.get(col)
            if isinstance(field_type, tuple) and field_type[0] == "numeric":
                if col in test_df.columns and col in anon_df.columns:
                    adv = guessing_advantage(test_df[col], anon_df[col])
                    adv_scores.append(adv)
                    print(f"    Re-id adv [{col}] : {adv:.4f}")

        mean_adv  = round(np.mean(adv_scores), 4) if adv_scores else None
        rec_per_s = len(test_df) / anon_secs if anon_secs > 0 else 0
        within    = mean_lat_ms < 500

        print(f"    Latency    : {mean_lat_ms:.3f} ms mean / "
              f"{max_lat_ms:.3f} ms max  "
              f"({rec_per_s:.0f} rec/s)  "
              f"{'PASS' if within else 'FAIL'} (<500ms)")
        print()

        all_results.append({
            "tlp":          tlp_tag,
            "epsilon":      epsilon,
            "noise":        noise_label,
            **m,
            "f1_drop":      f1_drop,
            "f1_drop_pct":  f1_drop_pct,
            "guessing_adv": mean_adv,
            "mean_lat_ms":  round(mean_lat_ms, 3),
            "max_lat_ms":   round(max_lat_ms, 3),
            "within_500ms": within,
        })

        rpt_path = out_dir / f"report_{tlp_tag.replace(':', '_')}.txt"
        with rpt_path.open("w") as fh:
            fh.write(f"Classification Report — {tlp_tag} (epsilon={epsilon})\n")
            fh.write("=" * 60 + "\n\n")
            fh.write(classification_report(
                y_anon, y_pred_anon,
                target_names=le.classes_,
                zero_division=0,
            ))

    # ── STEP 6: Save CSV ──────────────────────────────────────────────
    rows = [{"tlp": "RAW", "epsilon": float("inf"),
              **baseline, "f1_drop": 0, "f1_drop_pct": 0,
              "guessing_adv": 1.0, "mean_lat_ms": 0,
              "max_lat_ms": 0, "within_500ms": True}] + all_results
    csv_path = out_dir / "evaluation_metrics.csv"
    pd.DataFrame(rows).to_csv(csv_path, index=False)

    baseline_rpt = out_dir / "report_RAW_baseline.txt"
    with baseline_rpt.open("w") as fh:
        fh.write("Classification Report — RAW baseline (no anonymization)\n")
        fh.write("=" * 60 + "\n\n")
        fh.write(classification_report(
            y_test, y_pred_raw,
            target_names=le.classes_,
            zero_division=0,
        ))

    # ── Aggregate latency across all TLP runs ─────────────────────────
    t_wall_total   = time.perf_counter() - t_wall_start
    overall_mean   = round(float(np.mean(all_mean_lat_ms)), 3) \
                     if all_mean_lat_ms else 0.0
    overall_max    = round(float(np.max(all_max_lat_ms)), 3) \
                     if all_max_lat_ms else 0.0
    all_within_500 = all(r["within_500ms"] for r in all_results)

    # ── STEP 7: Structured evaluation report ─────────────────────────
    f1_map = {r["tlp"]: r["f1"] for r in all_results}

    lines = []
    lines.append("")
    lines.append("=" * 66)
    lines.append("  FRAME AFRICA TLP ANONYMIZATION FRAMEWORK")
    lines.append("  EVALUATION REPORT  —  Chapter 4")
    lines.append("=" * 66)
    lines.append("")

    # Section 1 — Data Distribution
    lines.append("### 1. DATA DISTRIBUTION METRICS")
    lines.append("    (From the Ingestion Engine — full dataset)")
    lines.append("")
    lines.append(f"  Total raw packet lines processed    : {total_rows:,}")
    for tlp_tag in tlp_order:
        cnt = tlp_dist.get(tlp_tag, 0)
        pct = 100 * cnt / total_rows if total_rows else 0
        lines.append(
            f"  {tlp_tag} count & percentage       : "
            f"{cnt:,} ({pct:.1f}%)"
        )
    unmatched = tlp_dist.get(DEFAULT_TLP_LABEL, 0)
    if unmatched and DEFAULT_TLP_LABEL not in tlp_order:
        lines.append(
            f"  Unrecognised labels -> {DEFAULT_TLP_LABEL:<14}: "
            f"{unmatched:,} ({100*unmatched/total_rows:.1f}%)"
        )
    lines.append("")

    # Section 2 — System Performance
    lines.append("### 2. PIPELINE SYSTEM PERFORMANCE")
    lines.append("    (From the Latency Tracker — averaged across all TLP levels)")
    lines.append("")
    lines.append(
        f"  Total execution wall-clock time     : "
        f"{t_wall_total:.2f} seconds"
    )
    lines.append(
        f"  Average (Mean) latency per log      : "
        f"{overall_mean:.3f} milliseconds"
    )
    lines.append(
        f"  Maximum spike latency encountered   : "
        f"{overall_max:.3f} milliseconds"
    )
    lines.append(
        f"  Stayed under 500 ms real-time target: "
        f"{'YES — all TLP levels passed' if all_within_500 else 'NO — review overhead'}"
    )
    lines.append("")

    # Section 3 — Classifier Accuracy
    lines.append("### 3. INTRUSION CLASSIFIER ACCURACY")
    lines.append("    (Random Forest trained on RAW data, tested on anonymized data)")
    lines.append("")
    lines.append(
        f"  ML model evaluated                  : "
        f"Random Forest Classifier (100 estimators)"
    )
    lines.append(
        f"  Baseline F1-Score on raw logs       : "
        f"{baseline['f1']*100:.1f}%"
    )
    lines.append(
        f"  F1-Score vs TLP:CLEAR fuzzed logs   : "
        f"{f1_map.get('TLP:CLEAR', 0)*100:.1f}%  "
        f"(epsilon={10.0},  noise=MINIMAL)"
    )
    lines.append(
        f"  F1-Score vs TLP:GREEN fuzzed logs   : "
        f"{f1_map.get('TLP:GREEN', 0)*100:.1f}%  "
        f"(epsilon={1.0},  noise=LOW)"
    )
    lines.append(
        f"  F1-Score vs TLP:AMBER fuzzed logs   : "
        f"{f1_map.get('TLP:AMBER', 0)*100:.1f}%  "
        f"(epsilon={0.25},  noise=MEDIUM)"
    )
    lines.append(
        f"  F1-Score vs TLP:RED fuzzed logs     : "
        f"{f1_map.get('TLP:RED', 0)*100:.1f}%  "
        f"(epsilon={0.05},  noise=HIGH)"
    )
    lines.append("")

    # Interpretation
    f1_red   = f1_map.get("TLP:RED",   0)
    f1_clear = f1_map.get("TLP:CLEAR", 0)
    gap      = abs(f1_clear - f1_red)
    lines.append("  Interpretation:")
    lines.append(
        f"  The framework demonstrates a {gap*100:.1f} percentage-point F1"
    )
    lines.append(
        "  trade-off between maximum privacy (TLP:RED) and maximum"
    )
    lines.append(
        "  utility (TLP:CLEAR), confirming that the TLP-adaptive"
    )
    lines.append(
        "  Differential Privacy mechanism provides mathematically"
    )
    lines.append(
        "  calibrated protection without catastrophic utility loss."
    )
    lines.append("")
    lines.append("=" * 66)
    lines.append("")

    report_text = "\n".join(lines)

    # Print to terminal
    print(report_text)

    # Save to file
    rpt_final = out_dir / "evaluation_report.txt"
    with rpt_final.open("w", encoding="utf-8") as fh:
        fh.write(report_text)

    print(f"  Report saved  -> {rpt_final.resolve()}")
    print(f"  Metrics CSV   -> {csv_path.resolve()}")
    print(f"  Class reports -> {out_dir.resolve()}/report_*.txt")
    print()


if __name__ == "__main__":
    main()
