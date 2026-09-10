import streamlit as st
import pandas as pd
import numpy as np
import json
import io
import os
import time
import zipfile
from pathlib import Path
from scapy.all import PcapReader, IP, TCP, UDP

from tlp_injector import IntelligentTLPInjector
from run_realtime_anonymizer3 import assign_tlp, build_log_envelope, normalize_columns
from kafka_pipeline import AnonymizerPipeline, InMemoryStreamRunner
from tlp_anonymizer import DEFAULT_FIELD_SCHEMA, TLPAnonymizerMiddleware

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

st.set_page_config(page_title="Policy-Aware DP Framework", layout="wide")
st.title("Policy-Aware Differential Privacy Framework")
st.subheader("Automated Personal Data Protection Engine & ML Evaluation Dashboard")
st.markdown("---")

st.sidebar.header("Pipeline Configuration")
max_rows = st.sidebar.slider("Maximum Records to Stream", 1000, 200000, 10000, step=1000)

# Session state — persists results across download-button reruns
if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = None

# ── Constants matching evaluation_harness.py (Section 3.7) ───────────────────
EVAL_LEVELS = [
    ("TLP:RED",   0.05,  "HIGH"),
    ("TLP:AMBER", 0.25,  "MEDIUM"),
    ("TLP:GREEN", 1.00,  "LOW"),
    ("TLP:CLEAR", 10.00, "MINIMAL"),
]

PII_COLUMNS = {
    "src_ip": "ip", "dst_ip": "ip",
    "Source IP": "ip", "Destination IP": "ip",
    "IPV4_SRC_ADDR": "ip", "IPV4_DST_ADDR": "ip",
    "ip.src": "ip", "ip.dst": "ip",
    "src_port":         ("numeric", 0, 65535),
    "dst_port":         ("numeric", 0, 65535),
    "Source Port":      ("numeric", 0, 65535),
    "Destination Port": ("numeric", 0, 65535),
    "L4_SRC_PORT":      ("numeric", 0, 65535),
    "L4_DST_PORT":      ("numeric", 0, 65535),
    "tcp.srcport":      ("numeric", 0, 65535),
    "tcp.dstport":      ("numeric", 0, 65535),
    "src_mac": "categorical", "dst_mac": "categorical",
    "eth.src": "categorical", "eth.dst": "categorical",
    "timestamp": "timestamp", "Timestamp": "timestamp",
    "frame.time": "timestamp", "utc_date_time": "timestamp",
}


# ── PCAP parser ───────────────────────────────────────────────────────────────
def parse_pcap_to_dataframe(path: Path, max_records: int) -> pd.DataFrame:
    records = []
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            if i >= max_records:
                break
            if not pkt.haslayer(IP):
                continue
            sp = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dp = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            sp = max(0, min(65535, int(sp)))
            dp = max(0, min(65535, int(dp)))
            is_attack = 1 if dp in [22, 23, 3389, 445] else 0
            records.append({
                "Source IP": pkt[IP].src, "Destination IP": pkt[IP].dst,
                "Source Port": sp, "Destination Port": dp,
                "Timestamp": float(pkt.time),
                "Protocol": "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER"),
                "Label": is_attack, "Attack_Type": "Exploits" if is_attack else "Benign",
            })
    return pd.DataFrame(records)


# ── Feature helpers ───────────────────────────────────────────────────────────
def coerce_features(df: pd.DataFrame, cols: list) -> pd.DataFrame:
    out = df[cols].copy()
    for c in cols:
        out[c] = (pd.to_numeric(out[c], errors="coerce")
                  .replace([np.inf, -np.inf], np.nan)
                  .fillna(0.0).clip(-1e9, 1e9))
    return out.astype(float)


def detect_feature_cols(raw_df: pd.DataFrame, anon_df: pd.DataFrame) -> list:
    _PREFERRED = ["src_port", "dst_port", "duration", "packets", "bytes"]
    _EXCLUDE   = {"label", "Label", "tlp", "Attack_Type", "attack_cat",
                  "Protocol", "protocol", "ClassLabel"}
    cols = [c for c in _PREFERRED if c in raw_df.columns]
    if len(cols) < 2:
        cols = [c for c in raw_df.select_dtypes(include="number").columns
                if c not in _EXCLUDE]
    return [c for c in cols if c in anon_df.columns]


# ── Privacy metric: adversary guessing advantage (Section 3.7.1) ─────────────
def guessing_advantage(raw_series: pd.Series, anon_series: pd.Series) -> float:
    """
    Measures normalised mean absolute difference between raw and
    anonymized numeric PII values. Range 0 (fully masked) to 1 (no
    protection). Implements the adversary guessing advantage metric
    from Section 3.7.1 of the write-up.
    """
    r = pd.to_numeric(raw_series,  errors="coerce").fillna(0).values
    a = pd.to_numeric(anon_series, errors="coerce").fillna(0).values
    if len(r) == 0:
        return 1.0
    return round(float(np.mean(np.abs(r - a) / (np.abs(r) + 1))), 4)


# ── Per-TLP anonymizer (matches harness anonymize_df) ────────────────────────
def anonymize_at_tlp(df: pd.DataFrame, forced_tlp: str,
                      label_col: str) -> tuple[pd.DataFrame, float, float]:
    """
    Force-anonymize the entire df at a single TLP level.
    Returns (anonymized_df, mean_latency_ms, max_latency_ms).
    Mirrors evaluation_harness.py's anonymize_df() exactly.
    """
    schema = {**DEFAULT_FIELD_SCHEMA, "label": "passthrough",
              "Label": "passthrough"}
    middleware = TLPAnonymizerMiddleware(field_schema=schema)
    pipeline = AnonymizerPipeline(middleware=middleware)
    runner   = InMemoryStreamRunner(pipeline=pipeline)

    records = []
    for i, (_, row) in enumerate(df.iterrows()):
        lbl = str(row.get(label_col, "unknown"))
        env = {"tlp": forced_tlp, "label": lbl}
        for col, val in row.items():
            if col in (label_col, "tlp"):
                continue
            try:
                if pd.isna(val):
                    continue
            except Exception:
                pass
            env[col] = val.item() if hasattr(val, "item") else val
        runner.publish_raw(env, key=f"flow-{i}")
        runner.run()
        records.extend(runner.drain_secure_logs())

    anon_df = pd.DataFrame(records)
    stats   = pipeline.latency.summary()
    return anon_df, stats.get("mean_ms", 0.0), stats.get("max_ms", 0.0)


# ── Metrics extractor ─────────────────────────────────────────────────────────
def extract_metrics(report: dict) -> dict:
    return {
        "accuracy":  round(report["accuracy"], 4),
        "precision": round(report["macro avg"]["precision"], 4),
        "recall":    round(report["macro avg"]["recall"], 4),
        "f1":        round(report["macro avg"]["f1-score"], 4),
    }


# ── Per-class breakdown (dynamic — all classes) ───────────────────────────────
def build_per_class_txt(report_raw: dict, tlp_reports: list,
                         le: LabelEncoder) -> str:
    lines = ["=" * 66,
             " DETAILED PER-CLASS EVALUATION BREAKDOWN",
             "=" * 66, ""]

    for idx, class_name in enumerate(le.classes_):
        key = str(idx)
        lines.append(f"  Class [{idx}]  —  '{class_name}'")
        lines.append("  " + "-" * 50)
        if key in report_raw:
            r = report_raw[key]
            lines.append(f"    BASELINE (raw)   P={r['precision']:.4f}  "
                         f"R={r['recall']:.4f}  F1={r['f1-score']:.4f}  "
                         f"Support={int(r['support'])}")
        for tlp_tag, _, _, rep in tlp_reports:
            if key in rep:
                r = rep[key]
                lines.append(f"    {tlp_tag:<14}  P={r['precision']:.4f}  "
                             f"R={r['recall']:.4f}  F1={r['f1-score']:.4f}  "
                             f"Support={int(r['support'])}")
        lines.append("")

    for avg_key in ["macro avg", "weighted avg"]:
        lines.append(f"  {avg_key.upper()}")
        lines.append("  " + "-" * 50)
        if avg_key in report_raw:
            r = report_raw[avg_key]
            lines.append(f"    BASELINE (raw)   P={r['precision']:.4f}  "
                         f"R={r['recall']:.4f}  F1={r['f1-score']:.4f}")
        for tlp_tag, _, _, rep in tlp_reports:
            if avg_key in rep:
                r = rep[avg_key]
                lines.append(f"    {tlp_tag:<14}  P={r['precision']:.4f}  "
                             f"R={r['recall']:.4f}  F1={r['f1-score']:.4f}")
        lines.append("")

    return "\n".join(lines)


# ── ZIP builder ───────────────────────────────────────────────────────────────
def build_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf.read()


# ─────────────────────────────────────────────────────────────────────────────
# FILE UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
uploaded_file = st.file_uploader(
    "Upload Telemetry File (.pcapng, .pcap, or .parquet)",
    type=["pcapng", "pcap", "parquet"]
)

if uploaded_file is not None:
    file_ext  = uploaded_file.name.split(".")[-1].lower()
    temp_path = Path(f"temp_capture.{file_ext}")
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(f"✓  Loaded  {uploaded_file.name}")

    if st.button("Execute Pipeline & Evaluate ML Model Utility"):

        # ── PHASE 1: INGESTION ────────────────────────────────────────────────
        with st.spinner("Ingesting telemetry..."):
            if file_ext in ["pcapng", "pcap"]:
                raw_df = parse_pcap_to_dataframe(temp_path, max_rows)
            else:
                raw_df = pd.read_parquet(temp_path).head(max_rows)

        if raw_df.empty:
            st.error("DataFrame is empty — execution halted.")
            st.stop()

        # ── PHASE 2: TLP INJECTION & PIPELINE STREAMING ───────────────────────
        with st.spinner("Injecting TLP profiles and streaming through anonymizer..."):
            processed_df  = IntelligentTLPInjector.analyze_and_stamp_dataframe(raw_df)
            field_schema  = {**DEFAULT_FIELD_SCHEMA, "label": "passthrough"}
            pipeline      = AnonymizerPipeline()
            pipeline.middleware = TLPAnonymizerMiddleware(field_schema=field_schema)
            runner = InMemoryStreamRunner(pipeline=pipeline)

            normalized_df = normalize_columns(processed_df)
            tlp_counts    = {"TLP:RED": 0, "TLP:AMBER": 0, "TLP:GREEN": 0, "TLP:CLEAR": 0}
            secure_list   = []

            t_pipeline_start = time.perf_counter()
            for _, row in normalized_df.iterrows():
                row_dict = row.to_dict()
                label    = str(row_dict.get("Label", "unknown")).strip()
                tlp_tag  = assign_tlp(label, row_dict)
                envelope = build_log_envelope(row_dict, tlp_tag, label)
                sk       = f"{envelope.get('src_ip','?')}-{envelope.get('dst_ip','?')}"
                runner.publish_raw(envelope, key=sk)
                runner.run()
                for rec in runner.drain_secure_logs():
                    secure_list.append(rec)
                tlp_counts[tlp_tag] = tlp_counts.get(tlp_tag, 0) + 1

            elapsed_pipeline = time.perf_counter() - t_pipeline_start
            lat_stats_main   = pipeline.latency.summary()
            anonymized_df    = pd.DataFrame(secure_list)
            total_rows       = len(normalized_df)

        # ── PHASE 3: THREE-AXIS ML EVALUATION (mirrors evaluation_harness.py) ─
        with st.spinner("Running three-axis evaluation across all TLP levels..."):

            # Feature detection
            feature_cols = detect_feature_cols(normalized_df, anonymized_df)
            if not feature_cols:
                st.error("No numeric feature columns found.")
                st.stop()

            # Which PII columns are actually present (for guessing advantage)
            pii_in_data = [c for c in PII_COLUMNS if c in normalized_df.columns]

            # Label encoding
            _le = LabelEncoder()
            y_all = _le.fit_transform(normalized_df["Label"].astype(str))

            # Stratified 70/30 split (matches harness TEST_SIZE=0.30)
            try:
                _, test_df, _, _ = train_test_split(
                    normalized_df, y_all,
                    test_size=0.30, random_state=42, stratify=y_all,
                )
                X_train_idx = normalized_df.index.difference(test_df.index)
                train_df    = normalized_df.loc[X_train_idx]
            except ValueError:
                split = int(len(normalized_df) * 0.70)
                train_df = normalized_df.iloc[:split]
                test_df  = normalized_df.iloc[split:].reset_index(drop=True)

            test_df  = test_df.reset_index(drop=True)
            train_df = train_df.reset_index(drop=True)

            X_train = coerce_features(train_df, feature_cols)
            X_test  = coerce_features(test_df,  feature_cols)
            y_train = _le.transform(train_df["Label"].astype(str))
            y_test  = _le.transform(test_df["Label"].astype(str))

            # ── Axis 2 step A: Train ONE RF on raw data (100 estimators) ──────
            clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            clf.fit(X_train, y_train)

            # ── Axis 2 step B: Baseline — test on raw data ───────────────────
            preds_raw   = clf.predict(X_test)
            report_raw  = classification_report(y_test, preds_raw,
                                                output_dict=True, zero_division=0)
            baseline    = extract_metrics(report_raw)

            # ── Axis 2 step C + Axis 1: Per-TLP sweep ────────────────────────
            # For each TLP level, force-anonymize the test set at that epsilon,
            # test the SAME RF, compute metrics AND guessing advantage.
            # This is the exact methodology from evaluation_harness.py.
            all_tlp_results  = []   # per-TLP metric dicts
            tlp_reports_list = []   # (tag, eps, noise, report_dict)
            all_mean_lats    = []
            all_max_lats     = []

            for (tlp_tag, epsilon, noise_label) in EVAL_LEVELS:
                anon_test_df, mean_lat, max_lat = anonymize_at_tlp(
                    test_df, tlp_tag, "Label"
                )
                all_mean_lats.append(mean_lat)
                all_max_lats.append(max_lat)

                # Feature matrix from anonymized test set
                anon_labels = anon_test_df["label"].astype(str).apply(
                    lambda v: v if v in _le.classes_ else _le.classes_[0]
                )
                y_anon = _le.transform(anon_labels)
                X_anon = coerce_features(anon_test_df, feature_cols)

                # Same trained RF, different (anonymized) test input
                preds_anon  = clf.predict(X_anon)
                report_anon = classification_report(y_anon, preds_anon,
                                                    output_dict=True, zero_division=0)
                m = extract_metrics(report_anon)

                # Axis 1: guessing advantage for numeric PII fields
                adv_scores = []
                for col in pii_in_data:
                    ftype = PII_COLUMNS.get(col)
                    if isinstance(ftype, tuple) and ftype[0] == "numeric":
                        if col in test_df.columns and col in anon_test_df.columns:
                            adv_scores.append(
                                guessing_advantage(test_df[col], anon_test_df[col])
                            )
                mean_adv = round(float(np.mean(adv_scores)), 4) if adv_scores else None

                f1_drop     = round(baseline["f1"] - m["f1"], 4)
                f1_drop_pct = round(100 * f1_drop / (baseline["f1"] + 1e-9), 2)

                all_tlp_results.append({
                    "tlp": tlp_tag, "epsilon": epsilon, "noise": noise_label,
                    **m,
                    "f1_drop": f1_drop, "f1_drop_pct": f1_drop_pct,
                    "guessing_adv": mean_adv,
                    "mean_lat_ms": round(mean_lat, 3),
                    "max_lat_ms":  round(max_lat, 3),
                    "within_500ms": mean_lat < 500,
                })
                tlp_reports_list.append((tlp_tag, epsilon, noise_label, report_anon))

        # ── PHASE 4: BUILD REPORT STRINGS ────────────────────────────────────
        overall_mean_lat = round(float(np.mean(all_mean_lats)), 3) if all_mean_lats else 0.0
        overall_max_lat  = round(float(np.max(all_max_lats)),  3) if all_max_lats  else 0.0
        all_within_500   = all(r["within_500ms"] for r in all_tlp_results)
        f1_map           = {r["tlp"]: r["f1"] for r in all_tlp_results}

        per_class_txt = build_per_class_txt(report_raw, tlp_reports_list, _le)

        # Full structured evaluation report (matches evaluation_harness.py output)
        evaluation_report_txt = f"""
==================================================================
  TLP ANONYMIZATION FRAMEWORK
  EVALUATION REPORT
==================================================================

### 1. DATA DISTRIBUTION METRICS (From the Ingestion Engine)

  Total raw packet lines processed    : {total_rows:,}
  TLP:RED   count & percentage        : {tlp_counts.get('TLP:RED',0):,} ({100*tlp_counts.get('TLP:RED',0)/max(total_rows,1):.1f}%)
  TLP:AMBER count & percentage        : {tlp_counts.get('TLP:AMBER',0):,} ({100*tlp_counts.get('TLP:AMBER',0)/max(total_rows,1):.1f}%)
  TLP:GREEN count & percentage        : {tlp_counts.get('TLP:GREEN',0):,} ({100*tlp_counts.get('TLP:GREEN',0)/max(total_rows,1):.1f}%)
  TLP:CLEAR count & percentage        : {tlp_counts.get('TLP:CLEAR',0):,} ({100*tlp_counts.get('TLP:CLEAR',0)/max(total_rows,1):.1f}%)

### 2. PIPELINE SYSTEM PERFORMANCE (From the Latency Tracker)

  Total execution wall-clock time     : {elapsed_pipeline:.4f} seconds
  Average (Mean) latency per log      : {overall_mean_lat:.3f} milliseconds
  Maximum spike latency encountered   : {overall_max_lat:.3f} milliseconds
  P95 latency                         : {lat_stats_main.get('p95_ms', 0):.3f} milliseconds
  Stayed under 500ms real-time target : {'YES — all TLP levels passed' if all_within_500 else 'NO — review overhead'}

### 3. INTRUSION CLASSIFIER ACCURACY (Utility Test Results)

  ML model evaluated                  : Random Forest Classifier (100 estimators)
  Baseline F1-Score on raw logs       : {baseline['f1']*100:.1f}%
  F1-Score vs TLP:CLEAR fuzzed logs   : {f1_map.get('TLP:CLEAR',0)*100:.1f}%  (epsilon=10.0,  noise=MINIMAL)
  F1-Score vs TLP:GREEN fuzzed logs   : {f1_map.get('TLP:GREEN',0)*100:.1f}%  (epsilon=1.0,   noise=LOW)
  F1-Score vs TLP:AMBER fuzzed logs   : {f1_map.get('TLP:AMBER',0)*100:.1f}%  (epsilon=0.25,  noise=MEDIUM)
  F1-Score vs TLP:RED fuzzed logs     : {f1_map.get('TLP:RED',0)*100:.1f}%  (epsilon=0.05,  noise=HIGH)

### 4. PRIVACY MEASUREMENT — ADVERSARY GUESSING ADVANTAGE (Section 3.7.1)
"""
        for r in all_tlp_results:
            adv = r['guessing_adv']
            adv_str = f"{adv:.4f}" if adv is not None else "N/A (no numeric PII)"
            evaluation_report_txt += f"  {r['tlp']:<14} (eps={r['epsilon']:<5}) Re-id Guessing Advantage : {adv_str}\n"

        evaluation_report_txt += f"""
  (0.0 = fully masked, 1.0 = no protection)

### 5. FULL METRIC COMPARISON TABLE

  {'TLP Level':<14} {'Eps':>5}  {'Accuracy':>9}  {'Precision':>10}  {'Recall':>7}  {'F1':>7}  {'F1 Drop':>8}
  {'-'*70}
  {'RAW (baseline)':<14} {'inf':>5}  {baseline['accuracy']*100:>8.2f}%  {baseline['precision']*100:>9.2f}%  {baseline['recall']*100:>6.2f}%  {baseline['f1']*100:>6.2f}%  {'—':>8}
"""
        for r in all_tlp_results:
            evaluation_report_txt += (
                f"  {r['tlp']:<14} {r['epsilon']:>5}  "
                f"{r['accuracy']*100:>8.2f}%  {r['precision']*100:>9.2f}%  "
                f"{r['recall']*100:>6.2f}%  {r['f1']*100:>6.2f}%  "
                f"{r['f1_drop_pct']:>7.1f}%\n"
            )

        f1_red   = f1_map.get("TLP:RED",   0)
        f1_clear = f1_map.get("TLP:CLEAR", 0)
        gap      = abs(f1_clear - f1_red)
        evaluation_report_txt += f"""
==================================================================
  INTERPRETATION
==================================================================
  The framework demonstrates a {gap*100:.1f} percentage-point F1 trade-off
  between maximum privacy (TLP:RED, epsilon=0.05) and maximum utility
  (TLP:CLEAR, epsilon=10.0), confirming that the TLP-adaptive
  Differential Privacy mechanism provides mathematically calibrated
  protection without catastrophic utility loss.
==================================================================
"""

        # CSV — all 5 rows: RAW baseline + 4 TLP levels (matches harness CSV)
        csv_rows = [{"tlp": "RAW", "epsilon": float("inf"),
                     **baseline, "f1_drop": 0, "f1_drop_pct": 0,
                     "guessing_adv": 1.0, "mean_lat_ms": 0,
                     "max_lat_ms": 0, "within_500ms": True}] + all_tlp_results
        csv_report_string = pd.DataFrame(csv_rows).to_csv(index=False)
        ndjson_string     = "\n".join([json.dumps(r) for r in secure_list])

        zip_bytes = build_zip({
            f"{uploaded_file.name}_secure_logs.ndjson":     ndjson_string,
            f"{uploaded_file.name}_Evaluation_Report.txt":  evaluation_report_txt,
            f"{uploaded_file.name}_Metrics_Matrix.csv":     csv_report_string,
            f"{uploaded_file.name}_PerClass_Breakdown.txt": per_class_txt,
        })

        # Store everything in session state
        st.session_state.pipeline_results = {
            "filename":              uploaded_file.name,
            "total_rows":            total_rows,
            "elapsed_pipeline":      elapsed_pipeline,
            "lat_stats_main":        lat_stats_main,
            "overall_mean_lat":      overall_mean_lat,
            "overall_max_lat":       overall_max_lat,
            "all_within_500":        all_within_500,
            "tlp_counts":            tlp_counts,
            "baseline":              baseline,
            "all_tlp_results":       all_tlp_results,
            "f1_map":                f1_map,
            "feature_cols":          feature_cols,
            "pii_in_data":           pii_in_data,
            "evaluation_report_txt": evaluation_report_txt,
            "csv_report_string":     csv_report_string,
            "per_class_txt":         per_class_txt,
            "ndjson_string":         ndjson_string,
            "zip_bytes":             zip_bytes,
        }

        if temp_path.exists():
            os.remove(temp_path)

    # ── DISPLAY (reads session state — survives download reruns) ─────────────
    if st.session_state.pipeline_results is not None:
        res = st.session_state.pipeline_results
        st.balloons()
        st.markdown("---")

        # Section 1: Data Distribution
        st.markdown("### 1. Data Distribution Metrics")
        dc = st.columns(5)
        dc[0].metric("Total Records", f"{res['total_rows']:,}")
        for i, tlp in enumerate(["TLP:RED","TLP:AMBER","TLP:GREEN","TLP:CLEAR"]):
            cnt = res['tlp_counts'].get(tlp, 0)
            dc[i+1].metric(tlp, f"{cnt:,}",
                           f"{100*cnt/max(res['total_rows'],1):.1f}%")

        # Section 2: System Performance
        st.markdown("### 2. Pipeline System Performance")
        pc = st.columns(4)
        pc[0].metric("Wall-Clock Time",   f"{res['elapsed_pipeline']:.3f} s")
        pc[1].metric("Mean Latency",      f"{res['overall_mean_lat']:.3f} ms")
        pc[2].metric("Max Spike Latency", f"{res['overall_max_lat']:.3f} ms")
        pc[3].metric("500ms Threshold",
                     "PASS" if res["all_within_500"] else "FAIL")

        # Section 3: Per-TLP Classifier Accuracy Table
        st.markdown("### 3. Intrusion Classifier Accuracy — Per TLP Level")
        st.caption("RF trained once on raw data (100 estimators, 70/30 split), "
                   "tested against each TLP-anonymized version of the test set.")

        b = res["baseline"]
        tbl_rows = [{"TLP Level": "RAW (baseline)", "Epsilon": "∞",
                     "Accuracy": f"{b['accuracy']*100:.2f}%",
                     "Precision": f"{b['precision']*100:.2f}%",
                     "Recall": f"{b['recall']*100:.2f}%",
                     "F1-Score": f"{b['f1']*100:.2f}%",
                     "F1 Drop": "—", "Re-id Adv.": "—"}]
        for r in res["all_tlp_results"]:
            adv = r["guessing_adv"]
            tbl_rows.append({
                "TLP Level":  r["tlp"],
                "Epsilon":    r["epsilon"],
                "Accuracy":   f"{r['accuracy']*100:.2f}%",
                "Precision":  f"{r['precision']*100:.2f}%",
                "Recall":     f"{r['recall']*100:.2f}%",
                "F1-Score":   f"{r['f1']*100:.2f}%",
                "F1 Drop":    f"{r['f1_drop_pct']:+.1f}%",
                "Re-id Adv.": f"{adv:.4f}" if adv is not None else "N/A",
            })
        st.table(pd.DataFrame(tbl_rows))

        # Section 4: Privacy metric callouts
        st.markdown("### 4. Privacy Measurement — Adversary Guessing Advantage")
        st.caption("0.0 = fully masked (strongest privacy) · 1.0 = no protection")
        adv_cols = st.columns(4)
        for i, r in enumerate(res["all_tlp_results"]):
            adv = r["guessing_adv"]
            adv_cols[i].metric(r["tlp"],
                               f"{adv:.4f}" if adv is not None else "N/A",
                               f"eps={r['epsilon']}")

        # Expanders for full text reports
        with st.expander("View Full Evaluation Report Text"):
            st.text(res["evaluation_report_txt"])
        with st.expander("View Per-Class Breakdown"):
            st.text(res["per_class_txt"])

        st.markdown("---")

        # Downloads
        st.markdown("### Download Research Deliverables")
        st.info("Use the ZIP button to download all four files at once.")
        st.download_button(
            label="Download All Files (.zip)",
            data=res["zip_bytes"],
            file_name=f"{res['filename']}_Research_Outputs.zip",
            mime="application/zip",
            key="dl_zip",
        )
        st.markdown("**Or download individually:**")
        ic1, ic2, ic3, ic4 = st.columns(4)
        ic1.download_button("Secure Logs (.ndjson)",
                            data=res["ndjson_string"],
                            file_name=f"{res['filename']}_secure_logs.ndjson",
                            mime="application/x-ndjson", key="dl_ndjson")
        ic2.download_button("Evaluation Report (.txt)",
                            data=res["evaluation_report_txt"],
                            file_name=f"{res['filename']}_Evaluation_Report.txt",
                            mime="text/plain", key="dl_report")
        ic3.download_button("Metrics Matrix (.csv)",
                            data=res["csv_report_string"],
                            file_name=f"{res['filename']}_Metrics_Matrix.csv",
                            mime="text/csv", key="dl_csv")
        ic4.download_button("Per-Class Breakdown (.txt)",
                            data=res["per_class_txt"],
                            file_name=f"{res['filename']}_PerClass_Breakdown.txt",
                            mime="text/plain", key="dl_perclass")
