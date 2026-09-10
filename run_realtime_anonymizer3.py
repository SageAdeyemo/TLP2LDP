r"""
run_realtime_anonymizer.py

=============================================================================
 END-TO-END REAL-TIME ANONYMIZER — INTEGRATED WORKFLOW FIX
=============================================================================
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

import pandas as pd

# Make sure the other modules in this project are importable regardless
# of where the script is invoked from.
sys.path.insert(0, str(Path(__file__).parent))

from kafka_pipeline import AnonymizerPipeline, InMemoryStreamRunner, LatencyTracker
from tlp_anonymizer import TLPAnonymizerMiddleware


# =============================================================================
# ① CONFIGURE YOUR FILE PATH HERE
# =============================================================================
PARQUET_FILE_PATH = r"C:\Users\A\Downloads\NF-UNSW-NB15-V2.parquet\NF-UNSW-NB15-V2.parquet"


# =============================================================================
# ② COLUMN MAP
# =============================================================================
COLUMN_MAP = {
    "Source IP":            "src_ip",       
    "Destination IP":       "dst_ip",
    "Source Port":          "src_port",
    "Destination Port":     "dst_port",
    "Timestamp":            "timestamp",
    "Flow Duration":        "duration",
    "Total Fwd Packets":    "packets",
    "Total Length of Fwd Packets": "bytes",
}


# =============================================================================
# ③ LABEL COLUMN
# =============================================================================
LABEL_COLUMN = "Label"


# =============================================================================
# OPTIONAL TUNING KNOBS
# =============================================================================
BATCH_SIZE    = None     
MAX_ROWS      = 10_000      
OUTPUT_FILE   = "secure_logs.ndjson"
PROGRESS_EVERY = 500      


# =============================================================================
# TLP ASSIGNMENT LOGIC WITH LIVE TRAFFIC FALLBACKS
# =============================================================================
LABEL_TO_TLP: dict[str, str] = {
    "BENIGN":                  "TLP:CLEAR",
    "Benign":                  "TLP:CLEAR",
    "benign":                  "TLP:CLEAR",
    "normal":                  "TLP:CLEAR",

    "DoS Hulk":                "TLP:CLEAR",
    "DoS GoldenEye":           "TLP:CLEAR",
    "DoS slowloris":           "TLP:CLEAR",
    "DoS Slowhttptest":        "TLP:CLEAR",
    "DDoS":                    "TLP:GREEN",

    "PortScan":                "TLP:AMBER",
    "FTP-Patator":             "TLP:AMBER",
    "SSH-Patator":             "TLP:AMBER",
    "Brute Force":             "TLP:AMBER",
    "Heartbleed":              "TLP:AMBER",
    "Web Attack – Brute Force":     "TLP:AMBER",
    "Web Attack – XSS":             "TLP:AMBER",
    "Web Attack – Sql Injection":   "TLP:AMBER",

    "Infiltration":            "TLP:RED",
    "Bot":                     "TLP:RED",
}
DEFAULT_TLP_FOR_UNKNOWN = "TLP:AMBER"   


def assign_tlp(label: str, row_dict: dict) -> str:
    """
    Return a TLP 2.0 tag for a given label. If unmapped or handling raw live PCAP, 
    evaluates destination ports to distribute traffic dynamically.
    """
    cleaned_label = str(label).strip()
    
    # 1. If it matches a known laboratory dataset label, use it
    if cleaned_label in LABEL_TO_TLP:
        return LABEL_TO_TLP[cleaned_label]
        
    # 2. LIVE TRAFFIC FALLBACK: Handle raw Wireshark network packet layouts
    # Normalize keys to check destination port variants
    r_norm = {str(k).lower().strip(): v for k, v in row_dict.items()}
    dst_port_raw = r_norm.get("destination port", r_norm.get("dst_port", r_norm.get("tcp.dstport", 0)))
    
    try:
        dst_port = int(float(dst_port_raw))
    except (ValueError, TypeError):
        dst_port = 0

    if dst_port in [3389, 445, 1433, 3306]: # Management / DB targets
        return "TLP:RED"
    elif dst_port in [22, 23, 21, 80]:     # Unencrypted Management / Legacy Web
        return "TLP:AMBER"
    elif dst_port in [53, 443, 853]:        # Commodity DNS/HTTPS traffic
        return "TLP:CLEAR"
        
    return DEFAULT_TLP_FOR_UNKNOWN


# =============================================================================
# COLUMN NORMALIZATION
# =============================================================================
def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    rename = {k.strip(): v for k, v in COLUMN_MAP.items()}
    return df.rename(columns=rename)


# =============================================================================
# LOG ENVELOPE BUILDER (WITH TIMESTAMP SERIALIZATION FIX)
# =============================================================================
def build_log_envelope(row: dict, tlp: str, label: str) -> dict:
    """
    Convert a single Parquet row into the JSON envelope format.
    Intercepts and converts non-serializable elements like Pandas Timestamps.
    """
    envelope: dict = {"tlp": tlp, "label": label}
    for key, value in row.items():
        if key in (LABEL_COLUMN, "tlp"):
            continue
            
        # --- FIX: Drop missing/NaN values early to clean up parsing strings
        if pd.isna(value) if not isinstance(value, (str, list, dict)) else False:
            continue
            
        # --- FIX: Convert Pandas Timestamps or Datetime entries to strings
        if hasattr(value, "isoformat") or type(value).__name__ in ["Timestamp", "datetime"]:
            envelope[key] = value.isoformat()
            continue
            
        # Cast numpy scalars to native Python types for JSON serialization
        if hasattr(value, "item"):
            value = value.item()
            
        envelope[key] = value
    return envelope


# =============================================================================
# MAIN  —  real-time streaming anonymization
# =============================================================================
def main() -> None:
    parquet_path = Path(PARQUET_FILE_PATH)
    if not parquet_path.exists():
        print(f"[ERROR] Parquet file not found: {parquet_path.resolve()}")
        sys.exit(1)

    print("=" * 66)
    print(" TLP-Driven Real-Time Anonymizer")
    print("=" * 66)
    print(f"  Source      : {parquet_path.resolve()}")
    print(f"  Output      : {Path(OUTPUT_FILE).resolve()}")
    print(f"  Batch size  : {BATCH_SIZE:,} rows")
    print(f"  Max rows    : {MAX_ROWS if MAX_ROWS else 'all'}")
    print()

    # Initialise the pipeline 
    pipeline = AnonymizerPipeline()
    latency  = LatencyTracker()

    print("  Reading Parquet schema ...")
    raw_df = pd.read_parquet(parquet_path, engine="pyarrow")
    
    # IMPORT AND EXECUTE YOUR NEW INTELLIGENT HOOK BEFORE PROCESSING CHUNKS
    from tlp_injector import IntelligentTLPInjector
    print("  Executing Intelligent TLP Policy Assignment Engine...")
    processed_df = IntelligentTLPInjector.analyze_and_stamp_dataframe(raw_df)
    
    # Use the processed dataframe structure to map your schema columns
    schema_df = normalize_columns(processed_df.head(0))
    print(f"  Columns found ({len(schema_df.columns)}): {list(schema_df.columns)}")

    from tlp_anonymizer import DEFAULT_FIELD_SCHEMA
    field_schema = {**DEFAULT_FIELD_SCHEMA, "label": "passthrough"}
    pipeline.middleware = TLPAnonymizerMiddleware(field_schema=field_schema)
    runner = InMemoryStreamRunner(pipeline=pipeline)

    import pyarrow.parquet as pq
    print("  Reading Parquet schema ...")
    schema_df = normalize_columns(
        pd.read_parquet(parquet_path, engine="pyarrow").head(0)
    )
    print(f"  Columns found ({len(schema_df.columns)}): {list(schema_df.columns)}")

    mapped = [v for k, v in COLUMN_MAP.items()
              if k.strip() in schema_df.columns or v in schema_df.columns]
    print(f"  Mapped PII fields : {mapped}")
    print()

  # ── Streaming loop ───────────────────────────────────────────────
    t_wall_start   = time.perf_counter()
    total_rows     = 0
    tlp_counts: dict[str, int] = {}
    output_path = Path(OUTPUT_FILE)

    print("  Loading and processing raw Parquet telemetry array...")
    raw_file_df = pd.read_parquet(parquet_path)
    
    # Run the intelligent taxonomy mapping fix here
    from tlp_injector import IntelligentTLPInjector
    print("  Enforcing programmatic TLP distribution matrix...")
    stamped_df = IntelligentTLPInjector.analyze_and_stamp_dataframe(raw_file_df)

    # Hard-cap rows if MAX_ROWS knob is active
    if MAX_ROWS:
        stamped_df = stamped_df.head(MAX_ROWS)

    # Normalize the output columns to fit pipeline expectations
    normalized_df = normalize_columns(stamped_df)

    print("[*] Streaming records into middleware processing topics...")
    with output_path.open("w", encoding="utf-8") as out_fh:
        # Process the records as an in-memory batch stream
        for _, row in normalized_df.iterrows():
            row_dict = row.to_dict()
            label    = str(row_dict.get(LABEL_COLUMN, "unknown")).strip()
            
            # Resolve tags cleanly
            tlp_tag  = assign_tlp(label, row_dict)
            envelope = build_log_envelope(row_dict, tlp_tag, label)

            stream_key = f"{envelope.get('src_ip', 'unknown')}-{envelope.get('dst_ip', 'unknown')}"
            runner.publish_raw(envelope, key=stream_key)

            t0 = time.perf_counter()
            runner.run()
            t1 = time.perf_counter()
            latency.record(t0, t1)

            secure_records = runner.drain_secure_logs()
            for rec in secure_records:
                out_fh.write(json.dumps(rec) + "\n")

            tlp_counts[tlp_tag] = tlp_counts.get(tlp_tag, 0) + 1
            total_rows += 1

            if total_rows % PROGRESS_EVERY == 0:
                elapsed = time.perf_counter() - t_wall_start
                rps     = total_rows / elapsed
                stats   = latency.summary()
                print(
                    f"  [{total_rows:>7,}] "
                    f"{rps:>7.0f} rec/s  "
                    f"mean_lat={stats.get('mean_ms', 0):.2f}ms  "
                    f"TLP={tlp_counts}"
                )

    elapsed_total = time.perf_counter() - t_wall_start
    stats = latency.summary()

    print()
    print("=" * 66)
    print(" PIPELINE COMPLETE")
    print("=" * 66)
    print(f"  Records processed : {total_rows:,}")
    print(f"  Wall-clock time   : {elapsed_total:.2f}s  "
          f"({total_rows / elapsed_total:.0f} records/sec)")
    print(f"  Output file       : {output_path.resolve()}")
    print()
    print("  TLP distribution (synthetic injection):")
    for tlp, count in sorted(tlp_counts.items()):
        pct = 100 * count / total_rows if total_rows else 0
        print(f"    {tlp:<12}  {count:>7,}  ({pct:.1f}%)")
    print()
    print("  Latency summary (Δt = t_export − t_ingest):")
    for k, v in stats.items():
        print(f"    {k:<20} {v}")
    print()
    if stats.get("within_threshold"):
        print("  ✓  Mean latency is within the 500ms operational threshold")
    else:
        print("  ✗  Mean latency EXCEEDED 500ms — review pipeline overhead")
    print()


if __name__ == "__main__":
    main()