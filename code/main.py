#!/usr/bin/env python3
"""
Main entrypoint for the Automated Deletion Audit Agent.
Evaluates deletion requests against multi-service evidence stores and outputs output.csv.
"""

import argparse
import os
import sys
import time
import pandas as pd

# Add code directory to path
code_dir = os.path.dirname(os.path.abspath(__file__))
if code_dir not in sys.path:
    sys.path.insert(0, code_dir)

from audit_engine import DeletionAuditEngine


def parse_args():
    parser = argparse.ArgumentParser(description="Run Automated Deletion Audit Pipeline")
    parser.add_argument(
        "--input",
        "-i",
        default=None,
        help="Path to deletion requests CSV (default: dataset/deletion_requests.csv)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Path to output CSV (default: output.csv at repo root)",
    )
    parser.add_argument(
        "--repo-root",
        "-r",
        default=None,
        help="Repository root directory (default: auto-detected)",
    )
    return parser.parse_args()


def main():
    start_time = time.time()
    args = parse_args()

    repo_root = args.repo_root or os.path.abspath(os.path.join(code_dir, ".."))
    input_path = args.input or os.path.join(repo_root, "dataset", "deletion_requests.csv")
    output_path = args.output or os.path.join(repo_root, "output.csv")

    print("=" * 60)
    print("Automated Deletion Audit Pipeline")
    print(f"Repo Root  : {repo_root}")
    print(f"Input File : {input_path}")
    print(f"Output File: {output_path}")
    print("=" * 60)

    # 1. Initialize Audit Engine
    print("\n[1/3] Initializing Deletion Audit Engine and building indexes...")
    engine = DeletionAuditEngine(repo_root)

    # 2. Load Requests
    print(f"\n[2/3] Loading deletion requests from {input_path}...")
    requests_df = pd.read_csv(input_path)
    total_cases = len(requests_df)
    print(f"Loaded {total_cases} requests to evaluate.")

    # 3. Execute Audit Engine
    print("\n[3/3] Evaluating cases and generating remediation steps...")
    results_df = engine.run_all(requests_df)

    # Sort results by numeric case ID
    def sort_key(cid):
        try:
            return int(str(cid).split("_")[1])
        except (IndexError, ValueError):
            return 999999

    results_df["_sort_key"] = results_df["case_id"].apply(sort_key)
    results_df = results_df.sort_values("_sort_key").drop(columns=["_sort_key"]).reset_index(drop=True)

    # Ensure output columns exact match: case_id, deletion_status, steps_json
    results_df = results_df[["case_id", "deletion_status", "steps_json"]]

    # Save output CSV
    results_df.to_csv(output_path, index=False)
    elapsed = time.time() - start_time

    print(f"\nSuccessfully wrote {len(results_df)} evaluated cases to {output_path}")
    status_counts = results_df["deletion_status"].value_counts().to_dict()
    print("Summary of Results:")
    for status, count in status_counts.items():
        print(f"  {status:15s}: {count:4d} ({count / total_cases * 100:.1f}%)")
    print(f"Total processing time: {elapsed:.2f} seconds ({elapsed / total_cases * 1000:.1f} ms/case)")
    print("=" * 60)


if __name__ == "__main__":
    main()
