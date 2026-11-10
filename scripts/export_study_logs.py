"""Export and summarize study logs across conditions (G1-G4)."""
import argparse
import csv
import os
import numpy as np

def export_study_summary(input_csv="results/study_logs.csv", output_csv="results/study_summary.csv"):
    if not os.path.exists(input_csv):
        print(f"No study log file found at {input_csv}.")
        return

    records = []
    with open(input_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = list(reader)

    if not records:
        print("Study log file is empty.")
        return

    conditions = ["G1", "G2", "G3", "G4"]
    summary_rows = []

    print("\nStudy Evaluation Summary (STUDY_MODE=1)")
    print(f"{'Condition':<10} | {'Trials':<8} | {'Warnings':<10} | {'Override Rate':<15} | {'Adopt Alt Rate':<15} | {'Median(ms)':<10}")
    print("-" * 78)

    for cond in conditions:
        sub = [r for r in records if r["condition"] == cond]
        n_trials = len(sub)
        if n_trials == 0:
            summary_rows.append({"condition": cond, "trials": 0, "warnings": 0, "override_rate": 0.0, "adopt_alt_rate": 0.0, "median_time_ms": 0.0})
            continue

        warnings = sum(1 for r in sub if r["warning_shown"] in ("1", 1))
        overrides = sum(1 for r in sub if r["overridden"] in ("1", 1))
        adoptions = sum(1 for r in sub if r["accepted_alternative"] in ("1", 1))
        times = [float(r["time_ms"]) for r in sub if r.get("time_ms")]

        override_rate = (overrides / warnings) if warnings > 0 else 0.0
        adopt_rate = (adoptions / warnings) if warnings > 0 else 0.0
        med_time = float(np.median(times)) if times else 0.0

        summary_rows.append({
            "condition": cond,
            "trials": n_trials,
            "warnings": warnings,
            "override_rate": override_rate,
            "adopt_alt_rate": adopt_rate,
            "median_time_ms": med_time
        })
        print(f"{cond:<10} | {n_trials:<8} | {warnings:<10} | {override_rate * 100:<14.1f}% | {adopt_rate * 100:<14.1f}% | {med_time:<10.1f}")

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["condition", "trials", "warnings", "override_rate", "adopt_alt_rate", "median_time_ms"])
        writer.writeheader()
        for r in summary_rows:
            writer.writerow({
                "condition": r["condition"],
                "trials": r["trials"],
                "warnings": r["warnings"],
                "override_rate": f"{r['override_rate']:.4f}",
                "adopt_alt_rate": f"{r['adopt_alt_rate']:.4f}",
                "median_time_ms": f"{r['median_time_ms']:.1f}"
            })
    print(f"\nExported summary to {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export and summarize study logs")
    parser.add_argument("--input", type=str, default="results/study_logs.csv")
    parser.add_argument("--output", type=str, default="results/study_summary.csv")
    args = parser.parse_args()
    export_study_summary(args.input, args.output)

