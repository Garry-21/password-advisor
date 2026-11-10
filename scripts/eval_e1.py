"""Evaluate semantic personal-context detector on test split (E1)."""
import argparse
import csv
import os
import sys
import numpy as np

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from modules.semantic import calculate_thematic_coverage
from vault.models import Profile
from scripts.gen_benchmark import PROFILES

PROFILE_MAP = {
    p["id"]: Profile(
        first_name=p["first"], surname=p["last"],
        city=p["city"], birth_year=p["year"], theme=p["theme"]
    ) for p in PROFILES
}

def bootstrap_ci(records, n_bootstraps=1000, seed=42):
    rng = np.random.RandomState(seed)
    pids = list({r["profile_id"] for r in records})
    f1s = []
    for _ in range(n_bootstraps):
        sampled_pids = rng.choice(pids, size=len(pids), replace=True)
        sample = [r for pid in sampled_pids for r in records if r["profile_id"] == pid]
        tp = sum(1 for r in sample if r["y_true"] == 1 and r["y_pred"] == 1)
        fp = sum(1 for r in sample if r["y_true"] == 0 and r["y_pred"] == 1)
        fn = sum(1 for r in sample if r["y_true"] == 1 and r["y_pred"] == 0)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        f1s.append(f1)
    return float(np.percentile(f1s, 2.5)), float(np.percentile(f1s, 97.5))

def run_eval(input_csv="results/benchmark.csv", out_dir="results"):
    os.makedirs(out_dir, exist_ok=True)
    records = []
    with open(input_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["split"] == "test":
                pid = row["profile_id"]
                prof = PROFILE_MAP[pid]
                res = calculate_thematic_coverage(row["password"], prof)
                score = res["score"] if isinstance(res, dict) else float(res)
                y_pred = 1 if score > 0.0 else 0
                records.append({
                    "profile_id": pid,
                    "category": row["category"],
                    "y_true": int(row["label_personal"]),
                    "y_pred": y_pred,
                    "score": score
                })

    categories = sorted(list({r["category"] for r in records}))
    cat_metrics = []
    for cat in categories:
        sub = [r for r in records if r["category"] == cat]
        tp = sum(1 for r in sub if r["y_true"] == 1 and r["y_pred"] == 1)
        fp = sum(1 for r in sub if r["y_true"] == 0 and r["y_pred"] == 1)
        tn = sum(1 for r in sub if r["y_true"] == 0 and r["y_pred"] == 0)
        fn = sum(1 for r in sub if r["y_true"] == 1 and r["y_pred"] == 0)
        prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fp == 0 else 0.0)
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        cat_metrics.append({"category": cat, "n": len(sub), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                            "precision": prec, "recall": rec, "f1": f1, "fpr": fpr})

    tot_tp = sum(r["tp"] for r in cat_metrics)
    tot_fp = sum(r["fp"] for r in cat_metrics)
    tot_tn = sum(r["tn"] for r in cat_metrics)
    tot_fn = sum(r["fn"] for r in cat_metrics)
    tot_prec = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) > 0 else 0.0
    tot_rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 0.0
    tot_f1 = 2 * tot_prec * tot_rec / (tot_prec + tot_rec) if (tot_prec + tot_rec) > 0 else 0.0
    tot_fpr = tot_fp / (tot_fp + tot_tn) if (tot_fp + tot_tn) > 0 else 0.0
    ci_low, ci_high = bootstrap_ci(records)

    # Save CSV
    csv_path = os.path.join(out_dir, "e1_metrics.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "n", "precision", "recall", "f1", "fpr"])
        writer.writeheader()
        for c in cat_metrics:
            writer.writerow({k: f"{c[k]:.4f}" if isinstance(c[k], float) else c[k]
                             for k in ["category", "n", "precision", "recall", "f1", "fpr"]})
        writer.writerow({"category": "TOTAL", "n": len(records), "precision": f"{tot_prec:.4f}",
                         "recall": f"{tot_rec:.4f}", "f1": f"{tot_f1:.4f}", "fpr": f"{tot_fpr:.4f}"})

    # Save Markdown Table
    md_path = os.path.join(out_dir, "e1_table.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Experiment E1: Semantic Detector Evaluation\n\n")
        f.write(f"**Bootstrap 95% CI for F1**: [{ci_low:.4f}, {ci_high:.4f}]\n\n")
        f.write(f"**Confusion Matrix**: TP={tot_tp}, FP={tot_fp}, TN={tot_tn}, FN={tot_fn}\n\n")
        f.write("| Category | N | Precision | Recall | F1 | FPR |\n|---|---|---|---|---|---|\n")
        for c in cat_metrics:
            f.write(f"| {c['category']} | {c['n']} | {c['precision']:.3f} | {c['recall']:.3f} | {c['f1']:.3f} | {c['fpr']:.3f} |\n")
        f.write(f"| **Overall** | **{len(records)}** | **{tot_prec:.3f}** | **{tot_rec:.3f}** | **{tot_f1:.3f}** | **{tot_fpr:.3f}** |\n")

    print(f"E1 evaluation complete. Results saved to {csv_path} and {md_path}")
    print(f"Overall F1: {tot_f1:.4f} (95% CI: [{ci_low:.4f}, {ci_high:.4f}]), FPR: {tot_fpr:.4f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate semantic detector (E1)")
    parser.add_argument("--input", type=str, default="results/benchmark.csv")
    parser.add_argument("--out_dir", type=str, default="results")
    args = parser.parse_args()
    run_eval(input_csv=args.input, out_dir=args.out_dir)
