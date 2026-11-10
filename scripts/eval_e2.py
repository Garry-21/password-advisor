"""Evaluate CAV vs baselines and ablations (E2)."""
import argparse
import csv
import os
import sys
import numpy as np
from sklearn.metrics import precision_recall_curve, auc
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from modules.semantic import calculate_thematic_coverage
from vault.models import Profile, Entry
from scripts.gen_benchmark import PROFILES

PROFILE_MAP = {
    p["id"]: Profile(
        first_name=p["first"], surname=p["last"],
        city=p["city"], birth_year=p["year"], theme=p["theme"]
    ) for p in PROFILES
}

KNOWN_BREACHES = {"password123!", "welcome2020", "dragon999", "monkey1234", "masterpass1", "trustnoone1"}

def compute_metrics(y_true, y_scores, threshold=0.5):
    y_pred = [1 if s >= threshold else 0 for s in y_scores]
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    try:
        p_curve, r_curve, _ = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(r_curve, p_curve)
    except Exception:
        pr_auc = 0.0
    return prec, rec, f1, pr_auc, fpr

def extract_features(row):
    pid = row["profile_id"]
    prof = PROFILE_MAP[pid]
    pwd = row["password"]
    # Simulated existing vault for derivative/reuse
    sim_entry = Entry(id="0", site_name="Base", url="https://base.local", username="user",
                      password=f"Summer{prof.birth_year}!", created_at="2024-01-01T00:00:00")
    # Features
    import zxcvbn
    z_res = zxcvbn.zxcvbn(pwd)
    z_risk = (4 - z_res["score"]) / 4.0
    hibp_risk = 1.0 if pwd.lower() in KNOWN_BREACHES else 0.0
    sem_res = calculate_thematic_coverage(pwd, prof)
    sem_risk = sem_res["score"] if isinstance(sem_res, dict) else float(sem_res)
    reuse_risk = 1.0 if pwd == sim_entry.password else 0.0
    from rapidfuzz import fuzz
    ratio = fuzz.ratio(pwd.lower(), sim_entry.password.lower()) / 100.0
    deriv_risk = ratio if ratio > 0.7 else 0.0
    age_risk = 0.0
    return [hibp_risk, z_risk, sem_risk, reuse_risk, deriv_risk, age_risk]

def run_e2(benchmark_csv="results/benchmark.csv", out_dir="results"):
    os.makedirs(out_dir, exist_ok=True)
    train_feats, train_labels = [], []
    test_feats, test_labels, test_rows = [], [], []

    with open(benchmark_csv, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            y = 0 if row["category"] in ["random", "hard_negative"] else 1
            feats = extract_features(row)
            if row["split"] == "train":
                train_feats.append(feats)
                train_labels.append(y)
            else:
                test_feats.append(feats)
                test_labels.append(y)
                test_rows.append(row)

    # Train Calibrated Scorer
    clf = LogisticRegression(random_state=42)
    clf.fit(train_feats, train_labels)

    # Models & Ablations
    models = {
        "zxcvbn only": lambda f: f[1],
        "HIBP only": lambda f: f[0],
        "zxcvbn + HIBP": lambda f: 0.5 * f[0] + 0.5 * f[1],
        "personal only": lambda f: f[2],
        "history only": lambda f: max(f[3], f[4]),
        "Full CAV (Fixed)": lambda f: min(1.0, 0.40 * f[0] + 0.15 * f[1] + 0.20 * f[2] + 0.15 * f[3] + 0.10 * f[4]),
        "Full CAV (Calibrated)": lambda f: float(clf.predict_proba([f])[0][1]),
        "Ablation: -Personal": lambda f: min(1.0, 0.50 * f[0] + 0.20 * f[1] + 0.18 * f[3] + 0.12 * f[4]),
        "Ablation: -Derivative": lambda f: min(1.0, 0.45 * f[0] + 0.15 * f[1] + 0.25 * f[2] + 0.15 * f[3]),
        "Ablation: -zxcvbn": lambda f: min(1.0, 0.47 * f[0] + 0.24 * f[2] + 0.17 * f[3] + 0.12 * f[4]),
        "Ablation: -HIBP": lambda f: min(1.0, 0.25 * f[1] + 0.35 * f[2] + 0.25 * f[3] + 0.15 * f[4]),
    }

    results = []
    for name, fn in models.items():
        scores = [fn(f) for f in test_feats]
        prec, rec, f1, pr_auc, fpr = compute_metrics(test_labels, scores, threshold=0.45)
        results.append({"model": name, "precision": prec, "recall": rec, "f1": f1, "pr_auc": pr_auc, "fpr": fpr})

    # Save CSV
    csv_path = os.path.join(out_dir, "e2_metrics.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["model", "precision", "recall", "f1", "pr_auc", "fpr"])
        w.writeheader()
        for r in results:
            w.writerow({k: f"{r[k]:.4f}" if isinstance(r[k], float) else r[k] for k in r})

    # Save Markdown
    md_path = os.path.join(out_dir, "e2_table.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Experiment E2: Baseline Comparisons & Signal Ablations\n\n")
        f.write("| Model / Ablation | Precision | Recall | F1 Score | PR-AUC | FPR |\n|---|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['model']} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['pr_auc']:.3f} | {r['fpr']:.3f} |\n")

    print(f"E2 evaluation complete. Results saved to {csv_path} and {md_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CAV against baselines (E2)")
    parser.add_argument("--input", type=str, default="results/benchmark.csv")
    parser.add_argument("--out_dir", type=str, default="results")
    args = parser.parse_args()
    run_e2(benchmark_csv=args.input, out_dir=args.out_dir)
