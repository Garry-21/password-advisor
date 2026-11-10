"""Targeted guessing evaluation harness (E3)."""
import warnings
warnings.warn("Legacy exploratory harness: do not use its outputs as independent review evidence. Use scripts/review_experiments.py or scripts/review_performance.py; see docs/REVIEW1_CHANGES.md.", RuntimeWarning)
import argparse
import csv
import itertools
import os
import sys
import numpy as np
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc, brier_score_loss

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from modules.semantic import calculate_thematic_coverage
from modules.syntactic import evaluate_syntactic_strength
from vault.models import Profile, Entry
from vault.audit import AuditConfig, calculate_risk_score

from rapidfuzz import fuzz
import re

COMMON_WORDS = ["password", "123456", "welcome", "admin", "qwerty", "dragon", "football", "monkey", "secret", "master", "summer", "winter"]
SUFFIXES = ["", "1", "!", "123", "123!", "1!", "2024", "2025", "@", "#", "99", "12"]

def s1_guesses(budget=1000):
    candidates = [f"{w}{s}" for w in COMMON_WORDS for s in SUFFIXES]
    return candidates[:budget]

def s2_guesses(prof, budget=1000):
    tokens = [prof.first_name, prof.surname, prof.city, str(prof.birth_year), str(prof.birth_year)[-2:], prof.theme]
    guesses = [f"{t}{s}" for t in tokens for s in SUFFIXES] + [f"{t}{s}!" for t in tokens for s in SUFFIXES]
    for t1, t2 in itertools.permutations(tokens, 2):
        guesses.extend([f"{t1}{t2}", f"{t1}{t2}!", f"{t1}_{t2}"])
    return list(dict.fromkeys(guesses))[:budget]

def s3_guesses(prev_pwd, budget=1000):
    guesses = [prev_pwd, prev_pwd.lower(), prev_pwd.upper(), prev_pwd.capitalize()]
    for s in SUFFIXES:
        guesses.extend([f"{prev_pwd}{s}", f"{prev_pwd.strip('!@#123')}{s}"])
    for m in re.finditer(r"\d{4}", prev_pwd):
        y = int(m.group())
        for dy in [-1, 1, 2]:
            guesses.append(prev_pwd[:m.start()] + str(y + dy) + prev_pwd[m.end():])
    return list(dict.fromkeys(guesses))[:budget]

def s4_guesses(prof, prev_pwd, budget=1000):
    g2 = s2_guesses(prof, budget=budget // 2)
    g3 = s3_guesses(prev_pwd, budget=budget // 2)
    combined = list(dict.fromkeys(g2 + g3))
    for t in [prof.first_name, prof.city, prof.surname, str(prof.birth_year)[-2:]]:
        combined.extend([f"{t}_{prev_pwd}", f"{prev_pwd}_{t}", f"{t}{prev_pwd}"])
    return list(dict.fromkeys(combined))[:budget]

def generate_e3_dataset(n_profiles=25, out_csv="results/e3_dataset.csv"):
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    from scripts.gen_benchmark import PROFILES
    rows = []
    for i, p in enumerate(PROFILES[:n_profiles]):
        pid = p["id"]
        prof_str = f"{p['first']}|{p['last']}|{p['city']}|{p['year']}|{p['theme']}"
        prev = f"Summer{p['year']}!"
        # Targets: S1-hit, S2-hit, S3-hit, S4-hit, Random strong
        rows.append((pid, prof_str, prev, "password123!", "S1"))
        rows.append((pid, prof_str, prev, f"{p['first']}{str(p['year'])[-2:]}!", "S2"))
        rows.append((pid, prof_str, prev, f"Summer{p['year']+1}!", "S3"))
        rows.append((pid, prof_str, prev, f"{p['city']}_{prev}", "S4"))
        rows.append((pid, prof_str, prev, f"kX9#mQ2${i}vL", "random"))
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["profile_id", "profile", "previous_password", "target_password", "category"])
        w.writerows(rows)
    return out_csv

def run_e3(input_csv="results/e3_dataset.csv", out_dir="results"):
    if not os.path.exists(input_csv):
        generate_e3_dataset(out_csv=input_csv)
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    with open(input_csv, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    y_true_all, cav_scores = [], []
    eval_records = []

    for r in rows:
        f, l, c, y, t = r["profile"].split("|")
        prof = Profile(first_name=f, surname=l, city=c, birth_year=int(y), theme=t)
        prev_pw = r["previous_password"]
        target = r["target_password"]

        # Check guessing under budgets
        g_s1_1k = target in s1_guesses(1000)
        g_s2_1k = target in s2_guesses(prof, 1000)
        g_s3_1k = target in s3_guesses(prev_pw, 1000)
        g_s4_1k = target in s4_guesses(prof, prev_pw, 1000)
        guessed_any = g_s1_1k or g_s2_1k or g_s3_1k or g_s4_1k
        y_true_all.append(1 if guessed_any else 0)

        # CAV Risk calculation
        breached = 1.0 if (target.lower() in {"password123!", "welcome2020", "123456", "dragon"} or target.lower().startswith("password")) else 0.0
        sem = calculate_thematic_coverage(target, prof)["score"]
        syn = 1.0 if evaluate_syntactic_strength(target)["score"] < 3 else 0.0
        ratio = fuzz.ratio(target.lower(), prev_pw.lower()) / 100.0
        deriv = ratio if ratio > 0.7 else 0.0
        risk = calculate_risk_score(b_i=breached, s_i=syn, C_i=sem, r_i=(1.0 if target == prev_pw else 0.0), d_i=deriv, a_i=0.0)
        cav_scores.append(risk)
        eval_records.append({"target": target, "category": r["category"], "guessed": guessed_any, "risk": risk})

    y_true, y_pred = np.array(y_true_all), np.array(cav_scores)
    roc_auc = roc_auc_score(y_true, y_pred) if len(set(y_true)) > 1 else 1.0
    p_cur, r_cur, _ = precision_recall_curve(y_true, y_pred)
    pr_auc, brier = auc(r_cur, p_cur), brier_score_loss(y_true, y_pred)
    bin_pred = (y_pred >= 0.35).astype(int)
    tp, fn = np.sum((y_true == 1) & (bin_pred == 1)), np.sum((y_true == 1) & (bin_pred == 0))
    fp, tn = np.sum((y_true == 0) & (bin_pred == 1)), np.sum((y_true == 0) & (bin_pred == 0))
    recall_guessed = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr_non_guessed = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Calibration by risk band
    bands = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)]
    calib_table = []
    for low, high in bands:
        idx = [i for i, s in enumerate(y_pred) if (low <= s < high or (high == 1.0 and s == 1.0))]
        n_band = len(idx)
        mean_risk = float(np.mean(y_pred[idx])) if n_band > 0 else 0.0
        obs_rate = float(np.mean(y_true[idx])) if n_band > 0 else 0.0
        calib_table.append({"band": f"{low:.1f}-{high:.1f}", "n": n_band, "mean_risk": mean_risk, "obs_rate": obs_rate})

    # Save CSV
    csv_path = os.path.join(out_dir, "e3_metrics.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        for k, v in [("roc_auc", roc_auc), ("pr_auc", pr_auc), ("brier_score", brier),
                    ("recall_on_guessed", recall_guessed), ("fpr_on_nonguessed", fpr_non_guessed)]:
            w.writerow([k, f"{v:.4f}"])

    # Save Markdown
    md_path = os.path.join(out_dir, "e3_table.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Experiment E3: Targeted Guessing Validation\n\n**ROC-AUC**: {roc_auc:.4f} | **PR-AUC**: {pr_auc:.4f} | **Brier Score**: {brier:.4f}\n\n**Recall on Guessed**: {recall_guessed:.3f} | **FPR on Non-Guessed**: {fpr_non_guessed:.3f}\n\n### Calibration by Risk Band\n\n| Risk Band | N | Mean Predicted Risk | Observed Guess Rate |\n|---|---|---|---|\n")
        for b in calib_table:
            f.write(f"| {b['band']} | {b['n']} | {b['mean_risk']:.3f} | {b['obs_rate']:.3f} |\n")

    print(f"E3 validation complete. ROC-AUC: {roc_auc:.4f}, PR-AUC: {pr_auc:.4f}, Brier: {brier:.4f}")
    print(f"Results saved to {csv_path} and {md_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Targeted Guessing Validation (E3)")
    parser.add_argument("--input", type=str, default="results/e3_dataset.csv")
    parser.add_argument("--out_dir", type=str, default="results")
    args = parser.parse_args()
    run_e3(input_csv=args.input, out_dir=args.out_dir)
