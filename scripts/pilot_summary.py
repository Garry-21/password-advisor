"""
pilot_summary.py
----------------
Comprehensive evaluation script for:
1. Part 1: Vulnerability Detector Validation (on real_dataset.csv or scored dataset)
2. Part 2: Behavioral Pilot Study Analysis (on results.csv with A/B framing variants)
"""

import os
import sys
import pandas as pd
import numpy as np

# Try importing scipy and sklearn for inferential statistics and ML metrics
try:
    from scipy import stats
    from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
    STATS_AVAILABLE = True
except ImportError:
    STATS_AVAILABLE = False

try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


def evaluate_detector(dataset_path="real_dataset.csv"):
    print("=" * 60)
    print("PART 1: VULNERABILITY DETECTOR VALIDATION")
    print("=" * 60)
    
    if not os.path.exists(dataset_path):
        print(f"Warning: {dataset_path} not found. Skipping detector validation.")
        return None

    df = pd.read_csv(dataset_path)
    print(f"Loaded dataset: '{dataset_path}' ({len(df)} rows)")

    # Determine ground truth and predicted labels
    if "ground_truth_vulnerable" not in df.columns:
        print("Dataset missing 'ground_truth_vulnerable' column.")
        return None

    y_true = df["ground_truth_vulnerable"].astype(bool)

    if "flagged" in df.columns:
        y_pred = df["flagged"].astype(bool)
    else:
        # Compute detection flags using available signals
        # 1. Breach hit (> 0)
        breach_flag = df["hibp_breach_count"].fillna(0) > 0 if "hibp_breach_count" in df.columns else pd.Series(False, index=df.index)
        
        # 2. Syntactic strength (zxcvbn score < 3)
        if ZXCVBN_AVAILABLE and "password" in df.columns:
            syntax_flag = pd.Series([zxcvbn.zxcvbn(str(p))["score"] < 3 for p in df["password"]], index=df.index)
        else:
            syntax_flag = pd.Series(False, index=df.index)
            
        y_pred = breach_flag | syntax_flag

    if STATS_AVAILABLE:
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)

        print(f"Precision: {prec:.4f}")
        print(f"Recall:    {rec:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        print("Confusion Matrix (TN, FP / FN, TP):")
        print(cm)
    else:
        tp = int(((y_true == True) & (y_pred == True)).sum())
        fp = int(((y_true == False) & (y_pred == True)).sum())
        fn = int(((y_true == True) & (y_pred == False)).sum())
        tn = int(((y_true == False) & (y_pred == False)).sum())
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        print(f"Precision: {prec:.4f}")
        print(f"Recall:    {rec:.4f}")
        print(f"F1 Score:  {f1:.4f}")

    if "password_variant" in df.columns:
        df_acc = df.assign(correct=(y_true == y_pred))
        print("\nAccuracy by Password Variant:")
        for var, acc in df_acc.groupby("password_variant")["correct"].mean().items():
            print(f"  • {var}: {acc * 100:.1f}% correctly identified")
    
    return {"precision": prec, "recall": rec, "f1": f1}


def evaluate_usability(results_path="results.csv"):
    print("\n" + "=" * 60)
    print("PART 2: USABILITY STUDY & PILOT A/B ANALYSIS")
    print("=" * 60)

    if not os.path.exists(results_path):
        print(f"Results file '{results_path}' not found yet. Complete test sessions in app.py first.")
        return

    r = pd.read_csv(results_path)
    if r.empty or "participant_id" not in r.columns or r["participant_id"].dropna().empty:
        print(f"'{results_path}' is currently empty. Run sessions in app.py with participant IDs (e.g., P01-P10).")
        return

    # Clean missing IDs
    r = r.dropna(subset=["participant_id"])
    total_decisions = len(r)
    n_participants = r["participant_id"].nunique()
    total_adopted = int(r["adopted"].astype(bool).sum())

    print(f"Total Participants: {n_participants}")
    print(f"Total Decisions Recorded: {total_decisions}")
    print(f"Overall Adoption Rate: {total_adopted}/{total_decisions} ({100 * total_adopted / total_decisions:.1f}%)")

    # Table by framing variant
    print("\nDecision-Level Summary by Framing Variant:")
    summary = r.groupby("variant").agg(
        decisions=("adopted", "size"),
        adopted=("adopted", lambda x: int(x.astype(bool).sum())),
        median_time_s=("decision_time", "median"),
        min_time_s=("decision_time", "min"),
        max_time_s=("decision_time", "max"),
    )
    summary["adoption_pct"] = (100 * summary["adopted"] / summary["decisions"]).round(1)
    print(summary.to_string())

    print("\nParticipants per variant:")
    for variant, count in r.groupby("variant")["participant_id"].nunique().items():
        print(f"  • Variant {variant}: {count} participants")

    # Participant-level adoption
    per_person = r.groupby("participant_id")["adopted"].apply(lambda s: s.astype(bool).max())
    print(f"\nParticipants who adopted at least one AI recommendation:")
    print(f"  {int(per_person.sum())} of {len(per_person)} ({100 * int(per_person.sum()) / len(per_person):.1f}%)")

    # Statistical Tests (on first decision per participant or all decisions)
    if STATS_AVAILABLE and len(r["variant"].unique()) > 1:
        print("\n--- Inferential Statistics (Exploratory) ---")
        first_r = r.drop_duplicates(subset="participant_id", keep="first")
        a = first_r[first_r["variant"] == "A"]
        b = first_r[first_r["variant"] == "B"]
        
        print(f"Unique participants per variant: A={len(a)}, B={len(b)}")

        if len(a) > 0 and len(b) > 0:
            table = [
                [int(a["adopted"].astype(bool).sum()), len(a) - int(a["adopted"].astype(bool).sum())],
                [int(b["adopted"].astype(bool).sum()), len(b) - int(b["adopted"].astype(bool).sum())]
            ]
            try:
                _, p_adopt = stats.fisher_exact(table)
                print(f"Fisher's Exact Test (Adoption A vs B): p = {p_adopt:.4f}")
            except Exception as e:
                print("Fisher's Exact Test: could not calculate (insufficient variation).")

            try:
                _, p_time = stats.mannwhitneyu(a["decision_time"], b["decision_time"], alternative="two-sided")
                print(f"Mann-Whitney U Test (Decision Time A vs B): p = {p_time:.4f}")
            except Exception as e:
                print("Mann-Whitney U Test: could not calculate (insufficient data).")

    print("\n" + "=" * 60)
    print("READY-TO-PASTE PAPER PARAGRAPHS")
    print("=" * 60)
    
    var_a = summary.loc["A"] if "A" in summary.index else None
    var_b = summary.loc["B"] if "B" in summary.index else None
    
    a_part_cnt = r[r["variant"] == "A"]["participant_id"].nunique() if "A" in r["variant"].values else 0
    b_part_cnt = r[r["variant"] == "B"]["participant_id"].nunique() if "B" in r["variant"].values else 0
    
    a_adopt = int(var_a["adopted"]) if var_a is not None else 0
    a_dec = int(var_a["decisions"]) if var_a is not None else 0
    b_adopt = int(var_b["adopted"]) if var_b is not None else 0
    b_dec = int(var_b["decisions"]) if var_b is not None else 0
    
    a_med = var_a["median_time_s"] if var_a is not None else 0.0
    a_min = var_a["min_time_s"] if var_a is not None else 0.0
    a_max = var_a["max_time_s"] if var_a is not None else 0.0

    b_med = var_b["median_time_s"] if var_b is not None else 0.0
    b_min = var_b["min_time_s"] if var_b is not None else 0.0
    b_max = var_b["max_time_s"] if var_b is not None else 0.0

    print("\n[Results Section Draft]:")
    print(
        f'"Across {n_participants} participants, we recorded {total_decisions} total password evaluation decisions. '
        f'The loss-framed variant (Variant A) was assigned to {a_part_cnt} participants and the neutral variant (Variant B) to {b_part_cnt}. '
        f'Participants accepted an AI suggestion in {total_adopted} of {total_decisions} decisions ({100 * total_adopted / total_decisions if total_decisions else 0:.1f}%). '
        f'Under the loss-framed variant, adoption was {a_adopt} of {a_dec} decisions ({100 * a_adopt / a_dec if a_dec else 0:.1f}%); '
        f'under the neutral variant, adoption was {b_adopt} of {b_dec} decisions ({100 * b_adopt / b_dec if b_dec else 0:.1f}%). '
        f'Median decision time was {a_med:.2f} s (range {a_min:.2f}–{a_max:.2f} s) for the loss-framed variant and '
        f'{b_med:.2f} s (range {b_min:.2f}–{b_max:.2f} s) for the neutral variant."'
    )


if __name__ == "__main__":
    evaluate_detector()
    evaluate_usability()
