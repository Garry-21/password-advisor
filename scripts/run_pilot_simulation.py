"""
simulate_pilot_study.py
-----------------------
Executes the standardized 10-participant pilot protocol (P01-P10, 3 trials each = 30 decisions).
Uses the actual detection engine:
- modules.syntactic: evaluate_syntactic_strength (zxcvbn), check_hibp_k_anonymity (HIBP)
- modules.semantic: calculate_thematic_coverage (PII & leet speak detection)

Saves synthetic decisions into results/synthetic_pilot.csv; these are not human observations.
"""

import csv
import random
import time
from datetime import datetime
import os
import sys

# Add parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity
from modules.semantic import calculate_thematic_coverage

random.seed(42)  # For reproducible scientific reporting

PROFILE = {
    "first_name": "Maya",
    "surname": "Carter",
    "city": "Denver",
    "birth_year": 1998,
    "theme": "Baking"
}

# 10 participants, 3 realistic password trials each adhering to the study prompts:
# Prompt 1: Online shopping password
# Prompt 2: Password using name or numbers from profile card
# Prompt 3: Social media account password
PARTICIPANT_TRIALS = {
    "P01": {"variant": "A", "passwords": ["ShopOnline123!", "MayaCarter1998", "BakingLover98"]},
    "P02": {"variant": "B", "passwords": ["DenverBakes!2", "M@y@1998#", "socialbutterfly99"]},
    "P03": {"variant": "A", "passwords": ["welcome2shop", "Carter98Bake", "InstaMayaCarter"]},
    "P04": {"variant": "B", "passwords": ["ilovecupcakes12", "Denver1998!", "MayaSocial2026"]},
    "P05": {"variant": "A", "passwords": ["CartOrder99$", "M1ch3ll3Carter", "CupcakeQueen98"]},
    "P06": {"variant": "B", "passwords": ["AmazonShopping!", "Maya98Denver", "bakingaddict2026"]},
    "P07": {"variant": "A", "passwords": ["ShopDenver98", "CarterDenver1998", "MayaBakesCakes!"]},
    "P08": {"variant": "B", "passwords": ["OnlineBoutique1", "C@rt3r1998!", "flourandsugar98"]},
    "P09": {"variant": "A", "passwords": ["ShopperMaya98!", "DenverBaking98", "CarterMaya98#"]},
    "P10": {"variant": "B", "passwords": ["StoreCheckout12", "Maya1998Bake!", "sweetpastry2026!"]}
}

RESULTS_FILE = "results/synthetic_pilot.csv"

def run_pilot():
    rows = []
    print("=" * 65)
    print("EXECUTING STANDARDIZED PILOT EXPERIMENT (P01–P10)")
    print("=" * 65)
    print(f"Profile: {PROFILE['first_name']} {PROFILE['surname']}, {PROFILE['city']}, {PROFILE['birth_year']} ({PROFILE['theme']})\n")

    for p_id, p_info in PARTICIPANT_TRIALS.items():
        variant = p_info["variant"]
        print(f"--> Participant {p_id} (Variant {variant}):")
        
        for i, pwd in enumerate(p_info["passwords"], start=1):
            # 1. Syntactic check
            syntax = evaluate_syntactic_strength(pwd)
            zxcvbn_score = syntax["score"]
            
            # 2. Breach check
            breach_hits = check_hibp_k_anonymity(pwd)
            if breach_hits == -1:
                breach_hits = 0  # fallback if offline
                
            # 3. Semantic check
            semantic_res = calculate_thematic_coverage(pwd, PROFILE)
            coverage_score = semantic_res["score"]
            matched_fields = semantic_res["matched_fields"]

            # Findings
            findings = []
            if breach_hits > 0:
                findings.append("breach")
            if coverage_score >= 0.3:
                findings.append("semantic")
            if zxcvbn_score < 3:
                findings.append("syntax")

            finding_types = ",".join(findings) if findings else "none"

            # Realistic decision time (seconds)
            # Variant A (loss-framed) typically elicits slightly more deliberate reading
            if variant == "A":
                decision_time = round(random.uniform(7.8, 15.6), 2)
                # Higher adoption probability under loss frame (e.g., ~73%)
                adopted = random.random() < 0.73 if findings else False
            else:
                decision_time = round(random.uniform(5.4, 12.8), 2)
                # Moderate adoption probability under neutral frame (e.g., ~47%)
                adopted = random.random() < 0.47 if findings else False

            row = [
                datetime.now().isoformat(),
                p_id,
                variant,
                decision_time,
                adopted,
                round(coverage_score, 2),
                breach_hits,
                zxcvbn_score,
                len(findings),
                finding_types,
                "synthetic"
            ]
            rows.append(row)
            print(f"    Trial {i}: Pwd='{pwd}' | Score={zxcvbn_score} | PII_Coverage={coverage_score:.2f} | Breach={breach_hits} | Adopted={adopted} ({decision_time}s)")

    # Write to results.csv
    with open(RESULTS_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "participant_id", "variant", "decision_time", "adopted", "coverage_score", "breach_hits", "zxcvbn_score", "n_findings", "finding_types", "source"])
        writer.writerows(rows)

    print(f"\n[OK] Successfully logged all {len(rows)} decisions into '{RESULTS_FILE}'.")

if __name__ == "__main__":
    run_pilot()
