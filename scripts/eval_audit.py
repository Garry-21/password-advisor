"""
scripts/eval_audit.py
---------------------
Evaluation Harness for Context-Aware Vault Audit Engine (Section 9):
- Evaluates detection performance against a ground-truth planted benchmark (80 entries)
- Computes Precision, Recall, and F1-score across all 6 vulnerability signals:
  1. HIBP Breach Detection
  2. Thematic Personal Information (PII) Leakage
  3. Syntactic Weakness (zxcvbn < 3)
  4. Exact Credential Reuse
  5. Derivative Password Families
  6. Stale Credentials (> rotation policy)
- Measures audit latency and calculates Vault Health Score (VHS)
- Outputs publication-ready Markdown tables
"""

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Set, Tuple

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault.models import Entry, Profile
from vault.audit import audit_vault, VaultAuditReport


@dataclass
class GroundTruthEntry:
    entry: Entry
    is_breached: bool
    has_pii: bool
    is_weak: bool
    is_reused: bool
    is_derivative: bool
    is_old: bool


def generate_benchmark_vault() -> Tuple[List[GroundTruthEntry], Profile]:
    profile = Profile(
        first_name="Alexander",
        surname="Hamilton",
        city="Albany",
        birth_year=1995,
        theme="scifi"
    )

    now_epoch = time.time()
    def past_iso(days_ago: int) -> str:
        past = now_epoch - (days_ago * 86400)
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(past))

    benchmarks: List[GroundTruthEntry] = []

    # 1. 10 Breached passwords (known HIBP passwords)
    breached_pw_list = [
        "password", "123456", "12345678", "qwerty", "111111",
        "dragon", "baseball", "football", "monkey", "shadow"
    ]
    for i, pw in enumerate(breached_pw_list):
        e = Entry(id=f"br_{i}", site_name=f"BreachSite_{i}", url="", username="user", password=pw)
        benchmarks.append(GroundTruthEntry(e, is_breached=True, has_pii=False, is_weak=True, is_reused=False, is_derivative=False, is_old=False))

    # 2. 10 PII Leaks (direct and leet variations of Alexander, Hamilton, Albany, 1995)
    pii_pw_list = [
        "Alexander1995!", "Hamilton#Albany95", "AlexAlbany1995$", "Al3xand3r95!",
        "HamiltonSecret#", "AlbanySummer95!", "AlexanderHamilton!", "Albany*1995*Key",
        "Alex1995Denver?", "Hamilton95Rock!"
    ]
    for i, pw in enumerate(pii_pw_list):
        e = Entry(id=f"pii_{i}", site_name=f"PIISite_{i}", url="", username="user", password=pw)
        benchmarks.append(GroundTruthEntry(e, is_breached=False, has_pii=True, is_weak=False, is_reused=False, is_derivative=False, is_old=False))

    # 3. 10 Weak Syntactic Passwords (zxcvbn < 3, but not in top 10 breached list)
    weak_pw_list = [
        "iloveyou1", "sunshine1", "master12", "welcome1", "princess1",
        "superman1", "trustno1", "computer1", "shadow1", "michael1"
    ]
    for i, pw in enumerate(weak_pw_list):
        e = Entry(id=f"wk_{i}", site_name=f"WeakSite_{i}", url="", username="user", password=pw)
        # Note: these might also be breached in HIBP, but ground truth is weak syntax
        benchmarks.append(GroundTruthEntry(e, is_breached=True, has_pii=False, is_weak=True, is_reused=False, is_derivative=False, is_old=False))

    # 4. 10 Exact Reuses (5 pairs of identical passwords across different sites)
    shared_passwords = [
        "UniqueSharedSecretAlpha#2026",
        "UniqueSharedSecretBeta$2026",
        "UniqueSharedSecretGamma%2026",
        "UniqueSharedSecretDelta^2026",
        "UniqueSharedSecretEpsilon&2026"
    ]
    for pair_idx, sp in enumerate(shared_passwords):
        e_a = Entry(id=f"re_{pair_idx}_a", site_name=f"Social_{pair_idx}_A", url="", username="user", password=sp)
        e_b = Entry(id=f"re_{pair_idx}_b", site_name=f"Forum_{pair_idx}_B", url="", username="user", password=sp)
        benchmarks.append(GroundTruthEntry(e_a, is_breached=False, has_pii=False, is_weak=False, is_reused=True, is_derivative=False, is_old=False))
        benchmarks.append(GroundTruthEntry(e_b, is_breached=False, has_pii=False, is_weak=False, is_reused=True, is_derivative=False, is_old=False))

    # 5. 10 Derivative Family Members (5 pairs of mutated base passwords)
    derivative_pairs = [
        ("Summer2024!", "Summer2025!"),
        ("WinterBreak99", "WinterBreak2020!"),
        ("AutumnLeaves#1", "AutumnLeaves#2"),
        ("SpringBreeze!", "SpringBreeze99$"),
        ("GalaxyQuest#2024", "GalaxyQuest#2025")
    ]
    for d_idx, (d1, d2) in enumerate(derivative_pairs):
        e1 = Entry(id=f"der_{d_idx}_1", site_name=f"ShopRetail_{d_idx}", url="", username="user", password=d1)
        e2 = Entry(id=f"der_{d_idx}_2", site_name=f"ShopOutlet_{d_idx}", url="", username="user", password=d2)
        benchmarks.append(GroundTruthEntry(e1, is_breached=False, has_pii=False, is_weak=False, is_reused=False, is_derivative=True, is_old=False))
        benchmarks.append(GroundTruthEntry(e2, is_breached=False, has_pii=False, is_weak=False, is_reused=False, is_derivative=True, is_old=False))

    # 6. 10 Stale / Old Passwords (> 90 days old, clean high-entropy)
    for i in range(10):
        pw = f"LongCleanSecureOldToken{i}#2022!XyZ"
        e = Entry(id=f"old_{i}", site_name=f"Archive_{i}", url="", username="user", password=pw, created_at=past_iso(120 + i * 30))
        benchmarks.append(GroundTruthEntry(e, is_breached=False, has_pii=False, is_weak=False, is_reused=False, is_derivative=False, is_old=True))

    # 7. 20 Clean Controls (high entropy, unique, unbreached, no PII)
    clean_pw_list = [
        "Correct-Horse-Battery-Staple-2026!#", "Quantum-Pulsar-Singularity-Warp-888$",
        "BlueOcean#Dolphin#CoralReef!2026", "Alpine-RockClimbing-Summit-2026!$",
        "Emerald-Forest-Moss-River-777^", "Starlight-Nebula-Orbital-Decay-444*",
        "Vibrant-Symphony-Sonata-Cadence-999&", "Rapid-Marathon-Decathlon-Sprint-111%",
        "Nomad-Expedition-Voyager-Compass-222@", "Cyber-Matrix-Vortex-Photon-333!",
        "Flour-Sourdough-Brioche-Pastry-555#", "Granite-Canyon-Glacier-Tundra-666$",
        "Acoustic-Rhythm-Harmony-Octave-777%", "Archery-Slalom-Triathlon-Gymnast-888^",
        "Itinerary-Safari-Lantern-Odyssey-999*", "Beacon-Dimension-Reactor-Circuit-123@",
        "Whispering-Willow-Blossom-Valley-456!", "Melodic-Ballad-Crescendo-Chorus-789#",
        "Alpine-Slalom-Hurdle-Velocity-321$", "Coastal-Glider-Wayfarer-Passage-654%"
    ]
    for i, pw in enumerate(clean_pw_list):
        e = Entry(id=f"clean_{i}", site_name=f"SecureApp_{i}", url="", username="user", password=pw)
        benchmarks.append(GroundTruthEntry(e, is_breached=False, has_pii=False, is_weak=False, is_reused=False, is_derivative=False, is_old=False))

    return benchmarks, profile


def compute_metrics(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def run_audit_evaluation():
    print("=" * 70)
    print("CONTEXT-AWARE VAULT (CAV) AUDIT EVALUATION")
    print("=" * 70)

    benchmarks, profile = generate_benchmark_vault()
    entries = [b.entry for b in benchmarks]
    gt_map = {b.entry.id: b for b in benchmarks}

    print(f"Total planted benchmark entries: {len(entries)}")
    print("Running audit_vault across all entries with concurrent HIBP check...")

    start_time = time.perf_counter()
    report = audit_vault(entries, profile=profile, rotation_policy_days=90, max_hibp_threads=10)
    elapsed = time.perf_counter() - start_time

    print(f"Audit completed in: {elapsed:.2f}s ({elapsed / len(entries) * 1000:.1f} ms/entry)")
    print(f"Vault Health Score (VHS): {report.vhs_score:.1f} / 100.0\n")

    # Counts for metrics
    stats = {
        "Breach (HIBP)": {"tp": 0, "fp": 0, "fn": 0},
        "PII Exposure": {"tp": 0, "fp": 0, "fn": 0},
        "Weak Complexity": {"tp": 0, "fp": 0, "fn": 0},
        "Exact Reuse": {"tp": 0, "fp": 0, "fn": 0},
        "Derivative Family": {"tp": 0, "fp": 0, "fn": 0},
        "Stale Credential": {"tp": 0, "fp": 0, "fn": 0},
    }

    for res in report.entry_results:
        gt = gt_map[res.entry_id]

        # 1. Breach
        det_breach = res.b_i > 0
        if det_breach and gt.is_breached:
            stats["Breach (HIBP)"]["tp"] += 1
        elif det_breach and not gt.is_breached:
            stats["Breach (HIBP)"]["fp"] += 1
        elif not det_breach and gt.is_breached:
            stats["Breach (HIBP)"]["fn"] += 1

        # 2. PII
        det_pii = res.C_i >= 0.3
        if det_pii and gt.has_pii:
            stats["PII Exposure"]["tp"] += 1
        elif det_pii and not gt.has_pii:
            stats["PII Exposure"]["fp"] += 1
        elif not det_pii and gt.has_pii:
            stats["PII Exposure"]["fn"] += 1

        # 3. Weak syntax
        det_weak = res.s_i > 0
        if det_weak and gt.is_weak:
            stats["Weak Complexity"]["tp"] += 1
        elif det_weak and not gt.is_weak:
            stats["Weak Complexity"]["fp"] += 1
        elif not det_weak and gt.is_weak:
            stats["Weak Complexity"]["fn"] += 1

        # 4. Exact Reuse
        det_reuse = res.r_i > 0
        if det_reuse and gt.is_reused:
            stats["Exact Reuse"]["tp"] += 1
        elif det_reuse and not gt.is_reused:
            stats["Exact Reuse"]["fp"] += 1
        elif not det_reuse and gt.is_reused:
            stats["Exact Reuse"]["fn"] += 1

        # 5. Derivative Family
        det_der = res.d_i > 0
        if det_der and gt.is_derivative:
            stats["Derivative Family"]["tp"] += 1
        elif det_der and not gt.is_derivative:
            stats["Derivative Family"]["fp"] += 1
        elif not det_der and gt.is_derivative:
            stats["Derivative Family"]["fn"] += 1

        # 6. Age
        det_old = res.a_i > 0
        if det_old and gt.is_old:
            stats["Stale Credential"]["tp"] += 1
        elif det_old and not gt.is_old:
            stats["Stale Credential"]["fp"] += 1
        elif not det_old and gt.is_old:
            stats["Stale Credential"]["fn"] += 1

    # Output Markdown Table
    print("### Context-Aware Vault Audit Benchmark Results\n")
    print("| Vulnerability Vector | True Pos (TP) | False Pos (FP) | False Neg (FN) | Precision | Recall | F1-Score |")
    print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

    for signal, counts in stats.items():
        prec, rec, f1 = compute_metrics(counts["tp"], counts["fp"], counts["fn"])
        print(f"| {signal} | {counts['tp']} | {counts['fp']} | {counts['fn']} | {prec:.3f} | {rec:.3f} | {f1:.3f} |")

    print(f"\n- **Overall VHS**: {report.vhs_score:.1f}")
    print(f"- **Total Flagged Breached**: {report.breached_count}")
    print(f"- **Total Flagged PII Leaks**: {report.personal_info_count}")
    print(f"- **Total Flagged Exact Reuses**: {report.reused_count}")
    print(f"- **Total Flagged Derivative Variations**: {report.derivative_count}")
    print(f"- **Total Flagged Stale (>90d)**: {report.old_count}")


if __name__ == "__main__":
    run_audit_evaluation()
