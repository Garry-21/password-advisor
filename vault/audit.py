"""
vault/audit.py
--------------
Context-Aware Vault Audit Engine:
- Continuous local security auditing of unlocked vault entries
- 6-signal risk vector: Breach (HIBP), Semantic PII Coverage, Syntactic Complexity,
  Exact Password Reuse, Derivative Families, and Age
- Derivative-family clustering using leet normalization and Levenshtein / fuzzy ratios
- Configurable weighted risk scoring and Vault Health Score (VHS)
"""

import json
import math
import os
import re
import string
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any

from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from vault.models import Entry, Profile
from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity
from modules.semantic import calculate_thematic_coverage, reverse_leet_translation

# ── Unified Audit Configuration (NIST 800-63B Compliant) ────────────────────
@dataclass
class AuditConfig:
    weights: Dict[str, float] = field(default_factory=lambda: {
        "breach": 0.45,
        "semantic": 0.25,
        "syntax": 0.15,
        "reuse": 0.10,
        "derivative": 0.05,
        "age": 0.00,        # Off by default per NIST 800-63B
    })
    enable_age_score: bool = False
    rotation_policy_days: int = 90
    max_correlated_contribution: float = 0.35  # Cap on reuse + derivative + semantic
    cluster_mode: str = "chain"                # "chain" (Union-Find) or "pairwise" (strict)
    calibrated_model_path: Optional[str] = "data/calibrated_scorer.json"

DEFAULT_CONFIG = AuditConfig()
WEIGHTS = dict(DEFAULT_CONFIG.weights)
DEFAULT_ROTATION_DAYS = 90


@dataclass
class EntryAuditResult:
    entry_id: str
    site_name: str
    username: str
    criticality: int
    b_i: float              # 1.0 (breached), 0.0 (clean), or None (check failed)
    breach_count: int
    C_i: float              # Thematic Coverage Score (0.0 to 1.0)
    matched_pii: List[str]
    s_i: float              # 1.0 (zxcvbn < 3), 0.0 (zxcvbn >= 3)
    zxcvbn_score: int
    r_i: float              # 1.0 if reused across accounts, else 0.0
    reuse_sites: List[str]
    d_i: float              # 1.0 if member of derivative family, else 0.0
    derivative_family_id: Optional[int]
    derivative_sites: List[str]
    a_i: float              # min(1.0, age_days / 365) if > rotation_days
    age_days: int
    risk_score: float       # R_i in [0.0, 1.0]
    finding_badges: List[str] = field(default_factory=list)


@dataclass
class VaultAuditReport:
    total_entries: int
    vhs_score: float                     # Vault Health Score [0.0, 100.0]
    breached_count: int
    personal_info_count: int
    weak_syntax_count: int
    reused_count: int
    derivative_count: int
    old_count: int
    derivative_families: Dict[int, List[str]] # family_id -> list of site names
    entry_results: List[EntryAuditResult]
    audit_timestamp: float = field(default_factory=time.time)


# ── Derivative Family Detection (Section 5.2) ────────────────────────────────

def extract_base_password(password: str) -> str:
    """
    Normalizes password for derivative-family clustering:
    1. Lowercase
    2. Strip leading and trailing digits, punctuation, and whitespace
    3. Character-level reverse leet substitution on remaining core
    4. Strip again if any punctuation remains
    """
    if not password:
        return ""
    
    strip_chars = string.digits + string.punctuation + string.whitespace
    core = password.lower().strip(strip_chars)
    if not core:
        core = password.lower()
        
    rev = reverse_leet_translation(core)
    base = rev.strip(strip_chars)
    return base if base else rev


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        if self.parent[i] == i:
            return i
        self.parent[i] = self.find(self.parent[i])
        return self.parent[i]

    def union(self, i: int, j: int):
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            self.parent[root_i] = root_j


def _are_derivatives(pw_i: str, pw_j: str, base_i: str, base_j: str) -> bool:
    """Checks if two passwords satisfy derivative relation."""
    # Condition 1: Identical non-empty base
    if base_i and base_j and len(base_i) >= 3 and base_i == base_j:
        return True

    # Condition 2: High fuzzy similarity on base
    if base_i and base_j and len(base_i) >= 4 and len(base_j) >= 4:
        if fuzz.ratio(base_i, base_j) >= 85.0:
            return True

    # Condition 3: Raw Levenshtein edit distance <= 2 (for passwords >= 6 chars)
    if len(pw_i) >= 6 and len(pw_j) >= 6:
        if Levenshtein.distance(pw_i, pw_j) <= 2:
            return True

    return False


def detect_derivative_families(
    entries: List[Entry],
    cluster_mode: str = "chain"
) -> Tuple[Dict[str, int], Dict[int, List[str]]]:
    """
    Clusters entries into derivative families.
    Modes:
      - 'chain': Transitive Union-Find clustering (A~B and B~C => {A, B, C}).
      - 'pairwise': Strict pairwise clique-only mode (no transitively chained groups;
        entries are clustered only if all pairs in the group share the derivative relation).
    """
    n = len(entries)
    if n <= 1:
        return {}, {}

    bases = [extract_base_password(e.password) for e in entries]

    # Pre-calculate pairwise adjacency
    adj = [[False] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            if _are_derivatives(entries[i].password, entries[j].password, bases[i], bases[j]):
                adj[i][j] = True
                adj[j][i] = True

    if cluster_mode == "pairwise":
        # Strict mode: form groups where every member is connected to every other member (cliques),
        # or disjoint pairwise pairs. A~B and B~C with A!~C will NOT merge A, B, and C together.
        assigned = set()
        family_id_counter = 1
        entry_to_family: Dict[str, int] = {}
        family_members: Dict[int, List[str]] = {}

        for i in range(n):
            if i in assigned:
                continue
            # Find all j connected to i
            candidates = [j for j in range(n) if j != i and adj[i][j] and j not in assigned]
            if not candidates:
                continue
            
            # Form maximum mutual clique starting with i
            clique = [i]
            for c in candidates:
                if all(adj[c][m] for m in clique):
                    clique.append(c)

            if len(clique) >= 2:
                fam_id = family_id_counter
                family_id_counter += 1
                for idx in clique:
                    assigned.add(idx)
                    entry_to_family[entries[idx].id] = fam_id
                family_members[fam_id] = [entries[idx].site_name for idx in clique]

        return entry_to_family, family_members

    # Default 'chain' mode using UnionFind
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if adj[i][j]:
                uf.union(i, j)

    clusters: Dict[int, List[int]] = {}
    for idx in range(n):
        root = uf.find(idx)
        clusters.setdefault(root, []).append(idx)

    entry_to_family: Dict[str, int] = {}
    family_members: Dict[int, List[str]] = {}
    family_id_counter = 1

    for _, member_indices in clusters.items():
        if len(member_indices) >= 2:
            fam_id = family_id_counter
            family_id_counter += 1
            site_list = [entries[idx].site_name for idx in member_indices]
            family_members[fam_id] = site_list
            for idx in member_indices:
                entry_to_family[entries[idx].id] = fam_id

    return entry_to_family, family_members


# ── Audit Engine Core ────────────────────────────────────────────────────────

def load_calibrated_scorer(model_path: Optional[str]) -> Optional[Dict[str, Any]]:
    """Loads calibrated logistic regression model coefficients if file exists."""
    if not model_path or not os.path.exists(model_path):
        return None
    try:
        with open(model_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def calculate_calibrated_risk(
    features: Dict[str, float],
    model: Dict[str, Any]
) -> float:
    """
    Computes risk score using logistic regression:
    P(vulnerable) = 1 / (1 + exp(-(intercept + sum(coef_i * feature_i))))
    """
    intercept = float(model.get("intercept", 0.0))
    coefs = model.get("coefficients", {})
    z = intercept
    for feat_name, val in features.items():
        z += float(coefs.get(feat_name, 0.0)) * float(val)
    # Sigmoid function
    try:
        risk = 1.0 / (1.0 + math.exp(-z))
    except OverflowError:
        risk = 1.0 if z > 0 else 0.0
    return max(0.0, min(1.0, risk))


def audit_vault(
    entries: List[Entry],
    profile: Optional[Profile] = None,
    rotation_policy_days: int = DEFAULT_ROTATION_DAYS,
    max_hibp_threads: int = 8,
    custom_weights: Optional[Dict[str, float]] = None,
    config: Optional[AuditConfig] = None,
    progress_callback = None
) -> VaultAuditReport:
    """
    Performs full in-memory security audit across all unlocked entries:
    - Concurrently verifies breach counts via HIBP range API
    - Evaluates syntactic complexity and thematic personal information leaks
    - Detects exact reuse and derivative clusters (chain or pairwise mode)
    - Prevents double counting via max_correlated_contribution cap
    - Supports calibrated logistic regression scoring if model exists
    - Computes per-entry risk R_i and overall Vault Health Score (VHS)
    """
    active_cfg = config if config is not None else DEFAULT_CONFIG
    active_weights = dict(active_cfg.weights)
    if custom_weights:
        active_weights.update(custom_weights)

    # Load optional calibrated model
    calibrated_model = load_calibrated_scorer(active_cfg.calibrated_model_path)

    total_entries = len(entries)
    if total_entries == 0:
        return VaultAuditReport(
            total_entries=0,
            vhs_score=100.0,
            breached_count=0,
            personal_info_count=0,
            weak_syntax_count=0,
            reused_count=0,
            derivative_count=0,
            old_count=0,
            derivative_families={},
            entry_results=[]
        )

    # 1. Exact reuse mapping
    password_to_sites: Dict[str, List[str]] = {}
    for e in entries:
        password_to_sites.setdefault(e.password, []).append(e.site_name)

    # 2. Derivative family mapping
    entry_to_fam, fam_to_sites = detect_derivative_families(entries, cluster_mode=active_cfg.cluster_mode)

    # 3. Concurrent HIBP checks
    hibp_results: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=min(max_hibp_threads, max(1, total_entries))) as executor:
        future_to_entry = {executor.submit(check_hibp_k_anonymity, e.password): e.id for e in entries}
        completed_count = 0
        for future in as_completed(future_to_entry):
            e_id = future_to_entry[future]
            try:
                hits = future.result()
            except Exception:
                hits = -1
            hibp_results[e_id] = hits
            completed_count += 1
            if progress_callback:
                progress_callback(completed_count, total_entries)

    # 4. Profile metadata mapping
    prof_meta = {
        "first_name": profile.first_name,
        "surname": profile.surname,
        "city": profile.city,
        "birth_year": profile.birth_year
    } if profile else {}

    now_time = time.time()
    entry_results: List[EntryAuditResult] = []

    sum_weighted_risk = 0.0
    sum_criticality = 0.0

    count_breached = 0
    count_personal = 0
    count_weak = 0
    count_reused = 0
    count_derivative = 0
    count_old = 0

    for e in entries:
        badges = []

        # Signal 1: Breach
        hits = hibp_results.get(e.id, 0)
        if hits > 0:
            b_i = 1.0
            count_breached += 1
            badges.append(f"Breached ({hits:,} hits)")
        elif hits == -1:
            # Explicit unknown handling: penalize with baseline unverified risk (0.5) so it's never treated as safe
            b_i = 0.5
            badges.append("Breach Check Unknown (Unverified)")
        else:
            b_i = 0.0

        # Signal 2: Semantic PII Coverage
        if prof_meta:
            sem_res = calculate_thematic_coverage(e.password, prof_meta)
            C_i = sem_res["score"]
            matched_pii = sem_res["matched_fields"]
        else:
            C_i = 0.0
            matched_pii = []

        if C_i >= 0.3:
            count_personal += 1
            badges.append(f"Personal Info ({', '.join(matched_pii)})")

        # Signal 3: Syntactic Complexity
        syntax = evaluate_syntactic_strength(e.password)
        zxcvbn_score = syntax["score"]
        if zxcvbn_score < 3:
            s_i = 1.0
            count_weak += 1
            badges.append(f"Weak Complexity (Score {zxcvbn_score}/4)")
        else:
            s_i = 0.0

        # Signal 4: Exact Password Reuse
        reused_with = [s for s in password_to_sites.get(e.password, []) if s != e.site_name]
        if reused_with:
            r_i = 1.0
            count_reused += 1
            badges.append(f"Reused across {len(reused_with) + 1} sites")
        else:
            r_i = 0.0

        # Signal 5: Derivative Family
        fam_id = entry_to_fam.get(e.id)
        if fam_id is not None:
            d_i = 1.0
            count_derivative += 1
            der_members = [s for s in fam_to_sites.get(fam_id, []) if s != e.site_name]
            badges.append(f"Derivative variation of {', '.join(der_members[:2])}")
        else:
            d_i = 0.0
            der_members = []

        # Signal 6: Age (Optional, off-by-default per NIST 800-63B)
        age_days = 0
        try:
            ts_str = e.modified_at or e.created_at
            if ts_str:
                clean_ts = ts_str.rstrip("Z") + "+00:00" if ts_str.endswith("Z") else ts_str
                dt = datetime.fromisoformat(clean_ts)
                entry_epoch = dt.timestamp()
                age_days = max(0, int((now_time - entry_epoch) / 86400.0))
        except Exception:
            age_days = 0

        if active_cfg.enable_age_score and age_days > rotation_policy_days:
            a_i = min(1.0, age_days / 365.0)
            count_old += 1
            badges.append(f"Old ({age_days}d)")
        else:
            a_i = 0.0

        # Calculate R_i
        feature_dict = {
            "breach": b_i,
            "semantic": C_i,
            "syntax": s_i,
            "reuse": r_i,
            "derivative": d_i,
            "age": a_i,
        }

        if calibrated_model is not None:
            r_risk = calculate_calibrated_risk(feature_dict, calibrated_model)
        else:
            # Prevent double-counting of correlated signals (reuse + derivative + semantic)
            correlated_sum = (
                active_weights["semantic"] * C_i +
                active_weights["reuse"] * r_i +
                active_weights["derivative"] * d_i
            )
            capped_correlated = min(active_cfg.max_correlated_contribution, correlated_sum)

            raw_risk = (
                active_weights["breach"] * b_i +
                active_weights["syntax"] * s_i +
                active_weights["age"] * a_i +
                capped_correlated
            )
            r_risk = min(1.0, raw_risk)

        crit_weight = float(max(1, min(3, e.criticality)))
        sum_weighted_risk += (crit_weight * r_risk)
        sum_criticality += crit_weight

        entry_results.append(EntryAuditResult(
            entry_id=e.id,
            site_name=e.site_name,
            username=e.username,
            criticality=e.criticality,
            b_i=b_i,
            breach_count=max(0, hits),
            C_i=C_i,
            matched_pii=matched_pii,
            s_i=s_i,
            zxcvbn_score=zxcvbn_score,
            r_i=r_i,
            reuse_sites=reused_with,
            d_i=d_i,
            derivative_family_id=fam_id,
            derivative_sites=der_members,
            a_i=a_i,
            age_days=age_days,
            risk_score=round(r_risk, 3),
            finding_badges=badges
        ))

    # Sort results by highest risk first
    entry_results.sort(key=lambda x: x.risk_score, reverse=True)

    # Compute VHS: 100 * (1 - sum(w_i * R_i) / sum(w_i))
    if sum_criticality > 0:
        vhs = round(100.0 * (1.0 - (sum_weighted_risk / sum_criticality)), 1)
    else:
        vhs = 100.0

    return VaultAuditReport(
        total_entries=total_entries,
        vhs_score=vhs,
        breached_count=count_breached,
        personal_info_count=count_personal,
        weak_syntax_count=count_weak,
        reused_count=count_reused,
        derivative_count=count_derivative,
        old_count=count_old,
        derivative_families=fam_to_sites,
        entry_results=entry_results
    )
