"""
vault/gate.py
-------------
Save-Time Gate & Behavioral Nudge Engine (Section 6):
- Intercepts Add and Edit entry operations before vault persistence
- Real-time pre-flight inspection for:
  1. HIBP breach hits
  2. Profile PII exposure (thematic coverage)
  3. Syntactic weakness (zxcvbn < 3)
  4. Exact reuse across existing vault entries
  5. Derivative variations of existing vault passwords
- Generates high-entropy offline replacement suggestions
- Returns decision structure with 3 explicit actions:
  ['use_generated', 'edit', 'save_anyway']
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any

from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from vault.models import Entry, Profile
from vault.audit import extract_base_password
from vault.generator import GeneratedPassword, generate_passphrase
from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity
from modules.semantic import calculate_thematic_coverage


class GateAction(str, Enum):
    USE_GENERATED = "use_generated"
    EDIT = "edit"
    SAVE_ANYWAY = "save_anyway"


@dataclass
class GateEvaluation:
    needs_nudge: bool
    reasons: List[str]
    is_breached: bool
    breach_hits: int
    pii_matched: List[str]
    thematic_score: float
    zxcvbn_score: int
    reused_sites: List[str]
    derivative_sites: List[str]
    suggested_password: Optional[GeneratedPassword] = None
    suggested_explanation: str = ""
    allowed_actions: List[GateAction] = field(default_factory=lambda: [
        GateAction.USE_GENERATED,
        GateAction.EDIT,
        GateAction.SAVE_ANYWAY
    ])


def evaluate_save_gate(
    candidate_password: str,
    target_site: str,
    existing_entries: List[Entry],
    profile: Optional[Profile] = None,
    current_entry_id: Optional[str] = None
) -> GateEvaluation:
    """
    Evaluates candidate password against all vulnerability vectors before saving.
    Excludes the entry itself (current_entry_id) if performing an edit operation.
    """
    reasons: List[str] = []
    
    # Filter other entries for reuse and derivative checks
    other_entries = [e for e in existing_entries if (not current_entry_id or e.id != current_entry_id)]

    # 1. HIBP Breach check
    try:
        hits = check_hibp_k_anonymity(candidate_password)
    except Exception:
        hits = 0  # Fail-open on network drop

    is_breached = hits > 0
    if is_breached:
        reasons.append(f"This password appeared {hits:,} times in past public data breaches.")

    # 2. Semantic Personal Information Leak
    pii_matched = []
    thematic_score = 0.0
    if profile:
        prof_meta = {
            "first_name": profile.first_name,
            "surname": profile.surname,
            "city": profile.city,
            "birth_year": profile.birth_year
        }
        sem_res = calculate_thematic_coverage(candidate_password, prof_meta)
        thematic_score = sem_res.get("score", 0.0)
        pii_matched = sem_res.get("matched_fields", [])
        if thematic_score >= 0.3 or pii_matched:
            matched_str = ", ".join(pii_matched) if pii_matched else "personal details"
            reasons.append(f"Contains personal information from your profile ({matched_str}).")

    # 3. Syntactic Complexity (zxcvbn)
    syntax = evaluate_syntactic_strength(candidate_password)
    zxcvbn_score = syntax.get("score", 0)
    if zxcvbn_score < 3:
        reasons.append(f"Password complexity is weak (score {zxcvbn_score}/4).")

    # 4. Exact Reuse Check
    reused_sites = [
        e.site_name for e in other_entries
        if e.password == candidate_password and e.site_name
    ]
    if reused_sites:
        reasons.append(f"Reused password already in use for: {', '.join(reused_sites)}.")

    # 5. Derivative Variation Check
    derivative_sites = []
    cand_base = extract_base_password(candidate_password)

    for e in other_entries:
        if e.password == candidate_password:
            continue  # Exact reuse already handled above

        # Check raw Levenshtein edit distance <= 2
        raw_dist = Levenshtein.distance(candidate_password, e.password)
        if raw_dist <= 2:
            derivative_sites.append(e.site_name)
            continue

        # Check normalized base similarity
        other_base = extract_base_password(e.password)
        if cand_base and other_base:
            if cand_base == other_base and len(cand_base) >= 3:
                derivative_sites.append(e.site_name)
                continue
            if len(cand_base) >= 4 and len(other_base) >= 4:
                ratio = fuzz.ratio(cand_base, other_base)
                if ratio >= 85:
                    derivative_sites.append(e.site_name)

    if derivative_sites:
        reasons.append(f"Derivative variation of password used for: {', '.join(derivative_sites)}.")

    needs_nudge = len(reasons) > 0

    # If nudge required, generate offline replacement suggestion
    suggested_pw: Optional[GeneratedPassword] = None
    suggested_exp = ""

    if needs_nudge:
        user_theme = profile.theme if (profile and profile.theme) else None
        suggested_pw = generate_passphrase(
            num_words=4,
            theme=user_theme,
            separator="-",
            capitalize=True,
            include_digit=True,
            include_symbol=True
        )
        if user_theme:
            suggested_exp = (
                f"We generated a memorable, un-crackable passphrase inspired by your '{user_theme}' theme. "
                f"It offers {suggested_pw.entropy_bits} bits of cryptographic entropy and zero reuse risk."
            )
        else:
            suggested_exp = (
                f"We generated a 4-word EFF passphrase with {suggested_pw.entropy_bits} bits of entropy. "
                "It is easy to remember and resistant to brute-force and dictionary attacks."
            )

    return GateEvaluation(
        needs_nudge=needs_nudge,
        reasons=reasons,
        is_breached=is_breached,
        breach_hits=max(0, hits),
        pii_matched=pii_matched,
        thematic_score=thematic_score,
        zxcvbn_score=zxcvbn_score,
        reused_sites=reused_sites,
        derivative_sites=derivative_sites,
        suggested_password=suggested_pw,
        suggested_explanation=suggested_exp
    )
