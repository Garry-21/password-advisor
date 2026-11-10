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
from vault.audit import extract_base_password, _are_derivatives
from vault.generator import GeneratedPassword, generate_passphrase
from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity, check_hibp_status, BreachStatus
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
    breach_status: BreachStatus = BreachStatus.NOT_BREACHED
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
        b_status, hits = check_hibp_status(candidate_password)
    except Exception:
        b_status, hits = BreachStatus.UNKNOWN, -1

    is_breached = (b_status == BreachStatus.BREACHED)
    if is_breached:
        reasons.append(f"This password appeared {hits:,} times in past public data breaches.")
    elif b_status == BreachStatus.UNKNOWN:
        reasons.append("Could not verify password against public breaches (network offline/unreachable). Treat with caution.")

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

        if _are_derivatives(candidate_password, e.password, cand_base, extract_base_password(e.password)):
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
                f"We generated a locally generated passphrase inspired by your '{user_theme}' theme. "
                f"It offers {suggested_pw.entropy_bits} bits of generation entropy; this is not a guarantee against compromise."
            )
        else:
            suggested_exp = (
                f"We generated a 4-word EFF passphrase with {suggested_pw.entropy_bits} bits of entropy. "
                "Keep it unique and private; generation entropy is not a measured cracking time."
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
        breach_status=b_status,
        suggested_password=suggested_pw,
        suggested_explanation=suggested_exp
    )
