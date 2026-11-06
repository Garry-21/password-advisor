"""
pages/6_Advisor_Pilot.py
------------------------
Research Pilot Password Advisor:
- Backward-compatible implementation of the research study interface
- Evaluates individual passwords against fictional participant profiles
- A/B framing variant testing and decision time tracking
- Safe logging of aggregate metrics to results.csv
"""

import os
import csv
import time
import random
from datetime import datetime
import streamlit as st

from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity
from modules.semantic import calculate_thematic_coverage
from modules.llm import get_mnemonic_suggestions, extract_passphrase_options
from modules.ui_copy import build_nudge
from vault.ui_common import apply_custom_styles


csv_file = "results.csv"
if not os.path.exists(csv_file):
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "participant_id", "consent", "variant", "decision_time", "adopted", "coverage_score", "breach_hits", "zxcvbn_score", "n_findings", "finding_types"])


def log_result(participant_id: str, adopted: bool, decision_time: float, coverage_score: float, breach_hits: int, zxcvbn_score: int, n_findings: int, finding_types: str, consent: bool = True):
    with open(csv_file, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            participant_id,
            consent,
            st.session_state.ab_variant,
            round(decision_time, 2),
            adopted,
            round(coverage_score, 2),
            breach_hits,
            zxcvbn_score,
            n_findings,
            finding_types
        ])


def render_advisor_pilot_page():
    apply_custom_styles()

    if "ab_variant" not in st.session_state:
        st.session_state.ab_variant = random.choice(["A", "B"])
    if "start_time" not in st.session_state:
        st.session_state.start_time = time.time()
    if "evaluated" not in st.session_state:
        st.session_state.evaluated = False

    st.title(" Password Advisor (Research Pilot)")
    st.markdown("Study session interface for testing participant response to contextual password feedback.")

    with st.expander(" Participant Consent & Study Instructions", expanded=False):
        st.markdown(
            "> *This is a class pilot of a password tool. Your participation is voluntary and you can stop at any time. "
            "You'll be given a made-up profile and asked to try three invented passwords. Please don't use any password you use for a real account. "
            "We record a random participant ID, the framing version you saw, your choices, and how long you took. "
            "We don't record your name or any password you type. Results will be reported only in aggregate.*"
        )

    # Participant setup
    col_p, col_c = st.columns([1, 2])
    with col_p:
        participant_id = st.text_input("Participant ID (e.g. P01)", value=st.session_state.get("_pilot_pid", "P01"))
        st.session_state._pilot_pid = participant_id
    with col_c:
        consent_agreed = st.checkbox("I agree to the participant consent terms above", value=True)

    if not participant_id or not consent_agreed:
        st.warning("Please enter your Participant ID and confirm consent to participate.")
        return

    st.info(
        "**Fictional Profile for this trial:**\n\n"
        "• **First Name:** Maya | **Surname:** Carter | **Hometown:** Denver | **Birth Year:** 1998 | **Theme:** Baking\n\n"
        "*Pre-filled to ensure consistent contextual analysis without collecting any real PII.*"
    )

    with st.form("metadata_form"):
        first_name = st.text_input("First Name", value="Maya")
        surname = st.text_input("Surname", value="Carter")
        city = st.text_input("Hometown", value="Denver")
        birth_year = st.number_input("Birth Year", min_value=1900, max_value=2026, value=1998)
        theme = st.text_input("Theme for suggestions (type any interest, hobby, or topic)", value="Baking", placeholder="e.g. Baking, Astronomy, Gaming, Sci-Fi, Coffee, Anime...")
        password = st.text_input("Enter an invented password to check (do NOT use a real password)", type="password")
        submitted = st.form_submit_button("Evaluate Password", type="primary")

    if submitted and password:
        st.session_state.start_time = time.time()
        metadata = {
            "first_name": first_name,
            "surname": surname,
            "city": city,
            "birth_year": birth_year
        }

        # 1. Syntactic & Breach Check
        syntax_metrics = evaluate_syntactic_strength(password)
        breach_count = check_hibp_k_anonymity(password)

        # 2. Semantic Analysis
        semantic_metrics = calculate_thematic_coverage(password, metadata)

        # 3. Aggregate Findings
        findings = []
        finding_types_list = []
        nudge_findings = []

        if breach_count > 0:
            findings.append(f"Found in public breaches ({breach_count:,} times)")
            finding_types_list.append("breach")
            nudge_findings.append({"type": "breach", "n": breach_count})
        elif breach_count == -1:
            findings.append("Breach database check unavailable")

        if syntax_metrics["score"] < 3:
            findings.append("Easily guessable pattern or too simple")
            finding_types_list.append("syntax")
            nudge_findings.append({"type": "syntax"})

        if semantic_metrics["score"] > 0:
            matched = ", ".join(semantic_metrics["matched_fields"])
            findings.append(f"Contains personal info from profile ({matched})")
            finding_types_list.append("semantic")
            nudge_findings.append({"type": "semantic", "detail": f"your {matched}"})

        # 4. Generate Framing Nudge
        variant = st.session_state.get("ab_variant", "A")
        nudge_text = build_nudge(variant=variant, findings=nudge_findings)

        # 5. Suggestions
        with st.spinner("Generating contextual passphrases..."):
            failure_reasons_str = "; ".join(findings) if findings else "weak or common password pattern"
            mnemonic_story = get_mnemonic_suggestions(failure_reasons_str, theme)
            passphrase_candidates = extract_passphrase_options(mnemonic_story, theme=theme)

        st.session_state.eval_results = {
            "syntax": syntax_metrics,
            "breach": breach_count,
            "semantic": semantic_metrics,
            "findings": findings,
            "finding_types": ",".join(finding_types_list),
            "n_findings": len(findings),
            "nudge": nudge_text,
            "mnemonic_story": mnemonic_story,
            "suggestions": passphrase_candidates,
            "submitted_password": password
        }
        st.session_state.evaluated = True

    if st.session_state.get("evaluated") and "eval_results" in st.session_state:
        res = st.session_state.eval_results

        st.markdown("### Step 2: Evaluation Results")
        if res["nudge"]:
            if st.session_state.ab_variant == "A":
                st.error(res["nudge"])
            else:
                st.warning(res["nudge"])
        else:
            st.success("Great job! No major vulnerabilities detected.")

        col1, col2, col3 = st.columns(3)
        col1.metric("Strength Score", f"{res['syntax']['score']}/4")
        col2.metric("Breach Exposure", f"{res['breach']:,} times" if res["breach"] > 0 else "0 (Safe)")
        col3.metric("Profile Overlap", f"{int(res['semantic']['score'] * 100)}%")

        st.markdown("### Step 3: Suggested Replacements")
        if res.get("mnemonic_story"):
            st.markdown(res["mnemonic_story"])

        st.markdown("#### Select a Passphrase to Adopt:")
        chosen_password = None
        for i, sug in enumerate(res["suggestions"]):
            col_a, col_b = st.columns([3, 1])
            col_a.markdown(f"**Option {i+1}:** `{sug}`")
            if col_b.button(f"Adopt #{i+1}", key=f"adopt_{i}"):
                chosen_password = sug
                break

        col_left, col_right = st.columns(2)
        with col_left:
            if chosen_password or st.button("Adopt Top Suggestion", type="primary"):
                dec_time = time.time() - st.session_state.start_time
                log_result(
                    participant_id=participant_id,
                    adopted=True,
                    decision_time=dec_time,
                    coverage_score=res["semantic"]["score"],
                    breach_hits=max(0, res["breach"]),
                    zxcvbn_score=res["syntax"]["score"],
                    n_findings=res["n_findings"],
                    finding_types=res["finding_types"]
                )
                st.success(f"Adopted! Decision logged ({dec_time:.1f}s).")
                st.session_state.evaluated = False

        with col_right:
            if st.button("Keep My Original Password"):
                dec_time = time.time() - st.session_state.start_time
                log_result(
                    participant_id=participant_id,
                    adopted=False,
                    decision_time=dec_time,
                    coverage_score=res["semantic"]["score"],
                    breach_hits=max(0, res["breach"]),
                    zxcvbn_score=res["syntax"]["score"],
                    n_findings=res["n_findings"],
                    finding_types=res["finding_types"]
                )
                st.info(f"Kept original. Decision logged ({dec_time:.1f}s).")
                st.session_state.evaluated = False


if __name__ == "__main__":
    render_advisor_pilot_page()
