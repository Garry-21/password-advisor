"""
pages/2_Security_Audit.py
-------------------------
Security Audit & Vulnerability Engine:
- Continuous local audit across all 6 vulnerability signals:
  1. HIBP range API breach checking
  2. Thematic Personal Info (PII) coverage
  3. Syntactic complexity (zxcvbn)
  4. Exact credential reuse
  5. Derivative family clustering
  6. Credential aging
- Vault Health Score (VHS) Gauge & Risk classification
- Derivative Family Cluster View
- One-Click Remediation (Quick Fix)
"""

import time
import streamlit as st

from vault.models import Entry
from vault.ui_common import require_unlocked_vault
from vault.audit import audit_vault, VaultAuditReport
from vault.generator import generate_passphrase


def render_audit_page():
    store, dek = require_unlocked_vault()
    profile = store.get_profile(dek)
    entries = store.list_entries(dek)

    st.title(" Context-Aware Security Audit")
    st.markdown(
        "Continuous zero-knowledge vulnerability auditing. Your passwords are evaluated "
        "against your personal profile, public breaches, and cross-account reuse patterns."
    )

    if not entries:
        st.info("No credentials stored yet. Add passwords in **My Vault** or import a CSV to run an audit.")
        return

    # ── Run Audit Trigger ───────────────────────────────────────────────────────
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        run_audit_now = st.button(" Run Full Audit", type="primary", use_container_width=True)
    with col_info:
        st.caption(f"Auditing {len(entries)} credentials across 6 risk vectors.")

    if run_audit_now or "_cached_audit_report" not in st.session_state:
        progress_bar = st.progress(0, text="Checking public breach range API...")

        def update_progress(done, total):
            pct = int((done / max(1, total)) * 100)
            progress_bar.progress(pct, text=f"Checking breaches ({done}/{total} entries)...")

        report: VaultAuditReport = audit_vault(
            entries=entries,
            profile=profile,
            max_hibp_threads=8,
            progress_callback=update_progress
        )
        progress_bar.empty()
        st.session_state._cached_audit_report = report
    else:
        report = st.session_state._cached_audit_report

    st.caption("Scores are heuristic priorities, not probabilities of compromise. Age alone does not require a password change.")
    if report.unknown_breach_count:
        st.warning(f"Breach status unknown for {report.unknown_breach_count} entries. Health score range: {report.vhs_lower_bound:.1f}–{report.vhs_score:.1f}. Retry when online.")
    # ── Vault Health Score (VHS) Display ────────────────────────────────────────
    vhs = report.vhs_score
    if vhs >= 85:
        grade = "A"
        grade_color = "#34d399" # emerald
        grade_desc = "Excellent Security Posture"
    elif vhs >= 70:
        grade = "B"
        grade_color = "#60a5fa" # blue
        grade_desc = "Good (Minor Improvements Needed)"
    elif vhs >= 50:
        grade = "C"
        grade_color = "#fbbf24" # amber
        grade_desc = "Moderate Risk (Action Recommended)"
    else:
        grade = "F"
        grade_color = "#f87171" # red
        grade_desc = "Critical Vulnerabilities Detected"

    if report.unknown_breach_count:
        grade, grade_desc, grade_color = "?", "Assessment incomplete", "#fbbf24"
    st.markdown(
        f"""
        <div class="vhs-gauge-card">
            <h4 style="margin: 0; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.85rem;">Vault Health Score (VHS)</h4>
            <div style="font-size: 4rem; font-weight: 800; color: {grade_color}; line-height: 1.1; margin: 0.5rem 0;">
                {vhs:.1f}<span style="font-size: 1.5rem; font-weight: 500; color: #64748b;"> / 100</span>
            </div>
            <div style="font-size: 1.1rem; font-weight: 600; color: {grade_color};">Grade {grade} — {grade_desc}</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.write("")

    # ── 6-Signal Metric Highlights ──────────────────────────────────────────────
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Breached (HIBP)", report.breached_count, delta=f"-{report.breached_count}" if report.breached_count > 0 else ("Unknown" if report.unknown_breach_count else "Not found"), delta_color="inverse")
    c2.metric("Personal Info (PII)", report.personal_info_count, delta=f"-{report.personal_info_count}" if report.personal_info_count > 0 else "Clean", delta_color="inverse")
    c3.metric("Weak Syntax", report.weak_syntax_count, delta=f"-{report.weak_syntax_count}" if report.weak_syntax_count > 0 else "Clean", delta_color="inverse")
    c4.metric("Exact Reuses", report.reused_count, delta=f"-{report.reused_count}" if report.reused_count > 0 else "Clean", delta_color="inverse")
    c5.metric("Derivative Variations", report.derivative_count, delta=f"-{report.derivative_count}" if report.derivative_count > 0 else "Clean", delta_color="inverse")
    c6.metric("Age > 90d (informational)", report.old_count)

    st.markdown("---")

    # ── Derivative Family Clusters ──────────────────────────────────────────────
    if report.derivative_families:
        st.subheader(" Derivative Password Families")
        st.caption(
            "Attackers who compromise one account routinely test slight variations (e.g. adding years, symbols, or leet substitutions) "
            "on your other services. These accounts are connected by similarity rules; indirect links need not be pairwise similar:"
        )

        for fam_id, site_names in report.derivative_families.items():
            with st.expander(f"Family #{fam_id}: {', '.join(site_names)} ({len(site_names)} services)", expanded=True):
                st.markdown(f"**Affected Services:** `{'`, `'.join(site_names)}`")
                st.caption("Remedy: Replace variations with independent passphrases generated from diverse themes.")

        st.markdown("---")

    # ── Detailed Per-Entry Findings ─────────────────────────────────────────────
    st.subheader(" Credential Vulnerability Breakdown")
    
    # Sort entries by risk score descending
    sorted_results = sorted(report.entry_results, key=lambda x: x.risk_score, reverse=True)

    for res in sorted_results:
        with st.container():
            col_site, col_risk, col_badges, col_fix = st.columns([2, 1, 3, 1.2])

            with col_site:
                st.markdown(f"**{res.site_name}**" + (f" ({res.username})" if res.username else ""))
                crit_label = {1: "Low Criticality", 2: "Medium Criticality", 3: "High Criticality"}[res.criticality]
                st.caption(crit_label)

            with col_risk:
                r_pct = int(res.risk_score * 100)
                r_color = "#34d399" if r_pct == 0 else "#f87171" if r_pct >= 50 else "#fbbf24"
                st.markdown(f"<span style='font-weight: 700; color: {r_color}; font-size: 1.1rem;'>{r_pct}% Risk</span>", unsafe_allow_html=True)

            with col_badges:
                if not res.finding_badges:
                    st.markdown("<span class='badge badge-success'>All Checks Clean</span>", unsafe_allow_html=True)
                else:
                    b_html = ""
                    for b in res.finding_badges:
                        b_type = "badge-danger" if "breached" in b.lower() else "badge-warning"
                        b_html += f"<span class='badge {b_type}'>{b}</span>"
                    st.markdown(b_html, unsafe_allow_html=True)

            with col_fix:
                if res.risk_score > 0:
                    if st.button(" Quick Fix", key=f"qf_{res.entry_id}", help="Generates and saves a clean passphrase"):
                        target_entry = store.get_entry(res.entry_id, dek)
                        if target_entry:
                            new_pass = generate_passphrase(num_words=4, theme=profile.theme if profile else None)
                            target_entry.password = new_pass.password
                            store.put_entry(target_entry, dek)
                            st.toast(f"Replaced password for {res.site_name} with {new_pass.entropy_bits}-bit passphrase!")
                            # Invalidate cached audit report
                            if "_cached_audit_report" in st.session_state:
                                del st.session_state._cached_audit_report
                            st.rerun()

            st.markdown("<hr style='margin: 0.4rem 0; opacity: 0.1;'/>", unsafe_allow_html=True)


if __name__ == "__main__":
    render_audit_page()
