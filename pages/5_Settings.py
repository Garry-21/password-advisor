"""
pages/5_Settings.py
-------------------
Settings & Profile Management:
- Context Profile configuration for Thematic Coverage audit
- Inactivity auto-lock timeout adjustment
- Master password rotation (re-wrapping DEK via Argon2id)
- Emergency recovery key management
- Audit weight customization
"""

import streamlit as st

from vault.models import Profile, VaultHeader
from vault.ui_common import require_unlocked_vault
from vault.crypto import change_master_password, generate_recovery_key, parse_recovery_key
from vault.session import validate_master_password, SessionManager
from vault.audit import WEIGHTS


def render_settings_page():
    store, dek = require_unlocked_vault()
    profile = store.get_profile(dek)

    st.title(" Vault Settings & Profile")
    st.markdown("Configure personal context profile, security parameters, and cryptographic keys.")

    tab_profile, tab_security, tab_master_pw, tab_audit_weights = st.tabs([
        " Personal Profile",
        " Session & Auto-Lock",
        " Change Master Password",
        " Audit Weights"
    ])

    # ── Tab 1: Profile Management ───────────────────────────────────────────────
    with tab_profile:
        st.markdown("#### Context Profile for Semantic Defense")
        st.caption(
            "This profile is used strictly locally by the semantic audit engine to identify passwords "
            "vulnerable to social-engineering and targeted dictionary guessing. It is encrypted in your vault."
        )

        with st.form("profile_update_form"):
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name", value=profile.first_name if profile else "")
                city = st.text_input("Hometown / City", value=profile.city if profile else "")
            with col2:
                surname = st.text_input("Surname", value=profile.surname if profile else "")
                birth_year = st.number_input("Birth Year", min_value=1900, max_value=2026, value=profile.birth_year if profile else 1998)

            curr_theme = profile.theme if (profile and profile.theme) else "baking"
            theme = st.text_input(
                "Preferred Passphrase Theme",
                value=curr_theme,
                placeholder="e.g. scifi, nature, anime, gaming, baking, sports...",
                help="Type any topic, hobby, or custom words you like. Used for generating personalized, memorable passphrases."
            )

            save_prof = st.form_submit_button("Save Profile Changes", type="primary")

        if save_prof:
            new_profile = Profile(
                first_name=first_name.strip(),
                surname=surname.strip(),
                city=city.strip(),
                birth_year=int(birth_year),
                theme=theme.strip()
            )
            store.save_profile(new_profile, dek)
            st.success("Context profile updated and encrypted.")
            if "_cached_audit_report" in st.session_state:
                del st.session_state._cached_audit_report
            st.rerun()

    # ── Tab 2: Session & Auto-Lock ──────────────────────────────────────────────
    with tab_security:
        st.markdown("#### Inactivity Auto-Lock")
        st.caption("Automatically zeroises encryption keys in host memory when no interactions occur.")

        curr_timeout = st.session_state.get("_cav_auto_lock_minutes", 5)
        new_timeout = st.select_slider(
            "Auto-Lock Timeout",
            options=[1, 2, 5, 10, 15, 30, 60],
            value=curr_timeout,
            format_func=lambda x: f"{x} minute{'s' if x > 1 else ''}"
        )

        if st.button("Apply Inactivity Timeout", type="primary"):
            st.session_state._cav_auto_lock_minutes = new_timeout
            st.success(f"Inactivity timeout set to {new_timeout} minutes.")

    # ── Tab 3: Master Password Rotation ─────────────────────────────────────────
    with tab_master_pw:
        st.markdown("#### Rotate Master Password")
        st.caption(
            "Envelope encryption allows you to rotate your master password without re-encrypting "
            "any of your stored records. The DEK is simply re-wrapped under a new Argon2id KEK."
        )

        with st.form("master_pw_rotate_form"):
            current_pw = st.text_input("Current Master Password", type="password")
            new_pw = st.text_input("New Master Password", type="password")
            confirm_new_pw = st.text_input("Confirm New Master Password", type="password")

            rotate_submit = st.form_submit_button("Rotate Master Password", type="primary")

        if rotate_submit:
            if not current_pw or not new_pw:
                st.error("All password fields are required.")
            elif new_pw != confirm_new_pw:
                st.error("New master passwords do not match.")
            else:
                is_valid, issues = validate_master_password(new_pw, profile=profile)
                if not is_valid:
                    for iss in issues:
                        st.error(f" {iss}")
                else:
                    header = store.get_header()
                    try:
                        with st.spinner("Re-deriving KEK and updating keyslots..."):
                            updated_header = change_master_password(header, current_pw, new_pw)
                            store.save_header(updated_header)
                        st.success("Master password successfully rotated! Your credentials remain encrypted under the same DEK.")
                    except Exception as e:
                        st.error(f"Rotation failed: {str(e)}")

    # ── Tab 4: Audit Weights ────────────────────────────────────────────────────
    with tab_audit_weights:
        st.markdown("#### Audit Signal Weighting")
        st.caption("These are transparent heuristic weights, not learned probabilities. Research model fitting is kept separate from the live vault.")
        st.table({"Signal": list(WEIGHTS), "Default weight": list(WEIGHTS.values())})
        st.info("Age contributes zero by default. Semantic, reuse and derivative contributions share a 0.35 cap. Alternative weights and fitted models are evaluated with the research scripts before any deployment.")


if __name__ == "__main__":
    render_settings_page()
