"""
pages/1_Vault.py
----------------
My Vault: Credential Management & Save-Time Gate:
- List, search, add, edit, and delete encrypted entries
- Integrated Save-Time Gate with behavioral nudges and 3 explicit actions:
  ['use_generated', 'edit', 'save_anyway']
- Clipboard copy with 20-second automatic clearing
- Criticality tagging and password history tracking
"""

import time
import uuid
import streamlit as st

from vault.models import Entry
from vault.ui_common import require_unlocked_vault
from vault.gate import evaluate_save_gate, GateAction
from vault.generator import generate_passphrase
from vault.clipboard import copy_to_clipboard
from vault.study import is_study_mode, assign_condition, log_study_event
from modules.syntactic import evaluate_syntactic_strength


def render_vault_page():
    store, dek = require_unlocked_vault()
    profile = store.get_profile(dek)

    st.title("My Vault")
    st.markdown("All entries are encrypted with **AES-256-GCM** and stored solely on your machine.")

    entries = store.list_entries(dek)

    study_active = is_study_mode()
    study_pid = st.session_state.get('_study_pid', 'P01')
    study_task = st.session_state.get('_study_task', 'T1')
    study_cond = assign_condition(study_pid) if study_active else 'G4'
    if study_active:
        with st.sidebar.expander('Study Mode (Active)', expanded=True):
            study_pid = st.text_input('Participant ID', value=study_pid)
            study_task = st.text_input('Task ID', value=study_task)
            st.session_state._study_pid = study_pid
            st.session_state._study_task = study_task
            study_cond = assign_condition(study_pid)
            st.info(f'Assigned Condition: **{study_cond}**')

    # ── Top Action Bar ──────────────────────────────────────────────────────────
    col_search, col_add = st.columns([3, 1])
    with col_search:
        search_query = st.text_input("Search entries (site, username, notes, tags)...", key="vault_search")
    with col_add:
        st.write("") # vertical spacing
        open_add = st.button("Add Entry", type="primary", use_container_width=True)

    if open_add or st.session_state.get("_show_add_modal"):
        if not st.session_state.get("_show_add_modal"):
            st.session_state._save_start_time = time.time()
        st.session_state._show_add_modal = True

    # ── Add / Edit Entry Dialog ────────────────────────────────────────────────
    if st.session_state.get("_show_add_modal"):
        edit_entry_id = st.session_state.get("_edit_entry_id")
        existing_e = None
        if edit_entry_id:
            existing_e = store.get_entry(edit_entry_id, dek)

        st.markdown("---")
        modal_title = "Edit Credential" if existing_e else "Add New Credential"
        st.subheader(modal_title)

        with st.form("entry_editor_form"):
            col1, col2 = st.columns(2)
            with col1:
                site_name = st.text_input("Site / Service Name", value=existing_e.site_name if existing_e else "")
                url = st.text_input("Website URL", value=existing_e.url if existing_e else "")
                username = st.text_input("Username or Email", value=existing_e.username if existing_e else "")
            with col2:
                criticality = st.select_slider(
                    "Account Criticality",
                    options=[1, 2, 3],
                    value=existing_e.criticality if existing_e else 2,
                    format_func=lambda x: {1: "1 - Low", 2: "2 - Medium", 3: "3 - High / Financial"}[x]
                )
                tags_str = st.text_input("Tags (comma-separated)", value=", ".join(existing_e.tags) if existing_e else "")
                notes = st.text_area("Notes", value=existing_e.notes if existing_e else "", height=68)

            st.markdown("#### Password")
            col_pw, col_gen = st.columns([3, 1])
            with col_pw:
                candidate_pw = st.text_input(
                    "Password",
                    value=existing_e.password if existing_e else st.session_state.get("_generated_fill", ""),
                    type="password",
                    key="cand_pw_input"
                )
            with col_gen:
                st.write("")
                if st.form_submit_button("Generate"):
                    theme_to_use = profile.theme if (profile and profile.theme) else None
                    suggested = generate_passphrase(num_words=4, theme=theme_to_use)
                    st.session_state._generated_fill = suggested.password
                    st.rerun()

            col_submit, col_cancel = st.columns([1, 4])
            with col_submit:
                submit_save = st.form_submit_button("Save Credential", type="primary")
            with col_cancel:
                cancel_save = st.form_submit_button("Cancel")

        if cancel_save:
            st.session_state._show_add_modal = False
            st.session_state._edit_entry_id = None
            st.session_state._nudge_eval = None
            st.rerun()

        if submit_save:
            if not site_name or not candidate_pw:
                st.error("Site name and password are required.")
            else:
                elapsed_ms = (time.time() - st.session_state.get("_save_start_time", time.time())) * 1000.0
                st.session_state._save_elapsed_ms = elapsed_ms

                entry_to_save = Entry(
                    id=existing_e.id if existing_e else str(uuid.uuid4()),
                    site_name=site_name,
                    url=url,
                    username=username,
                    password=candidate_pw,
                    notes=notes,
                    criticality=criticality,
                    tags=[t.strip() for t in tags_str.split(",") if t.strip()]
                )

                # ── Study Mode Condition Branching ─────────────────────────
                if study_active and study_cond == "G1":
                    z_res = evaluate_syntactic_strength(candidate_pw)
                    if z_res["score"] < 3:
                        st.session_state._nudge_eval = GateEvaluation(
                            needs_nudge=True,
                            reasons=[f"Weak password complexity: zxcvbn score {z_res['score']}/4"],
                            is_breached=False, breach_hits=0, pii_matched=[], thematic_score=0.0,
                            zxcvbn_score=z_res["score"], reused_sites=[], derivative_sites=[],
                            suggested_password=None
                        )
                        st.session_state._pending_entry_data = entry_to_save.__dict__
                        st.rerun()
                    else:
                        store.put_entry(entry_to_save, dek)
                        log_study_event(study_pid, "G1", study_task, candidate_pw, False, False, False, elapsed_ms)
                        st.session_state._show_add_modal = False
                        st.session_state._edit_entry_id = None
                        st.success(f"Saved credential for **{site_name}**.")
                        st.rerun()

                elif study_active and study_cond == "G2":
                    store.put_entry(entry_to_save, dek)
                    gate_eval = evaluate_save_gate(candidate_pw, site_name, entries, profile, existing_e.id if existing_e else None)
                    if gate_eval.needs_nudge:
                        log_study_event(study_pid, "G2", study_task, candidate_pw, True, True, False, elapsed_ms)
                        st.warning("Saved credential, but flagged: " + ", ".join(gate_eval.reasons))
                    else:
                        log_study_event(study_pid, "G2", study_task, candidate_pw, False, False, False, elapsed_ms)
                        st.success(f"Saved credential for **{site_name}**.")
                    st.session_state._show_add_modal = False
                    st.session_state._edit_entry_id = None
                    st.rerun()

                else:
                    gate_eval = evaluate_save_gate(candidate_pw, site_name, entries, profile, existing_e.id if existing_e else None)
                    if study_active and study_cond == "G3":
                        gate_eval.suggested_password = None

                    if gate_eval.needs_nudge:
                        st.session_state._nudge_eval = gate_eval
                        st.session_state._pending_entry_data = entry_to_save.__dict__
                        st.rerun()
                    else:
                        store.put_entry(entry_to_save, dek)
                        if study_active:
                            log_study_event(study_pid, study_cond, study_task, candidate_pw, False, False, False, elapsed_ms)
                        st.session_state._show_add_modal = False
                        st.session_state._edit_entry_id = None
                        st.session_state._generated_fill = ""
                        st.success(f"Saved credential for **{site_name}**.")
                        st.rerun()

    # ── Save-Time Gate Nudge Modal ──────────────────────────────────────────────
    if st.session_state.get("_nudge_eval") and st.session_state.get("_pending_entry_data"):
        nudge: GateEvaluation = st.session_state._nudge_eval
        pending = st.session_state._pending_entry_data

        st.warning("**Security Alert: Potential Password Vulnerability Detected**")
        st.markdown("Our local detector identified the following concerns before saving:")
        for r in nudge.reasons:
            st.markdown(f"- **{r}**")

        if nudge.suggested_password:
            st.info(
                f"**Recommended Alternative ({nudge.suggested_password.entropy_bits} bits entropy):**\n\n"
                f"### `{nudge.suggested_password.password}`\n\n"
                f"{nudge.suggested_explanation}"
            )

        has_alt = nudge.suggested_password is not None
        if has_alt:
            col_adopt, col_edit, col_anyway = st.columns(3)
            with col_adopt:
                if st.button("Use Recommended Passphrase", type="primary", use_container_width=True):
                    pending["password"] = nudge.suggested_password.password
                    e = Entry(**pending)
                    store.put_entry(e, dek)
                    if study_active:
                        log_study_event(study_pid, study_cond, study_task, pending["password"], True, False, True, st.session_state.get("_save_elapsed_ms", 0.0))
                    st.session_state._nudge_eval = None
                    st.session_state._pending_entry_data = None
                    st.session_state._show_add_modal = False
                    st.session_state._edit_entry_id = None
                    st.success(f"Saved secure passphrase for **{pending['site_name']}**.")
                    st.rerun()
        else:
            col_edit, col_anyway = st.columns(2)

        with col_edit:
            if st.button("Edit Password", use_container_width=True):
                st.session_state._nudge_eval = None
                st.rerun()

        with col_anyway:
            if st.button(" Save Anyway (Override)", use_container_width=True):
                e = Entry(**pending)
                store.put_entry(e, dek)
                if study_active:
                    log_study_event(study_pid, study_cond, study_task, pending["password"], True, True, False, st.session_state.get("_save_elapsed_ms", 0.0))
                st.session_state._nudge_eval = None
                st.session_state._pending_entry_data = None
                st.session_state._show_add_modal = False
                st.session_state._edit_entry_id = None
                st.warning(f"Saved with warnings for **{pending['site_name']}**.")
                st.rerun()

        st.markdown("---")

    # ── Display Entries ────────────────────────────────────────────────────────
    filtered_entries = store.list_entries(dek, search_query=search_query)

    if not entries:
        st.info("Your vault is currently empty. Click ** Add Entry** above or visit **Import & Backup** to import your passwords.")
        return

    st.markdown(f"**Stored Credentials ({len(filtered_entries)} of {len(entries)})**")

    for e in filtered_entries:
        with st.container():
            col_icon, col_details, col_actions = st.columns([0.5, 3.5, 2])
            
            with col_icon:
                st.markdown("### ")

            with col_details:
                st.markdown(f"**{e.site_name}**" + (f" — *{e.username}*" if e.username else ""))
                if e.url:
                    st.caption(f" [{e.url}]({e.url})")
                
                # Criticality badge
                crit_map = {1: ("badge-info", "Low"), 2: ("badge-warning", "Medium"), 3: ("badge-danger", "High Priority")}
                b_class, b_text = crit_map.get(e.criticality, ("badge-info", "Normal"))
                badge_html = f"<span class='badge {b_class}'>{b_text}</span>"
                for tag in e.tags:
                    badge_html += f"<span class='badge badge-info'>#{tag}</span>"
                st.markdown(badge_html, unsafe_allow_html=True)

                if e.notes:
                    st.caption(f" {e.notes}")

            with col_actions:
                c1, c2, c3 = st.columns([1, 1, 1])
                with c1:
                    if st.button(" Copy", key=f"cp_{e.id}", help="Copies to clipboard (clears in 20s)"):
                        copy_to_clipboard(e.password, timeout_seconds=20)
                        st.toast(f"Copied password for {e.site_name}! Auto-clears in 20s.")
                with c2:
                    if st.button(" Edit", key=f"edit_{e.id}"):
                        st.session_state._show_add_modal = True
                        st.session_state._edit_entry_id = e.id
                        st.rerun()
                with c3:
                    if st.button("", key=f"del_{e.id}", help="Delete credential"):
                        store.delete_entry(e.id)
                        st.toast(f"Deleted {e.site_name}.")
                        st.rerun()

                # Show password toggle
                reveal_key = f"_reveal_{e.id}"
                is_revealed = st.toggle("Show Password", key=reveal_key)
                if is_revealed:
                    st.code(e.password, language="text")

            st.markdown("<hr style='margin: 0.5rem 0; opacity: 0.15;'/>", unsafe_allow_html=True)


if __name__ == "__main__":
    render_vault_page()
