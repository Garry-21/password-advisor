"""
pages/3_Password_Generator.py
-----------------------------
Local Password & Passphrase Generator:
- 100% offline CSPRNG generation
- EFF Large Wordlist passphrases (7,776 words)
- Offline thematic vocabulary integration (Baking, Sci-Fi, Nature, Music, Sports, Travel)
- Random character mode with configurable pools and ambiguous character filtering
- Exact combinatorial entropy display (H = sum(log2(pool_i)))
- Clipboard copy with 20-second automatic clearing
"""

import streamlit as st

from vault.ui_common import require_unlocked_vault
from vault.generator import (
    generate_passphrase,
    generate_random_password,
    get_available_themes,
    DEFAULT_SYMBOL_POOL
)
from vault.clipboard import copy_to_clipboard


def render_generator_page():
    store, dek = require_unlocked_vault()
    profile = store.get_profile(dek)

    st.title(" Local Password Generator")
    st.markdown(
        "Generate cryptographically secure passphrases and passwords. Generated entirely "
        "offline using Python's hardware-backed CSPRNG (`secrets` module)."
    )

    tab_passphrase, tab_random = st.tabs([" Memorizable Passphrase (EFF)", " Random Characters"])

    # ── Tab 1: Passphrase Generator ─────────────────────────────────────────────
    with tab_passphrase:
        col_ctrls, col_preview = st.columns([1.5, 2.5])

        with col_ctrls:
            st.markdown("#### Passphrase Configuration")
            num_words = st.slider("Word Count", min_value=3, max_value=8, value=4, help="4 EFF words offer >50 bits of entropy")
            
            default_theme_val = profile.theme if (profile and profile.theme) else ""
            custom_theme = st.text_input(
                "Incorporate Thematic Vocabulary / Words (optional)",
                value=default_theme_val,
                placeholder="e.g. Scifi, Nature, Gaming, Coffee, or custom words...",
                help="Type any topic, hobby, or custom words to blend into the passphrase. Leave empty for pure EFF words."
            )
            separator = st.selectbox("Word Separator", ["-", ".", "_", " "], index=0)

            c_cap, c_num, c_sym = st.columns(3)
            with c_cap:
                capitalize = st.checkbox("Capitalize", value=True)
            with c_num:
                include_digit = st.checkbox("Include Digit", value=True)
            with c_sym:
                include_symbol = st.checkbox("Include Symbol", value=True)

            gen_trigger = st.button(" Generate Passphrase", type="primary", use_container_width=True)

        theme_arg = custom_theme.strip().lower() if (custom_theme and custom_theme.strip() and custom_theme.strip().lower() != "none") else None
        passphrase_res = generate_passphrase(
            num_words=num_words,
            theme=theme_arg,
            separator=separator,
            capitalize=capitalize,
            include_digit=include_digit,
            include_symbol=include_symbol
        )

        with col_preview:
            st.markdown("#### Generated Passphrase")
            st.code(passphrase_res.password, language="text")

            col_cp, col_entropy = st.columns([1, 2])
            with col_cp:
                if st.button(" Copy to Clipboard", key="btn_cp_phrase", use_container_width=True):
                    copy_to_clipboard(passphrase_res.password, timeout_seconds=20)
                    st.toast("Passphrase copied! Auto-clears in 20s.")

            with col_entropy:
                bits = passphrase_res.entropy_bits
                st.markdown(f"**Entropy:** `{bits} bits` | *Exceeds NIST guidelines*")

            st.caption(
                f"Formula: $H = {passphrase_res.details.get('eff_words_count')} \\times \\log_2(7776) + \\text{{theme}} + \\text{{digit}} + \\text{{symbol}} = {bits}\\text{{ bits}}$"
            )

    # ── Tab 2: Random Characters ────────────────────────────────────────────────
    with tab_random:
        col_r_ctrls, col_r_preview = st.columns([1.5, 2.5])

        with col_r_ctrls:
            st.markdown("#### Character Options")
            length = st.slider("Password Length", min_value=8, max_value=64, value=20)

            col_u, col_l = st.columns(2)
            with col_u:
                use_upper = st.checkbox("Uppercase (A-Z)", value=True)
            with col_l:
                use_lower = st.checkbox("Lowercase (a-z)", value=True)

            col_d, col_s = st.columns(2)
            with col_d:
                use_digits = st.checkbox("Digits (0-9)", value=True)
            with col_s:
                use_symbols = st.checkbox("Symbols (!@#...)", value=True)

            exclude_ambig = st.checkbox("Exclude Ambiguous (l, 1, I, O, 0)", value=True)

            rand_trigger = st.button(" Generate Password", key="btn_gen_rand", type="primary", use_container_width=True)

        rand_res = generate_random_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_ambiguous=exclude_ambig
        )

        with col_r_preview:
            st.markdown("#### Generated Password")
            st.code(rand_res.password, language="text")

            col_r_cp, col_r_entropy = st.columns([1, 2])
            with col_r_cp:
                if st.button(" Copy to Clipboard", key="btn_cp_rand", use_container_width=True):
                    copy_to_clipboard(rand_res.password, timeout_seconds=20)
                    st.toast("Password copied! Auto-clears in 20s.")

            with col_r_entropy:
                r_bits = rand_res.entropy_bits
                st.markdown(f"**Entropy:** `{r_bits} bits` | *Pool size: {rand_res.details.get('pool_size')} chars*")

            st.caption(
                f"Formula: $H = {length} \\times \\log_2({rand_res.details.get('pool_size')}) = {r_bits}\\text{{ bits}}$"
            )


if __name__ == "__main__":
    render_generator_page()
