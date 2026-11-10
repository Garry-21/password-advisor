"""
app.py
------
Context-Aware Local Vault (CAV) & Secure Password Advisor:
- Main Streamlit router powered by st.navigation
- Persistent local cryptographic security (Argon2id + AES-256-GCM)
- Continuous context-aware auditing against breaches, personal context, and derivative variations
"""

import streamlit as st
from vault.ui_common import apply_custom_styles

st.set_page_config(
    page_title="Context-Aware Vault",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

apply_custom_styles()

pages = {
    "Vault": [
        st.Page("pages/1_Vault.py", title="My Vault", default=True),
        st.Page("pages/2_Security_Audit.py", title="Security Audit"),
        st.Page("pages/3_Password_Generator.py", title="Password Generator"),
    ],
    "Tools & Data": [
        st.Page("pages/4_Import_Export.py", title="Import & Backup"),
        st.Page("pages/5_Settings.py", title="Settings & Profile"),
    ],
    "Research Pilot": [
        st.Page("pages/6_Advisor_Pilot.py", title="Legacy Advisor Pilot"),
        st.Page("pages/7_Controlled_Study.py", title="Controlled Study G1–G4"),
    ]
}

pg = st.navigation(pages)
pg.run()
