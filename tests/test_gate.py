"""
tests/test_gate.py
------------------
Unit tests for Save-Time Gate and Behavioral Nudge engine:
- Interception of breached passwords
- Detection of user profile PII exposure
- Detection of exact reuse across existing vault entries
- Detection of derivative variations
- Clean password pass-through (needs_nudge == False)
- Self-exclusion on entry edit operations
"""

import pytest
from vault.models import Entry, Profile
from vault.gate import evaluate_save_gate, GateAction


@pytest.fixture
def sample_profile():
    return Profile(
        first_name="Maya",
        surname="Carter",
        city="Denver",
        birth_year=1998,
        theme="baking"
    )


@pytest.fixture
def existing_vault_entries():
    return [
        Entry(id="e1", site_name="BankOfAmerica", url="https://bankofamerica.com", username="maya", password="UltraSecure#Random%Token!2026", criticality=3),
        Entry(id="e2", site_name="Netflix", url="https://netflix.com", username="maya", password="Summer2024!", criticality=1),
        Entry(id="e3", site_name="Spotify", url="https://spotify.com", username="maya", password="SharedMusicPass123$$", criticality=1),
    ]


def test_clean_password_passes_gate(sample_profile, existing_vault_entries):
    clean_pw = "Abacus-Alibi-Canyon-Breeze-2026!#"
    gate_eval = evaluate_save_gate(
        candidate_password=clean_pw,
        target_site="WorkApp",
        existing_entries=existing_vault_entries,
        profile=sample_profile
    )
    assert not gate_eval.needs_nudge
    assert len(gate_eval.reasons) == 0
    assert not gate_eval.is_breached
    assert not gate_eval.reused_sites
    assert not gate_eval.derivative_sites


def test_breached_password_triggers_gate(sample_profile, existing_vault_entries):
    gate_eval = evaluate_save_gate(
        candidate_password="password",
        target_site="NewSite",
        existing_entries=existing_vault_entries,
        profile=sample_profile
    )
    assert gate_eval.needs_nudge
    assert gate_eval.is_breached
    assert gate_eval.breach_hits > 0
    assert any("breach" in r.lower() for r in gate_eval.reasons)
    assert gate_eval.suggested_password is not None
    assert gate_eval.suggested_password.entropy_bits >= 50


def test_pii_leak_triggers_gate(sample_profile, existing_vault_entries):
    gate_eval = evaluate_save_gate(
        candidate_password="MayaDenver1998!",
        target_site="NewSite",
        existing_entries=existing_vault_entries,
        profile=sample_profile
    )
    assert gate_eval.needs_nudge
    assert len(gate_eval.pii_matched) > 0
    assert any("personal information" in r.lower() for r in gate_eval.reasons)
    assert gate_eval.suggested_password is not None


def test_exact_reuse_triggers_gate(sample_profile, existing_vault_entries):
    gate_eval = evaluate_save_gate(
        candidate_password="SharedMusicPass123$$",
        target_site="SoundCloud",
        existing_entries=existing_vault_entries,
        profile=sample_profile
    )
    assert gate_eval.needs_nudge
    assert "Spotify" in gate_eval.reused_sites
    assert any("already in use" in r.lower() for r in gate_eval.reasons)


def test_derivative_triggers_gate(sample_profile, existing_vault_entries):
    # Vault has Summer2024! on Netflix. Candidate is Summer2025!
    gate_eval = evaluate_save_gate(
        candidate_password="Summer2025!",
        target_site="Hulu",
        existing_entries=existing_vault_entries,
        profile=sample_profile
    )
    assert gate_eval.needs_nudge
    assert "Netflix" in gate_eval.derivative_sites
    assert any("derivative" in r.lower() for r in gate_eval.reasons)


def test_edit_operation_excludes_self(sample_profile, existing_vault_entries):
    # When editing Netflix (id="e2"), saving the same password shouldn't flag reuse against itself
    gate_eval = evaluate_save_gate(
        candidate_password="Summer2024!",
        target_site="Netflix",
        existing_entries=existing_vault_entries,
        profile=sample_profile,
        current_entry_id="e2"
    )
    # Shouldn't flag reuse with Netflix because e2 is excluded
    assert "Netflix" not in gate_eval.reused_sites
    assert "Netflix" not in gate_eval.derivative_sites


def test_gate_actions_and_theme_suggestion(sample_profile, existing_vault_entries):
    gate_eval = evaluate_save_gate(
        candidate_password="123",
        target_site="Test",
        existing_entries=existing_vault_entries,
        profile=sample_profile
    )
    assert gate_eval.needs_nudge
    assert GateAction.USE_GENERATED in gate_eval.allowed_actions
    assert GateAction.EDIT in gate_eval.allowed_actions
    assert GateAction.SAVE_ANYWAY in gate_eval.allowed_actions
    # Theme suggestion check
    assert "baking" in gate_eval.suggested_explanation.lower()
