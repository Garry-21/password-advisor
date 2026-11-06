"""
tests/test_session.py
---------------------
Tests for SessionManager and master password policy (Phase 2):
- Unlock lifecycle with password and recovery key
- Auto-lock timeout after idle duration
- Memory key zeroisation
- Dogfooding master password validation
"""

import time
import tempfile
import os
import pytest

from vault.models import VaultHeader, Profile
from vault.crypto import create_vault_header, generate_recovery_key, parse_recovery_key
from vault.store import VaultStore
from vault.session import (
    SessionManager,
    validate_master_password,
    SESSION_KEY_DEK,
    SESSION_KEY_UNLOCKED
)


@pytest.fixture
def session_env():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_session_vault.db")
        store = VaultStore(db_path=db_path)
        formatted_rec, rec_raw = generate_recovery_key()
        header, dek, _ = create_vault_header("MasterPassword123!", recovery_key=rec_raw)
        store.save_header(header)
        session_state = {}
        try:
            yield store, header, dek, formatted_rec, rec_raw, session_state
        finally:
            store.close()


def test_unlock_lifecycle_with_password(session_env):
    store, header, expected_dek, _, _, state = session_env

    # 1. Initially locked
    assert SessionManager.is_unlocked(state) is False

    # 2. Wrong password
    ok, msg = SessionManager.unlock_with_password(store, state, "WrongPass123!")
    assert ok is False
    assert SessionManager.is_unlocked(state) is False

    # 3. Correct password
    ok, msg = SessionManager.unlock_with_password(store, state, "MasterPassword123!")
    assert ok is True
    assert SessionManager.is_unlocked(state) is True
    assert SessionManager.get_dek(state) == expected_dek

    # 4. Lock vault & zeroise
    SessionManager.lock_vault(state)
    assert SessionManager.is_unlocked(state) is False
    assert state[SESSION_KEY_DEK] is None


def test_unlock_with_recovery_key(session_env):
    store, header, expected_dek, formatted_rec, rec_raw, state = session_env

    parsed_rec = parse_recovery_key(formatted_rec)
    ok, msg = SessionManager.unlock_with_recovery(store, state, parsed_rec)
    assert ok is True
    assert SessionManager.is_unlocked(state) is True
    assert SessionManager.get_dek(state) == expected_dek


def test_auto_lock_inactivity(session_env):
    store, header, expected_dek, _, _, state = session_env
    SessionManager.unlock_with_password(store, state, "MasterPassword123!")
    assert SessionManager.is_unlocked(state) is True

    # Simulate 6 minutes of inactivity (timeout default = 5 min)
    state["_cav_last_activity"] = time.time() - 360.0

    was_locked = SessionManager.check_auto_lock(state)
    assert was_locked is True
    assert SessionManager.is_unlocked(state) is False


def test_master_password_policy():
    profile = Profile(first_name="Maya", surname="Carter", city="Denver", birth_year=1998)

    # 1. Weak password fails syntax
    ok, issues = validate_master_password("123456", profile)
    assert ok is False
    assert any("too weak" in issue for issue in issues)

    # 2. Personal info leaks fail semantic check
    ok, issues = validate_master_password("MayaCarter1998!", profile)
    assert ok is False
    assert any("personal information" in issue for issue in issues)

    # 3. Breached password fails breach check
    ok, issues = validate_master_password("password", profile)
    assert ok is False

    # 4. Strong, unique, non-personal password passes
    ok, issues = validate_master_password("Quantum-Baking-Constellation-2026!#", profile)
    assert ok is True
    assert len(issues) == 0
