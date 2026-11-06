"""
tests/test_store.py
-------------------
Tests for SQLite encrypted repository (Phase 2):
- CRUD operations for encrypted records
- In-memory search filtering (no plaintext stored in database)
- Hex / binary strings verification: ensures zero plaintext site names,
  usernames, or passwords exist in vault.db file
- Throttling and exponential backoff on failed unlock attempts
"""

import os
import tempfile
import pytest

from vault.models import Entry, VaultHeader, Profile
from vault.crypto import create_vault_header, generate_dek
from vault.store import VaultStore


@pytest.fixture
def temp_vault():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_vault.db")
        store = VaultStore(db_path=db_path)
        header, dek, _ = create_vault_header("MasterPassword123!")
        store.save_header(header)
        try:
            yield store, header, dek, db_path
        finally:
            store.close()


def test_crud_operations(temp_vault):
    store, header, dek, _ = temp_vault
    
    # 1. Create
    entry = Entry(
        id="e1",
        site_name="ProtonMail",
        url="https://mail.proton.me",
        username="alice@proton.me",
        password="SuperSecretPassword2026!#",
        notes="Primary email account",
        tags=["email", "personal"],
        criticality=3
    )
    store.put_entry(entry, dek)
    assert store.count_entries() == 1

    # 2. Read
    fetched = store.get_entry("e1", dek)
    assert fetched is not None
    assert fetched.id == "e1"
    assert fetched.site_name == "ProtonMail"
    assert fetched.username == "alice@proton.me"
    assert fetched.password == "SuperSecretPassword2026!#"
    assert fetched.criticality == 3

    # 3. Update
    fetched.notes = "Updated primary email notes"
    store.put_entry(fetched, dek)
    updated = store.get_entry("e1", dek)
    assert updated.notes == "Updated primary email notes"
    assert store.count_entries() == 1

    # 4. Delete
    deleted = store.delete_entry("e1")
    assert deleted is True
    assert store.count_entries() == 0
    assert store.get_entry("e1", dek) is None


def test_in_memory_search(temp_vault):
    store, header, dek, _ = temp_vault
    
    e1 = Entry(id="1", site_name="Github", url="https://github.com", username="developer", password="pwd")
    e2 = Entry(id="2", site_name="GitLab", url="https://gitlab.com", username="admin", password="pwd")
    e3 = Entry(id="3", site_name="Google", url="https://google.com", username="user@gmail.com", password="pwd")
    
    store.put_entry(e1, dek)
    store.put_entry(e2, dek)
    store.put_entry(e3, dek)

    # Search query matches Github and GitLab
    results = store.list_entries(dek, search_query="git")
    assert len(results) == 2
    sites = {r.site_name for r in results}
    assert sites == {"Github", "GitLab"}

    # Search for google
    g_res = store.list_entries(dek, search_query="google")
    assert len(g_res) == 1
    assert g_res[0].site_name == "Google"


def test_hex_strings_zero_plaintext_leak(temp_vault):
    store, header, dek, db_path = temp_vault
    
    # Store highly specific strings
    secret_site = "SecretFinancialBank987654"
    secret_user = "classifiedUserAlpha112233"
    secret_pass = "UltraConfidentialPasscodeXYZ9988"
    
    entry = Entry(
        id="crit-1",
        site_name=secret_site,
        url="https://secret.bank.example",
        username=secret_user,
        password=secret_pass,
        notes="Extremely secret notes content"
    )
    store.put_entry(entry, dek)

    # Read raw database binary file
    with open(db_path, "rb") as f:
        raw_db_content = f.read()

    # None of the secret strings must appear in plaintext anywhere in the SQLite file
    assert secret_site.encode("utf-8") not in raw_db_content
    assert secret_user.encode("utf-8") not in raw_db_content
    assert secret_pass.encode("utf-8") not in raw_db_content
    assert b"Extremely secret notes content" not in raw_db_content


def test_failed_unlock_throttling(temp_vault):
    store, _, _, _ = temp_vault
    
    # Initial state: allowed
    allowed, remaining = store.check_unlock_allowed()
    assert allowed is True
    assert remaining == 0.0

    # 1st failure (no penalty)
    p1 = store.record_failed_unlock()
    assert p1 == 0.0
    allowed, _ = store.check_unlock_allowed()
    assert allowed is True

    # 2nd failure (no penalty)
    p2 = store.record_failed_unlock()
    assert p2 == 0.0

    # 3rd failure (2s backoff)
    p3 = store.record_failed_unlock()
    assert p3 == 2.0
    allowed, remaining = store.check_unlock_allowed()
    assert allowed is False
    assert remaining > 0.0

    # Reset
    store.reset_failed_unlocks()
    allowed_after_reset, _ = store.check_unlock_allowed()
    assert allowed_after_reset is True
