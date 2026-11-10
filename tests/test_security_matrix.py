"""
tests/test_security_matrix.py
-----------------------------
Comprehensive Security Test Matrix:
1. Zero plaintext in SQLite database file or encrypted backup artifacts
2. Ciphertext, authentication tag, and record-id (AAD) tampering detected
3. Wrong / modified recovery key fails
4. Auto-lock timeout blocks access and zeroises DEK from memory
5. Failed-login throttling enforces exponential backoff
6. Backup restore tamper test detects corrupted/modified payloads
7. Clipboard auto-clear removes copied secret after configured timeout
"""

import os
import sqlite3
import time
import pytest
from cryptography.exceptions import InvalidTag

from vault.crypto import (
    create_vault_header,
    unlock_dek_with_password,
    unlock_dek_with_recovery,
    generate_recovery_key,
    parse_recovery_key,
    encrypt_entry,
    decrypt_entry,
    encrypt_profile,
    decrypt_profile,
    AuthError,
)
from vault.models import Entry, Profile, VaultHeader
from vault.store import VaultStore
from vault.session import (
    SessionManager,
    SESSION_KEY_DEK,
    SESSION_KEY_UNLOCKED,
    SESSION_KEY_LAST_ACTIVITY,
    SESSION_KEY_AUTO_LOCK_MINUTES,
)
from vault.backup import create_encrypted_backup, restore_encrypted_backup
from vault.clipboard import copy_with_auto_clear
import pyperclip


@pytest.fixture
def temp_vault_dir(tmp_path):
    return tmp_path


# ── 1. No Plaintext in SQLite File or Backups ─────────────────────────────────
def test_no_plaintext_in_sqlite_or_backups(temp_vault_dir):
    db_path = str(temp_vault_dir / "vault.db")
    store = VaultStore(db_path)
    password = "CorrectHorseBatteryStaple2026!"
    secret_pw = "SuperConfidentialSecretPassword123!"
    secret_note = "ExtremelyPrivateVaultNote456"
    secret_surname = "SecretBagginsSurname"

    header, dek, formatted_rec = create_vault_header(password)
    store.save_header(header)

    entry = Entry(
        id="ent-001",
        site_name="MyBank",
        url="https://bank.example.com",
        username="alice",
        password=secret_pw,
        notes=secret_note
    )
    store.put_entry(entry, dek)

    prof = Profile(first_name="Frodo", surname=secret_surname, city="Shire", birth_year=1990, theme="rings")
    store.save_profile(prof, dek)

    # Check raw sqlite bytes
    with open(db_path, "rb") as f:
        raw_db_bytes = f.read()

    assert secret_pw.encode() not in raw_db_bytes
    assert secret_note.encode() not in raw_db_bytes
    assert secret_surname.encode() not in raw_db_bytes

    # Create backup and check raw backup bytes
    backup_path = str(temp_vault_dir / "backup.spvault")
    create_encrypted_backup(store, backup_path)

    with open(backup_path, "rb") as f:
        raw_backup = f.read()

    assert secret_pw.encode() not in raw_backup
    assert secret_note.encode() not in raw_backup
    assert secret_surname.encode() not in raw_backup


# ── 2. Ciphertext, Tag, and Record-ID (AAD) Tampering Detected ───────────────
def test_tampering_detection(temp_vault_dir):
    master_pw = "ValidMasterPass123!"
    _, dek, _ = create_vault_header(master_pw)

    entry = Entry(
        id="record-999",
        site_name="CryptoBank",
        url="https://cryptobank.local",
        username="bob",
        password="MySecretCryptoPassword!"
    )
    nonce, ct = encrypt_entry(entry, dek)

    # A) Tamper with ciphertext
    tampered_ct = bytearray(ct)
    tampered_ct[5] ^= 0xFF
    with pytest.raises((InvalidTag, AuthError)):
        decrypt_entry("record-999", nonce, bytes(tampered_ct), dek)

    # B) Tamper with authentication tag (last 16 bytes of ct)
    tampered_tag = bytearray(ct)
    tampered_tag[-1] ^= 0x01
    with pytest.raises((InvalidTag, AuthError)):
        decrypt_entry("record-999", nonce, bytes(tampered_tag), dek)

    # C) Tamper with Record-ID / AAD binding
    with pytest.raises((InvalidTag, AuthError)):
        decrypt_entry("record-DIFFERENT", nonce, ct, dek)


# ── 3. Wrong / Modified / Reused Recovery Key Fails ───────────────────────────
def test_recovery_key_failure(temp_vault_dir):
    master_pw = "ValidMasterPass123!"
    formatted_rec, rec_bytes = generate_recovery_key()
    header, dek, _ = create_vault_header(master_pw, recovery_key=rec_bytes)

    # Valid recovery key succeeds
    recovered_dek = unlock_dek_with_recovery(header, rec_bytes)
    assert recovered_dek == dek

    # Wrong recovery key fails
    wrong_key = os.urandom(32)
    with pytest.raises(AuthError):
        unlock_dek_with_recovery(header, wrong_key)

    # Modified recovery key fails
    modified_key = bytearray(rec_bytes)
    modified_key[0] ^= 0x01
    with pytest.raises(AuthError):
        unlock_dek_with_recovery(header, bytes(modified_key))


# ── 4. Auto-lock Blocks Access and Zeroises Key ───────────────────────────────
def test_auto_lock_lifecycle():
    state = {}
    dummy_dek = bytearray(os.urandom(32))
    state[SESSION_KEY_DEK] = dummy_dek
    state[SESSION_KEY_UNLOCKED] = True
    state[SESSION_KEY_LAST_ACTIVITY] = time.time() - 360.0  # 6 minutes ago
    state[SESSION_KEY_AUTO_LOCK_MINUTES] = 5  # 5 minute timeout

    assert SessionManager.is_unlocked(state) is True

    # Check auto-lock
    locked = SessionManager.check_auto_lock(state)
    assert locked is True
    assert SessionManager.is_unlocked(state) is False
    assert state[SESSION_KEY_DEK] is None
    # Verify memory zeroisation: original bytearray cleared
    assert len(dummy_dek) == 0


# ── 5. Failed-login Throttling ────────────────────────────────────────────────
def test_failed_login_throttling(temp_vault_dir):
    db_path = str(temp_vault_dir / "throttle_vault.db")
    store = VaultStore(db_path)
    header, _, _ = create_vault_header("MasterPassword123!")
    store.save_header(header)

    state = {}
    # First 2 failed attempts should record failure without long lockout
    for _ in range(2):
        success, _ = SessionManager.unlock_with_password(store, state, "WrongPassword!")
        assert success is False

    # 3rd consecutive failed attempt triggers throttling penalty
    success, msg = SessionManager.unlock_with_password(store, state, "WrongPassword!")
    assert success is False
    allowed, wait_secs = store.check_unlock_allowed()
    assert allowed is False
    assert wait_secs > 0


# ── 6. Backup Restore Tamper Test ─────────────────────────────────────────────
def test_backup_restore_tamper(temp_vault_dir):
    db_path = str(temp_vault_dir / "orig.db")
    store = VaultStore(db_path)
    header, dek, _ = create_vault_header("MasterPassword123!")
    store.save_header(header)

    entry = Entry(id="ent-1", site_name="Site1", url="https://site1.com", username="u1", password="pw1")
    store.put_entry(entry, dek)

    backup_path = str(temp_vault_dir / "valid_backup.spvault")
    create_encrypted_backup(store, backup_path)

    # Corrupt backup ciphertext in JSON
    with open(backup_path, "r", encoding="utf-8") as f:
        content = f.read()

    import json
    data = json.loads(content)
    # Flip bytes in the ciphertext of record 0
    orig_ct = bytearray.fromhex(data["records"][0]["ct"])
    orig_ct[0] ^= 0xAA
    data["records"][0]["ct"] = orig_ct.hex()

    tampered_backup_path = str(temp_vault_dir / "tampered.spvault")
    with open(tampered_backup_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    # Restoring into a fresh store
    fresh_db = str(temp_vault_dir / "fresh.db")
    fresh_store = VaultStore(fresh_db)
    restore_encrypted_backup(tampered_backup_path, fresh_store)

    # Attempting to decrypt the tampered entry must raise AuthError or InvalidTag
    with pytest.raises((InvalidTag, AuthError)):
        fresh_store.get_entry("ent-1", dek)


# ── 7. Clipboard Clears After Configured Interval ────────────────────────────
def test_clipboard_auto_clear():
    test_secret = "TemporaryClipboardSecret999!"
    # Test copy with 1 second auto-clear
    success = copy_with_auto_clear(test_secret, auto_clear_seconds=1)
    if not success:
        pytest.skip("pyperclip is unavailable or headless display lacks clipboard")

    assert pyperclip.paste() == test_secret

    # Wait for the auto-clear timer (1.2s)
    time.sleep(1.2)
    assert pyperclip.paste() != test_secret
