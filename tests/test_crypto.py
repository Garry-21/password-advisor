"""
tests/test_crypto.py
--------------------
Rigorous cryptographic test suite for Context-Aware Vault (Phase 1):
- Round-trip property-based testing with hypothesis
- Tamper detection (single-byte flips in header, nonce, ciphertext)
- Record swapping detection via AAD
- Nonce uniqueness across high-volume generations
- Envelope encryption password rotation without re-encrypting records
- Recovery key unlocking and tamper resistance
- Argon2 parameter tampering detection
"""

import hmac
import secrets
import pytest
from hypothesis import given, settings, strategies as st

from vault.models import Entry, VaultHeader, AuthError, CryptoError
from vault.crypto import (
    generate_dek,
    create_vault_header,
    unlock_dek_with_password,
    unlock_dek_with_recovery,
    change_master_password,
    encrypt_entry,
    decrypt_entry,
    generate_recovery_key,
    parse_recovery_key,
    derive_history_key,
    hash_password_for_history,
)

# ── 1. Property-Based Round-Trip Testing with Hypothesis ─────────────────────

@settings(max_examples=1000, deadline=None)
@given(
    site_name=st.text(min_size=1, max_size=50),
    url=st.text(min_size=1, max_size=100),
    username=st.text(min_size=1, max_size=50),
    password=st.text(min_size=1, max_size=100),
    notes=st.text(min_size=0, max_size=200),
    criticality=st.integers(min_value=1, max_value=3)
)
def test_hypothesis_roundtrip_entry(site_name, url, username, password, notes, criticality):
    dek = generate_dek()
    entry = Entry(
        id=secrets.token_hex(8),
        site_name=site_name,
        url=url,
        username=username,
        password=password,
        notes=notes,
        criticality=criticality
    )

    nonce, ct = encrypt_entry(entry, dek)
    decrypted = decrypt_entry(entry.id, nonce, ct, dek)

    assert decrypted.id == entry.id
    assert decrypted.site_name == entry.site_name
    assert decrypted.url == entry.url
    assert decrypted.username == entry.username
    assert decrypted.password == entry.password
    assert decrypted.notes == entry.notes
    assert decrypted.criticality == entry.criticality


# ── 2. Wrong Master Password Fails Without Revealing Details ─────────────────

def test_wrong_master_password_fails():
    header, dek, _ = create_vault_header("CorrectMasterPassword123!")
    
    with pytest.raises(AuthError) as exc_info:
        unlock_dek_with_password(header, "WrongPassword456!")
    
    # Error message must be generic and not leak internal details
    msg = str(exc_info.value)
    assert "Failed to unlock vault" in msg
    assert "CorrectMasterPassword123" not in msg


# ── 3. Tamper Detection: Single-Byte Flips Raise AuthError ────────────────────

def test_tamper_detection_in_entry_ciphertext():
    dek = generate_dek()
    entry = Entry(id="e1", site_name="Github", url="https://github.com", username="user", password="secretPassword1!")
    nonce, ct = encrypt_entry(entry, dek)

    # Flip one byte in ciphertext
    mutated_ct = bytearray(ct)
    mutated_ct[len(mutated_ct) // 2] ^= 0x01
    
    with pytest.raises(AuthError):
        decrypt_entry("e1", nonce, bytes(mutated_ct), dek)


def test_tamper_detection_in_entry_nonce():
    dek = generate_dek()
    entry = Entry(id="e1", site_name="Github", url="https://github.com", username="user", password="secretPassword1!")
    nonce, ct = encrypt_entry(entry, dek)

    mutated_nonce = bytearray(nonce)
    mutated_nonce[0] ^= 0x01

    with pytest.raises(AuthError):
        decrypt_entry("e1", bytes(mutated_nonce), ct, dek)


def test_tamper_detection_in_header_wrapped_dek():
    header, dek, _ = create_vault_header("MyPass123!")
    
    slot = header.keyslots["password"]
    wrapped = bytearray.fromhex(slot["wrapped_dek_hex"])
    wrapped[0] ^= 0x01
    header.keyslots["password"]["wrapped_dek_hex"] = wrapped.hex()

    with pytest.raises(AuthError):
        unlock_dek_with_password(header, "MyPass123!")


# ── 4. Swapping Two Records' Ciphertexts is Detected (AAD Binding) ────────────

def test_swapping_records_detected_via_aad():
    dek = generate_dek()
    entry1 = Entry(id="rec-001", site_name="Bank", url="https://bank.com", username="u1", password="pw1")
    entry2 = Entry(id="rec-002", site_name="Social", url="https://social.com", username="u2", password="pw2")

    nonce1, ct1 = encrypt_entry(entry1, dek)
    nonce2, ct2 = encrypt_entry(entry2, dek)

    # Attempt to decrypt entry1's ciphertext under entry2's ID
    with pytest.raises(AuthError):
        decrypt_entry("rec-002", nonce1, ct1, dek)

    # Attempt to decrypt entry2's ciphertext under entry1's ID
    with pytest.raises(AuthError):
        decrypt_entry("rec-001", nonce2, ct2, dek)


# ── 5. Nonce Uniqueness Across High-Volume Generations ───────────────────────

def test_nonce_uniqueness_across_encryptions():
    dek = generate_dek()
    entry = Entry(id="perf-id", site_name="Site", url="https://site.com", username="user", password="pw")
    
    # Verify 100,000 nonces generated are strictly unique
    nonces = set()
    for _ in range(100000):
        nonce, _ = encrypt_entry(entry, dek)
        nonces.add(nonce)

    assert len(nonces) == 100000


# ── 6. Master Password Change (Re-wrapping DEK) ──────────────────────────────

def test_master_password_rotation():
    header, dek, _ = create_vault_header("OldMasterPass123!")
    
    # Encrypt a record with current DEK
    entry = Entry(id="e10", site_name="Email", url="https://mail.com", username="me", password="mySecret12345!")
    nonce, ct = encrypt_entry(entry, dek)

    # Rotate master password
    updated_header = change_master_password(header, "OldMasterPass123!", "NewMasterPass456!")

    # Old password must now fail
    with pytest.raises(AuthError):
        unlock_dek_with_password(updated_header, "OldMasterPass123!")

    # New password successfully unlocks the same DEK
    unlocked_dek = unlock_dek_with_password(updated_header, "NewMasterPass456!")
    assert hmac.compare_digest(unlocked_dek, dek)

    # Records decrypt untouched with the unlocked DEK
    decrypted_entry = decrypt_entry("e10", nonce, ct, unlocked_dek)
    assert decrypted_entry.password == "mySecret12345!"


# ── 7. Recovery Key Unlocks; Wrong Recovery Key Fails ────────────────────────

def test_recovery_key_unlock_and_rejection():
    formatted_rec, rec_raw = generate_recovery_key()
    header, dek, _ = create_vault_header("MasterPass123!", recovery_key=rec_raw)

    # Unlock via recovery key
    parsed_rec = parse_recovery_key(formatted_rec)
    unlocked_dek = unlock_dek_with_recovery(header, parsed_rec)
    assert hmac.compare_digest(unlocked_dek, dek)

    # Wrong recovery key must fail
    _, wrong_raw = generate_recovery_key()
    with pytest.raises(AuthError):
        unlock_dek_with_recovery(header, wrong_raw)


# ── 8. Argon2 Parameter Tampering Detected ───────────────────────────────────

def test_argon2_parameter_tampering_detected():
    header, dek, _ = create_vault_header("MasterPass123!")
    
    # Malicious actor lowers memory cost in header to attempt cheap brute-force
    header.argon2["m"] = 1024  # Below ARGON2_MIN_MEMORY (32 MiB)

    with pytest.raises(CryptoError):
        unlock_dek_with_password(header, "MasterPass123!")


# ── 9. Password History HMAC Subkey ──────────────────────────────────────────

def test_password_history_hmac_dedup():
    dek = generate_dek()
    hist_key = derive_history_key(dek)
    
    h1 = hash_password_for_history("OldPassword123!", hist_key)
    h2 = hash_password_for_history("OldPassword123!", hist_key)
    h3 = hash_password_for_history("DifferentPassword!", hist_key)

    assert h1 == h2
    assert h1 != h3
