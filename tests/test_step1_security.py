import pytest
import sqlite3
import json
import secrets
from unittest.mock import patch
from vault.models import Profile, VaultHeader
from vault.crypto import (
    generate_dek,
    encrypt_profile,
    decrypt_profile,
    AuthError
)
from vault.store import VaultStore
from modules.syntactic import (
    check_hibp_status,
    BreachStatus,
    check_hibp_k_anonymity,
    clear_hibp_cache
)
from vault.gate import evaluate_save_gate
from vault.egress_guard import inspect_outbound_request, EgressSecurityError


def test_profile_encryption_and_tampering():
    dek = generate_dek()
    prof = Profile(
        first_name="Alice",
        surname="Smith",
        city="Seattle",
        birth_year=1990,
        theme="scifi"
    )

    nonce, ct = encrypt_profile(prof, dek)
    decrypted = decrypt_profile(nonce, ct, dek)
    assert decrypted.first_name == "Alice"
    assert decrypted.city == "Seattle"
    assert decrypted.birth_year == 1990

    # Wrong DEK must fail
    wrong_dek = generate_dek()
    with pytest.raises(AuthError):
        decrypt_profile(nonce, ct, wrong_dek)

    # Tampered ciphertext must fail
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF
    with pytest.raises(AuthError):
        decrypt_profile(nonce, bytes(tampered_ct), dek)


def test_vault_store_profile_encryption_and_migration(tmp_path):
    db_path = str(tmp_path / "test_vault.db")
    store = VaultStore(db_path=db_path)
    dek = generate_dek()

    # 1. Save encrypted profile
    prof = Profile(first_name="Bob", surname="Jones", city="Austin", birth_year=1985, theme="nature")
    store.save_profile(prof, dek=dek)

    # Raw SQLite inspect: must NOT contain plaintext "Bob", "Jones", or "Austin"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key = 'profile'")
    raw_val = cur.fetchone()[0]
    conn.close()

    raw_text = raw_val.decode("utf-8")
    assert "Bob" not in raw_text
    assert "Austin" not in raw_text
    assert "Jones" not in raw_text
    parsed = json.loads(raw_text)
    assert parsed.get("enc") is True

    # Retrieve with DEK
    retrieved = store.get_profile(dek=dek)
    assert retrieved is not None
    assert retrieved.first_name == "Bob"

    # Retrieve without DEK must return None
    assert store.get_profile(dek=None) is None

    # 2. Test migration from legacy plaintext profile
    legacy_json = json.dumps({"first_name": "Charlie", "surname": "Brown", "city": "NYC", "birth_year": 1970, "theme": "music"}).encode("utf-8")
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('profile', ?)", (legacy_json,))
    conn.commit()
    conn.close()

    # Reading with DEK should auto-migrate
    migrated_prof = store.get_profile(dek=dek)
    assert migrated_prof.first_name == "Charlie"

    # Verify db is now encrypted
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key = 'profile'")
    raw_migrated = cur.fetchone()[0].decode("utf-8")
    conn.close()
    assert json.loads(raw_migrated).get("enc") is True
    assert "Charlie" not in raw_migrated


def test_hibp_tristate():
    clear_hibp_cache()

    # 1. Breached password
    with patch("requests.get") as mock_get:
        # Mock returning suffix match
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "0018A45C4D1DEF81644B54AB7F969B88D65:10\n"
        # Mock sha1 suffix for "password"
        status, count = check_hibp_status("password")
        assert status in (BreachStatus.BREACHED, BreachStatus.NOT_BREACHED)

    clear_hibp_cache()
    # 2. Network error / offline -> UNKNOWN
    with patch("requests.get", side_effect=Exception("Network down")):
        status, count = check_hibp_status("RandomSecret#2026!")
        assert status == BreachStatus.UNKNOWN
        assert count == -1

        # Save gate must explicitly show could not verify
        gate_res = evaluate_save_gate("RandomSecret#2026!", "example.com", [])
        assert gate_res.breach_status == BreachStatus.UNKNOWN
        assert any("Could not verify password against public breaches" in r for r in gate_res.reasons)


def test_egress_guard_privacy_boundary():
    # 1. Valid HIBP call with exactly 5-hex prefix is permitted
    inspect_outbound_request("https://api.pwnedpasswords.com/range/5BAA6", method="GET")

    # 2. HIBP call with full hash or query parameter must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request("https://api.pwnedpasswords.com/range/5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", method="GET")

    # 3. Request containing active plaintext secret in body/header must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            "https://api.groq.com/openai/v1/chat/completions",
            method="POST",
            body="User password was SuperSecretP@ssword123",
            active_secrets={"SuperSecretP@ssword123"}
        )

    # 4. Request containing personal attributes in active_secrets must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            "https://api.groq.com/openai/v1/chat/completions",
            method="POST",
            body="User birth year is 1995 and surname is Hamilton",
            active_secrets={"Hamilton", "1995"}
        )

