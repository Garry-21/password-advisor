"""
tests/test_import_export.py
---------------------------
Unit tests for CSV Importers and Encrypted Backup / Restore:
- Google Chrome password CSV parsing
- Bitwarden password CSV parsing
- Encrypted .spvault backup export and zero-plaintext assertion
- Encrypted .spvault restore into a new store and seamless unlock
- Decrypted CSV export round-trip
"""

import io
import json
import tempfile
import pytest
from pathlib import Path

from vault.models import Entry, Profile
from vault.store import VaultStore
from vault.crypto import create_vault_header, unlock_dek_with_password
from vault.importers import parse_csv_stream
from vault.backup import (
    create_encrypted_backup,
    restore_encrypted_backup,
    export_decrypted_csv
)


def test_chrome_csv_import():
    chrome_csv = """name,url,username,password,note
GitHub,https://github.com,octocat,ghp_SuperSecretPass123!,"Main developer token"
Google,https://google.com,testuser@gmail.com,GooglePass#2026,"Personal account"
"""
    entries, warnings = parse_csv_stream(io.StringIO(chrome_csv))
    assert len(entries) == 2
    assert len(warnings) == 0

    assert entries[0].site_name == "GitHub"
    assert entries[0].url == "https://github.com"
    assert entries[0].username == "octocat"
    assert entries[0].password == "ghp_SuperSecretPass123!"
    assert entries[0].notes == "Main developer token"

    assert entries[1].site_name == "Google"
    assert entries[1].password == "GooglePass#2026"


def test_bitwarden_csv_import():
    bw_csv = """folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,0,login,Slack,"Work team chat",,0,https://slack.com,work_user@corp.com,SlackPass_2026$,
,1,login,AWS Console,"Root credentials",,0,https://aws.amazon.com,aws_admin,AWSRootSecret%99,
"""
    entries, warnings = parse_csv_stream(io.StringIO(bw_csv))
    assert len(entries) == 2
    assert len(warnings) == 0

    assert entries[0].site_name == "Slack"
    assert entries[0].url == "https://slack.com"
    assert entries[0].username == "work_user@corp.com"
    assert entries[0].password == "SlackPass_2026$"
    assert entries[0].notes == "Work team chat"

    assert entries[1].site_name == "AWS Console"
    assert entries[1].password == "AWSRootSecret%99"


def test_encrypted_backup_and_restore_round_trip():
    with tempfile.TemporaryDirectory() as temp_dir:
        store_path1 = Path(temp_dir) / "vault1.db"
        store_path2 = Path(temp_dir) / "vault2.db"
        backup_file = Path(temp_dir) / "backup.spvault"

        master_pw = "MasterPassword#Vault2026!"
        store1 = VaultStore(db_path=str(store_path1))

        # 1. Initialize store1
        header, dek, rec_key = create_vault_header(master_pw)
        store1.save_header(header)

        # 2. Add sample entries
        e1 = Entry(id="e1", site_name="Bank", url="", username="user", password="BankSecretPassword123!")
        e2 = Entry(id="e2", site_name="Mail", url="", username="user", password="MailSecretPassword456!")
        store1.put_entry(e1, dek)
        store1.put_entry(e2, dek)

        # 3. Create encrypted backup
        count = create_encrypted_backup(store1, str(backup_file))
        assert count == 2
        assert backup_file.exists()

        # 4. Strict check: zero plaintext secrets in backup file!
        with open(backup_file, "r", encoding="utf-8") as f:
            backup_raw_text = f.read()

        assert "BankSecretPassword123!" not in backup_raw_text
        assert "MailSecretPassword456!" not in backup_raw_text
        assert master_pw not in backup_raw_text

        # 5. Restore into completely fresh store2
        store2 = VaultStore(db_path=str(store_path2))
        restored_count = restore_encrypted_backup(str(backup_file), store2)
        assert restored_count == 2

        # 6. Unlock store2 with original master password
        restored_header = store2.get_header()
        assert restored_header is not None
        restored_dek = unlock_dek_with_password(restored_header, master_pw)

        # 7. Decrypt entries in store2 and verify exact match
        r1 = store2.get_entry("e1", restored_dek)
        r2 = store2.get_entry("e2", restored_dek)
        assert r1 is not None and r1.password == "BankSecretPassword123!"
        assert r2 is not None and r2.password == "MailSecretPassword456!"


def test_decrypted_csv_export():
    with tempfile.TemporaryDirectory() as temp_dir:
        csv_file = Path(temp_dir) / "export.csv"
        entries = [
            Entry(id="1", site_name="SiteA", url="https://a.com", username="ua", password="pa", notes="na"),
            Entry(id="2", site_name="SiteB", url="https://b.com", username="ub", password="pb", notes="nb"),
        ]
        export_decrypted_csv(entries, str(csv_file))
        assert csv_file.exists()

        parsed, warnings = parse_csv_stream(io.StringIO(csv_file.read_text(encoding="utf-8")))
        assert len(parsed) == 2
        assert parsed[0].site_name == "SiteA"
        assert parsed[0].password == "pa"
        assert parsed[1].site_name == "SiteB"
        assert parsed[1].password == "pb"
