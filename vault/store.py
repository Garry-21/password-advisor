"""
vault/store.py
--------------
SQLite repository for encrypted records and vault metadata:
- Database path: platformdirs.user_data_dir("SecurePasswordAdvisor")/vault.db
- Zero plaintext records in storage: records table contains only (id, nonce, ct, schema)
- Atomic writes via transactions
- Interactive unlock throttling with exponential backoff
"""

import json
import os
import shutil
import sqlite3
import time
from contextlib import contextmanager
from typing import List, Optional, Tuple, Dict, Any
from pathlib import Path
import platformdirs

from vault.models import Entry, VaultHeader, Profile, AuthError, CryptoError
from vault.crypto import (
    encrypt_entry,
    decrypt_entry,
    encrypt_profile,
    decrypt_profile,
    unlock_dek_with_password,
    unlock_dek_with_recovery,
    SCHEMA_VERSION
)

APP_NAME = "SecurePasswordAdvisor"
DEFAULT_DB_FILENAME = "vault.db"


def get_default_db_path() -> str:
    """Returns standard OS user data directory path for vault.db."""
    data_dir = platformdirs.user_data_dir(APP_NAME)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, DEFAULT_DB_FILENAME)


class VaultStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path if db_path else get_default_db_path()
        self._ensure_dir_permissions()
        self._init_tables()

    def _ensure_dir_permissions(self):
        """Creates directory with restricted user-only permissions where supported."""
        dir_path = os.path.dirname(os.path.abspath(self.db_path))
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
            try:
                # 0o700 on POSIX (owner read/write/execute only)
                os.chmod(dir_path, 0o700)
            except Exception:
                pass

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def close(self):
        """Closes store resources."""
        pass

    def _init_tables(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value BLOB
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY,
                    nonce BLOB NOT NULL,
                    ct BLOB NOT NULL,
                    schema INTEGER NOT NULL DEFAULT 1
                );
            """)

    def vault_exists(self) -> bool:
        """Returns True if vault header has been created and initialized."""
        return self.get_header() is not None

    # ── Header & Profile Management ──────────────────────────────────────────

    def save_header(self, header: VaultHeader):
        header_bytes = json.dumps(header.to_dict()).encode("utf-8")
        with self._get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?);",
                         ("header", header_bytes))

    def get_header(self) -> Optional[VaultHeader]:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT value FROM meta WHERE key = 'header';")
                row = cursor.fetchone()
                if not row or not row[0]:
                    return None
                try:
                    data = json.loads(row[0].decode("utf-8"))
                    return VaultHeader.from_dict(data)
                except Exception:
                    return None
        except sqlite3.OperationalError:
            return None

    def save_profile(self, profile: Profile, dek: Optional[bytes] = None):
        if dek is not None:
            nonce, ct = encrypt_profile(profile, bytes(dek))
            payload = json.dumps({
                "enc": True,
                "nonce_hex": nonce.hex(),
                "ct_hex": ct.hex(),
                "schema": SCHEMA_VERSION
            }).encode("utf-8")
        else:
            payload = json.dumps(profile.to_dict()).encode("utf-8")

        with self._get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?);",
                         ("profile", payload))

    def get_profile(self, dek: Optional[bytes] = None) -> Optional[Profile]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT value FROM meta WHERE key = 'profile';")
            row = cursor.fetchone()
            if not row or not row[0]:
                return None
            try:
                data = json.loads(row[0].decode("utf-8"))
            except Exception:
                return None

            # Case 1: encrypted profile
            if isinstance(data, dict) and data.get("enc"):
                if dek is None:
                    return None  # Cannot decrypt without unlocked DEK
                nonce = bytes.fromhex(data["nonce_hex"])
                ct = bytes.fromhex(data["ct_hex"])
                schema = data.get("schema", SCHEMA_VERSION)
                return decrypt_profile(nonce, ct, bytes(dek), schema_version=schema)

            # Case 2: legacy plaintext profile -> automatic migration if dek is provided
            if isinstance(data, dict):
                legacy_profile = Profile.from_dict(data)
                if dek is not None:
                    # Migrate plaintext profile to encrypted
                    try:
                        self.save_profile(legacy_profile, bytes(dek))
                    except Exception:
                        pass
                return legacy_profile

            return None

    # ── Failed Unlock Throttling ─────────────────────────────────────────────

    def get_failed_attempts_info(self) -> Tuple[int, float]:
        """Returns (failed_attempts_count, next_allowed_epoch_time)."""
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM meta WHERE key = 'failed_attempts';")
            r1 = c.fetchone()
            attempts = int(r1[0].decode("utf-8")) if r1 and r1[0] else 0

            c.execute("SELECT value FROM meta WHERE key = 'next_allowed_time';")
            r2 = c.fetchone()
            next_time = float(r2[0].decode("utf-8")) if r2 and r2[0] else 0.0

            return attempts, next_time

    def check_unlock_allowed(self) -> Tuple[bool, float]:
        """
        Checks if unlock attempt is allowed under throttling rules.
        Returns (is_allowed, seconds_remaining).
        """
        _, next_time = self.get_failed_attempts_info()
        now = time.time()
        if now < next_time:
            return False, round(next_time - now, 1)
        return True, 0.0

    def record_failed_unlock(self) -> float:
        """
        Increments failed attempt counter and applies exponential backoff:
        Attempts: 1-2 (0s), 3 (2s), 4 (4s), 5 (8s), 6 (16s) ... up to 300s (5 min).
        Returns the lockout duration in seconds.
        """
        attempts, _ = self.get_failed_attempts_info()
        attempts += 1

        if attempts <= 2:
            delay = 0.0
        else:
            delay = min(300.0, 2 ** (attempts - 2))

        next_time = time.time() + delay

        with self._get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('failed_attempts', ?);",
                         (str(attempts).encode("utf-8"),))
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('next_allowed_time', ?);",
                         (str(next_time).encode("utf-8"),))
        return delay

    def reset_failed_unlocks(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM meta WHERE key IN ('failed_attempts', 'next_allowed_time');")

    # ── Encrypted Record CRUD Operations ─────────────────────────────────────

    def put_entry(self, entry: Entry, dek: bytes):
        """
        Encrypts and stores (or updates) an entry.
        No plaintext entry data touches the database.
        """
        nonce, ct = encrypt_entry(entry, dek, schema_version=SCHEMA_VERSION)
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO records (id, nonce, ct, schema)
                VALUES (?, ?, ?, ?);
            """, (entry.id, nonce, ct, SCHEMA_VERSION))

    def get_entry(self, entry_id: str, dek: bytes) -> Optional[Entry]:
        """
        Retrieves and decrypts a single entry by ID.
        Raises AuthError if record fails integrity verification.
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT nonce, ct, schema FROM records WHERE id = ?;", (entry_id,))
            row = cursor.fetchone()
            if not row:
                return None
            nonce, ct, schema = row
            return decrypt_entry(entry_id, nonce, ct, dek, schema_version=schema)

    def list_entries(self, dek: bytes, search_query: Optional[str] = None) -> List[Entry]:
        """
        Loads and decrypts all records in memory, optionally applying search filter.
        Search happens strictly in memory after unlock.
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT id, nonce, ct, schema FROM records;")
            rows = cursor.fetchall()

        entries: List[Entry] = []
        q = search_query.strip().lower() if search_query else None

        for entry_id, nonce, ct, schema in rows:
            entry = decrypt_entry(entry_id, nonce, ct, dek, schema_version=schema)
            if q:
                # Search across site name, username, url, notes, tags
                matched = (
                    q in entry.site_name.lower() or
                    q in entry.username.lower() or
                    q in entry.url.lower() or
                    q in entry.notes.lower() or
                    any(q in tag.lower() for tag in entry.tags)
                )
                if not matched:
                    continue
            entries.append(entry)

        return entries

    def delete_entry(self, entry_id: str) -> bool:
        """Deletes an encrypted record by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM records WHERE id = ?;", (entry_id,))
            return cursor.rowcount > 0

    def count_entries(self) -> int:
        """Returns total number of encrypted records stored in vault."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM records;")
            return cursor.fetchone()[0]

    def backup_database(self, dest_path: str):
        """Creates an atomic copy of the live database file before migration or backup."""
        with self._get_connection() as conn:
            # Force WAL checkpoint to ensure all data is flushed to main file
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        shutil.copy2(self.db_path, dest_path)
