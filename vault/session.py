"""
vault/session.py
----------------
Session state management, auto-lock lifecycle, key zeroisation,
and master password policy enforcement.
"""

import time
from typing import Optional, Tuple, List, Dict, Any

from vault.models import VaultHeader, Profile, AuthError
from vault.crypto import (
    unlock_dek_with_password,
    unlock_dek_with_recovery,
)
from vault.store import VaultStore
from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity
from modules.semantic import calculate_thematic_coverage

DEFAULT_LOCKOUT_MINUTES = 5

SESSION_KEY_DEK = "_cav_dek"
SESSION_KEY_UNLOCKED = "_cav_unlocked"
SESSION_KEY_LAST_ACTIVITY = "_cav_last_activity"
SESSION_KEY_AUTO_LOCK_MINUTES = "_cav_auto_lock_minutes"


class SessionManager:
    @staticmethod
    def is_unlocked(state_dict: Dict[str, Any]) -> bool:
        """Returns True if vault is currently unlocked with active DEK in memory."""
        dek = state_dict.get(SESSION_KEY_DEK)
        return bool(state_dict.get(SESSION_KEY_UNLOCKED) and dek and len(dek) == 32)

    @staticmethod
    def get_dek(state_dict: Dict[str, Any]) -> Optional[bytes]:
        """Returns DEK bytes if unlocked, else None."""
        if not SessionManager.is_unlocked(state_dict):
            return None
        raw_ba = state_dict[SESSION_KEY_DEK]
        return bytes(raw_ba)

    @staticmethod
    def update_activity(state_dict: Dict[str, Any]):
        """Records timestamp of user activity."""
        state_dict[SESSION_KEY_LAST_ACTIVITY] = time.time()

    @staticmethod
    def check_auto_lock(state_dict: Dict[str, Any]) -> bool:
        """
        Checks if idle duration exceeded auto-lock timeout.
        If exceeded, immediately locks vault and zeroises key.
        Returns True if locked due to inactivity.
        """
        if not SessionManager.is_unlocked(state_dict):
            return False

        last_act = state_dict.get(SESSION_KEY_LAST_ACTIVITY, time.time())
        timeout_min = state_dict.get(SESSION_KEY_AUTO_LOCK_MINUTES, DEFAULT_LOCKOUT_MINUTES)
        
        if time.time() - last_act >= (timeout_min * 60.0):
            SessionManager.lock_vault(state_dict)
            return True
        return False

    @staticmethod
    def unlock_with_password(
        store: VaultStore,
        state_dict: Dict[str, Any],
        master_password: str,
        device_secret: Optional[bytes] = None
    ) -> Tuple[bool, str]:
        """
        Attempts to unlock vault with master password.
        Enforces throttling backoff on repeated failures.
        Returns (success: bool, message: str).
        """
        allowed, wait_secs = store.check_unlock_allowed()
        if not allowed:
            return False, f"Too many failed unlock attempts. Please wait {wait_secs:.0f}s before retrying."

        header = store.get_header()
        if not header:
            return False, "Vault database does not exist or has not been initialized."

        try:
            raw_dek = unlock_dek_with_password(header, master_password, device_secret)
            # Store in memory as mutable bytearray for secure zeroisation on lock
            state_dict[SESSION_KEY_DEK] = bytearray(raw_dek)
            state_dict[SESSION_KEY_UNLOCKED] = True
            state_dict[SESSION_KEY_LAST_ACTIVITY] = time.time()
            store.reset_failed_unlocks()
            return True, "Vault unlocked successfully."
        except AuthError:
            penalty = store.record_failed_unlock()
            if penalty > 0:
                return False, f"Invalid master password. Throttling active: wait {penalty:.0f}s."
            return False, "Invalid master password."
        except Exception as e:
            return False, f"Unlock error: {str(e)}"

    @staticmethod
    def unlock_with_recovery(
        store: VaultStore,
        state_dict: Dict[str, Any],
        recovery_key_bytes: bytes
    ) -> Tuple[bool, str]:
        """
        Attempts to unlock vault with raw 32-byte recovery key.
        Returns (success: bool, message: str).
        """
        allowed, wait_secs = store.check_unlock_allowed()
        if not allowed:
            return False, f"Too many failed attempts. Wait {wait_secs:.0f}s."
        header = store.get_header()
        if not header:
            return False, "Vault database does not exist."

        try:
            raw_dek = unlock_dek_with_recovery(header, recovery_key_bytes)
            state_dict[SESSION_KEY_DEK] = bytearray(raw_dek)
            state_dict[SESSION_KEY_UNLOCKED] = True
            state_dict[SESSION_KEY_LAST_ACTIVITY] = time.time()
            store.reset_failed_unlocks()
            return True, "Vault unlocked with recovery key."
        except AuthError:
            store.record_failed_unlock()
            return False, "Invalid recovery key."
        except Exception as e:
            return False, f"Recovery unlock error: {str(e)}"

    @staticmethod
    def lock_vault(state_dict: Dict[str, Any]):
        """
        Zeroises the DEK bytearray in memory and clears all unlocked session state.
        """
        if SESSION_KEY_DEK in state_dict and isinstance(state_dict[SESSION_KEY_DEK], bytearray):
            ba = state_dict[SESSION_KEY_DEK]
            for i in range(len(ba)):
                ba[i] = 0
            ba.clear()

        # Clear decrypted objects, widget passwords, pending forms and cached reports.
        # Keep only the store handle and non-secret timeout configuration.
        for key in list(state_dict):
            if key not in {"_vault_store", SESSION_KEY_AUTO_LOCK_MINUTES}:
                del state_dict[key]
        state_dict[SESSION_KEY_DEK] = None
        state_dict[SESSION_KEY_UNLOCKED] = False
        state_dict[SESSION_KEY_LAST_ACTIVITY] = 0.0


# ── Master Password Policy (Dogfooding Detector) ─────────────────────────────

def validate_master_password(password: str, profile: Optional[Profile] = None) -> Tuple[bool, List[str]]:
    """
    Dogfoods our own multi-tier detector for the master password:
    1. zxcvbn score >= 3 (syntactic complexity)
    2. HIBP hits == 0 (no known breaches)
    3. Thematic coverage score < 0.3 against user profile (no personal info leaks)
    Returns:
        (is_valid: bool, issues: list of violation strings)
    """
    issues = []

    # 1. Syntactic strength check
    syntax = evaluate_syntactic_strength(password)
    if syntax["score"] < 3:
        issues.append(f"Master password is too weak (zxcvbn score: {syntax['score']}/4). Must be score 3 or 4.")

    # 2. Breach check
    breach_hits = check_hibp_k_anonymity(password)
    if breach_hits > 0:
        issues.append(f"Master password has appeared in {breach_hits:,} known data breaches. Choose a unique password.")
    elif breach_hits == -1:
        # Network error; warn but don't hard fail if offline
        pass

    # 3. Semantic / Profile check
    if profile:
        meta = {
            "first_name": profile.first_name,
            "surname": profile.surname,
            "city": profile.city,
            "birth_year": profile.birth_year
        }
        semantic = calculate_thematic_coverage(password, meta)
        if semantic["score"] >= 0.3:
            fields = ", ".join(semantic["matched_fields"]) if semantic["matched_fields"] else "personal details"
            issues.append(f"Master password contains guessable personal information ({fields}).")

    return (len(issues) == 0, issues)
