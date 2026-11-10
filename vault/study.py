"""
vault/study.py
--------------
Study Mode implementation for user experiment evaluation:
- Activated via STUDY_MODE=1 env flag
- 4 Conditions (G1, G2, G3, G4) assigned via seeded deterministic hash per participant ID
- Secure local CSV logging (salted hash only, NEVER plaintext passwords)
"""

import csv
import hashlib
import os
import time
from typing import Optional, Dict, Any

CONDITIONS = ["G1", "G2", "G3", "G4"]
DEFAULT_STUDY_LOG = "results/study_logs.csv"
STUDY_SALT = "cav_study_salt_sec_2026"


def is_study_mode() -> bool:
    """Returns True if STUDY_MODE environment variable is set to '1'."""
    return os.environ.get("STUDY_MODE") == "1"


def assign_condition(participant_id: str) -> str:
    """
    Deterministic seeded assignment of participant to one of 4 conditions:
    G1: conventional zxcvbn feedback only
    G2: contextual warning shown after saving
    G3: contextual warning shown before saving (no alternative)
    G4: pre-save warning plus immediate safer alternative
    """
    pid_clean = participant_id.strip().upper()
    h = hashlib.sha256(f"assign_{pid_clean}".encode("utf-8")).hexdigest()
    idx = int(h[:8], 16) % len(CONDITIONS)
    return CONDITIONS[idx]


def hash_password_salted(password: str, participant_id: str) -> str:
    """Computes irreversible salted SHA-256 hash. Plaintext is never stored."""
    salted = f"{STUDY_SALT}:{participant_id}:{password}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()


def log_study_event(
    participant_id: str,
    condition: str,
    task_id: str,
    final_password: str,
    warning_shown: bool,
    overridden: bool,
    accepted_alternative: bool,
    time_ms: float,
    log_path: str = DEFAULT_STUDY_LOG
):
    """
    Appends study trial decision to local CSV log.
    Ensures zero plaintext password leakage (only salted hash is written).
    """
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_exists = os.path.exists(log_path)

    salted_hash = hash_password_salted(final_password, participant_id)

    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "participant_id",
                "condition",
                "task_id",
                "salted_hash_final_password",
                "warning_shown",
                "overridden",
                "accepted_alternative",
                "time_ms"
            ])
        writer.writerow([
            participant_id,
            condition,
            task_id,
            salted_hash,
            int(warning_shown),
            int(overridden),
            int(accepted_alternative),
            f"{time_ms:.1f}"
        ])

