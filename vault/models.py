"""
vault/models.py
---------------
Data models for entries, vault header, keyslots, and user profile.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
import time
import json


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class AuthError(CryptoError):
    """Raised when authentication/integrity verification fails."""
    pass


@dataclass
class PasswordHistoryItem:
    pw_hash_hmac: str
    changed_at: str


@dataclass
class Entry:
    id: str
    site_name: str
    url: str
    username: str
    password: str
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    criticality: int = 1  # 1 (low), 2 (medium), 3 (high)
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    modified_at: Optional[str] = None
    password_history: List[Dict[str, str]] = field(default_factory=list)

    def __post_init__(self):
        if self.modified_at is None:
            self.modified_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entry":
        created = data.get("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        return cls(
            id=data["id"],
            site_name=data.get("site_name", ""),
            url=data.get("url", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            criticality=int(data.get("criticality", 1)),
            created_at=created,
            modified_at=data.get("modified_at", created),
            password_history=data.get("password_history", [])
        )

    @classmethod
    def from_json_bytes(cls, raw_bytes: bytes) -> "Entry":
        data = json.loads(raw_bytes.decode("utf-8"))
        return cls.from_dict(data)


@dataclass
class Profile:
    first_name: str
    surname: str
    city: str
    birth_year: int
    theme: str = "Baking"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Profile":
        return cls(
            first_name=data.get("first_name", ""),
            surname=data.get("surname", ""),
            city=data.get("city", ""),
            birth_year=int(data.get("birth_year", 1990)),
            theme=data.get("theme", "Baking")
        )


@dataclass
class KeySlot:
    slot_type: str  # "password" or "recovery"
    nonce_hex: str
    wrapped_dek_hex: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VaultHeader:
    version: int = 1
    salt_hex: str = ""
    argon2: Dict[str, int] = field(default_factory=lambda: {"m": 65536, "t": 3, "p": 4})
    keyslots: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    has_device_secret: bool = False
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def canonical_aad_bytes(self) -> bytes:
        """
        Returns canonical JSON bytes of header metadata used as AAD for wrapping keyslots.
        Keyslot ciphertexts are excluded so that keyslot values do not circularly depend on themselves.
        """
        aad_data = {
            "version": self.version,
            "salt_hex": self.salt_hex,
            "argon2": self.argon2,
            "has_device_secret": self.has_device_secret,
            "created_at": self.created_at
        }
        return json.dumps(aad_data, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultHeader":
        return cls(
            version=int(data.get("version", 1)),
            salt_hex=data.get("salt_hex", ""),
            argon2=data.get("argon2", {"m": 65536, "t": 3, "p": 4}),
            keyslots=data.get("keyslots", {}),
            has_device_secret=bool(data.get("has_device_secret", False)),
            created_at=data.get("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        )
