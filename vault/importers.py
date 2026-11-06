"""
vault/importers.py
------------------
Vault Import Engine (Section 8):
- Imports passwords from standard CSV formats:
  - Google Chrome / Google Password Manager CSV
  - Bitwarden CSV
  - Generic / custom CSV with automatic column mapping
- Robust multiline handling and sanitization
"""

import csv
import io
import uuid
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urlparse

from vault.models import Entry


def _clean_site_name(name: str, url: str) -> str:
    """Infers clean site name if missing."""
    if name and name.strip():
        return name.strip()
    if url and url.strip():
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            netloc = parsed.netloc or parsed.path
            return netloc.replace("www.", "").split(":")[0]
        except Exception:
            return url.strip()
    return "Unknown Site"


def detect_csv_format(headers: List[str]) -> str:
    """Detects CSV format based on header row."""
    norm_headers = [h.strip().lower() for h in headers if h]
    
    if "login_password" in norm_headers or "login_username" in norm_headers:
        return "bitwarden"
    if "url" in norm_headers and "username" in norm_headers and "password" in norm_headers:
        return "chrome"
    return "generic"


def parse_csv_stream(stream: io.StringIO) -> Tuple[List[Entry], List[str]]:
    """
    Parses a CSV string stream into a list of Entry objects.
    Returns: (parsed_entries, warnings)
    """
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        return [], ["Empty CSV file or missing headers."]

    format_type = detect_csv_format(reader.fieldnames)
    entries: List[Entry] = []
    warnings: List[str] = []

    for row_idx, row in enumerate(reader, start=1):
        # Normalize keys
        row_norm = {k.strip().lower(): v for k, v in row.items() if k is not None}

        site_name = ""
        url = ""
        username = ""
        password = ""
        notes = ""

        if format_type == "bitwarden":
            site_name = row_norm.get("name", "")
            url = row_norm.get("login_uri", "")
            username = row_norm.get("login_username", "")
            password = row_norm.get("login_password", "")
            notes = row_norm.get("notes", "")
        elif format_type == "chrome":
            site_name = row_norm.get("site_name") or row_norm.get("name") or ""
            url = row_norm.get("url", "")
            username = row_norm.get("username", "")
            password = row_norm.get("password", "")
            notes = row_norm.get("note", "") or row_norm.get("notes", "")
        else:
            # Generic heuristics
            site_name = row_norm.get("site_name") or row_norm.get("name") or row_norm.get("site") or row_norm.get("title") or ""
            url = row_norm.get("url") or row_norm.get("website") or row_norm.get("login_url") or ""
            username = row_norm.get("username") or row_norm.get("user") or row_norm.get("email") or row_norm.get("login") or ""
            password = row_norm.get("password") or row_norm.get("pass") or row_norm.get("pwd") or ""
            notes = row_norm.get("notes") or row_norm.get("note") or row_norm.get("comment") or ""

        if not password:
            warnings.append(f"Row {row_idx}: Skipped entry for '{site_name or url}' because password is empty.")
            continue

        site_name = _clean_site_name(site_name, url)

        entry = Entry(
            id=str(uuid.uuid4()),
            site_name=site_name,
            url=url.strip(),
            username=username.strip(),
            password=password,
            notes=notes.strip() if notes else ""
        )
        entries.append(entry)

    return entries, warnings


def parse_csv_file(file_path: str) -> Tuple[List[Entry], List[str]]:
    """Loads and parses a CSV file from disk."""
    with open(file_path, "r", encoding="utf-8-sig", errors="replace") as f:
        content = f.read()
    return parse_csv_stream(io.StringIO(content))
