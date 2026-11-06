"""
vault/egress_guard.py
---------------------
Egress Guard & Network Leak Prevention (Section 7):
- Strict outbound URL and method allowlist enforcement
- Prevents raw passwords, full SHA-1 hashes, or vault secrets from leaving the host
- Inspects URLs, query parameters, HTTP headers, and request bodies
- Intercepts requests via inspection hooks and optional context manager
"""

import json
import re
from contextlib import contextmanager
from typing import Set, Optional, Dict, Any
from urllib.parse import urlparse

# Strict regex patterns for allowed endpoints
HIBP_RANGE_REGEX = re.compile(r"^https://api\.pwnedpasswords\.com/range/([0-9A-Fa-f]{5})$")
GROQ_API_REGEX = re.compile(r"^https://api\.groq\.com/openai/v1/chat/completions$")
LOCALHOST_REGEX = re.compile(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?(/.*)?$")


class EgressSecurityError(Exception):
    """Raised when an outbound network call violates privacy or security constraints."""
    pass


def inspect_outbound_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Any] = None,
    active_secrets: Optional[Set[str]] = None
) -> None:
    """
    Validates that an outbound HTTP request adheres to privacy boundaries:
    1. Endpoint and method must match allowlist.
    2. HIBP requests must only include the 5-char SHA-1 prefix, never full hashes.
    3. No string from active_secrets may appear in URL, query, headers, or body.
    """
    method_upper = method.upper()

    # 1. Allowlist validation
    is_hibp = bool(HIBP_RANGE_REGEX.match(url))
    is_groq = bool(GROQ_API_REGEX.match(url))
    is_local = bool(LOCALHOST_REGEX.match(url))

    if not (is_hibp or is_groq or is_local):
        raise EgressSecurityError(
            f"Egress violation: Destination '{url}' is not in the allowed outbound endpoint registry."
        )

    # 2. Protocol & Parameter Constraints
    if is_hibp:
        if method_upper != "GET":
            raise EgressSecurityError(f"Egress violation: HIBP range endpoint only supports GET, got {method_upper}.")
        
        match = HIBP_RANGE_REGEX.match(url)
        prefix = match.group(1) if match else ""
        if len(prefix) != 5:
            raise EgressSecurityError("Egress violation: HIBP query must contain exactly 5 hex characters.")

    if is_groq:
        if method_upper != "POST":
            raise EgressSecurityError(f"Egress violation: Groq completion endpoint only supports POST, got {method_upper}.")

    # 3. Secret Leakage Detection
    if active_secrets:
        # Prepare text representations
        url_text = url.lower()
        
        # Serialize body to string for substring scanning
        body_text = ""
        if body:
            if isinstance(body, bytes):
                try:
                    body_text = body.decode("utf-8", errors="ignore").lower()
                except Exception:
                    body_text = ""
            elif isinstance(body, str):
                body_text = body.lower()
            elif isinstance(body, (dict, list)):
                try:
                    body_text = json.dumps(body).lower()
                except Exception:
                    body_text = str(body).lower()

        # Scan headers (excluding Authorization header bearer token)
        header_text = ""
        if headers:
            for k, v in headers.items():
                if k.lower() != "authorization":
                    header_text += f" {str(v).lower()}"

        for secret in active_secrets:
            if not secret or len(secret) < 3:
                continue
            secret_lower = secret.lower()

            if secret_lower in url_text:
                raise EgressSecurityError("Egress violation: Secret detected in outbound request URL!")

            if secret_lower in body_text:
                raise EgressSecurityError("Egress violation: Vault secret detected in outbound request payload!")

            if secret_lower in header_text:
                raise EgressSecurityError("Egress violation: Vault secret detected in outbound request headers!")


@contextmanager
def egress_guard_context(active_secrets: Optional[Set[str]] = None):
    """
    Context manager that patches `requests.Session.send` to enforce egress filtering.
    """
    import requests
    original_send = requests.Session.send

    def guarded_send(self, request, **kwargs):
        inspect_outbound_request(
            url=request.url,
            method=request.method,
            headers=dict(request.headers) if request.headers else None,
            body=request.body,
            active_secrets=active_secrets
        )
        return original_send(self, request, **kwargs)

    requests.Session.send = guarded_send
    try:
        yield
    finally:
        requests.Session.send = original_send
