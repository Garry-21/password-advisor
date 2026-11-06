"""
tests/test_egress.py
--------------------
Unit tests for Egress Guard network boundary protection:
- Verification of HIBP k-anonymity 5-hex prefix allowlist
- Blocking full hashes or passwords in HIBP URLs
- Verification of Groq endpoint method and payload constraints
- Blocking arbitrary unauthorized domains
- Detection and blocking of vault secrets in URLs, bodies, and headers
- Context manager runtime interception
"""

import pytest
import requests
from vault.egress_guard import (
    inspect_outbound_request,
    egress_guard_context,
    EgressSecurityError
)


def test_hibp_allowlist_valid():
    # Valid 5-hex GET request
    inspect_outbound_request(
        url="https://api.pwnedpasswords.com/range/21BD1",
        method="GET"
    )
    inspect_outbound_request(
        url="https://api.pwnedpasswords.com/range/a1b2c",
        method="GET"
    )


def test_hibp_violations_blocked():
    # Full 40-char hash in URL must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            url="https://api.pwnedpasswords.com/range/21BD10018A4EAE002F44F69E37444B1A042396B8",
            method="GET"
        )

    # POST method to HIBP must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            url="https://api.pwnedpasswords.com/range/21BD1",
            method="POST"
        )

    # Non-hex prefix must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            url="https://api.pwnedpasswords.com/range/21ZZ9",
            method="GET"
        )


def test_unauthorized_endpoints_blocked():
    unauthorized_urls = [
        "https://evil.com/leak",
        "https://analytics.google.com/collect",
        "https://api.pwnedpasswords.com/password/test",
        "https://api.groq.com/v1/models"
    ]
    for url in unauthorized_urls:
        with pytest.raises(EgressSecurityError):
            inspect_outbound_request(url=url, method="GET")


def test_groq_endpoint_validation():
    # Valid Groq POST
    inspect_outbound_request(
        url="https://api.groq.com/openai/v1/chat/completions",
        method="POST",
        body={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": "Hello"}]}
    )

    # Groq GET must be blocked
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            url="https://api.groq.com/openai/v1/chat/completions",
            method="GET"
        )


def test_vault_secret_leakage_in_body_blocked():
    active_secrets = {"MasterKey#2026", "SuperSecretBankPassword!", "UserPersonalToken99"}

    # Leaking vault password in body
    leaking_body = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": "Help me improve SuperSecretBankPassword!"}]
    }

    with pytest.raises(EgressSecurityError) as exc_info:
        inspect_outbound_request(
            url="https://api.groq.com/openai/v1/chat/completions",
            method="POST",
            body=leaking_body,
            active_secrets=active_secrets
        )
    assert "payload" in str(exc_info.value).lower()


def test_vault_secret_leakage_in_url_blocked():
    active_secrets = {"SecretInUrlToken"}
    with pytest.raises(EgressSecurityError):
        inspect_outbound_request(
            url="https://api.pwnedpasswords.com/range/21BD1?q=SecretInUrlToken",
            method="GET",
            active_secrets=active_secrets
        )


def test_egress_guard_context_manager_intercept():
    active_secrets = {"ClassifiedVaultToken!#"}

    with egress_guard_context(active_secrets=active_secrets):
        # 1. Block unauthorized domain
        with pytest.raises(EgressSecurityError):
            requests.get("https://unauthorized-telemetry.example.org")

        # 2. Block secret leak even on authorized endpoint
        with pytest.raises(EgressSecurityError):
            requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json={"prompt": "my token is ClassifiedVaultToken!#"}
            )
