import pytest
from modules.syntactic import (
    evaluate_syntactic_strength,
    check_hibp_k_anonymity,
    clear_hibp_cache,
    _HIBP_PREFIX_CACHE
)

def test_evaluate_syntactic_strength():
    weak = evaluate_syntactic_strength("123456")
    assert weak["score"] < 2
    assert "guesses_log10" in weak

    strong = evaluate_syntactic_strength("Correct-Horse-Battery-Staple-2026!#$")
    assert strong["score"] >= 3

def test_hibp_known_breached_password():
    # 'password' is a very commonly breached password
    count = check_hibp_k_anonymity("password")
    assert count > 1000000, f"Expected large breach count for 'password', got {count}"

def test_hibp_random_clean_password():
    # A long random string that is almost certainly not breached
    count = check_hibp_k_anonymity("thisIsAReallyLongRandomPassword123!@#ThatShouldNotBeBreached")
    assert count == 0, f"Expected 0 breach count, got {count}"

def test_hibp_prefix_caching():
    clear_hibp_cache()
    # Query twice; second query must read from memory cache
    res1 = check_hibp_k_anonymity("password")
    assert len(_HIBP_PREFIX_CACHE) > 0
    res2 = check_hibp_k_anonymity("password")
    assert res1 == res2
