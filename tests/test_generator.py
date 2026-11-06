"""
tests/test_generator.py
-----------------------
Unit and property tests for CSPRNG generator module:
- EFF wordlist loading and integrity (7,776 words)
- Offline thematic vocabulary integration
- Passphrase generation with exact entropy computation
- Random character password generation with guaranteed character classes
- Uniqueness and entropy scaling
"""

import math
import pytest
from vault.generator import (
    load_eff_wordlist,
    get_available_themes,
    load_theme_words,
    generate_passphrase,
    generate_random_password,
    calculate_passphrase_entropy
)


def test_eff_wordlist_integrity():
    words = load_eff_wordlist()
    assert len(words) == 7776
    assert all(isinstance(w, str) and len(w) > 0 for w in words)
    assert all(w.islower() for w in words)
    # Check sample words from EFF list
    assert "abacus" in words
    assert "zoom" in words


def test_available_themes():
    themes = get_available_themes()
    assert "baking" in themes
    assert "scifi" in themes
    assert "nature" in themes
    assert "music" in themes
    assert "sports" in themes
    assert "travel" in themes


def test_theme_words_loading():
    baking_words = load_theme_words("baking")
    assert len(baking_words) >= 20
    assert "flour" in baking_words
    assert "sourdough" in baking_words

    scifi_words = load_theme_words("scifi")
    assert len(scifi_words) >= 20
    assert "quantum" in scifi_words


def test_passphrase_generation_default():
    gen = generate_passphrase(num_words=4, separator="-", capitalize=True, include_digit=True, include_symbol=True)
    assert gen.mode == "passphrase"
    assert len(gen.words) == 4
    # Check that entropy is computed accurately: 4 * log2(7776) + log2(10) + log2(8) ~= 51.7 + 3.32 + 3.0 = 58.0 bits
    expected_bits = 4 * math.log2(7776) + math.log2(10) + math.log2(8)
    assert abs(gen.entropy_bits - round(expected_bits, 1)) < 0.2
    assert gen.entropy_bits >= 50.0

    # Ensure last char is symbol and second-to-last is digit
    last_char = gen.password[-1]
    second_last = gen.password[-2]
    assert last_char in "!@#$%^&*"
    assert second_last.isdigit()


def test_passphrase_with_theme():
    gen = generate_passphrase(num_words=3, theme="baking", separator=".", capitalize=False)
    assert gen.theme_used == "baking"
    assert len(gen.words) == 4  # 3 EFF + 1 theme
    baking_vocab = set(load_theme_words("baking"))
    # One of the words must be from the baking vocabulary
    assert any(w.lower() in baking_vocab for w in gen.words)


def test_random_password_generation():
    length = 20
    gen = generate_random_password(
        length=length,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True,
        exclude_ambiguous=True
    )
    assert gen.mode == "random"
    assert len(gen.password) == length
    # Check character class presence
    assert any(c.isupper() for c in gen.password)
    assert any(c.islower() for c in gen.password)
    assert any(c.isdigit() for c in gen.password)
    assert any(c in "!@#$%^&*" for c in gen.password)
    # Check ambiguous excluded
    ambiguous = set("l1IO0o")
    assert not any(c in ambiguous for c in gen.password)


def test_entropy_monotonicity():
    p3 = generate_passphrase(num_words=3, include_digit=False, include_symbol=False)
    p4 = generate_passphrase(num_words=4, include_digit=False, include_symbol=False)
    p5 = generate_passphrase(num_words=5, include_digit=False, include_symbol=False)
    assert p3.entropy_bits < p4.entropy_bits < p5.entropy_bits

    r12 = generate_random_password(length=12)
    r16 = generate_random_password(length=16)
    r24 = generate_random_password(length=24)
    assert r12.entropy_bits < r16.entropy_bits < r24.entropy_bits


def test_csprng_uniqueness():
    generated = {generate_passphrase().password for _ in range(100)}
    assert len(generated) == 100


def test_custom_typed_theme():
    # User types custom words/theme not in predefined files
    custom_words = load_theme_words("cyberpunk, neon, matrix")
    assert "cyberpunk" in custom_words
    assert "neon" in custom_words
    assert "matrix" in custom_words

    gen = generate_passphrase(num_words=4, theme="cyberpunk, neon, matrix")
    assert gen.theme_used is not None
    # Verify that one of the custom words was included
    assert any(w.lower() in ["cyberpunk", "neon", "matrix"] for w in gen.words)
