"""
vault/generator.py
------------------
CSPRNG Password and Passphrase Generator:
- Generates high-entropy passphrases using EFF Large Wordlist (7,776 words)
- Offline thematic vocabulary integration (e.g. Baking, Sci-Fi, Nature)
- Random character password generation with customizable pools
- Exact combinatorial entropy calculation (H = sum(log2(pool_i)))
- 100% offline: zero external LLM or network calls
"""

import math
import os
import re
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple

# Locate project-level data directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
THEMES_DIR = DATA_DIR / "themes"
EFF_WORDLIST_PATH = DATA_DIR / "eff_large_wordlist.txt"

# In-memory caches
_CACHED_EFF_WORDS: Optional[List[str]] = None
_CACHED_THEMES: Dict[str, List[str]] = {}

DEFAULT_SYMBOL_POOL = "!@#$%^&*"


@dataclass
class GeneratedPassword:
    password: str
    entropy_bits: float
    mode: str                  # "passphrase" or "random"
    words: List[str] = field(default_factory=list)
    theme_used: Optional[str] = None
    details: Dict[str, str] = field(default_factory=dict)


def load_eff_wordlist() -> List[str]:
    """
    Loads and caches the EFF Large Wordlist (7,776 words).
    Falls back to a curated embedded list if the file is absent.
    """
    global _CACHED_EFF_WORDS
    if _CACHED_EFF_WORDS is not None:
        return _CACHED_EFF_WORDS

    words: List[str] = []
    if EFF_WORDLIST_PATH.exists():
        with open(EFF_WORDLIST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    words.append(parts[1].lower())
                elif len(parts) == 1 and not parts[0].isdigit():
                    words.append(parts[0].lower())

    if len(words) < 500:
        # Emergency embedded fallback wordlist (50 words)
        words = [
            "abacus", "abdomen", "ability", "ablaze", "abnormal", "abrasive", "abroad", "abrupt",
            "absence", "absurd", "abundant", "accent", "accept", "access", "accident", "acclaim",
            "accord", "account", "accuracy", "accurate", "achieve", "acrobat", "activate", "actress",
            "adapt", "addition", "address", "adequate", "admiral", "admit", "adore", "advance",
            "adventure", "aerial", "affect", "afford", "afraid", "agency", "agenda", "agent",
            "agile", "agree", "airline", "airport", "alarm", "album", "alchemy", "alert", "algebra", "alibi"
        ]

    _CACHED_EFF_WORDS = words
    return _CACHED_EFF_WORDS


def get_available_themes() -> List[str]:
    """
    Returns list of discovered offline theme vocabulary names (e.g. ['baking', 'music', 'nature', 'scifi', 'sports', 'travel']).
    """
    if not THEMES_DIR.exists():
        return []
    themes = []
    for p in THEMES_DIR.glob("*.txt"):
        themes.append(p.stem.lower())
    return sorted(themes)


def load_theme_words(theme_name: str) -> List[str]:
    """
    Loads words for a specific theme from data/themes/<theme_name>.txt.
    """
    global _CACHED_THEMES
    norm_name = theme_name.strip().lower()
    if norm_name in _CACHED_THEMES:
        return _CACHED_THEMES[norm_name]

    theme_file = THEMES_DIR / f"{norm_name}.txt"
    words: List[str] = []
    if theme_file.exists():
        with open(theme_file, "r", encoding="utf-8") as f:
            for line in f:
                w = line.strip().lower()
                if w and not w.startswith("#"):
                    words.append(w)
    elif norm_name:
        # If user typed arbitrary words or a custom topic without an offline file,
        # extract valid word tokens directly from the input string
        custom_tokens = [
            w for w in re.split(r'[,;|\s]+', norm_name)
            if len(w) >= 2 and any(c.isalpha() for c in w)
        ]
        if custom_tokens:
            words = custom_tokens

    _CACHED_THEMES[norm_name] = words
    return words


def calculate_passphrase_entropy(
    num_eff_words: int,
    eff_pool_size: int,
    has_theme_word: bool,
    theme_pool_size: int,
    has_digit: bool,
    has_symbol: bool,
    symbol_pool_size: int
) -> float:
    """
    Calculates exact combinatorial entropy in bits:
    H = sum(log2(pool_size))
    """
    bits = 0.0
    if num_eff_words > 0 and eff_pool_size > 0:
        bits += num_eff_words * math.log2(eff_pool_size)
    if has_theme_word and theme_pool_size > 0:
        bits += math.log2(theme_pool_size)
    if has_digit:
        bits += math.log2(10)  # digits 0-9
    if has_symbol and symbol_pool_size > 0:
        bits += math.log2(symbol_pool_size)
    return round(bits, 1)


def generate_passphrase(
    num_words: int = 4,
    theme: Optional[str] = None,
    separator: str = "-",
    capitalize: bool = True,
    include_digit: bool = True,
    include_symbol: bool = True,
    symbol_pool: str = DEFAULT_SYMBOL_POOL
) -> GeneratedPassword:
    """
    Generates a cryptographically secure passphrase using CSPRNG:
    - num_words from EFF large wordlist
    - Optional theme word from offline vocabulary
    - Optional appended or embedded digit and symbol
    - Computes exact entropy
    """
    eff_words = load_eff_wordlist()
    eff_pool_size = len(eff_words)

    selected_words: List[str] = []
    theme_used: Optional[str] = None
    theme_pool_size = 0

    # Handle theme word
    if theme:
        theme_vocab = load_theme_words(theme)
        if theme_vocab:
            theme_used = theme.strip().lower()
            theme_pool_size = len(theme_vocab)
            theme_word = secrets.choice(theme_vocab)
            selected_words.append(theme_word)

    # Fill remaining words from EFF list
    needed_eff = max(1, num_words)
    eff_picks = [secrets.choice(eff_words) for _ in range(needed_eff)]
    
    # If a theme word was added, insert it at a random position
    if theme_used:
        insert_pos = secrets.randbelow(len(eff_picks) + 1)
        eff_picks.insert(insert_pos, selected_words[0])
    
    words_to_use = eff_picks

    if capitalize:
        formatted_words = [w.capitalize() for w in words_to_use]
    else:
        formatted_words = [w.lower() for w in words_to_use]

    passphrase_core = separator.join(formatted_words)

    # Optional digit and symbol
    digit_char = str(secrets.randbelow(10)) if include_digit else ""
    symbol_char = secrets.choice(symbol_pool) if (include_symbol and symbol_pool) else ""

    final_password = f"{passphrase_core}{digit_char}{symbol_char}"

    entropy = calculate_passphrase_entropy(
        num_eff_words=needed_eff,
        eff_pool_size=eff_pool_size,
        has_theme_word=bool(theme_used),
        theme_pool_size=theme_pool_size,
        has_digit=include_digit,
        has_symbol=include_symbol and bool(symbol_pool),
        symbol_pool_size=len(symbol_pool)
    )

    return GeneratedPassword(
        password=final_password,
        entropy_bits=entropy,
        mode="passphrase",
        words=words_to_use,
        theme_used=theme_used,
        details={
            "eff_words_count": str(needed_eff),
            "theme_word_included": str(bool(theme_used)),
            "digit_included": str(include_digit),
            "symbol_included": str(include_symbol)
        }
    )


def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    symbol_pool: str = DEFAULT_SYMBOL_POOL,
    exclude_ambiguous: bool = False
) -> GeneratedPassword:
    """
    Generates a cryptographically secure random character password using CSPRNG:
    - Guarantees at least 1 character from each selected class
    - Shuffles characters using CSPRNG Fisher-Yates
    - Computes exact entropy: length * log2(pool_size)
    """
    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    sym_chars = symbol_pool

    if exclude_ambiguous:
        ambiguous = set("l1IO0o")
        upper_chars = "".join(c for c in upper_chars if c not in ambiguous)
        lower_chars = "".join(c for c in lower_chars if c not in ambiguous)
        digit_chars = "".join(c for c in digit_chars if c not in ambiguous)

    pool = ""
    guaranteed = []

    if use_upper and upper_chars:
        pool += upper_chars
        guaranteed.append(secrets.choice(upper_chars))
    if use_lower and lower_chars:
        pool += lower_chars
        guaranteed.append(secrets.choice(lower_chars))
    if use_digits and digit_chars:
        pool += digit_chars
        guaranteed.append(secrets.choice(digit_chars))
    if use_symbols and sym_chars:
        pool += sym_chars
        guaranteed.append(secrets.choice(sym_chars))

    if not pool:
        pool = string.ascii_letters + string.digits
        guaranteed.append(secrets.choice(pool))

    total_length = max(len(guaranteed), length)
    remaining_count = total_length - len(guaranteed)
    chars = guaranteed + [secrets.choice(pool) for _ in range(remaining_count)]

    # CSPRNG Fisher-Yates shuffle
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    password = "".join(chars)
    entropy = round(total_length * math.log2(len(pool)), 1)

    return GeneratedPassword(
        password=password,
        entropy_bits=entropy,
        mode="random",
        words=[],
        theme_used=None,
        details={
            "length": str(total_length),
            "pool_size": str(len(pool))
        }
    )
