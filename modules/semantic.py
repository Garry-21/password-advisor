import re

LEET_MAP = {
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
}

import re
import itertools

LEET_MAP = {
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
}

# Common English stopwords/syllables to never flag as partial attribute matches
COMMON_SHORT_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can",
    "had", "her", "was", "one", "our", "out", "day", "get", "has", "him",
    "his", "how", "man", "new", "now", "old", "see", "two", "way", "who",
    "boy", "did", "its", "let", "put", "say", "she", "too", "use", "red",
    "cat", "dog", "sun", "sky", "car", "sea", "air", "run", "eat", "big",
    "pro", "dev", "app", "web", "net", "top", "max", "vip", "bot", "win"
}

def reverse_leet_translation(text: str) -> str:
    """Translates common leetspeak characters back to Latin letters."""
    reversed_text = ""
    for char in text:
        reversed_text += LEET_MAP.get(char, char)
    return reversed_text.lower()


def _normalize_string(text: str) -> str:
    """Strips separators and normalizes to clean alphanumeric lowercase string."""
    cleaned = re.sub(r"[\s\-_\.:;,|/\\]+", "", text)
    return reverse_leet_translation(cleaned.lower())


def calculate_thematic_coverage(password: str, metadata: dict) -> dict:
    """
    Enhanced personal-context detector:
    - Normalizes leetspeak, case, and punctuation separators
    - Detects full attributes (first name, surname, city)
    - Detects partial attributes (first 3-4 chars of name/surname/city) with minimum match length
      and stopword filtering to prevent false positives
    - Detects 4-digit and 2-digit birth years (requiring boundary or co-occurrence with name)
    - Detects reordered and combined multi-attributes (e.g. CarterDenver, DenverMaya98)
    - Keeps false positives low on hard-negatives (unrelated passwords with short accidental tokens)
    """
    if not password or not metadata:
        return {"score": 0.0, "matched_fields": []}

    if hasattr(metadata, "__dict__") and not isinstance(metadata, dict):
        meta_dict = {
            "first_name": getattr(metadata, "first_name", ""),
            "surname": getattr(metadata, "surname", ""),
            "city": getattr(metadata, "city", ""),
            "birth_year": getattr(metadata, "birth_year", None),
            "theme": getattr(metadata, "theme", ""),
        }
    elif isinstance(metadata, dict):
        meta_dict = metadata
    else:
        meta_dict = {}

    password_lower = password.lower()
    norm_pw = _normalize_string(password)
    total_length = max(1, len(password))

    matched_spans: list[tuple[int, int]] = []
    matched_fields = set()

    # 1. Collect declared string attributes
    string_fields = {
        "name": str(meta_dict.get("first_name", "")).strip(),
        "surname": str(meta_dict.get("surname", "")).strip(),
        "hometown": str(meta_dict.get("city", "")).strip(),
    }

    raw_candidates: list[tuple[str, str, bool]] = []
    # (field_name, search_token, is_full_attribute)

    for field_name, value in string_fields.items():
        if not value:
            continue
        val_norm = _normalize_string(value)
        if len(val_norm) < 3:
            continue

        # Full attribute match
        raw_candidates.append((field_name, val_norm, True))

        # Partial attribute match (first 3 and 4 characters)
        if len(val_norm) >= 5:
            # 4-char prefix
            p4 = val_norm[:4]
            if p4 not in COMMON_SHORT_WORDS:
                raw_candidates.append((f"{field_name}_prefix4", p4, False))
        if len(val_norm) >= 4:
            # 3-char prefix
            p3 = val_norm[:3]
            if p3 not in COMMON_SHORT_WORDS:
                raw_candidates.append((f"{field_name}_prefix3", p3, False))

    # Search candidates in normalized password
    detected_field_tokens = {}
    for field_name, token, is_full in raw_candidates:
        if token in norm_pw:
            # Enforce minimum length for partial matches
            if not is_full and len(token) < 3:
                continue
            base_field = field_name.split("_")[0]
            matched_fields.add(base_field)
            if base_field not in detected_field_tokens or len(token) > len(detected_field_tokens[base_field]):
                detected_field_tokens[base_field] = token

    # Check combined / reordered attributes (e.g., surname + name, city + surname)
    found_bases = list(detected_field_tokens.keys())
    if len(found_bases) >= 2:
        for b1, b2 in itertools.permutations(found_bases, 2):
            combo = detected_field_tokens[b1] + detected_field_tokens[b2]
            if combo in norm_pw:
                matched_fields.add("multi_attribute")

    # 2. Birth year checking (4-digit and 2-digit)
    dob = meta_dict.get("birth_year")
    dob_matched_len = 0
    if dob:
        dob_str = str(dob).strip()
        dob_short = dob_str[-2:] if len(dob_str) >= 2 else ""

        # Check full 4-digit year
        if dob_str in password_lower or dob_str in norm_pw:
            dob_matched_len = 4
            matched_fields.add("birth year")
        elif dob_short:
            # For 2-digit year (e.g. '98'), to avoid false positives on random digits,
            # only count it if adjacent to a boundary/separator OR co-occurring with a personal attribute
            has_other_personal = len(matched_fields) > 0
            has_boundary_year = bool(
                re.search(rf"(?:^|[^0-9]){re.escape(dob_short)}(?:$|[^0-9])", password_lower)
            )
            if has_other_personal or (has_boundary_year and password_lower.endswith(dob_short)):
                dob_matched_len = 2
                matched_fields.add("birth year")

    # 3. Calculate coverage percentage
    # Sum unique matched characters without double counting overlaps
    covered_indices = set()
    for token in detected_field_tokens.values():
        start = 0
        while True:
            idx = norm_pw.find(token, start)
            if idx == -1:
                break
            for i in range(idx, idx + len(token)):
                covered_indices.add(i)
            start = idx + 1

    covered_chars = len(covered_indices) + dob_matched_len
    score = min(1.0, covered_chars / total_length)

    return {
        "score": round(score, 3),
        "matched_fields": sorted(list(matched_fields))
    }
