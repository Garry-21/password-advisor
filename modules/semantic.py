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

def reverse_leet_translation(text: str) -> str:
    reversed_text = ""
    for char in text:
        # Simple character-by-character leet reversal
        reversed_text += LEET_MAP.get(char, char)
    return reversed_text.lower()

def calculate_thematic_coverage(password: str, metadata: dict) -> dict:
    """
    Returns a dict like:
    {
        "score": float (0 to 1),
        "matched_fields": list[str]
    }
    """
    if not password or not metadata:
        return {"score": 0.0, "matched_fields": []}
        
    password_lower = password.lower()
    password_leet_reversed = reverse_leet_translation(password_lower)
    
    total_length = len(password)
    matched_chars_count = 0
    matched_fields = set()
    
    # 1. Check direct substring matches for name, surname, hometown
    string_fields = {
        "name": metadata.get("first_name", ""),
        "surname": metadata.get("surname", ""),
        "hometown": metadata.get("city", ""),
    }
    
    for field_name, value in string_fields.items():
        if not value:
            continue
        val_lower = str(value).lower()
        if len(val_lower) < 3: # Ignore very short strings
            continue
            
        if val_lower in password_lower or val_lower in password_leet_reversed:
            matched_chars_count += len(val_lower)
            matched_fields.add(field_name)
            
    # 2. Check numeric date pattern for DOB
    dob = metadata.get("birth_year")
    if dob:
        dob_str = str(dob)
        dob_short = dob_str[-2:] # e.g. 1994 -> 94
        
        # Give preference to full year match, else short year
        if dob_str in password_lower:
            matched_chars_count += 4
            matched_fields.add("birth year")
        elif len(dob_short) == 2 and dob_short in password_lower:
            matched_chars_count += 2
            matched_fields.add("birth year")
            
    # Avoid counting overlapping matches multiple times naively,
    # but for a simple coverage score, sum of matched lengths capped at total_length is often used.
    # We will cap it at total_length.
    matched_chars_count = min(matched_chars_count, total_length)
    score = matched_chars_count / total_length if total_length > 0 else 0.0
    
    return {
        "score": score,
        "matched_fields": list(matched_fields)
    }
