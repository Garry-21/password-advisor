import os
import re
from dotenv import load_dotenv

load_dotenv()

def _generate_offline_fallback(theme: str) -> str:
    """Provides high-entropy offline passphrase suggestions with mnemonics when no API key is set."""
    try:
        from vault.generator import generate_passphrase
        t = theme.capitalize() if theme else "Secure"
        p1 = generate_passphrase(num_words=3, theme=theme, separator="-").password
        p2 = generate_passphrase(num_words=4, theme=theme, separator=".").password
        p3 = generate_passphrase(num_words=4, theme=theme, separator="_").password
        return (
            f"Here are 3 locally generated passphrases inspired by **{t}**:\n\n"
            f"1. **`{p1}`**\n"
            f"   *Mnemonic Story:* Picture your favorite {t.lower()} adventure with these vivid checkpoints in mind.\n\n"
            f"2. **`{p2}`**\n"
            f"   *Mnemonic Story:* Imagine entering a secure vault guarded by three unforgettable {t.lower()} guardians.\n\n"
            f"3. **`{p3}`**\n"
            f"   *Mnemonic Story:* An exclusive passkey known only to master {t.lower()} explorers.\n\n"
            f"Passphrases are generated locally via CSPRNG. Entropy depends on the selected word pool and options."
        )
    except Exception as e:
        return f"Offline generation fallback error: {str(e)}"


def extract_passphrase_options(text: str, theme: str = "") -> list:
    """Extracts exactly 3 candidate passphrases from LLM output, or falls back to CSPRNG generator."""
    from vault.generator import generate_passphrase

    # Search for backtick-wrapped candidates
    matches = re.findall(r'`([^`\s\n]{8,})`', text)
    valid = [m.strip() for m in matches if 8 <= len(m.strip()) <= 60]

    # If fewer than 3 found, generate remaining from local CSPRNG
    while len(valid) < 3:
        sep = ["-", ".", "_"][len(valid) % 3]
        pw = generate_passphrase(num_words=4, theme=theme, separator=sep).password
        valid.append(pw)

    return valid[:3]


def get_mnemonic_suggestions(failure_reasons: str, theme: str = "") -> str:
    """Generate suggestions locally. No theme, profile, password or finding leaves the host."""
    load_dotenv(override=True)
    if not theme and failure_reasons:
        # Fallback if invoked with only theme as single argument
        theme = failure_reasons
        failure_reasons = "weak password pattern or common credential reuse"

    assert isinstance(failure_reasons, str), "failure_reasons must be a string"
    assert isinstance(theme, str), "theme must be a string"

    # Password suggestions must remain local even when an API key is configured.
    # A remote language model cannot provide verifiable generation entropy.
    return _generate_offline_fallback(theme)
