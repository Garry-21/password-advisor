import os
import re
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# Candidate models supported on Groq
CANDIDATE_MODELS = [
    os.environ.get("GROQ_MODEL"),
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-20b",
    "llama-3.3-70b-versatile",
]
CANDIDATE_MODELS = [m for m in CANDIDATE_MODELS if m]


def _generate_offline_fallback(theme: str) -> str:
    """Provides high-entropy offline passphrase suggestions with mnemonics when no API key is set."""
    try:
        from vault.generator import generate_passphrase
        t = theme.capitalize() if theme else "Secure"
        p1 = generate_passphrase(num_words=3, theme=theme, separator="-").password
        p2 = generate_passphrase(num_words=4, theme=theme, separator=".").password
        p3 = generate_passphrase(num_words=4, theme=theme, separator="_").password
        return (
            f"Here are 3 cryptographically strong passphrases inspired by **{t}**:\n\n"
            f"1. **`{p1}`**\n"
            f"   *Mnemonic Story:* Picture your favorite {t.lower()} adventure with these vivid checkpoints in mind.\n\n"
            f"2. **`{p2}`**\n"
            f"   *Mnemonic Story:* Imagine entering a secure vault guarded by three unforgettable {t.lower()} guardians.\n\n"
            f"3. **`{p3}`**\n"
            f"   *Mnemonic Story:* An exclusive passkey known only to master {t.lower()} explorers.\n\n"
            f"Each passphrase offers >50 bits of combinatorial entropy generated locally via CSPRNG."
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
    """
    Generates passphrase suggestions using an open model hosted on Groq.

    PRIVACY BOUNDARY: The only inputs this function receives are an abstracted
    string summarizing why the password failed (e.g., 'breached password,
    contains birth year') and a user-selected theme (e.g., 'Astronomy').
    At no point does this function receive the user's raw password or their
    raw PII — directly backing up the Section 6.2 privacy claim in the paper.
    """
    load_dotenv(override=True)
    if not theme and failure_reasons:
        # Fallback if invoked with only theme as single argument
        theme = failure_reasons
        failure_reasons = "weak password pattern or common credential reuse"

    assert isinstance(failure_reasons, str), "failure_reasons must be a string"
    assert isinstance(theme, str), "theme must be a string"

    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key or api_key == "your-groq-api-key-here" or api_key.startswith("your-groq-"):
        return _generate_offline_fallback(theme)

    prompt = f"""The user's previous password was rejected for these reasons: {failure_reasons}
Their chosen theme of interest is: {theme}

Please suggest 3 new strong passphrases inspired by this theme.
Requirements for each passphrase:
- At least 14 characters long
- Mix of uppercase, lowercase, numbers, and symbols
- Wrap each proposed passphrase in backticks (e.g., `Passphrase#2024!`)
- For each passphrase, provide a short mnemonic story (1-2 sentences) to help the user remember it.
"""

    client = Groq(api_key=api_key)
    last_err = None

    for model_name in CANDIDATE_MODELS:
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
            )
            return response.choices[0].message.content
        except Exception as e:
            last_err = e
            continue

    # If all models fail, gracefully fall back to local offline generation
    fallback_msg = _generate_offline_fallback(theme)
    return fallback_msg
