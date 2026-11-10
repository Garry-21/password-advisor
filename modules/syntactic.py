import hashlib
import requests
import zxcvbn

def evaluate_syntactic_strength(password: str) -> dict:
    res = zxcvbn.zxcvbn(password)
    return {
        "score": res["score"],                    # 0-4
        "guesses_log10": res["guesses_log10"],
        "warning": res["feedback"]["warning"],
        "suggestions": res["feedback"]["suggestions"],
    }

from enum import Enum

class BreachStatus(str, Enum):
    BREACHED = "breached"
    NOT_BREACHED = "not_breached"
    UNKNOWN = "unknown"

def check_hibp_status(password: str) -> tuple[BreachStatus, int]:
    """
    Returns (BreachStatus, count).
    - BREACHED: count > 0
    - NOT_BREACHED: count == 0
    - UNKNOWN: count == -1 (offline / timeout / network error; never safe)
    """
    count = check_hibp_k_anonymity(password)
    if count > 0:
        return BreachStatus.BREACHED, count
    elif count == 0:
        return BreachStatus.NOT_BREACHED, 0
    else:
        return BreachStatus.UNKNOWN, -1

_HIBP_PREFIX_CACHE: dict[str, dict[str, int]] = {}

def clear_hibp_cache():
    """Clear in-memory HIBP range cache (useful for testing)."""
    _HIBP_PREFIX_CACHE.clear()

def check_hibp_k_anonymity(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    if prefix in _HIBP_PREFIX_CACHE:
        return _HIBP_PREFIX_CACHE[prefix].get(suffix, 0)

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "PasswordAdvisor-ResearchPilot/1.0",
        "Add-Padding": "true"
    }
    for attempt in range(2):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            prefix_map: dict[str, int] = {}
            for line in response.text.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    try:
                        prefix_map[parts[0].strip().upper()] = int(parts[1].strip())
                    except ValueError:
                        continue
            _HIBP_PREFIX_CACHE[prefix] = prefix_map
            return prefix_map.get(suffix, 0)
        except requests.RequestException:
            if attempt == 0:
                continue
            return -1   # sentinel: "check failed", distinct from "0 = clean"
        except Exception:
            return -1
    return 0
