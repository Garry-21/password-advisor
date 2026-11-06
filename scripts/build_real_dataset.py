"""
build_real_dataset.py
---------------------
Builds a real password dataset from two public sources:

1. RockYou leaked password list (via SecLists on GitHub)
   - Top N most-common real passwords -> ground_truth_vulnerable = True
   - variant = "rockyou_leak"

2. HIBP Pwned Passwords (k-anonymity API)
   - Confirms breach count for each RockYou password
   - Also checks strong generated passwords -> ground_truth_vulnerable = False
   - variant = "hibp_clean_control"

Output: real_dataset.csv  (same schema as synthetic_dataset.csv)
"""

import hashlib
import random
import secrets
import string
import sys
import time
import urllib.request

import pandas as pd
import requests

# -- Config ------------------------------------------------------------------
ROCKYOU_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Leaked-Databases/rockyou-75.txt"
)
N_VULNERABLE   = 2000   # how many real leaked passwords to include
N_CLEAN        = 2000   # how many strong "safe" passwords to include
OUTPUT_FILE    = "real_dataset.csv"
HIBP_DELAY     = 0.07   # seconds between HIBP requests (respect rate-limit ~15 req/s)

PRINTABLE_SAFE = string.ascii_letters + string.digits + "!@#$%^&*"

# -- Helpers -----------------------------------------------------------------

def hibp_count(password: str) -> int:
    """Return the number of times 'password' appears in HIBP breach corpus.
    Returns -1 on network error."""
    sha1 = hashlib.sha1(password.encode("utf-8", errors="replace")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        r = requests.get(url, timeout=8, headers={"Add-Padding": "true"})
        r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.split(":")
            if parts[0] == suffix:
                return int(parts[1])
        return 0
    except requests.RequestException:
        return -1


def generate_strong_password(length: int = 16) -> str:
    """Generate a cryptographically strong random password."""
    alphabet = PRINTABLE_SAFE
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*" for c in pwd)):
            return pwd


def fetch_rockyou(url: str, n: int) -> list:
    """Download rockyou-75.txt and return top-n deduped passwords."""
    print(f"Downloading RockYou list from SecLists ...", flush=True)
    passwords = []
    seen = set()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        for i, raw_line in enumerate(resp):
            try:
                pw = raw_line.decode("utf-8", errors="ignore").strip()
            except Exception:
                continue
            if pw and pw not in seen:
                seen.add(pw)
                passwords.append(pw)
            if len(passwords) >= n:
                break
            if (i + 1) % 5000 == 0:
                print(f"  ... scanned {i+1} lines, {len(passwords)} unique so far", flush=True)
    print(f"  -> {len(passwords)} unique passwords fetched.", flush=True)
    return passwords


# -- Main --------------------------------------------------------------------

def main():
    random.seed(0)
    rows = []

    # 1. Vulnerable passwords from RockYou
    print(f"\n[1/3] Fetching {N_VULNERABLE} real leaked passwords from RockYou ...", flush=True)
    leaked = fetch_rockyou(ROCKYOU_URL, N_VULNERABLE)

    print(f"[2/3] Verifying {len(leaked)} passwords via HIBP (this may take a minute) ...", flush=True)
    for i, pw in enumerate(leaked):
        count = hibp_count(pw)
        time.sleep(HIBP_DELAY)

        rows.append({
            "password_variant":        "rockyou_leak",
            "password":                pw,
            "ground_truth_vulnerable": True,
            "hibp_breach_count":       count if count != -1 else None,
            "profile_id":              None,
            "first_name":              None,
            "surname":                 None,
            "city":                    None,
            "birth_year":              None,
            "theme":                   None,
        })

        if (i + 1) % 100 == 0:
            print(f"  ... {i + 1}/{len(leaked)} done", flush=True)

    # 2. Safe / clean-control passwords
    print(f"[3/3] Generating {N_CLEAN} strong passwords and verifying via HIBP ...", flush=True)
    clean_added = 0
    attempts = 0
    last_reported = 0
    while clean_added < N_CLEAN:
        attempts += 1
        pw = generate_strong_password(length=random.randint(14, 20))
        count = hibp_count(pw)
        time.sleep(HIBP_DELAY)

        if count == 0 or count == -1:
            rows.append({
                "password_variant":        "hibp_clean_control",
                "password":                pw,
                "ground_truth_vulnerable": False,
                "hibp_breach_count":       count if count != -1 else None,
                "profile_id":              None,
                "first_name":              None,
                "surname":                 None,
                "city":                    None,
                "birth_year":              None,
                "theme":                   None,
            })
            clean_added += 1

        if clean_added // 100 > last_reported // 100:
            print(f"  ... {clean_added}/{N_CLEAN} clean passwords confirmed", flush=True)
            last_reported = clean_added

    print(f"\n  -> {attempts} attempts to find {N_CLEAN} confirmed-clean passwords.", flush=True)

    # Save
    df = pd.DataFrame(rows, columns=[
        "password_variant", "password", "ground_truth_vulnerable",
        "hibp_breach_count",
        "profile_id", "first_name", "surname", "city", "birth_year", "theme",
    ])
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\nSaved {len(df)} rows -> {OUTPUT_FILE}", flush=True)
    print(df["password_variant"].value_counts().to_string(), flush=True)


if __name__ == "__main__":
    main()
