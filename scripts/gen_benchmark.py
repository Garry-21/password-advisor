"""Benchmark dataset generator for personal-context evaluation."""
import argparse
import csv
import os
import random

PROFILES = [
    {"id": f"P{i:02d}", "first": f, "last": l, "city": c, "year": y, "theme": t}
    for i, (f, l, c, y, t) in enumerate([
        ("Alice", "Smith", "Boston", 1988, "football"),
        ("Robert", "Miller", "Denver", 1992, "guitar"),
        ("David", "Wilson", "Austin", 1985, "chess"),
        ("Sophia", "Taylor", "Seattle", 1996, "hiking"),
        ("James", "Anderson", "Miami", 1979, "tennis"),
        ("Emma", "Thomas", "Chicago", 2001, "gaming"),
        ("Daniel", "Jackson", "Atlanta", 1990, "cooking"),
        ("Olivia", "White", "Phoenix", 1994, "painting"),
        ("Michael", "Harris", "Dallas", 1983, "running"),
        ("Emily", "Martin", "Portland", 1998, "photography"),
        ("William", "Clark", "Detroit", 1976, "camping"),
        ("Ava", "Lewis", "Houston", 2003, "swimming"),
        ("Alexander", "Walker", "Orlando", 1987, "reading"),
        ("Mia", "Hall", "Nashville", 1995, "cycling"),
        ("Benjamin", "Allen", "SanDiego", 1991, "surfing"),
        ("Charlotte", "Young", "Philadelphia", 1989, "gardening"),
        ("Lucas", "King", "SanJose", 1997, "biking"),
        ("Amelia", "Wright", "Columbus", 2000, "baking"),
        ("Henry", "Scott", "Charlotte", 1982, "golf"),
        ("Harper", "Green", "Memphis", 1993, "yoga"),
    ], start=1)
]

LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
UNRELATED_WEAK = ["password123!", "welcome2020", "dragon999", "monkey1234", "masterpass1", "trustnoone1"]
RANDOM_PASSWORDS = ["kX9#mQ2$vL", "pZ7*jR4!wT", "vN3@bL8$yC", "qW5#mF9!xZ", "tR2&hP7@kJ", "cD8^yV3#mB"]
HARD_NEGATIVES = ["specialist99!", "elasticity2021", "notebookPro88", "cathedral#44", "evergreen77!", "microscope42"]

def apply_leet(s: str) -> str:
    return "".join(LEET_MAP.get(c.lower(), c) for c in s)

def unseen_mutation(p: dict) -> str:
    # Separate mutation not used by detector: reverse + consonant strip
    rev_name = p["first"][::-1].lower()
    return f"{rev_name}_{p['city'][:2]}_{p['year'] % 100}!"

def generate_benchmark(seed: int = 42, out_path: str = "results/benchmark.csv"):
    random.seed(seed)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    # 70/30 split on profile_id
    shuffled_profiles = list(PROFILES)
    random.shuffle(shuffled_profiles)
    train_cutoff = int(len(shuffled_profiles) * 0.7)
    train_ids = {p["id"] for p in shuffled_profiles[:train_cutoff]}

    rows = []
    for p in PROFILES:
        pid = p["id"]
        split = "train" if pid in train_ids else "test"
        y2 = str(p["year"])[-2:]
        
        # 1. Direct
        rows.append((pid, f"{p['first']}{p['year']}!", "direct", 1, split))
        rows.append((pid, f"{p['last']}_{p['city']}", "direct", 1, split))
        # 2. Leetspeak
        rows.append((pid, f"{apply_leet(p['first'])}{p['year']}#", "leetspeak", 1, split))
        rows.append((pid, f"{apply_leet(p['last'])}_{p['city']}", "leetspeak", 1, split))
        # 3. Partial
        rows.append((pid, f"{p['first'][:4]}{y2}!", "partial", 1, split))
        rows.append((pid, f"{p['last'][:3]}_{p['city'][:4]}", "partial", 1, split))
        # 4. Reordered
        rows.append((pid, f"{p['year']}{p['city']}_{p['first']}", "reordered", 1, split))
        rows.append((pid, f"{p['city']}{y2}{p['last']}", "reordered", 1, split))
        # 5. Multi-attribute
        rows.append((pid, f"{p['first']}{p['last']}{p['year']}{p['city']}", "multi_attribute", 1, split))
        rows.append((pid, f"{p['first']}_{p['theme']}_{y2}", "multi_attribute", 1, split))
        # 6. History-derived (family mutation)
        rows.append((pid, f"Summer{p['year']}!", "history_derived", 1, split))
        rows.append((pid, f"{p['first']}Vault{y2}", "history_derived", 1, split))
        # 7. Unseen transformation
        rows.append((pid, unseen_mutation(p), "unseen_transformation", 1, split))
        # 8. Hard negatives (unrelated but share coincidental ngrams)
        rows.append((pid, random.choice(HARD_NEGATIVES), "hard_negative", 0, split))
        # 9. Unrelated weak
        rows.append((pid, random.choice(UNRELATED_WEAK), "unrelated_weak", 0, split))
        # 10. Random strong
        rows.append((pid, random.choice(RANDOM_PASSWORDS), "random", 0, split))

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["profile_id", "password", "category", "label_personal", "split"])
        writer.writerows(rows)
    print(f"Generated {len(rows)} samples across {len(PROFILES)} profiles into {out_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate benchmark dataset")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="results/benchmark.csv")
    args = parser.parse_args()
    generate_benchmark(seed=args.seed, out_path=args.output)

