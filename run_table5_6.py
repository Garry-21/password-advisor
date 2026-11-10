import random
import string
from faker import Faker
from modules.semantic import calculate_thematic_coverage, reverse_leet_translation

fake = Faker()
random.seed(42)
Faker.seed(42)

# Leet map according to Table 0 in paper:
# 0->o, 1->i, 2->z, 3->e, 4->a, 5->s, 7->t, @->a, $->s, !->i, +->t
LEET_ENCODE = {
    'o': '0', 'i': '1', 'z': '2', 'e': '3', 'a': '4', 's': '5', 't': '7'
}

def to_leet(s: str) -> str:
    return "".join(LEET_ENCODE.get(c.lower(), c) for c in s)

def generate_random_chars(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

N_PROFILES = 1000
constructions = ['direct_pii', 'leet_pii', 'partial_pii', 'clean_control']
counts = {c: {'samples': 0, 'correct': 0} for c in constructions}

all_tp = 0
all_fp = 0
all_tn = 0
all_fn = 0

for _ in range(N_PROFILES):
    first_name = fake.first_name()
    surname = fake.last_name()
    city = fake.city()
    birth_year = random.randint(1960, 2006)
    
    metadata = {
        'first_name': first_name,
        'surname': surname,
        'city': city,
        'birth_year': birth_year
    }
    
    # 1. direct_pii: First name + birth year
    pw_direct = f"{first_name}{birth_year}"
    # 2. leet_pii: Leetspeak-transformed first name + birth year
    pw_leet = f"{to_leet(first_name)}{birth_year}"
    # 3. partial_pii: Four random characters + birth year + two random characters
    pw_partial = f"{generate_random_chars(4)}{birth_year}{generate_random_chars(2)}"
    # 4. clean_control: Twelve random characters
    pw_clean = generate_random_chars(12)
    
    samples = [
        ('direct_pii', pw_direct, True),
        ('leet_pii', pw_leet, True),
        ('partial_pii', pw_partial, True),
        ('clean_control', pw_clean, False),
    ]
    
    for c_name, pw, gt_vulnerable in samples:
        res = calculate_thematic_coverage(pw, metadata)
        pred_vulnerable = res['score'] >= 0.30
        
        counts[c_name]['samples'] += 1
        if pred_vulnerable == gt_vulnerable:
            counts[c_name]['correct'] += 1
            
        if gt_vulnerable and pred_vulnerable:
            all_tp += 1
        elif not gt_vulnerable and pred_vulnerable:
            all_fp += 1
        elif not gt_vulnerable and not pred_vulnerable:
            all_tn += 1
        elif gt_vulnerable and not pred_vulnerable:
            all_fn += 1

total_samples = sum(c['samples'] for c in counts.values())
prec = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0.0
rec = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0.0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

print(f"=== TABLE 5: DETECTOR EVALUATION (N={total_samples}) ===")
print(f"TP: {all_tp}")
print(f"FP: {all_fp}")
print(f"TN: {all_tn}")
print(f"FN: {all_fn}")
print(f"Precision: {prec:.4f}")
print(f"Recall: {rec:.4f}")
print(f"F1-Score: {f1:.4f}")

print("\n=== TABLE 6: PER-CONSTRUCTION RESULTS ===")
for c_name, data in counts.items():
    s = data['samples']
    corr = data['correct']
    acc = corr / s if s > 0 else 0.0
    print(f"{c_name}: Samples={s}, Correct={corr}, Accuracy={acc:.4f} ({acc*100:.2f}%)")

