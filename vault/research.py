"""Offline research primitives. Attack candidates never receive the target password."""
import itertools
import re
from vault.audit import _are_derivatives, extract_base_password, calculate_risk_score, AuditConfig
from modules.semantic import calculate_thematic_coverage
from modules.syntactic import evaluate_syntactic_strength

FEATURES = ('breach', 'semantic', 'syntax', 'reuse', 'derivative', 'age')
LEGACY = AuditConfig(weights=dict(zip(FEATURES, (.4, .25, .15, .1, .05, .05))),
                     enable_age_score=True, max_correlated_contribution=1.0)
COMMON = ('password', 'welcome', 'dragon', 'monkey', 'admin', 'qwerty', 'summer', 'football')

def guesses(profile, previous, scenario, budget=1000):
    """Deterministic toy attacker v1; not a reproduction of published neural attacks.

    Budget counts distinct guesses; the stream order is independent of the budget.
    """
    if scenario not in ('S1', 'S2', 'S3', 'S4', 'S5') or budget < 1:
        raise ValueError('Invalid attack scenario or budget')
    tokens = [str(profile.get(k, '')) for k in ('first_name','surname','city','birth_year')]
    tokens = [t for t in tokens if t]
    def general():
        for suffix in ('', '123!', '123', '1', '2026!', '!'):
            for word in COMMON:
                yield word + suffix
        for n in range(10000):
            for word in COMMON:
                yield word + str(n) + '!'
    def personal():
        for a, b in itertools.permutations(tokens, 2):
            for separator in ('', '_', '-'):
                yield a + separator + b + '!'
                yield a + separator + b
        for n in range(10000):
            for token in tokens:
                yield token + str(n) + '!'
                yield token.lower() + str(n)
    def history():
        if not previous:
            return
        yield previous
        yield previous.lower()
        for m in re.finditer(r'\d{4}', previous):
            for delta in (1, -1, 2, -2):
                yield previous[:m.start()] + str(int(m.group()) + delta) + previous[m.end():]
        for suffix in ('!', '1', '123', '2026!', '#'):
            yield previous + suffix
        for n in range(10000):
            yield previous.rstrip('!#0123456789') + str(n) + '!'
    sources = {'S1':[general], 'S2':[personal], 'S3':[history],
               'S4':[personal,history], 'S5':[general,personal,history]}[scenario]
    streams = [iter(f()) for f in sources]
    seen = set()
    while streams and len(seen) < budget:
        for stream in list(streams):
            try:
                item = next(stream)
            except StopIteration:
                streams.remove(stream)
                continue
            if item not in seen:
                seen.add(item)
                yield item
                if len(seen) >= budget:
                    return

def attack_rank(password, profile, previous, scenario, budget):
    for rank, candidate in enumerate(guesses(profile, previous, scenario, budget), 1):
        if candidate == password:
            return rank
    return None

def features(row):
    password, profile = row['password'], row['profile']
    others = row.get('other_passwords', [])
    base = extract_base_password(password)
    return [float(row['breach_count'] > 0),
            calculate_thematic_coverage(password, profile)['score'],
            float(evaluate_syntactic_strength(password)['score'] < 3),
            float(password in others),
            float(any(_are_derivatives(password, other, base, extract_base_password(other)) for other in others)),
            min(1., row.get('age_days', 0) / 365.) if row.get('age_days', 0) > 90 else 0.]

def fixed_score(vector, legacy=False):
    return calculate_risk_score(*vector, config=LEGACY if legacy else AuditConfig())
