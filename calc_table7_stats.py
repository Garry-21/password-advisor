import pandas as pd
import numpy as np
from scipy import stats

df = pd.read_csv('results.csv')
a = df[df['variant'] == 'A']
b = df[df['variant'] == 'B']

a_time = a['decision_time']
b_time = b['decision_time']

a_mean = a_time.mean()
a_std = a_time.std()
a_med = a_time.median()
a_q25 = a_time.quantile(0.25)
a_q75 = a_time.quantile(0.75)
a_iqr = a_q75 - a_q25

b_mean = b_time.mean()
b_std = b_time.std()
b_med = b_time.median()
b_q25 = b_time.quantile(0.25)
b_q75 = b_time.quantile(0.75)
b_iqr = b_q75 - b_q25

# Two-proportion z-test or Fisher's exact on decisions:
# Table: [[9, 6], [4, 11]] (adopted, rejected)
table_dec = [[9, 6], [4, 11]]
odds_ratio, p_fisher = stats.fisher_exact(table_dec)
stat_mw, p_mw = stats.mannwhitneyu(a_time, b_time, alternative='two-sided')

# Cohen's d for decision time
pooled_std = np.sqrt(((len(a_time)-1)*a_std**2 + (len(b_time)-1)*b_std**2) / (len(a_time) + len(b_time) - 2))
cohens_d = (a_mean - b_mean) / pooled_std

print("--- VARIANT A (Loss-framed) ---")
print(f"Decisions: {len(a)}, Adopted: {a['adopted'].sum()}, Rate: {a['adopted'].mean():.1%}")
print(f"Mean ± SD: {a_mean:.2f} ± {a_std:.2f} s")
print(f"Median [IQR]: {a_med:.2f} [{a_q25:.2f} - {a_q75:.2f}] (IQR={a_iqr:.2f} s)")

print("\n--- VARIANT B (Neutral) ---")
print(f"Decisions: {len(b)}, Adopted: {b['adopted'].sum()}, Rate: {b['adopted'].mean():.1%}")
print(f"Mean ± SD: {b_mean:.2f} ± {b_std:.2f} s")
print(f"Median [IQR]: {b_med:.2f} [{b_q25:.2f} - {b_q75:.2f}] (IQR={b_iqr:.2f} s)")

print("\n--- STATISTICAL TESTS ---")
print(f"Adoption difference: Fisher's exact test Odds Ratio = {odds_ratio:.2f}, p = {p_fisher:.4f}")
print(f"Decision time difference: Mann-Whitney U = {stat_mw:.1f}, p = {p_mw:.4f}")
print(f"Cohen's d (effect size): {cohens_d:.2f}")

