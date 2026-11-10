# Review 1 executed results

These are synthetic engineering results, not independent evidence of real-world guessing resistance or intervention effectiveness. No human participants were recruited. The original historical results were not overwritten.

## Verification

**102 tests passed**, with one dependency deprecation warning, in 6.77 seconds. Full output is retained in `test_results.txt`.

Tests use deterministic HIBP and clipboard fixtures. Streamlit AppTest covers the four study conditions and actual vault warning/override persistence. Python compilation also passed. The dependency warning concerns zxcvbn-python deprecation.

## Synthetic E1 through E3

Dataset: 11,022 rows across 1,002 fictional profiles; 3,674 held-out samples. Seed 42. Attacks S1–S5; budgets 100 and 1,000. Dataset fingerprint and package/host metadata are in `manifest.json`.

| E1 personal relationship metric | Held-out value |
|---|---:|
| precision | 0.9890 |
| recall | 0.8769 |
| f1 | 0.9296 |
| fpr | 0.0259 |
| balanced_accuracy | 0.9255 |
| pr_auc | 0.9664 |

E2 uses the common S5@1000 outcome. Each threshold is selected on validation at FPR <= 5%; achieved test FPRs differ. PR-AUC uses average precision.

| Method | Recall | FPR | PR-AUC | Brier |
|---|---:|---:|---:|---:|
| B1_syntax | 0.0000 | 0.0000 | 0.5798 | 0.5942 |
| B2_breach_fixture | 0.1530 | 0.0000 | 0.6563 | 0.5033 |
| B3_syntax_breach | 0.0000 | 0.0000 | 0.5798 | 0.5942 |
| B4_personal | 0.0000 | 0.0000 | 0.7639 | 0.2362 |
| B5_history | 0.3060 | 0.0000 | 0.7184 | 0.4124 |
| B6_submitted_weights | 0.1530 | 0.0000 | 0.7728 | 0.3192 |
| CAV_current | 0.1530 | 0.0000 | 0.7812 | 0.3333 |
| B7_logistic | 0.5025 | 0.0483 | 0.9559 | 0.0435 |

The conservative binary syntax baseline selects no positive predictions at this validation FPR constraint, so its zero recall is a limitation of that operating point, not proof that zxcvbn is ineffective. Current CAV still misses many recoverable examples. The logistic model is promising on this fixture, but is neither externally validated nor automatically deployed. Its lower Brier score is relative to this attacker outcome, not a general compromise probability. Existing 0.35 correlation capping has not been empirically justified.

Detailed outputs: `e1.json`, `e2.json`, `e3.json`, `calibration.json`, `criticality_ablation.json`, `clusters.json`, `heldout_predictions.json`, `attack_outcomes.json`, and `research_scorer.json`. Planted clustering results test a narrow transformation family and should not be generalized. No faithful B8 published-model comparison was performed.

## E6 local performance

Three timed trials per operation plus a separate traced-memory run. HIBP was stubbed; syntax and semantic evaluation were real. This is one development host and random fictional vaults. Tail quantiles from three trials are descriptive and unstable.

| Entries | Median full local audit ms | Median save gate ms | Median derivative grouping ms |
|---:|---:|---:|---:|
| 10 | 5.98 | 1.32 | 0.03 |
| 100 | 52.72 | 1.25 | 1.79 |
| 500 | 284.88 | 1.87 | 43.44 |
| 1,000 | 685.80 | 2.48 | 183.27 |
| 5,000 | 8508.28 | 6.84 | 4736.90 |

`performance.json` also records component-removal runs, raw latency values, p95/p99 and peak traced Python allocations. Worst-case derivative time remains quadratic despite removing the adjacency matrix. Native allocations and network latency are excluded. Argon2 configuration timings are in `argon2.txt`; these host timings are not quantified adversary attack cost and do not justify the script's historical “optimal” label.

## Evidence still unavailable

Independent dataset/adjudication, faithfully reproduced contextual baselines, larger-budget published attacks, prospective human observations, power analysis, usability/recall questionnaires, live packet capture, clipboard-history checks, multiple hardware platforms and robust tail estimates. The new implementation makes these evaluations more reproducible; it does not claim they have occurred.
