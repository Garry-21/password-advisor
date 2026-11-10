# Review 1 experimental protocol

This protocol separates implementation checks from evidence needed for publication. Freeze it, the code revision, dataset provenance and hypotheses before collecting independent test data. A large synthetic sample does not remedy biased construction or external-validity limitations.

## E1 independent contextual risk

The implemented runner is `scripts/review_experiments.py`. The generated smoke fixture contains 11 categories, including direct, leet, partial, reordered, multi-attribute, history-derived, exact reuse, unrelated weak, random, hard-negative and unseen transformations. Personal relationship labels are construction labels; guessing outcomes are separately measured by an attacker. They are never inferred from detector warnings.

For independent validation, supply authorized JSONL rows with these fields:

```json
{"id":"sample-1","profile_id":"user-1","family_id":"family-1","template_id":"template-1","split":"train","profile":{"first_name":"Fictional","surname":"Example","city":"Imaginary","birth_year":1998},"password":"fictional-target","previous_password":"fictional-history","other_passwords":["fictional-history"],"label_personal":0,"breach_count":0,"age_days":30,"criticality":2,"category":"random","provenance":"record the actual authorized source and independent labelling procedure"}
```

All three explicit splits (`train`, `validation`, `test`) are required. The validator rejects overlapping profile IDs, family IDs, template IDs and exact passwords across splits. Dataset custodians must independently group near-duplicate families; IDs alone cannot verify correct grouping. Supplied breach counts must be observed and nonnegative; unknown breach records require separate missingness analysis rather than fabricated negative evidence. Keep the dataset private when it is not fully fictional. The output stores sample IDs and measurements, not passwords or profile attributes.

Use independently authored transformations and adjudicated personal labels; prespecify exclusions and data rights. Do not tune detectors after examining the test set. The supplied synthetic generator separates profile/family/template groups, but its broad transformation classes remain related across partitions. It is not an independent benchmark.

E1 reports confusion counts, precision, recall, F1, false-positive rate, balanced accuracy, average-precision PR-AUC, ROC-AUC and category breakdowns. E1's score threshold is selected on validation data at FPR <= 5%. Error records support inspection without exporting target secrets. Per-category confidence intervals and external adjudication remain necessary for a final manuscript.

## E2 common outcomes and ablations

All methods use the same S5 attacker outcome at the largest configured budget. Shared feature extraction uses the application's semantic, syntax and derivative implementations. B1 is the binary zxcvbn weakness flag; a future paper should also compare its continuous guess-count estimate. B2 uses supplied breach evidence (a tiny blocklist fixture in synthetic mode, explicitly not live HIBP). B3 is their maximum. B4 is personal coverage. B5 combines reuse and derivative flags. B6 preserves the submitted weights 0.40/0.25/0.15/0.10/0.05/0.05 without the correlation cap. Current CAV is evaluated separately. B7 is logistic regression fitted on training data only.

Each of the six signal ablations is evaluated twice: fixed original weights with the excluded feature set to zero and no renormalization; and a logistic model refitted without that feature. Criticality is evaluated separately at the vault aggregation level. No clinical or economic meaning is assigned to the 1–3 criticality scale.

Thresholds are selected on validation at FPR <= 5%, then frozen for test. This matches the validation operating-point constraint; held-out FPRs need not match exactly. Reports include Brier scores and risk-band observed success. Fixed scores remain heuristic categories. An exported logistic model is research-only and is never automatically loaded by the live vault. A 300-replicate paired profile bootstrap gives recall-difference intervals against B1 for current CAV and B7. The small set of broad synthetic templates is an additional dependence/validity limitation.

B8 is not implemented: no published contextual model has been faithfully reproduced or evaluated here. Do not label the toy attacker as MDIGuess, PII-Pass2Path or Cipher-Guard, or claim superiority to them.

## E3 bounded offline attacks

S1 uses a small generic dictionary and suffixes. S2 uses declared fictional personal attributes. S3 mutates a previous password. S4 interleaves personal/history guesses. S5 interleaves all three sources. Candidates never receive the target password. Guesses are distinct, ordered and budget-prefix consistent. The result records actual candidate count and first matching rank.

Executed budgets: 100 and 1,000. Larger budgets from the faculty review (10,000 and 100,000) can be requested with `--budgets 100 1000 10000 100000`; finite candidate streams may exhaust, so inspect `distinct_guesses` and never report nominal budget as actual work. Published-model attacks and independently collected data are still required for defensible security claims.

```sh
.venv/bin/python scripts/review_experiments.py --input /absolute/path/authorized-benchmark.jsonl --out results/review1-independent --budgets 100 1000
```

Non-recovery means only “not guessed by this attack within this budget.” It does not establish safety. Clustering analysis reports pairwise metrics, adjusted Rand index, B-cubed precision/recall and recovery of planted year mutations. Chain groups are connected components; pairwise mode uses deterministic greedy complete-link groups, not maximum-clique optimization.

## E4 prospective study

Use the isolated Controlled Study page. G1 receives syntax feedback; G2 receives contextual feedback after saving in a temporary study session; G3 receives the equivalent feedback before saving; G4 adds a local alternative. G2 warnings persist until the participant edits or keeps the saved credential. No study task writes into the real vault. All conditions use the same fictional tasks/profile and underlying contextual rules. The current task order is fixed; counterbalancing is required before definitive recruitment.

Primary outcome: per-participant fraction of final fictional passwords recovered by the prespecified S5 toy attacker within 1,000 guesses. Replace/extend the attacker before final preregistration if a stronger benchmark is adopted. The label is independent of warning rules. Secondary logged outcomes are override, recommendation adoption and full task time. Understanding, validated usability, delayed recall and warning fatigue questionnaires are not yet collected by this prototype.

Obtain institutional clearance or an authorized determination before recruitment. Document the reference, consent materials, exclusions, withdrawal process, retention period, blinded allocation and secure pseudonym mapping. Hash allocation with a study-specific seed is reproducible but not guaranteed balanced; use a preregistered randomized allocation schedule for a definitive study. Do not describe historical pilot assignment as randomized without original records.

The review's 50 participants per group is a planning scenario, not a completed power analysis. Before recruitment, estimate the control event rate, minimum relevant effect, tasks/person, intraparticipant correlation, dropout and multiplicity policy; power the G3–G2 timing and G4–G3 alternative contrasts using simulation or a statistician-reviewed clustered model.

```sh
.venv/bin/python scripts/export_study_logs.py --input data/private/study_events.csv --source human --output results/review1-human/study_summary.json
```

This analysis rejects legacy provenance-free logs, separates sources, rejects duplicate participant/task records, reports participant-level means and bootstrap intervals, and contrasts G3–G2, G4–G3 and G4–G1. Small samples cannot support robust inference. No human study was run during this project revision.

## E5 and E6

See `SECURITY_MATRIX.md` for adversaries, tests, acceptance criteria and limitations. Unit tests stub the network and OS clipboard: they test the application contract, not real packet capture or clipboard history. Argon2 timings are host computation measurements, not estimates of adversary GPU cost.

Performance measures full local audit, save gate, derivative clustering and separate removal of derivatives, semantics and syntax at 10, 100, 500, 1,000 and 5,000 entries. Real syntax and semantic work is timed; HIBP is stubbed and explicitly excluded. Raw times, medians, p95/p99, traced Python peak memory, Python/platform metadata and repeat counts are recorded. Three repeats yield descriptive tail quantiles only. Native memory, network latency, heterogeneous hardware, realistic correlated vault distributions and a larger repeat count remain follow-up measurements.
