# Privacy Preserving Context Aware Password Risk Assessment with Cross Account Dependency Analysis and Save Time Intervention

## Revised abstract

Password strength can depend on personal information and relationships with other credentials in addition to structural complexity. This project implements a local assessment workflow combining breach evidence, personal-context coverage, syntactic weakness, reuse and derivative relationships, with password age retained as an optional research feature rather than default compromise evidence. An encrypted vault supports the workflow, while a save-time intervention offers editing, overriding and locally generated alternatives. The revised evaluation separates personal-relationship labels from bounded attacker outcomes, compares conventional and calibrated baselines, and evaluates individual feature removals. Executed synthetic fixtures and functional tests establish reproducibility of this implementation, but do not establish independent predictive validity or behavioral effectiveness. A prospective four-condition fictional-task interface supports subsequent comparison of conventional, post-save, pre-save and pre-save-with-alternative feedback. Independent datasets, faithful published-model baselines and an approved, adequately powered human study remain necessary before claims of research superiority or publication readiness.

## Introduction and research gap

A structurally complex password may remain predictable from information available to an attacker. Personal-context assessment and combined personal/history attacks already exist. The defensible question is whether local assessment and vault-level relationships add measurable detection value, and whether acting before storage changes retained credential choices. Integration alone does not establish novelty. The encrypted vault is implementation infrastructure, not a proposed new cipher.

The research questions are:

1. Does locally declared personal context improve attack-relevant detection relative to conventional strength estimation at a controlled false-positive rate?
2. Do cross-account relationships improve detection under history-aware attackers, and what are the costs of transitive clustering?
3. Does pre-save feedback reduce vulnerable retained fictional credentials relative to equivalent post-save feedback, and does an immediate alternative add benefit?
4. Can these behaviors be delivered with acceptable local privacy exposure and computational overhead?

The corresponding hypotheses concern incremental detection, calibration, intervention timing and alternatives. They remain hypotheses until independently validated.

## Related work and contribution boundary

| Work | Established direction | Required comparison or distinction |
|---|---|---|
| Wheeler, zxcvbn | Low-budget structural guessing estimates | Conventional baseline, not a substitute for user-specific information. [USENIX paper](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler/) |
| Atzori and colleagues, 2024 | Password evaluation using reconstructed social-network information and generative models | CAV uses locally declared attributes; personal-context assessment itself is not novel. [Publisher article](https://doi.org/10.1016/j.osnem.2024.100278) |
| Ou and colleagues, 2026 | Targeted guessing using personal information and old passwords | Evaluate defensive findings against attack outcomes; do not conflate a lexical flag with successful recovery. [Publisher article](https://link.springer.com/article/10.1186/s42400-025-00430-0) |
| MDIGuess, 2026 | Joint exploitation of historical passwords, PII and generic leaked-password information | Multi-source integration is prior art; this repository's toy attacker is not a reproduction. [IEEE research summary](https://signalprocessingsociety.org/publications-resources/ieee-transactions-information-forensics-and-security/2026/09/mdiguess) |
| Alatawi, Cipher-Guard, 2026 | Adaptive context-aware password assessment | Compare transparent local heuristics against trained methods under shared data and outcomes before claiming an advantage. [Publisher article](https://doi.org/10.1049/ise2/3930060) |
| Zou and colleagues, 2024 | Protection-motivation interventions for breached-password changes | Compare intervention timing and alternatives directly rather than infer effectiveness from suggestion acceptance. [Author-hosted paper](https://yixinzou.github.io/publications/pdf/tochi2024-zou.pdf) |

These sources establish overlap and motivate comparisons. Their reported metrics are not transplanted into CAV result tables, because datasets, attack budgets and outcomes differ. No exhaustive novelty search or verified journal-quartile determination is claimed.

## Threat model

A locked-storage adversary can read or modify database/backup files. A guessing adversary has general statistics (S1), personal identifiers (S2), one prior password (S3), personal and prior-password information (S4), or all sources (S5). Evaluation is offline on fictional or otherwise authorized data. A network observer may see HIBP prefixes and timing, though plaintext passwords and personal attributes are not sent through that application path. Unlocked-host compromise, browser memory, clipboard history, snapshots and rollback/deletion attacks are outside the proven guarantees. The security matrix connects each exercised property to its tests and limits.

## Proposed assessment

The production heuristic currently weights breach evidence at 0.45, semantic coverage at 0.25, weak syntax at 0.15, exact reuse at 0.10 and derivative membership at 0.05. Age has zero default weight. Semantic/reuse/derivative contributions share a 0.35 cap; this is an explicit heuristic, not empirical proof that correlated evidence has been corrected. The original six submitted weights are preserved as a research baseline.

Unknown breach status is missing evidence. The audit evaluates both breach endpoints to produce a score interval and a criticality-weighted health interval, and labels the assessment incomplete. No 0.5 probability is assigned to a failed lookup. These bounds cover missing breach evidence, not full uncertainty in the model.

Age is informational by default, consistent with the principle against routine periodic changes in [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4-Implementation-Resources/faqs/). This does not imply general NIST compliance or certification. Explicit rotation-policy research configurations remain possible.

Derivative families support connected components and deterministic greedy complete-link groups. Connected components can include indirectly linked passwords that fail the direct pair rule. Streaming pair comparisons remove the quadratic adjacency matrix without changing the chain relation; worst-case comparison time remains quadratic. A family flag is not proof of exploitability.

Logistic regression provides an interpretable comparison. Models are trained only on training folds and ablations are refitted. The research artifact is kept separate from live application configuration and is not automatically deployed.

## Architecture and privacy

AES-GCM protects credentials and profiles under the vault data key. Password/recovery key wrapping and Argon2id remain established supporting mechanisms. Profile writes require an unlocked key; legacy plaintext profiles migrate on authenticated application access and failures are not suppressed. Backups preserve encrypted metadata. Restore checks supplied credentials and encrypted contents before atomic replacement and then locks the session.

Suggestions use the local CSPRNG. The old remote suggestion path is removed, so an API key does not send user themes or failure reasons to an LLM. The HIBP boundary validates the intended endpoint and prevents redirects; malformed responses remain unknown. Locking clears decrypted objects and widget state in addition to the mutable key. These are bounded engineering improvements, not a proof of security under arbitrary host compromise.

## Evaluation and observed limits

See `results/review1/SUMMARY.md` for executed counts, measurements and negative findings, and `REVIEW1_PROTOCOL.md` for exact methods. E1 personal labels and E2/E3 attack labels are distinct. All baseline methods share common outcomes, while validation determines operating thresholds. Error records, risk bands, model coefficients, ablations, split checks and dependency versions are retained for reproduction.

No independent corpus has been collected and no B8 published contextual model has been reproduced. The synthetic generator was authored in this implementation effort, so it cannot constitute independent external validation. Per-category uncertainty, broader attacks, multilingual personal information, source-template uncertainty and realistic correlated vault distributions require follow-up work.

The existing 10-person pilot and any simulation files must not support a claim that loss framing is superior. Original participant records, assignment procedure and provenance need reconciliation before even descriptive human claims are reused. The new study page is a feasibility implementation; no participants were recruited in this revision. Post-save retention is temporary study storage, not a real changed account password. Questionnaire, follow-up and actual account-change outcomes remain unmeasured.

Performance reports exclude network time and measure one machine. Three repeats do not establish stable p99 latency. Tests establish behavior in the tested scenarios only. Backup rollback/deletion, immutable memory copies, clipboard history and historical plaintext artifacts remain limitations.

## Conclusion and submission criteria

The revision improves implementation consistency, privacy defaults, failure handling and research reproducibility. Its synthetic experiments provide useful debugging evidence, including substantial missed attack outcomes, rather than confirmation of every hypothesis. Publication claims should remain limited to implemented mechanisms and the stated synthetic measurements. Stronger claims require independent labels and data, faithful state-of-the-art comparisons, attacker diversity, approved participant recruitment, prospective statistical power and adequate cross-platform security/performance evidence.

The faculty's suggested journals remain candidate venues. No submission, current quartile verification or acceptance prediction has been performed. The workspace contains an older Word draft titled “AI-Assisted Secure Password Advisor Using Personal Risk Profiling,” describing a three-signal advisor. It differs from the six-signal CAV manuscript named in the faculty review. The older draft is preserved; this document supplies updated manuscript framing for the current project without silently overwriting its historical claims or author records.
