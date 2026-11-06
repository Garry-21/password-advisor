# Changelog

## [Phase 0] - 2026-10-17
### Added
- `.streamlit/config.toml`: Configured `[server] address="127.0.0.1"` and `[browser] gatherUsageStats=false`.
- `tests/test_semantic.py`: Comprehensive test suite for leet-speak reversal and thematic PII coverage scoring.
- `tests/test_ui_copy.py`: Unit tests for Variant A (loss-framed) and Variant B (neutral) nudge copy.
- In-memory cache for HIBP 5-char prefix lookups with `Add-Padding: true` header in `modules/syntactic.py`.
- Participant consent checkbox and participant ID validation in `app.py`.
- `pytest.ini` with `pythonpath = .` and `testpaths = tests`.
- `docs/DECISIONS.md`.

### Changed
- `modules/llm.py`: Configured `DEFAULT_MODEL` to `llama-3.3-70b-versatile` with graceful error reporting.
- `.gitignore`: Added `*.spvault`, `vault.db`, `data/private/`, `.env`, `results.csv`, `real_dataset.csv`.
- `tests/test_syntactic.py`: Added test coverage for syntax strength evaluation and HIBP prefix cache verification.

### Security
- Deleted uncommitted `.env` file containing live API keys.
- Ensured no secrets or private databases are checked in.

## [Phase 1] - 2026-10-17
### Added
- `vault/models.py`: Strongly-typed dataclasses for `Entry`, `PasswordHistoryItem`, `Profile`, `KeySlot`, and `VaultHeader`. Custom exceptions `CryptoError` and `AuthError`.
- `vault/crypto.py`: Envelope encryption using Argon2id (`m=64 MiB, t=3, p=4`), HKDF-SHA256, and AES-256-GCM. Supports keyslots (`password`, `recovery`), AAD-bound entry encryption, and DEK-derived password history hashing.
- `tests/test_crypto.py`: Comprehensive test suite including 1,000 Hypothesis property-based tests, 100,000 nonce uniqueness test, tamper detection, AAD swapping prevention, master password rotation, and recovery key unlock.
- `scripts/eval_vault_crypto.py`: Benchmark script calibrating Argon2id execution time on the host.

## [Phase 2] - 2026-10-17
### Added
- `vault/store.py`: SQLite repository storing encrypted records. Ensures zero plaintext site names, URLs, usernames, or passwords in storage. Implements WAL mode, user directory permissions via `platformdirs`, atomic writes, in-memory decrypted search, and exponential throttling for failed unlock attempts.
- `vault/session.py`: SessionManager implementing auto-lock on inactivity, memory DEK zeroisation, recovery key unlock, and dogfooding master password policy validation (zxcvbn >= 3, HIBP count = 0, PII coverage < 0.3).
- `vault/clipboard.py`: Timed clipboard auto-clearing after 20 seconds, only clearing if clipboard still holds the original secret.
- `tests/test_store.py`: CRUD tests, in-memory search filter tests, hex/strings binary scan asserting zero plaintext leaks, and throttling backoff tests.
- `tests/test_session.py`: Session lifecycle tests, auto-lock timeout tests, and master password policy verification.
- `tests/test_clipboard.py`: Clipboard copy and auto-clear daemon timer tests.

### Verification
- `pytest -q`: **34 passed, 1 warning** (100% green).

## [Phase 3] - 2026-10-17
### Added
- `vault/audit.py`: Context-aware 6-signal audit engine calculating Vault Health Score (VHS) and per-entry risk vectors (Breach, PII, Syntactic, Exact Reuse, Derivative Families, Age).
- Derivative family clustering using normalized base extraction, reverse leet substitution, and Union-Find graph clustering.
- `tests/test_audit.py`: 20-entry planted vault test verifying detection of all planted vulnerabilities and score monotonicity.

## [Phase 4] - 2026-10-17
### Added
- `vault/generator.py`: CSPRNG password & passphrase generator with EFF Large Wordlist (7,776 words) and offline thematic vocabularies (baking, scifi, nature, music, sports, travel).
- Exact combinatorial entropy calculation ($H = \sum \log_2(\text{pool})$).
- `vault/gate.py`: Save-time gate intercepting add/edit entry operations with behavioral nudges and 3 explicit actions: `use_generated`, `edit`, `save_anyway`.
- `tests/test_generator.py` and `tests/test_gate.py`.

## [Phase 5] - 2026-10-17
### Added
- `vault/egress_guard.py`: Network boundary guard enforcing strict endpoint allowlist (HIBP range API with 5-hex prefix, Groq API) and inspecting URLs, headers, and request bodies for vault secrets.
- `tests/test_egress.py`: Unit tests for allowlist filtering and secret leakage detection.

## [Phase 6] - 2026-10-17
### Added
- `vault/importers.py`: CSV import engine for Google Chrome, Bitwarden, and generic CSV formats.
- `vault/backup.py`: Encrypted `.spvault` zero-knowledge backup and restore, plus decrypted CSV export with warning disclosures.
- `tests/test_import_export.py`: Round-trip tests for backup, restore, and CSV imports.

## [Phase 7 & Multi-Page UI] - 2026-10-17
### Added
- `scripts/eval_audit.py`: Benchmark measuring Precision, Recall, and F1 across all 6 vulnerability vectors.
- `scripts/eval_perf.py`: Cryptographic throughput and scaling benchmarks (Argon2id median 165ms, AES-GCM 13,275 decrypts/sec, audit scaling ~15ms/entry).
- Multi-page Streamlit application powered by `st.navigation`:
  - `pages/1_Vault.py`: Credential management, search, and save-time gate nudges.
  - `pages/2_Security_Audit.py`: VHS score gauge, 6-signal breakdown, derivative family clusters, and 1-click Quick Fix.
  - `pages/3_Password_Generator.py`: Interactive passphrase and random character generator with live entropy.
  - `pages/4_Import_Export.py`: Drag-and-drop CSV import and .spvault encrypted backup.
  - `pages/5_Settings.py`: Personal profile configuration, auto-lock timeout, and master password rotation.
  - `pages/6_Advisor_Pilot.py`: Preserved research pilot workflow with A/B testing and logging to `results.csv`.
- `vault/ui_common.py`: Shared authentication gatekeeper (`require_unlocked_vault()`), auto-lock ticker, and glassmorphic styling.

### Verification
- `pytest -q`: **63 passed, 1 warning in 28.52s** (100% green across entire suite).
