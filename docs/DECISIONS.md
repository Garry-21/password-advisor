# Architectural & Security Decisions

This log records security, cryptographic, and architectural design decisions made during the Context-Aware Vault (CAV) implementation.

## DEC-001: Phase 0 Security & Privacy Hardening
- **Date**: 2026-10-17
- **Decision**: 
  1. Remove `.env` containing live API keys and ignore all vault/secret files (`*.spvault`, `vault.db`, `data/private/`, `.env`).
  2. Set `DEFAULT_MODEL` in `llm.py` to `llama-3.3-70b-versatile` (supported on Groq) with graceful error fallback.
  3. Implement in-memory prefix caching in `check_hibp_k_anonymity` with `Add-Padding: true` to prevent side-channel leaks and redundant network round-trips.
  4. Restrict Streamlit server to `127.0.0.1` and disable usage telemetry via `.streamlit/config.toml`.
  5. Include explicit participant consent and participant ID tracking in `app.py`.

## DEC-002: Envelope Encryption & Key Derivation (Phase 1)
- **Date**: 2026-10-17
- **Decision**: 
  1. Implement Argon2id ($m=64\text{ MiB}, t=3, p=4$) for master password key derivation with lower-bound parameter checks.
  2. Use AES-256-GCM envelope encryption where Data Encryption Key (DEK) is generated with CSPRNG and wrapped into individual `KeySlot` objects (password, recovery).
  3. Bind AES-GCM Associated Authenticated Data (AAD) to `f"{entry_id}:{schema_version}"` to detect and reject ciphertext swapping between records.
  4. Derive password history hashes using HMAC-SHA256 with an independent HKDF-derived subkey from the DEK.

## DEC-003: Zero-Plaintext Storage & Ephemeral Memory Model (Phase 2)
- **Date**: 2026-10-17
- **Decision**: 
  1. Store all records in SQLite (`records` table) strictly as raw binary ciphertexts and nonces with user-only file permissions (`0o700`).
  2. Maintain DEK in memory as a mutable `bytearray`, zeroised upon manual lock or 5-minute inactivity timeout.
  3. Enforce exponential unlock throttling (0s, 0s, 2s, 4s, 8s, up to 300s) directly in the metadata table to prevent brute-force attacks.
  4. Implement 20-second automatic clipboard clearing on a background daemon thread that only clears if the clipboard content still matches the copied secret.

## DEC-004: 6-Signal Audit Engine & Derivative Family Clustering (Phase 3)
- **Date**: 2026-10-17
- **Decision**: 
  1. Audit unlocked entries across 6 distinct risk signals: Breach ($b_i$, HIBP), Semantic PII Coverage ($C_i$), Syntactic Complexity ($s_i$, zxcvbn), Exact Reuse ($r_i$), Derivative Families ($d_i$), and Age ($a_i$).
  2. Cluster derivative families by stripping affixes, applying reverse leet normalization, and running Union-Find clustering across identical bases, Levenshtein distance $\le 2$, and fuzzy ratio $\ge 85$.
  3. Calculate overall Vault Health Score: $\text{VHS} = 100 \cdot (1 - \frac{\sum w_i R_i}{\sum w_i})$ with criticality weighting.

## DEC-005: Save-Time Gate & Local Passphrase Generator (Phase 4)
- **Date**: 2026-10-17
- **Decision**: 
  1. Intercept Add and Edit credential actions before committing to SQLite with behavioral nudges and 3 explicit actions: `use_generated`, `edit`, `save_anyway`.
  2. Bundle EFF Large Wordlist (7,776 words) and offline thematic vocabularies (Baking, Sci-Fi, Nature, Music, Sports, Travel).
  3. Generate CSPRNG passphrases completely offline without external LLM calls, calculating exact combinatorial entropy $H = \sum \log_2(\text{pool})$.

## DEC-006: Egress Guard Network Boundary (Phase 5)
- **Date**: 2026-10-17
- **Decision**: 
  1. Enforce strict outbound URL allowlist: HIBP range API (GET only, exactly 5-hex prefix) and Groq API (POST only).
  2. Inspect outbound request URLs, query parameters, headers, and request payloads for plaintext vault secrets, raising `EgressSecurityError` immediately on detection.

## DEC-007: Zero-Plaintext Backup & Multi-Page Navigation (Phases 6 & 7)
- **Date**: 2026-10-17
- **Decision**: 
  1. Provide `.spvault` encrypted backup exporting raw ciphertexts and Argon2id keyslots with zero plaintext disclosure.
  2. Support CSV imports from Google Chrome and Bitwarden.
  3. Migrate to Streamlit 1.64 `st.navigation` with unified authentication gatekeeper (`require_unlocked_vault()`), live auto-refresh ticker, and dark glassmorphic styling.
