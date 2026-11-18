# Changelog

All notable changes to **Sig**[**NET**] are documented in this file.

## [0.4.0] - 2026-11-17

### Security (Cross-Boundary & Lifecycle Hardening `WP-CODEX-1` .. `WP-CODEX-7`)
- **`WP-CODEX-1` — Live Per-Call Expiration & 16-Hop Multi-Generation Lineage (`src/crypto/token.rs`, `src/policy/mod.rs`, `src/ledger/mod.rs`):** Added `lineage_token_hashes: Vec<String>` (`MAX_DELEGATION_DEPTH = 16`) to `CapabilityClaims`, enforced live per-call clock checks (`now_unix > claims.expires_at_unix`) inside `evaluate_tool_call`, and cascaded CRL revocation (`is_capability_revoked`) and rate-limit accounting across the full ancestor chain ($T_0 \to T_1 \to \dots \to T_k$).
- **`WP-CODEX-2` — Unified Platform-Aware Safe Path Subset Semantics (`src/policy/mod.rs`, `src/crypto/token.rs`):** Extracted `verify_safe_path_subset` and `canonicalize_and_validate_policy_path` shared across token minting, attenuation, and runtime evaluation (plus host `std::fs::canonicalize` symlink/junction checks when paths exist on disk), eliminating sibling-prefix privilege escalation (`/workspace/safe` -> `/workspace/safe_secrets`) during attenuation.
- **`WP-CODEX-3` — Verified Fail-Closed Windows ACLs & SQLite WAL Sidecar Hardening (`src/ledger/mod.rs`):** `enforce_owner_only_acl` now verifies `icacls` exit status `0` fail-closed via `whoami`/`USERNAME`, and `enforce_vault_and_sidecar_acls` locks the parent directory, `signet.db`, `signet.db-wal`, and `signet.db-shm` after WAL initialization.
- **`WP-CODEX-4` — Cancel-Safe `CancelSafeLineReader<R>`, Write Timeouts & Child Lifecycle Cleanup (`src/proxy/mod.rs`):** Replaced the future-local line buffer inside `tokio::select!` with `CancelSafeLineReader<R>` (preserving partial frame chunks across cancelled polls), bounded stdio writes with `MAX_STDIO_WRITE_TIMEOUT` (`10s`), and enforced child `kill().await` + `wait().await` on all exit paths.
- **`WP-CODEX-5` — Atomic `BEGIN IMMEDIATE` Transactions for Merkle Appends & CRL Revocation (`src/ledger/mod.rs`):** Wrapped `append_audit_event` and `revoke_token` inside `TransactionBehavior::Immediate` (`BEGIN IMMEDIATE`), serializing Merkle sequence head reads and binding CRL updates atomically to their signed Merkle receipts.
- **`WP-CODEX-6` — Full-Metadata Tool Schema Pinning & Atomic Catalog Commits (`src/policy/pin.rs`, `src/ledger/mod.rs`, `src/proxy/mod.rs`):** Expanded `McpToolDefinition` to hash and poison-scan `title`, `outputSchema`, `annotations`, and `#[serde(flatten)] extra_fields`. Added `verify_or_pin_tool_catalog_atomic` and `--strict-pins` CLI enforcement.
- **`WP-CODEX-7` — Cross-Process SQLite Quotas, Default-Deny Child Environment & CLI `Verify` Strict JSON (`src/ledger/mod.rs`, `src/proxy/mod.rs`, `src/main.rs`):** Added `rate_limit_events` SQLite table (`check_and_record_persistent_rate_limit`) for cross-process rate-limiting; switched child process spawning to `cmd.env_clear()` + `SAFE_OS_ENV_ALLOWLIST` + `--pass-env`; upgraded `signet verify --args` to `parse_strict_json_no_dup_keys`.

## [0.3.0] - 2026-11-15

### Security (Adversarial Security Audit `[SEC-01]` .. `[SEC-06]`)
- **`[SEC-01]` — Child MCP Process Environment Secret Scrubbing (`CWE-526` / `CWE-200`):** `build_sanitized_child_command` strips `SIGNET_PASSPHRASE`, `SIGNET_TOKEN`, `SIGNET_DB_PATH`, `LOOM_PASSPHRASE`, `LOOM_DB_PATH`, `FARADAY_PASSPHRASE`, `FARADAY_DB_PATH`, and all `SIGNET_*`/`LOOM_*`/`FARADAY_*`/`VAULT_*` environment variables before spawning child MCP servers.
- **`[SEC-02]` — Strict Duplicate-Key JSON Rejection, Depth Guard & Canonical Re-Serialization (`CWE-436`):** Added `parse_strict_json_no_dup_keys` (`MAX_JSON_DEPTH = 64`) that rejects duplicate object keys at deserialization time and re-serializes canonical JSON before forwarding to downstream MCP servers.
- **`[SEC-03]` — 8-Round Percent-Decode (Fail-Closed), Windows UNC/Device Namespace, NTFS ADS & DOS Device Guard (`CWE-22` / `CWE-41`):** Expanded percent-decoding to 8 rounds (failing closed if `%XX` sequences remain) and blocked `\\?\`, `\\.\`, `//` UNC paths, NTFS Alternate Data Streams (`file.txt:secret:$DATA`), and reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
- **`[SEC-04]` — Sybil-Resistant Parent-Lineage Rate Limiting (`CWE-770`):** Rate-limit invocations are now charged against both `claims.token_id` and `claims.parent_token_hash` so attenuating multiple child tokens cannot multiply a parent token's `max_calls_per_minute` budget.
- **`[SEC-05]` — Unconditional Server Frame Inspection Against `\u0074ools` Escape (`CWE-345`):** Removed naive substring filter on server frames and enforced strict JSON parsing on `tools/list` responses so JSON Unicode escapes (`\u0074ools`) cannot evade `BLAKE3` schema pinning or `[SIG-02]` poison scanning.
- **`[SEC-06]` — Constant-Time Verifier Equality, Stack Key Zeroization & SQLite `secure_delete` (`CWE-208` / `CWE-316`):** Added `constant_time_eq_32`, stack zeroization of `Ed25519` secret key bytes (`priv_arr.zeroize()`) and CLI passphrases, and `PRAGMA secure_delete = ON`.

## [0.2.0] - 2026-11-14

### Security (Red Team Remediation `WP-1` .. `WP-6`)
- **`WP-1` — JSON-RPC 2.0 Batch Array Firewall Enforcement (`CWE-436` / `CWE-863`):** `process_client_jsonrpc_line` and `verify_server_tools_list_payload` now inspect both single JSON objects and JSON-RPC 2.0 Batch Arrays (`Value::Array`), blocking any batch containing an unauthorized `tools/call` or malformed element.
- **`WP-2` — Canonical Path Segment-Boundary & Percent-Decode Guard (`CWE-22`):** Added iterative percent-decoding (`%2e%2e%2f`, `%252e%252e%252f`), embedded NUL-byte rejection, Unicode homoglyph dot normalization (`U+FF0E`, `U+2024`, `U+FE52`, `U+3002`), `file://` URI scheme stripping, and strict segment-boundary prefix matching so `/workspace/safe` never matches sibling `/workspace/safe_secrets`.
- **`WP-3` — Bounded 4 MiB JSON-RPC Frame Reader (`CWE-770`):** Replaced unbounded `BufReader::next_line()` with `read_bounded_jsonrpc_line` (`MAX_JSONRPC_LINE_BYTES = 4 MiB`) to eliminate OOM Denial-of-Service from newline-less stdio streams.
- **`WP-4` — Cryptographic Token Revocation List (`CRL`) & Parent-Cascade Revocation (`CWE-613`):** Added `revoked_tokens` SQLite table, `signet token revoke --token <ID_OR_TOKEN> --reason <REASON>`, and parent-to-child cascade revocation checks across `signet proxy` and `signet verify`.
- **`WP-5` — Unicode Zero-Width & Bidi Anti-Poisoning Scanner (`CWE-176`):** `scan_tool_for_poisoning` now blocks hidden Unicode Bidirectional overrides (`U+202A..U+202E`, `U+2066..U+2069`) and strips zero-width token splitters (`U+200B..U+200F`, `U+FEFF`, `U+00AD`) before evaluating prompt-injection patterns.
- **`WP-6` — Bounded Regex DFA Size Limit, Rate-Window GC & SQLite Busy Timeout (`CWE-400` / `CWE-662`):** Enforced 256 KiB DFA size limits on `denied_arg_patterns`, automatic expired-key pruning in `rate_windows`, and a 5,000 ms SQLite WAL `busy_timeout`.

## [0.1.0] - 2026-11-14

### Added
- **`Ed25519` Authority Vault & Capability Tokens (`src/crypto/`):** `Argon2id` + `HKDF-SHA256` + `XChaCha20-Poly1305` encrypted `Ed25519` signing key vault and self-contained attenuable `sig1.<payload>.<sig>` capability tokens.
- **Append-Only `BLAKE3` Merkle Audit Log (`src/ledger/mod.rs`):** Bundled `rusqlite 0.42.0` (`SQLite 3.51.2+`) WAL store linking every tool call decision via `BLAKE3` hash chains and `Ed25519` row signatures, with owner-only ACL enforcement (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix).
- **Capability Policy & Anti-Rug-Pull Engine (`src/policy/`):** Tool allow/deny evaluation, deep JSON argument path-traversal & prefix-containment guards, sliding-window rate limiting, `BLAKE3` MCP tool schema pinning, and prompt-injection description scanning.
- **JSON-RPC 2.0 Stdio Proxy & Ratatui v0.30+ Dashboard (`src/proxy/`, `src/tui/`):** Added `signet init`, `signet token`, `signet pin`, `signet proxy`, `signet verify`, `signet audit`, and `signet tui` with `sanitize_terminal_str` (`CWE-150`).
