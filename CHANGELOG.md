# Changelog

All notable changes to **Sig**[**NET**] are documented in this file.

## [0.1.0] - 2026-11-14

### Added
- **`Ed25519` Authority Vault & Capability Tokens (`src/crypto/`):** `Argon2id` + `HKDF-SHA256` + `XChaCha20-Poly1305` encrypted `Ed25519` signing key vault and self-contained attenuable `sig1.<payload>.<sig>` capability tokens.
- **Append-Only `BLAKE3` Merkle Audit Log (`src/ledger/mod.rs`):** Bundled `rusqlite 0.42.0` (`SQLite 3.51.2+`) WAL store linking every tool call decision via `BLAKE3` hash chains and `Ed25519` row signatures, with owner-only ACL enforcement (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix).
- **Capability Policy & Anti-Rug-Pull Engine (`src/policy/`):** Tool allow/deny evaluation, deep JSON argument path-traversal & prefix-containment guards, sliding-window rate limiting, `BLAKE3` MCP tool schema pinning, and prompt-injection description scanning.
- **JSON-RPC 2.0 Stdio Proxy & Ratatui v0.30+ Dashboard (`src/proxy/`, `src/tui/`):** Added `signet init`, `signet token`, `signet pin`, `signet proxy`, `signet verify`, `signet audit`, and `signet tui` with `sanitize_terminal_str` (`CWE-150`).
