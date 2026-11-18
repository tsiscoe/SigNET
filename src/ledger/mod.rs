//! Append-Only SQLite WAL `BLAKE3` Merkle Hash-Chain & `Ed25519` Signed Receipt Ledger (`signet.db`).
//!
//! Hardened in **SigNET v0.4.0** (`WP-CODEX-1`, `WP-CODEX-3`, `WP-CODEX-5`, `WP-CODEX-6`, `WP-CODEX-7`):
//! - **`[CODEX-P0-01]` (Full Ancestor Lineage CRL):** `is_capability_revoked` and
//!   `is_token_revoked_with_lineage` check the token's ID, hash, and every ancestor hash in
//!   `lineage_token_hashes` ($T_0 \to T_1 \to \dots \to T_k$).
//! - **`[CODEX-P0-03]` (Verified Fail-Closed Windows ACLs & WAL Sidecars):** `enforce_owner_only_acl`
//!   verifies that `icacls` exits with code `0`, and `enforce_vault_and_sidecar_acls` locks the
//!   parent vault directory, `signet.db`, `signet.db-wal`, and `signet.db-shm` after WAL init.
//! - **`[CODEX-P1-02]` (Atomic `BEGIN IMMEDIATE` Transactions):** `append_audit_event` and
//!   `revoke_token` execute inside `TransactionBehavior::Immediate` so Merkle head reads, CRL writes,
//!   and receipt appends are strictly serialized and atomic.
//! - **`[CODEX-P1-03]` (Atomic Catalog Pinning):** `verify_or_pin_tool_catalog_atomic` validates
//!   the entire `tools/list` response inside one transaction before committing any pins.
//! - **`[CODEX-P1-04]` (Cross-Process SQLite Rate-Limit Quotas):** `check_and_record_persistent_rate_limit`
//!   tracks 60-second sliding-window quotas in SQLite across all `signet proxy` and `signet verify` processes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    MasterSeed, SALT_LEN, aead_decrypt, aead_encrypt, blake3_domain_hex, constant_time_eq_32,
    generate_ed25519_keypair, generate_salt, sign_bytes_hex,
    token::{CapabilityClaims, VerifiedCapability},
    verify_bytes_hex,
};
use zeroize::Zeroize;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const KEY_AAD: &[u8] = b"signet-v1|authority-signing-key";

/// A single signed, hash-chained audit receipt in the SigNET transparency log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReceipt {
    pub seq: i64,
    pub timestamp: String,
    pub subject: String,
    pub token_id: String,
    pub tool_name: String,
    pub args_blake3: String,
    pub decision: String,
    pub reason: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub ed25519_sig: String,
}

/// Pinned MCP tool schema record stored in `signet.db`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPinRecord {
    pub server_name: String,
    pub tool_name: String,
    pub schema_blake3: String,
    pub pinned_at: String,
}

/// Revoked capability token record stored in `signet.db` (`WP-4` CRL).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedTokenRecord {
    pub token_id: String,
    pub token_hash: Option<String>,
    pub revoked_at: String,
    pub reason: String,
}

/// Summary returned by [`SignetLedger::verify_merkle_chain`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationReport {
    pub total_entries: usize,
    pub head_hash: String,
    pub authority_pubkey_hex: String,
    pub valid: bool,
}

/// SQLite WAL store managing the `Ed25519` authority keypair, `BLAKE3` tool pins, and Merkle audit log.
pub struct SignetLedger {
    conn: Connection,
    db_path: PathBuf,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SignetLedger {
    /// Open or initialize a `SignetLedger` at `db_path` using `passphrase`.
    pub fn open_with_passphrase(db_path: &Path, passphrase: &[u8], fast_kdf: bool) -> Result<Self> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create SigNET directory {}", parent.display())
            })?;
            if !fast_kdf {
                enforce_owner_only_acl(parent, true)?;
            }
        }

        let conn = Connection::open(db_path).with_context(|| {
            format!(
                "failed to open SigNET SQLite ledger at {}",
                db_path.display()
            )
        })?;

        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;

        Self::init_schema(&conn)?;

        let existing_meta = Self::load_meta(&conn)?;
        let (signing_key, verifying_key) = match existing_meta {
            Some((salt, expected_verifier, pubkey_bytes, enc_privkey)) => {
                let seed = if fast_kdf {
                    MasterSeed::derive_fast_for_test(passphrase, &salt)?
                } else {
                    MasterSeed::derive_from_passphrase(passphrase, &salt)?
                };
                let subkeys = seed.derive_vault_subkeys(&salt)?;
                if !constant_time_eq_32(&subkeys.verifier, &expected_verifier) {
                    return Err(anyhow!(
                        "Invalid passphrase for SigNET authority vault at {}",
                        db_path.display()
                    ));
                }
                let dec_priv = aead_decrypt(&subkeys.aead_key, &enc_privkey, KEY_AAD)?;
                let mut priv_arr: [u8; 32] = dec_priv
                    .0
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow!("corrupted Ed25519 secret key length"))?;
                let sk = SigningKey::from_bytes(&priv_arr);
                priv_arr.zeroize();
                let vk = VerifyingKey::from_bytes(&pubkey_bytes)
                    .map_err(|_| anyhow!("corrupted Ed25519 public key"))?;
                (sk, vk)
            }
            None => {
                let salt = generate_salt();
                let seed = if fast_kdf {
                    MasterSeed::derive_fast_for_test(passphrase, &salt)?
                } else {
                    MasterSeed::derive_from_passphrase(passphrase, &salt)?
                };
                let subkeys = seed.derive_vault_subkeys(&salt)?;
                let sk = generate_ed25519_keypair();
                let vk = sk.verifying_key();
                let enc_privkey = aead_encrypt(&subkeys.aead_key, &sk.to_bytes(), KEY_AAD)?;
                Self::save_meta(
                    &conn,
                    &salt,
                    &subkeys.verifier,
                    &vk.to_bytes(),
                    &enc_privkey,
                )?;
                (sk, vk)
            }
        };

        // [CODEX-P0-03]: Enforce verified owner-only ACLs on db_path AND its SQLite WAL/SHM sidecars
        // AFTER WAL mode and schema creation have materialized on disk.
        if !fast_kdf {
            enforce_vault_and_sidecar_acls(db_path)?;
        }

        Ok(Self {
            conn,
            db_path: db_path.to_path_buf(),
            signing_key,
            verifying_key,
        })
    }

    /// Open an in-memory `SignetLedger` for high-speed `proptest!` verification.
    pub fn open_in_memory_for_test(passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        let salt = [0x3Cu8; SALT_LEN];
        let seed = MasterSeed::derive_fast_for_test(passphrase, &salt)?;
        let subkeys = seed.derive_vault_subkeys(&salt)?;
        let signing_key = generate_ed25519_keypair();
        let verifying_key = signing_key.verifying_key();
        let enc_privkey = aead_encrypt(&subkeys.aead_key, &signing_key.to_bytes(), KEY_AAD)?;
        Self::save_meta(
            &conn,
            &salt,
            &subkeys.verifier,
            &verifying_key.to_bytes(),
            &enc_privkey,
        )?;
        Ok(Self {
            conn,
            db_path: PathBuf::from(":memory:"),
            signing_key,
            verifying_key,
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS signet_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                pubkey BLOB NOT NULL,
                encrypted_privkey BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tool_schema_pins (
                server_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                schema_blake3 TEXT NOT NULL,
                pinned_at TEXT NOT NULL,
                PRIMARY KEY (server_name, tool_name)
            );

            CREATE TABLE IF NOT EXISTS merkle_audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                subject TEXT NOT NULL,
                token_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                args_blake3 TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE,
                ed25519_sig TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT,
                revoked_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rate_limit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_key TEXT NOT NULL,
                ts_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_ts
                ON rate_limit_events (bucket_key, ts_unix_ms);",
        )
        .context("failed to initialize SigNET SQLite schema")?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn load_meta(
        conn: &Connection,
    ) -> Result<Option<([u8; SALT_LEN], [u8; 32], [u8; 32], Vec<u8>)>> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT salt, verifier, pubkey, encrypted_privkey FROM signet_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;

        if let Some((s, v, pk, epk)) = row {
            let salt: [u8; SALT_LEN] = s.try_into().map_err(|_| anyhow!("bad salt len"))?;
            let verifier: [u8; 32] = v.try_into().map_err(|_| anyhow!("bad verifier len"))?;
            let pubkey: [u8; 32] = pk.try_into().map_err(|_| anyhow!("bad pubkey len"))?;
            Ok(Some((salt, verifier, pubkey, epk)))
        } else {
            Ok(None)
        }
    }

    fn save_meta(
        conn: &Connection,
        salt: &[u8; SALT_LEN],
        verifier: &[u8; 32],
        pubkey: &[u8; 32],
        enc_privkey: &[u8],
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO signet_meta (id, salt, verifier, pubkey, encrypted_privkey, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                salt.as_slice(),
                verifier.as_slice(),
                pubkey.as_slice(),
                enc_privkey,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn authority_pubkey_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Append a new firewall decision (`ALLOW` or `DENY`) to the `BLAKE3` Merkle hash-chain
    /// and sign the receipt with the authority's `Ed25519` key inside a serialized `BEGIN IMMEDIATE`
    /// SQLite write transaction (`[CODEX-P1-02]`).
    pub fn append_audit_event(
        &self,
        subject: &str,
        token_id: &str,
        tool_name: &str,
        args_json: &str,
        decision: &str,
        reason: &str,
    ) -> Result<AuditReceipt> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .context("failed to start BEGIN IMMEDIATE transaction for Merkle append")?;
        let receipt = Self::append_audit_event_in_tx(
            &tx,
            &self.signing_key,
            subject,
            token_id,
            tool_name,
            args_json,
            decision,
            reason,
        )?;
        tx.commit()
            .context("failed to commit Merkle audit receipt transaction")?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    fn append_audit_event_in_tx(
        tx: &Transaction<'_>,
        signing_key: &SigningKey,
        subject: &str,
        token_id: &str,
        tool_name: &str,
        args_json: &str,
        decision: &str,
        reason: &str,
    ) -> Result<AuditReceipt> {
        let (last_seq, prev_hash) = tx
            .query_row(
                "SELECT seq, entry_hash FROM merkle_audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
            .unwrap_or((0, GENESIS_PREV_HASH.to_string()));

        let next_seq = last_seq + 1;
        let timestamp = Utc::now().to_rfc3339();
        let args_blake3 = blake3_domain_hex("signet-v1-args", &[args_json.as_bytes()]);

        let entry_hash = Self::compute_entry_hash(
            next_seq,
            &timestamp,
            subject,
            token_id,
            tool_name,
            &args_blake3,
            decision,
            reason,
            &prev_hash,
        );

        let ed25519_sig = sign_bytes_hex(signing_key, entry_hash.as_bytes());

        tx.execute(
            "INSERT INTO merkle_audit_log (
                seq, timestamp, subject, token_id, tool_name, args_blake3, decision, reason, prev_hash, entry_hash, ed25519_sig
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                next_seq,
                timestamp,
                subject,
                token_id,
                tool_name,
                args_blake3,
                decision,
                reason,
                prev_hash,
                entry_hash,
                ed25519_sig
            ],
        )?;

        Ok(AuditReceipt {
            seq: next_seq,
            timestamp,
            subject: subject.to_string(),
            token_id: token_id.to_string(),
            tool_name: tool_name.to_string(),
            args_blake3,
            decision: decision.to_string(),
            reason: reason.to_string(),
            prev_hash,
            entry_hash,
            ed25519_sig,
        })
    }

    /// Cryptographically verify the entire append-only `BLAKE3` Merkle chain and every `Ed25519` row signature.
    pub fn verify_merkle_chain(&self) -> Result<ChainVerificationReport> {
        let entries = self.list_audit_receipts()?;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();

        for (expected_seq, r) in (1i64..).zip(entries.iter()) {
            if r.seq != expected_seq {
                return Err(anyhow!(
                    "Merkle chain sequence gap detected at seq={} (expected seq={expected_seq})",
                    r.seq
                ));
            }
            if r.prev_hash != expected_prev {
                return Err(anyhow!(
                    "Merkle chain broken at seq={}: prev_hash '{}' != expected '{}'",
                    r.seq,
                    r.prev_hash,
                    expected_prev
                ));
            }

            let recomputed = Self::compute_entry_hash(
                r.seq,
                &r.timestamp,
                &r.subject,
                &r.token_id,
                &r.tool_name,
                &r.args_blake3,
                &r.decision,
                &r.reason,
                &r.prev_hash,
            );

            if recomputed != r.entry_hash {
                return Err(anyhow!(
                    "Merkle entry_hash tamper detected at seq={}: stored '{}' != recomputed '{recomputed}'",
                    r.seq,
                    r.entry_hash
                ));
            }

            verify_bytes_hex(&self.verifying_key, r.entry_hash.as_bytes(), &r.ed25519_sig)
                .with_context(|| format!("Ed25519 receipt signature invalid at seq={}", r.seq))?;

            expected_prev = r.entry_hash.clone();
        }

        Ok(ChainVerificationReport {
            total_entries: entries.len(),
            head_hash: expected_prev,
            authority_pubkey_hex: self.authority_pubkey_hex(),
            valid: true,
        })
    }

    /// List all audit receipts in chronological order.
    pub fn list_audit_receipts(&self) -> Result<Vec<AuditReceipt>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, timestamp, subject, token_id, tool_name, args_blake3, decision, reason, prev_hash, entry_hash, ed25519_sig
             FROM merkle_audit_log ORDER BY seq ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(AuditReceipt {
                seq: r.get(0)?,
                timestamp: r.get(1)?,
                subject: r.get(2)?,
                token_id: r.get(3)?,
                tool_name: r.get(4)?,
                args_blake3: r.get(5)?,
                decision: r.get(6)?,
                reason: r.get(7)?,
                prev_hash: r.get(8)?,
                entry_hash: r.get(9)?,
                ed25519_sig: r.get(10)?,
            });
        }
        Ok(out)
    }

    /// Verify or record a single `BLAKE3` tool schema pin (`anti-rug-pull`).
    pub fn verify_or_pin_tool_schema(
        &self,
        server_name: &str,
        tool_name: &str,
        schema_blake3: &str,
    ) -> Result<()> {
        self.verify_or_pin_tool_catalog_atomic(
            server_name,
            &[(tool_name.to_string(), schema_blake3.to_string())],
            false,
        )
    }

    /// `[CODEX-P1-03]`: Atomically verify (and if permitted, pin) an entire catalog of `(tool_name, schema_blake3)`
    /// pairs inside a single `BEGIN IMMEDIATE` transaction. If any tool in the batch fails verification
    /// (or is unpinned when `strict_preapproved_only` is `true`), the entire transaction rolls back and
    /// **zero** pins from the catalog are committed.
    pub fn verify_or_pin_tool_catalog_atomic(
        &self,
        server_name: &str,
        tool_hashes: &[(String, String)],
        strict_preapproved_only: bool,
    ) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .context("failed to start BEGIN IMMEDIATE transaction for catalog pinning")?;

        let mut to_insert: Vec<(&str, &str)> = Vec::new();

        for (tool_name, schema_blake3) in tool_hashes {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT schema_blake3 FROM tool_schema_pins WHERE server_name = ?1 AND tool_name = ?2",
                    params![server_name, tool_name],
                    |r| r.get(0),
                )
                .optional()?;

            match existing {
                Some(pinned_hash) => {
                    if pinned_hash != *schema_blake3 {
                        return Err(anyhow!(
                            "MCP Schema Rug-Pull Detected for '{server_name}::{tool_name}': pinned BLAKE3 '{pinned_hash}' != live '{schema_blake3}'"
                        ));
                    }
                }
                None => {
                    if strict_preapproved_only {
                        return Err(anyhow!(
                            "Strict Pin Mode Blocked unpinned MCP tool '{server_name}::{tool_name}' (BLAKE3 '{schema_blake3}')"
                        ));
                    }
                    to_insert.push((tool_name.as_str(), schema_blake3.as_str()));
                }
            }
        }

        let now_str = Utc::now().to_rfc3339();
        for (tool_name, schema_blake3) in to_insert {
            tx.execute(
                "INSERT INTO tool_schema_pins (server_name, tool_name, schema_blake3, pinned_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![server_name, tool_name, schema_blake3, &now_str],
            )?;
        }

        tx.commit()
            .context("failed to commit atomic tool catalog pins")?;
        Ok(())
    }

    /// List all pinned MCP tool schemas.
    pub fn list_tool_pins(&self) -> Result<Vec<ToolPinRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT server_name, tool_name, schema_blake3, pinned_at
             FROM tool_schema_pins ORDER BY server_name ASC, tool_name ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(ToolPinRecord {
                server_name: r.get(0)?,
                tool_name: r.get(1)?,
                schema_blake3: r.get(2)?,
                pinned_at: r.get(3)?,
            });
        }
        Ok(out)
    }

    /// Revoke a capability token by `token_id` (and optional `token_hash`), recording the revocation
    /// both in `revoked_tokens` and in the `BLAKE3` Merkle audit log atomically inside a single
    /// `BEGIN IMMEDIATE` transaction (`[CODEX-P1-02]`).
    pub fn revoke_token(
        &self,
        token_id: &str,
        token_hash: Option<&str>,
        reason: &str,
    ) -> Result<RevokedTokenRecord> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .context("failed to start BEGIN IMMEDIATE transaction for token revocation")?;

        let revoked_at = Utc::now().to_rfc3339();
        tx.execute(
            "INSERT OR REPLACE INTO revoked_tokens (token_id, token_hash, revoked_at, reason)
             VALUES (?1, ?2, ?3, ?4)",
            params![token_id, token_hash, &revoked_at, reason],
        )?;

        Self::append_audit_event_in_tx(
            &tx,
            &self.signing_key,
            "signet-authority",
            token_id,
            "signet::revoke_token",
            token_hash.unwrap_or(""),
            "DENY",
            &format!("Token revoked: {reason}"),
        )?;

        tx.commit()
            .context("failed to commit atomic CRL + Merkle receipt transaction")?;

        Ok(RevokedTokenRecord {
            token_id: token_id.to_string(),
            token_hash: token_hash.map(ToString::to_string),
            revoked_at,
            reason: reason.to_string(),
        })
    }

    /// `[CODEX-P0-01]`: Check whether a [`VerifiedCapability`] (or any ancestor in its multi-generation
    /// `lineage_token_hashes` / `parent_token_hash` chain) is revoked in the CRL.
    pub fn is_capability_revoked(&self, capability: &VerifiedCapability) -> Result<Option<String>> {
        let ancestors = capability.claims.all_ancestor_hashes();
        self.is_token_revoked_with_lineage(
            &capability.claims.token_id,
            &capability.token_hash,
            &ancestors,
        )
    }

    /// `[CODEX-P0-01]`: Check whether `token_id`, `token_hash`, or any ancestor hash in `ancestor_hashes`
    /// appears in the `revoked_tokens` CRL.
    pub fn is_token_revoked_with_lineage(
        &self,
        token_id: &str,
        token_hash: &str,
        ancestor_hashes: &[String],
    ) -> Result<Option<String>> {
        let direct: Option<String> = self
            .conn
            .query_row(
                "SELECT reason FROM revoked_tokens WHERE token_id = ?1 OR token_hash = ?2 OR token_id = ?2 LIMIT 1",
                params![token_id, token_hash],
                |r| r.get(0),
            )
            .optional()?;

        if let Some(reason) = direct {
            return Ok(Some(format!(
                "Token '{token_id}' is revoked in CRL: {reason}"
            )));
        }

        for ancestor_hash in ancestor_hashes {
            let anc_revoked: Option<String> = self
                .conn
                .query_row(
                    "SELECT reason FROM revoked_tokens WHERE token_hash = ?1 OR token_id = ?1 LIMIT 1",
                    params![ancestor_hash],
                    |r| r.get(0),
                )
                .optional()?;

            if let Some(reason) = anc_revoked {
                return Ok(Some(format!(
                    "Ancestor token '{ancestor_hash}' is revoked in CRL (cascade revocation): {reason}"
                )));
            }
        }

        Ok(None)
    }

    /// Check whether `token_id`, `token_hash`, or `parent_token_hash` (cascade revocation) appears
    /// in the `revoked_tokens` CRL (`WP-4`). Kept for compatibility with 1-hop callers.
    pub fn is_token_revoked(
        &self,
        token_id: &str,
        token_hash: &str,
        parent_token_hash: Option<&str>,
    ) -> Result<Option<String>> {
        let ancestors: Vec<String> = parent_token_hash
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();
        self.is_token_revoked_with_lineage(token_id, token_hash, &ancestors)
    }

    /// `[CODEX-P1-04]`: Cross-process sliding-window rate-limit check backed by `signet.db`
    /// (`rate_limit_events`). Enforces `claims.max_calls_per_minute` across `token_id` and every
    /// ancestor in `claims.all_ancestor_hashes()` atomically inside `BEGIN IMMEDIATE`.
    pub fn check_and_record_persistent_rate_limit(
        &self,
        claims: &CapabilityClaims,
    ) -> Result<bool> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .context("failed to start BEGIN IMMEDIATE transaction for rate limit")?;

        let now_ms = Utc::now().timestamp_millis();
        let cutoff_ms = now_ms - 60_000;

        tx.execute(
            "DELETE FROM rate_limit_events WHERE ts_unix_ms < ?1",
            params![cutoff_ms],
        )?;

        let mut buckets = vec![format!("token:{}", claims.token_id)];
        for anc in claims.all_ancestor_hashes() {
            buckets.push(format!("ancestor:{anc}"));
        }

        let limit = i64::from(claims.max_calls_per_minute);
        for b in &buckets {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM rate_limit_events WHERE bucket_key = ?1 AND ts_unix_ms >= ?2",
                params![b, cutoff_ms],
                |r| r.get(0),
            )?;
            if count >= limit {
                tx.commit()?;
                return Ok(false);
            }
        }

        for b in &buckets {
            tx.execute(
                "INSERT INTO rate_limit_events (bucket_key, ts_unix_ms) VALUES (?1, ?2)",
                params![b, now_ms],
            )?;
        }

        tx.commit()?;
        Ok(true)
    }

    /// List all revoked capability tokens in chronological order.
    pub fn list_revoked_tokens(&self) -> Result<Vec<RevokedTokenRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT token_id, token_hash, revoked_at, reason
             FROM revoked_tokens ORDER BY revoked_at DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(RevokedTokenRecord {
                token_id: r.get(0)?,
                token_hash: r.get(1)?,
                revoked_at: r.get(2)?,
                reason: r.get(3)?,
            });
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_entry_hash(
        seq: i64,
        timestamp: &str,
        subject: &str,
        token_id: &str,
        tool_name: &str,
        args_blake3: &str,
        decision: &str,
        reason: &str,
        prev_hash: &str,
    ) -> String {
        let seq_bytes = seq.to_le_bytes();
        blake3_domain_hex(
            "signet-v1-merkle-node",
            &[
                &seq_bytes,
                timestamp.as_bytes(),
                subject.as_bytes(),
                token_id.as_bytes(),
                tool_name.as_bytes(),
                args_blake3.as_bytes(),
                decision.as_bytes(),
                reason.as_bytes(),
                prev_hash.as_bytes(),
            ],
        )
    }
}

/// Resolve the default `SigNET` SQLite ledger path (`%APPDATA%\signet\signet.db` or `~/.local/share/signet/signet.db`).
pub fn default_ledger_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("SIGNET_DB_PATH") {
        return PathBuf::from(override_path);
    }
    let base = dirs::data_local_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("signet").join("signet.db")
}

/// `[CODEX-P0-03]`: Enforce owner-only ACLs on the vault directory, `db_path`, and SQLite WAL
/// sidecar files (`-wal` and `-shm`) if present on disk.
pub fn enforce_vault_and_sidecar_acls(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
        && parent.exists()
    {
        enforce_owner_only_acl(parent, true)?;
    }
    if db_path.exists() {
        enforce_owner_only_acl(db_path, false)?;
    }

    let db_os = db_path.as_os_str();
    for suffix in ["-wal", "-shm"] {
        let mut sidecar_os = db_os.to_os_string();
        sidecar_os.push(suffix);
        let sidecar_path = PathBuf::from(sidecar_os);
        if sidecar_path.exists() {
            enforce_owner_only_acl(&sidecar_path, false)?;
        }
    }
    Ok(())
}

/// `[CODEX-P0-03]`: Enforce strict owner-only filesystem ACLs (`icacls /inheritance:r` on Windows,
/// `0700`/`0600` on Unix) and fail closed if permission application fails!
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set mode {:o} on {}", mode, path.display()))?;
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(anyhow!(
                "effective Unix mode {:o} != expected {:o} on {}",
                applied,
                mode,
                path.display()
            ));
        }
    }

    #[cfg(windows)]
    {
        let principal = resolve_windows_owner_principal()?;
        let grant_spec = if is_dir {
            format!("{principal}:(OI)(CI)F")
        } else {
            format!("{principal}:F")
        };
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant_spec)
            .output()
            .with_context(|| format!("failed to execute icacls on {}", path.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "icacls failed to enforce owner-only ACL on {} (status={}): {} {}",
                path.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn resolve_windows_owner_principal() -> Result<String> {
    if let Ok(out) = std::process::Command::new("whoami").output()
        && out.status.success()
    {
        let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !who.is_empty() {
            return Ok(who);
        }
    }
    if let Ok(username) = std::env::var("USERNAME") {
        let trimmed = username.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(anyhow!(
        "Unable to resolve Windows owner principal via `whoami` or `USERNAME` for ACL enforcement"
    ))
}
