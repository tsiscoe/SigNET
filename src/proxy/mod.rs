//! JSON-RPC 2.0 MCP Stdio Interceptor & Line-Frame Firewall (`signet proxy`).
//!
//! Hardened in **SigNET v0.4.0** (`WP-1..4` + `[SEC-01..05]` + `WP-CODEX-1,4,6,7`):
//! - **`[CODEX-P0-01]` (Per-Call Expiry & Multi-Generation CRL):** Evaluates live expiration and
//!   full ancestor lineage revocation (`ledger.is_capability_revoked`) on every `tools/call`.
//! - **`[CODEX-P1-01]` (Cancel-Safe `CancelSafeLineReader` & Bounded I/O):** Preserves partial
//!   chunk state across cancelled `tokio::select!` polls, enforces a 10-second write timeout,
//!   and guarantees child termination + reap (`kill` + `wait`) on every exit path.
//! - **`[CODEX-P1-03]` (Atomic Catalog Pinning):** Scans and verifies all tools in a `tools/list`
//!   frame before committing any pins atomically in one `BEGIN IMMEDIATE` transaction.
//! - **`[CODEX-P1-04]` (Default-Deny Child Environment & Persistent SQLite Quotas):** Clears the
//!   child environment (`env_clear`) and restores only safe OS baseline variables (`SAFE_OS_ENV_ALLOWLIST`)
//!   plus explicit `--pass-env` keys, while enforcing cross-process SQLite rate-limit quotas.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};

use crate::crypto::token::VerifiedCapability;
use crate::ledger::SignetLedger;
use crate::policy::{
    PolicyDecision, PolicyEvaluator,
    pin::{McpToolDefinition, compute_tool_schema_blake3, scan_tool_for_poisoning},
};

/// Maximum permitted JSON-RPC 2.0 line frame size (4 MiB) to prevent OOM DoS (`WP-3` / `CWE-770`).
pub const MAX_JSONRPC_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum permitted JSON nesting depth (`[SEC-02]`).
pub const MAX_JSON_DEPTH: usize = 64;
/// Maximum duration allowed for a single stdio frame write + flush (`[CODEX-P1-01]`).
pub const MAX_STDIO_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Environment variables unconditionally scrubbed before spawning a child MCP server (`[SEC-01]`).
pub const SCRUBBED_ENV_KEYS: &[&str] = &[
    "SIGNET_PASSPHRASE",
    "SIGNET_TOKEN",
    "SIGNET_DB_PATH",
    "LOOM_PASSPHRASE",
    "LOOM_DB_PATH",
    "FARADAY_PASSPHRASE",
    "FARADAY_DB_PATH",
    "VAULT_PASSPHRASE",
    "VAULT_DB_PATH",
];

/// Safe baseline OS environment variables permitted through the default-deny child environment filter (`[CODEX-P1-04]`).
pub const SAFE_OS_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "TZ",
    "RUST_LOG",
    "RUST_BACKTRACE",
];

/// Outcome of inspecting a single client -> server JSON-RPC message or batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrameAction {
    /// Forward the canonicalized JSON-RPC line to the child MCP server.
    Forward(String),
    /// Block the request and return this JSON-RPC error response directly to the client.
    RejectWithJsonRpcError(String),
}

/// Result of reading a single bounded line from an async stream (`WP-3` + `[CODEX-P1-01]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedLineResult {
    /// Complete line within `max_bytes`.
    Line(String),
    /// Line exceeded `max_bytes` and was drained/discarded without unbounded heap growth.
    Oversized { max_bytes: usize },
    /// Clean EOF reached.
    Eof,
}

/// `[CODEX-P1-01]`: Cancel-safe buffered JSON-RPC line reader.
/// Stores in-progress line bytes (`buf`) and `oversized` state inside the struct rather than inside
/// an ephemeral `async fn` stack frame, so cancellation inside `tokio::select!` never loses
/// partially consumed chunks!
pub struct CancelSafeLineReader<R> {
    reader: R,
    buf: Vec<u8>,
    oversized: bool,
    max_bytes: usize,
}

impl<R> CancelSafeLineReader<R>
where
    R: AsyncBufRead + Unpin,
{
    pub fn new(reader: R, max_bytes: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            oversized: false,
            max_bytes,
        }
    }

    /// Read the next `\n`-delimited frame. Fully cancel-safe across `tokio::select!` branches.
    pub async fn next_line(&mut self) -> Result<BoundedLineResult> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                if self.buf.is_empty() && !self.oversized {
                    return Ok(BoundedLineResult::Eof);
                }
                let was_oversized = std::mem::replace(&mut self.oversized, false);
                let taken = std::mem::take(&mut self.buf);
                if was_oversized {
                    return Ok(BoundedLineResult::Oversized {
                        max_bytes: self.max_bytes,
                    });
                }
                return Self::decode_frame_bytes(taken);
            }

            if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
                let chunk = &available[..newline_pos];
                if !self.oversized {
                    if self.buf.len() + chunk.len() > self.max_bytes {
                        self.oversized = true;
                        self.buf.clear();
                    } else {
                        self.buf.extend_from_slice(chunk);
                    }
                }
                self.reader.consume(newline_pos + 1);
                let was_oversized = std::mem::replace(&mut self.oversized, false);
                let taken = std::mem::take(&mut self.buf);
                if was_oversized {
                    return Ok(BoundedLineResult::Oversized {
                        max_bytes: self.max_bytes,
                    });
                }
                return Self::decode_frame_bytes(taken);
            } else {
                let chunk_len = available.len();
                if !self.oversized {
                    if self.buf.len() + chunk_len > self.max_bytes {
                        self.oversized = true;
                        self.buf.clear();
                    } else {
                        self.buf.extend_from_slice(available);
                    }
                }
                self.reader.consume(chunk_len);
            }
        }
    }

    fn decode_frame_bytes(mut buf: Vec<u8>) -> Result<BoundedLineResult> {
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        let line = String::from_utf8(buf).context("JSON-RPC frame is not valid UTF-8")?;
        Ok(BoundedLineResult::Line(line))
    }
}

/// Parse a JSON string into a [`serde_json::Value`] while strictly rejecting any object containing
/// duplicate keys (`[SEC-02]` / `CWE-436`) and enforcing [`MAX_JSON_DEPTH`].
pub fn parse_strict_json_no_dup_keys(raw: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let seed = StrictValueSeed { depth: 0 };
    let val = seed
        .deserialize(&mut deserializer)
        .map_err(|e| anyhow!("Strict JSON validation failed: {e}"))?;
    deserializer
        .end()
        .map_err(|e| anyhow!("Trailing data after JSON root: {e}"))?;
    Ok(val)
}

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom(format!(
                "JSON nesting depth exceeds maximum allowed ({MAX_JSON_DEPTH})"
            )));
        }
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> std::result::Result<Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite float in JSON"))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec = Vec::new();
        while let Some(elem) = seq.next_element_seed(StrictValueSeed {
            depth: self.depth + 1,
        })? {
            vec.push(elem);
        }
        Ok(Value::Array(vec))
    }

    fn visit_map<A>(self, mut map_access: A) -> std::result::Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map_access.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "Duplicate JSON object key '{key}' rejected (CWE-436 parser-differential protection)"
                )));
            }
            let val = map_access.next_value_seed(StrictValueSeed {
                depth: self.depth + 1,
            })?;
            map.insert(key, val);
        }
        Ok(Value::Object(map))
    }
}

/// Read a single `\n`-delimited line from `reader` with a hard byte ceiling `max_bytes` (`WP-3`).
/// For multi-branch `tokio::select!` loops, use [`CancelSafeLineReader`] directly.
pub async fn read_bounded_jsonrpc_line<R>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<BoundedLineResult>
where
    R: AsyncBufRead + Unpin,
{
    let mut cancel_safe = CancelSafeLineReader::new(reader, max_bytes);
    cancel_safe.next_line().await
}

/// Inspect a single client -> server JSON-RPC line (`Value::Object` or `Value::Array` batch).
/// Enforces strict duplicate-key rejection (`[SEC-02]`), full-lineage CRL revocation (`[CODEX-P0-01]`),
/// per-call expiry (`[CODEX-P0-01]`), cross-process SQLite rate limits (`[CODEX-P1-04]`), and
/// canonical re-serialization (`[SEC-02]`).
pub fn process_client_jsonrpc_line(
    ledger: &SignetLedger,
    evaluator: &PolicyEvaluator,
    capability: &VerifiedCapability,
    line: &str,
) -> Result<ClientFrameAction> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(ClientFrameAction::Forward(String::new()));
    }

    // [SEC-02]: Enforce strict JSON parsing (no duplicate keys, depth <= 64).
    let msg = match parse_strict_json_no_dup_keys(trimmed) {
        Ok(v) => v,
        Err(strict_err) => {
            let receipt = ledger.append_audit_event(
                &capability.claims.subject,
                &capability.claims.token_id,
                "jsonrpc::strict_parse_guard",
                trimmed,
                "DENY",
                &strict_err.to_string(),
            )?;
            let err_resp = json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {
                    "code": -32600,
                    "message": format!("SigNET Strict JSON Guard Blocked Frame: {strict_err}"),
                    "data": {
                        "merkle_seq": receipt.seq,
                        "entry_hash": receipt.entry_hash,
                        "ed25519_sig": receipt.ed25519_sig
                    }
                }
            });
            return Ok(ClientFrameAction::RejectWithJsonRpcError(
                serde_json::to_string(&err_resp)?,
            ));
        }
    };

    // [SEC-02]: Re-serialize canonical JSON from the validated AST so downstream MCP servers
    // never see raw lexer tricks or whitespace/unicode ambiguities!
    let canonical_line = serde_json::to_string(&msg)?;

    match &msg {
        Value::Object(_) => {
            evaluate_single_jsonrpc_object(ledger, evaluator, capability, &msg, &canonical_line)
        }
        Value::Array(batch) => {
            if batch.is_empty() {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32600,
                        "message": "SigNET Capability Firewall Blocked empty JSON-RPC batch array"
                    }
                });
                return Ok(ClientFrameAction::RejectWithJsonRpcError(
                    serde_json::to_string(&err_resp)?,
                ));
            }

            // WP-1: Inspect every element in the JSON-RPC 2.0 batch array.
            for item in batch {
                if !item.is_object() {
                    let receipt = ledger.append_audit_event(
                        &capability.claims.subject,
                        &capability.claims.token_id,
                        "jsonrpc::batch_malformed",
                        trimmed,
                        "DENY",
                        "Malformed non-object element inside JSON-RPC batch array",
                    )?;
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {
                            "code": -32600,
                            "message": "SigNET Capability Firewall Blocked malformed JSON-RPC batch element",
                            "data": {
                                "merkle_seq": receipt.seq,
                                "entry_hash": receipt.entry_hash,
                                "ed25519_sig": receipt.ed25519_sig
                            }
                        }
                    });
                    return Ok(ClientFrameAction::RejectWithJsonRpcError(
                        serde_json::to_string(&err_resp)?,
                    ));
                }

                if let ClientFrameAction::RejectWithJsonRpcError(err_json) =
                    evaluate_single_jsonrpc_object(
                        ledger,
                        evaluator,
                        capability,
                        item,
                        &canonical_line,
                    )?
                {
                    return Ok(ClientFrameAction::RejectWithJsonRpcError(err_json));
                }
            }

            Ok(ClientFrameAction::Forward(canonical_line))
        }
        _ => Ok(ClientFrameAction::Forward(canonical_line)),
    }
}

fn evaluate_single_jsonrpc_object(
    ledger: &SignetLedger,
    evaluator: &PolicyEvaluator,
    capability: &VerifiedCapability,
    msg: &Value,
    canonical_line: &str,
) -> Result<ClientFrameAction> {
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method != "tools/call" {
        return Ok(ClientFrameAction::Forward(canonical_line.to_string()));
    }

    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown_tool");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let args_str = serde_json::to_string(&arguments).unwrap_or_else(|_| "{}".to_string());

    // [CODEX-P0-01]: Check Cryptographic Token Revocation List (CRL) across the ENTIRE ancestor lineage!
    if let Some(revoked_reason) = ledger.is_capability_revoked(capability)? {
        let receipt = ledger.append_audit_event(
            &capability.claims.subject,
            &capability.claims.token_id,
            tool_name,
            &args_str,
            "DENY",
            &revoked_reason,
        )?;
        let err_resp = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32001,
                "message": format!("SigNET Capability Firewall Blocked '{}': {}", tool_name, revoked_reason),
                "data": {
                    "merkle_seq": receipt.seq,
                    "entry_hash": receipt.entry_hash,
                    "ed25519_sig": receipt.ed25519_sig
                }
            }
        });
        return Ok(ClientFrameAction::RejectWithJsonRpcError(
            serde_json::to_string(&err_resp)?,
        ));
    }

    // [CODEX-P1-04]: Check cross-process persistent SQLite rate-limit quota across the full lineage
    if !ledger.check_and_record_persistent_rate_limit(&capability.claims)? {
        let reason = format!(
            "Rate limit exceeded in persistent ledger for token '{}' (or ancestor lineage): max {} calls/min",
            capability.claims.token_id, capability.claims.max_calls_per_minute
        );
        let receipt = ledger.append_audit_event(
            &capability.claims.subject,
            &capability.claims.token_id,
            tool_name,
            &args_str,
            "DENY",
            &reason,
        )?;
        let err_resp = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32001,
                "message": format!("SigNET Capability Firewall Blocked '{}': {}", tool_name, reason),
                "data": {
                    "merkle_seq": receipt.seq,
                    "entry_hash": receipt.entry_hash,
                    "ed25519_sig": receipt.ed25519_sig
                }
            }
        });
        return Ok(ClientFrameAction::RejectWithJsonRpcError(
            serde_json::to_string(&err_resp)?,
        ));
    }

    let decision = evaluator.evaluate_tool_call(&capability.claims, tool_name, &arguments);
    let receipt = ledger.append_audit_event(
        &capability.claims.subject,
        &capability.claims.token_id,
        tool_name,
        &args_str,
        decision.code_str(),
        decision.reason(),
    )?;

    match decision {
        PolicyDecision::Allow { .. } => Ok(ClientFrameAction::Forward(canonical_line.to_string())),
        PolicyDecision::Deny { reason } => {
            let err_resp = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": format!("SigNET Capability Firewall Blocked '{}': {}", tool_name, reason),
                    "data": {
                        "merkle_seq": receipt.seq,
                        "entry_hash": receipt.entry_hash,
                        "ed25519_sig": receipt.ed25519_sig
                    }
                }
            });
            Ok(ClientFrameAction::RejectWithJsonRpcError(
                serde_json::to_string(&err_resp)?,
            ))
        }
    }
}

/// Inspect a `tools/list` result payload (single object or batch array) from an MCP server,
/// enforcing strict duplicate-key parsing (`[SEC-02]`), full-metadata `BLAKE3` schema pins,
/// atomic catalog commit (`[CODEX-P1-03]`), and `[SIG-02]` prompt-injection scanning (`[SEC-05]`).
pub fn verify_server_tools_list_payload(
    ledger: &SignetLedger,
    server_name: &str,
    jsonrpc_response: &str,
) -> Result<usize> {
    verify_server_tools_list_payload_with_mode(ledger, server_name, jsonrpc_response, false)
}

/// Variant of [`verify_server_tools_list_payload`] supporting `strict_pins` mode (`[CODEX-P1-03]`).
pub fn verify_server_tools_list_payload_with_mode(
    ledger: &SignetLedger,
    server_name: &str,
    jsonrpc_response: &str,
    strict_pins: bool,
) -> Result<usize> {
    let trimmed = jsonrpc_response.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    let msg = parse_strict_json_no_dup_keys(trimmed)
        .context("invalid or duplicate-key JSON-RPC response from MCP server")?;

    let mut total_verified = 0usize;
    match &msg {
        Value::Object(_) => {
            total_verified +=
                verify_single_tools_list_object(ledger, server_name, &msg, strict_pins)?;
        }
        Value::Array(items) => {
            for item in items {
                total_verified +=
                    verify_single_tools_list_object(ledger, server_name, item, strict_pins)?;
            }
        }
        _ => {}
    }

    Ok(total_verified)
}

fn verify_single_tools_list_object(
    ledger: &SignetLedger,
    server_name: &str,
    msg: &Value,
    strict_pins: bool,
) -> Result<usize> {
    let Some(tools_val) = msg.pointer("/result/tools") else {
        return Ok(0);
    };

    let tools: Vec<McpToolDefinition> = serde_json::from_value(tools_val.clone())
        .context("failed to parse MCP result.tools array")?;

    // [CODEX-P1-03]: Phase 1 — Scan EVERY tool in the catalog for poisoning and compute its
    // full-metadata BLAKE3 digest BEFORE touching SQLite so a poisoned later tool never leaves
    // earlier tools committed!
    let mut catalog_hashes: Vec<(String, String)> = Vec::with_capacity(tools.len());
    for tool in &tools {
        if let Err(poison_err) = scan_tool_for_poisoning(tool) {
            let _ = ledger.append_audit_event(
                server_name,
                "mcp-schema-guard",
                &tool.name,
                &tool.description,
                "DENY",
                &poison_err.to_string(),
            );
            return Err(poison_err);
        }

        let schema_hash = compute_tool_schema_blake3(server_name, tool)?;
        catalog_hashes.push((tool.name.clone(), schema_hash));
    }

    // [CODEX-P1-03]: Phase 2 — Verify and commit the entire catalog atomically inside one
    // BEGIN IMMEDIATE transaction!
    if let Err(rug_err) =
        ledger.verify_or_pin_tool_catalog_atomic(server_name, &catalog_hashes, strict_pins)
    {
        let _ = ledger.append_audit_event(
            server_name,
            "mcp-schema-guard",
            "tools/list",
            "catalog_atomic_pin",
            "DENY",
            &rug_err.to_string(),
        );
        return Err(rug_err);
    }

    Ok(tools.len())
}

/// Return `true` if an environment variable name matches known secret/credential patterns (`[SEC-01]` + `[CODEX-P1-04]`).
pub fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.trim().to_ascii_uppercase();
    if SCRUBBED_ENV_KEYS
        .iter()
        .any(|&k| k.eq_ignore_ascii_case(&upper))
    {
        return true;
    }

    const SECRET_PREFIXES: &[&str] = &[
        "SIGNET_",
        "LOOM_",
        "FARADAY_",
        "VAULT_",
        "OPENAI_",
        "ANTHROPIC_",
        "CLAUDE_",
        "GEMINI_",
        "GOOGLE_API_",
        "AWS_",
        "AZURE_",
        "GITHUB_",
        "GH_",
        "GITLAB_",
        "SLACK_",
        "STRIPE_",
        "HF_",
        "HUGGINGFACE_",
    ];
    if SECRET_PREFIXES.iter().any(|pref| upper.starts_with(pref)) {
        return true;
    }

    const SECRET_SUFFIXES: &[&str] = &[
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSPHRASE",
        "_CREDENTIAL",
        "_CREDENTIALS",
        "_PRIVATE_KEY",
        "_PAT",
    ];
    SECRET_SUFFIXES.iter().any(|suf| upper.ends_with(suf))
}

/// Compute the list of environment variable names that must be stripped before spawning an
/// untrusted child MCP server (`[SEC-01]` + `[CODEX-P1-04]`).
pub fn compute_scrubbed_env_keys<I, K>(env_keys: I) -> Vec<String>
where
    I: IntoIterator<Item = K>,
    K: AsRef<str>,
{
    let mut to_remove: Vec<String> = SCRUBBED_ENV_KEYS.iter().map(|&s| s.to_string()).collect();

    for k in env_keys {
        let key_str = k.as_ref();
        if is_sensitive_env_key(key_str) && !to_remove.contains(&key_str.to_string()) {
            to_remove.push(key_str.to_string());
        }
    }
    to_remove
}

/// Build a sanitized `tokio::process::Command` using a default-deny `env_clear()` baseline that
/// preserves only [`SAFE_OS_ENV_ALLOWLIST`] (minus any [`is_sensitive_env_key`]) plus explicit
/// operator-approved `pass_env` variable names (`[SEC-01]` + `[CODEX-P1-04]`).
pub fn build_sanitized_child_command(command_args: &[String]) -> Command {
    build_sanitized_child_command_with_allowlist(command_args, &[])
}

/// Build a sanitized `tokio::process::Command` with explicit operator `--pass-env` overrides (`[CODEX-P1-04]`).
pub fn build_sanitized_child_command_with_allowlist(
    command_args: &[String],
    pass_env: &[String],
) -> Command {
    let mut cmd = Command::new(&command_args[0]);
    cmd.args(&command_args[1..]);
    cmd.env_clear();
    cmd.kill_on_drop(true);

    for (k_os, v_os) in std::env::vars_os() {
        let Some(k_str) = k_os.to_str() else {
            continue;
        };
        let explicitly_passed = pass_env.iter().any(|p| p.eq_ignore_ascii_case(k_str));
        let in_safe_os_baseline = SAFE_OS_ENV_ALLOWLIST
            .iter()
            .any(|s| s.eq_ignore_ascii_case(k_str));

        // Never pass SIGNET_PASSPHRASE/SIGNET_TOKEN even if mistakenly requested; allow safe OS vars
        // or explicit operator `--pass-env` vars.
        let is_signet_internal = SCRUBBED_ENV_KEYS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(k_str))
            || k_str.to_ascii_uppercase().starts_with("SIGNET_");

        if !is_signet_internal
            && (explicitly_passed || (in_safe_os_baseline && !is_sensitive_env_key(k_str)))
        {
            cmd.env(k_os, v_os);
        }
    }

    cmd
}

async fn write_line_with_timeout<W>(writer: &mut W, line: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(MAX_STDIO_WRITE_TIMEOUT, async {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| {
        anyhow!(
            "Stdio frame write timed out after {:?}",
            MAX_STDIO_WRITE_TIMEOUT
        )
    })?
    .context("Stdio frame write failed")
}

/// Run the asynchronous stdio proxy wrapping a child MCP server command with 4 MiB cancel-safe
/// frame bounds (`WP-3` + `[CODEX-P1-01]`), default-deny child environment (`[CODEX-P1-04]`),
/// and unconditional atomic server frame inspection (`[SEC-05]` + `[CODEX-P1-03]`).
pub async fn run_stdio_proxy(
    ledger: &SignetLedger,
    capability: &VerifiedCapability,
    server_name: &str,
    command_args: &[String],
) -> Result<()> {
    run_stdio_proxy_with_options(ledger, capability, server_name, command_args, &[], false).await
}

/// Run the asynchronous stdio proxy with explicit `--pass-env` and `--strict-pins` options (`[CODEX-P1-03..04]`).
pub async fn run_stdio_proxy_with_options(
    ledger: &SignetLedger,
    capability: &VerifiedCapability,
    server_name: &str,
    command_args: &[String],
    pass_env: &[String],
    strict_pins: bool,
) -> Result<()> {
    if command_args.is_empty() {
        return Err(anyhow!("No child MCP server command specified after '--'"));
    }

    let mut child = build_sanitized_child_command_with_allowlist(command_args, pass_env)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn child MCP server '{}'", command_args[0]))?;

    let mut child_stdin = child.stdin.take().expect("piped stdin");
    let child_stdout = child.stdout.take().expect("piped stdout");

    let mut host_line_reader =
        CancelSafeLineReader::new(BufReader::new(tokio::io::stdin()), MAX_JSONRPC_LINE_BYTES);
    let mut child_line_reader =
        CancelSafeLineReader::new(BufReader::new(child_stdout), MAX_JSONRPC_LINE_BYTES);
    let mut host_stdout = tokio::io::stdout();

    let evaluator = PolicyEvaluator::new();

    let proxy_res: Result<()> = async {
        loop {
            tokio::select! {
                host_res = host_line_reader.next_line() => {
                    match host_res? {
                        BoundedLineResult::Line(line) => {
                            match process_client_jsonrpc_line(ledger, &evaluator, capability, &line)? {
                                ClientFrameAction::Forward(fwd) => {
                                    if !fwd.is_empty() {
                                        write_line_with_timeout(&mut child_stdin, &fwd).await?;
                                    }
                                }
                                ClientFrameAction::RejectWithJsonRpcError(err_json) => {
                                    write_line_with_timeout(&mut host_stdout, &err_json).await?;
                                }
                            }
                        }
                        BoundedLineResult::Oversized { max_bytes } => {
                            let receipt = ledger.append_audit_event(
                                &capability.claims.subject,
                                &capability.claims.token_id,
                                "jsonrpc::oversized_frame",
                                "oversized_client_frame",
                                "DENY",
                                &format!("Client JSON-RPC frame exceeded {max_bytes} bytes limit"),
                            )?;
                            let err_resp = json!({
                                "jsonrpc": "2.0",
                                "id": Value::Null,
                                "error": {
                                    "code": -32600,
                                    "message": format!("SigNET Frame Firewall: JSON-RPC line exceeds {max_bytes} bytes limit"),
                                    "data": {
                                        "merkle_seq": receipt.seq,
                                        "entry_hash": receipt.entry_hash,
                                        "ed25519_sig": receipt.ed25519_sig
                                    }
                                }
                            });
                            let err_str = serde_json::to_string(&err_resp)?;
                            write_line_with_timeout(&mut host_stdout, &err_str).await?;
                        }
                        BoundedLineResult::Eof => break,
                    }
                }
                srv_res = child_line_reader.next_line() => {
                    match srv_res? {
                        BoundedLineResult::Line(line) => {
                            // [SEC-05] + [CODEX-P1-03]: Unconditionally inspect server JSON-RPC response frames
                            // with full-metadata BLAKE3 pinning and atomic catalog transactions.
                            verify_server_tools_list_payload_with_mode(
                                ledger,
                                server_name,
                                &line,
                                strict_pins,
                            )?;
                            write_line_with_timeout(&mut host_stdout, &line).await?;
                        }
                        BoundedLineResult::Oversized { max_bytes } => {
                            let _ = ledger.append_audit_event(
                                server_name,
                                "mcp-schema-guard",
                                "jsonrpc::oversized_server_frame",
                                "oversized_server_frame",
                                "DENY",
                                &format!("Server JSON-RPC frame exceeded {max_bytes} bytes limit"),
                            );
                            return Err(anyhow!(
                                "MCP server '{server_name}' sent oversized JSON-RPC frame exceeding {max_bytes} bytes"
                            ));
                        }
                        BoundedLineResult::Eof => break,
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    // [CODEX-P1-01]: Guaranteed child termination and process reaping on EVERY exit path (Ok or Err)
    drop(child_stdin);
    let _ = child.kill().await;
    let _ = child.wait().await;

    proxy_res
}
