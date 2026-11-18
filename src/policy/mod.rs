//! Capability Firewall Policy Engine: evaluates `tools/call` requests against [`CapabilityClaims`],
//! live per-call expiration (`[CODEX-P0-01]`), unified safe path subset containment (`[CODEX-P0-02]`),
//! regex deny-lists (`WP-6`), and full-lineage Sybil-resistant sliding-window rate limits
//! (`[SEC-04]` + `[CODEX-P0-01]`).

pub mod pin;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Utc;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::token::CapabilityClaims;

/// Outcome of evaluating a single MCP tool call against a [`CapabilityClaims`] grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow { reason: String },
    Deny { reason: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn code_str(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "ALLOW",
            Self::Deny { .. } => "DENY",
        }
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::Allow { reason } | Self::Deny { reason } => reason,
        }
    }
}

/// Stateful firewall evaluator tracking per-token and full-lineage sliding-window invocation timestamps.
pub struct PolicyEvaluator {
    rate_windows: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self {
            rate_windows: Mutex::new(HashMap::new()),
        }
    }

    /// Evaluate whether `tool_name` with `args` is permitted under `claims`.
    /// Enforces per-call live expiration (`[CODEX-P0-01]`), full ancestor lineage quotas (`[CODEX-P0-01]`),
    /// and unified segment-boundary + symlink-resolved path containment (`[CODEX-P0-02]`).
    pub fn evaluate_tool_call(
        &self,
        claims: &CapabilityClaims,
        tool_name: &str,
        args: &Value,
    ) -> PolicyDecision {
        // 0. [CODEX-P0-01]: Enforce live clock expiration on EVERY tool call (not only at proxy startup)
        let now_unix = Utc::now().timestamp();
        if claims.issued_at_unix > claims.expires_at_unix || now_unix > claims.expires_at_unix {
            return PolicyDecision::Deny {
                reason: format!(
                    "Capability token '{}' expired at unix={} (now={now_unix})",
                    claims.token_id, claims.expires_at_unix
                ),
            };
        }

        // 1. Explicit deny_tools check (always takes precedence)
        if claims.deny_tools.iter().any(|d| d == tool_name || d == "*") {
            return PolicyDecision::Deny {
                reason: format!(
                    "Tool '{tool_name}' is explicitly denied by capability token '{}'",
                    claims.token_id
                ),
            };
        }

        // 2. Explicit allow_tools check
        let is_allowed_tool = claims
            .allow_tools
            .iter()
            .any(|a| a == "*" || a == tool_name);
        if !is_allowed_tool {
            return PolicyDecision::Deny {
                reason: format!(
                    "Tool '{tool_name}' is not in allow_tools {:?} for subject '{}'",
                    claims.allow_tools, claims.subject
                ),
            };
        }

        // 3. Sliding-window rate limit check (60-second window, bound to token_id AND all ancestors [CODEX-P0-01])
        let ancestors = claims.all_ancestor_hashes();
        if !self.check_and_record_rate_limit(
            &claims.token_id,
            &ancestors,
            claims.max_calls_per_minute,
        ) {
            return PolicyDecision::Deny {
                reason: format!(
                    "Rate limit exceeded for token '{}' (or ancestor lineage): max {} calls/min",
                    claims.token_id, claims.max_calls_per_minute
                ),
            };
        }

        // 4. Deep JSON argument inspection (WP-2 + [SEC-03] + [CODEX-P0-02]: unified canonicalization,
        //    8-round percent-decoded traversal, null-byte, Unicode dot, Windows UNC/device namespace,
        //    NTFS ADS, DOS reserved names, file:// URI stripping, segment-boundary allowed_paths containment,
        //    and host symlink/junction resolution when paths exist on disk)
        let mut string_leaves = Vec::new();
        collect_json_strings(args, &mut string_leaves);

        for (key_hint, val_str) in &string_leaves {
            let decoded = match canonicalize_and_validate_policy_path(val_str) {
                Ok(d) => d,
                Err(anomaly) => {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "Argument '{key_hint}' rejected by path safety guard: {anomaly} ('{val_str}')"
                        ),
                    };
                }
            };

            if !claims.allowed_paths.is_empty()
                && looks_like_path_arg(key_hint, val_str, &decoded)
                && let Err(subset_err) = verify_safe_path_subset(val_str, &claims.allowed_paths)
            {
                return PolicyDecision::Deny {
                    reason: format!(
                        "Argument '{key_hint}' path '{val_str}' (canonical: '{decoded}') is outside allowed_paths {:?}: {subset_err}",
                        claims.allowed_paths
                    ),
                };
            }
        }

        // 5. Denied argument regex patterns check (WP-6: bounded DFA size limit to prevent ReDoS)
        let serialized_args = args.to_string();
        for pat_str in &claims.denied_arg_patterns {
            match RegexBuilder::new(pat_str)
                .size_limit(256 * 1024)
                .dfa_size_limit(256 * 1024)
                .build()
            {
                Ok(re) => {
                    if re.is_match(&serialized_args) {
                        return PolicyDecision::Deny {
                            reason: format!("Arguments matched denied pattern '{pat_str}'"),
                        };
                    }
                }
                Err(_) => {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "Denied pattern '{pat_str}' failed bounded regex compilation (fail-closed)"
                        ),
                    };
                }
            }
        }

        PolicyDecision::Allow {
            reason: format!(
                "Permitted by capability token '{}' (subject='{}')",
                claims.token_id, claims.subject
            ),
        }
    }

    fn check_and_record_rate_limit(
        &self,
        token_id: &str,
        ancestor_hashes: &[String],
        max_rpm: u32,
    ) -> bool {
        let mut guard = self.rate_windows.lock().expect("rate_windows mutex");
        let now = Instant::now();
        let window = Duration::from_secs(60);

        // WP-6: Garbage-collect expired token vectors so rate_windows never grows unboundedly
        guard.retain(|_, timestamps| {
            timestamps.retain(|&ts| now.duration_since(ts) < window);
            !timestamps.is_empty()
        });

        let token_count = guard.get(token_id).map_or(0, Vec::len);
        if token_count >= max_rpm as usize {
            return false;
        }

        // [SEC-04] + [CODEX-P0-01]: Check every ancestor bucket in the full delegation chain
        // BEFORE recording timestamps so a rejected call does not partially charge only some ancestors.
        for anc in ancestor_hashes {
            let bucket = format!("ancestor:{anc}");
            let count = guard.get(&bucket).map_or(0, Vec::len);
            if count >= max_rpm as usize {
                return false;
            }
        }

        for anc in ancestor_hashes {
            let bucket = format!("ancestor:{anc}");
            guard.entry(bucket).or_default().push(now);
        }
        guard.entry(token_id.to_string()).or_default().push(now);
        true
    }
}

/// `[CODEX-P0-02]`: Canonicalize and validate any path or string argument against NUL bytes,
/// >8-round percent-encoding, `..` traversal, Windows UNC/device namespaces, NTFS ADS, and DOS devices.
pub fn canonicalize_and_validate_policy_path(raw: &str) -> Result<String, String> {
    let decoded = decode_and_normalize_arg(raw).map_err(str::to_string)?;

    if contains_path_traversal(raw) || contains_path_traversal(&decoded) {
        return Err("Path traversal sequence ('..') blocked".to_string());
    }

    if let Err(win_err) = check_windows_unc_ads_and_dos_devices(&decoded) {
        return Err(win_err.to_string());
    }

    Ok(decoded)
}

/// `[CODEX-P0-02]`: Unified platform-aware safe path subset relation shared across token minting,
/// token attenuation (`src/crypto/token.rs`), and runtime policy evaluation (`src/policy/mod.rs`).
/// Ensures `candidate_path` is canonical, traversal-free, and strictly inside at least one of
/// `allowed_prefixes` on a directory segment boundary (plus symlink/junction realpath check if on disk).
pub fn verify_safe_path_subset(
    candidate_path: &str,
    allowed_prefixes: &[String],
) -> Result<String, String> {
    let decoded = canonicalize_and_validate_policy_path(candidate_path)?;
    if allowed_prefixes.is_empty() {
        return Ok(decoded);
    }

    let mut matched_lexical = false;
    for prefix in allowed_prefixes {
        let canonical_prefix = canonicalize_and_validate_policy_path(prefix)?;
        if path_starts_with_segment_boundary(&decoded, &canonical_prefix) {
            matched_lexical = true;
            break;
        }
    }

    if !matched_lexical {
        return Err(format!(
            "path '{decoded}' does not match any allowed segment prefix in {allowed_prefixes:?}"
        ));
    }

    // If the candidate path (or its parent on disk) and an allowed prefix exist on the host filesystem,
    // also verify std::fs::canonicalize so symlink/NTFS junction escapes inside an allowed folder are caught!
    verify_host_realpath_if_present(&decoded, allowed_prefixes)?;

    Ok(decoded)
}

fn verify_host_realpath_if_present(
    decoded_candidate: &str,
    allowed_prefixes: &[String],
) -> Result<(), String> {
    let cand_path = Path::new(decoded_candidate);
    let resolved_cand = if cand_path.exists() {
        std::fs::canonicalize(cand_path).ok()
    } else if let Some(parent) = cand_path.parent()
        && !parent.as_os_str().is_empty()
        && parent.exists()
    {
        std::fs::canonicalize(parent).ok().map(|rp| {
            if let Some(fname) = cand_path.file_name() {
                rp.join(fname)
            } else {
                rp
            }
        })
    } else {
        None
    };

    let Some(real_cand) = resolved_cand else {
        return Ok(());
    };

    let mut existing_real_prefixes = Vec::new();
    for p in allowed_prefixes {
        let pp = Path::new(p);
        if pp.exists()
            && let Ok(rp) = std::fs::canonicalize(pp)
        {
            existing_real_prefixes.push(rp);
        }
    }

    if existing_real_prefixes.is_empty() {
        return Ok(());
    }

    let real_cand_str = real_cand.to_string_lossy();
    let covered = existing_real_prefixes.iter().any(|rp| {
        let rp_str = rp.to_string_lossy();
        path_starts_with_segment_boundary(&real_cand_str, &rp_str)
    });

    if !covered {
        return Err(format!(
            "symlink/junction realpath '{}' escapes allowed physical roots",
            real_cand.display()
        ));
    }

    Ok(())
}

fn collect_json_strings<'a>(val: &'a Value, out: &mut Vec<(String, &'a str)>) {
    walk_json("", val, out);
}

fn walk_json<'a>(key: &str, val: &'a Value, out: &mut Vec<(String, &'a str)>) {
    match val {
        Value::String(s) => out.push((key.to_string(), s.as_str())),
        Value::Array(arr) => {
            for item in arr {
                walk_json(key, item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                walk_json(k, v, out);
            }
        }
        _ => {}
    }
}

/// WP-2 + [SEC-03]: Iterative percent-decoding (up to 8 rounds, fail-closed on residual `%XX`),
/// null-byte rejection, Unicode homoglyph dot normalization, and `file://` URI scheme stripping.
fn decode_and_normalize_arg(raw: &str) -> Result<String, &'static str> {
    if raw.contains('\0') {
        return Err("embedded NUL byte detected");
    }

    // Fold Unicode homoglyph dots (U+FF0E fullwidth full stop, U+2024 one dot leader,
    // U+FE52 small full stop, U+3002 ideographic full stop) to ASCII '.' so traversal checks catch them.
    let mut current: String = raw
        .chars()
        .map(|c| match c {
            '\u{FF0E}' | '\u{2024}' | '\u{FE52}' | '\u{3002}' => '.',
            _ => c,
        })
        .collect();

    for _ in 0..8 {
        let next = percent_decode_once(&current)?;
        if next.contains('\0') {
            return Err("percent-encoded NUL byte (%00) detected");
        }
        if next == current {
            break;
        }
        current = next;
    }

    // [SEC-03]: If valid `%XX` hex sequences still remain after 8 decode rounds, reject fail-closed!
    if has_remaining_percent_hex(&current) {
        return Err("excessive nested percent-encoding (>8 layers) rejected");
    }

    let trimmed = current.trim();
    let lower = trimmed.to_ascii_lowercase();
    let without_scheme = if lower.starts_with("file://localhost/") {
        format!("/{}", &trimmed[17..])
    } else if let Some(rest) = lower.strip_prefix("file:///") {
        let raw_rest = &trimmed[8..];
        if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
            raw_rest.to_string()
        } else {
            format!("/{raw_rest}")
        }
    } else if lower.starts_with("file://") {
        trimmed[7..].to_string()
    } else {
        trimmed.to_string()
    };

    Ok(without_scheme)
}

fn has_remaining_percent_hex(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'%' && hex_val(b[i + 1]).is_some() && hex_val(b[i + 2]).is_some() {
            return true;
        }
        i += 1;
    }
    false
}

fn percent_decode_once(input: &str) -> Result<String, &'static str> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            let decoded_byte = (hi << 4) | lo;
            if decoded_byte == 0 {
                return Err("percent-encoded NUL byte (%00) detected");
            }
            out.push(decoded_byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| "invalid UTF-8 sequence in percent-encoded argument")
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// [SEC-03]: Block Windows UNC network shares (`\\server\share`, `//server/share` NTLM hash leak),
/// Win32 device namespaces (`\\?\`, `\\.\`), NTFS Alternate Data Streams (`file.txt:secret:$DATA`),
/// and Windows reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
fn check_windows_unc_ads_and_dos_devices(decoded: &str) -> Result<(), &'static str> {
    let trimmed = decoded.trim();
    if trimmed.starts_with(r"\\?\")
        || trimmed.starts_with(r"\\.\")
        || trimmed.starts_with("//")
        || trimmed.starts_with(r"\\")
    {
        return Err("Windows UNC network share or Win32 device namespace path is forbidden");
    }

    // Check for NTFS Alternate Data Streams (`:` in a path component other than a drive letter `C:` or URL scheme `http://`)
    let norm = trimmed.replace('\\', "/");
    if !norm.contains("://") && (norm.starts_with('/') || norm.contains('/')) {
        for (idx, seg) in norm.split('/').enumerate() {
            if seg.is_empty() {
                continue;
            }
            // Allow `C:` as the first segment on Windows
            if idx == 0 && seg.len() == 2 && seg.as_bytes()[1] == b':' {
                continue;
            }
            if seg.contains(':') {
                return Err("NTFS Alternate Data Stream (ADS ':') in path segment is forbidden");
            }
            let stem = seg.split('.').next().unwrap_or(seg).trim();
            if is_windows_reserved_dos_device(stem) {
                return Err("Windows reserved DOS device name (CON/NUL/COM/LPT) is forbidden");
            }
        }
    }

    Ok(())
}

fn is_windows_reserved_dos_device(stem: &str) -> bool {
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn contains_path_traversal(s: &str) -> bool {
    let norm = s.replace('\\', "/");
    if norm == ".." || norm.starts_with("../") || norm.ends_with("/..") || norm.contains("/../") {
        return true;
    }
    norm.split('/').any(|seg| seg.trim() == "..")
}

fn looks_like_path_arg(key: &str, raw_val: &str, decoded_val: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const PATH_KEYS: &[&str] = &[
        "path",
        "file",
        "dir",
        "root",
        "cwd",
        "target",
        "uri",
        "url",
        "source",
        "src",
        "dest",
        "destination",
        "location",
        "folder",
        "worktree",
        "repo",
    ];
    if PATH_KEYS.iter().any(|pk| k.contains(pk)) {
        return true;
    }

    for v in [raw_val, decoded_val] {
        if v.starts_with('/')
            || v.starts_with('\\')
            || v.starts_with("./")
            || v.starts_with(".\\")
            || v.starts_with("~/")
            || v.starts_with("~\\")
            || v.to_ascii_lowercase().starts_with("file://")
            || (v.len() >= 3
                && v.as_bytes()[1] == b':'
                && (v.as_bytes()[2] == b'\\' || v.as_bytes()[2] == b'/'))
        {
            return true;
        }
    }
    false
}

/// WP-2 + [CODEX-P0-02]: Enforce strict path-segment boundary matching so allowed prefix `/workspace/safe`
/// matches `/workspace/safe` and `/workspace/safe/notes.md`, but NEVER matches `/workspace/safe_secrets`.
pub fn path_starts_with_segment_boundary(candidate: &str, allowed_prefix: &str) -> bool {
    let norm_cand = normalize_path_str(candidate);
    let norm_pref = normalize_path_str(allowed_prefix);

    if norm_pref.is_empty() {
        return false;
    }
    if norm_cand == norm_pref {
        return true;
    }
    if let Some(remainder) = norm_cand.strip_prefix(&norm_pref) {
        return remainder.starts_with('/');
    }
    false
}

fn normalize_path_str(p: &str) -> String {
    let mut s = p.replace('\\', "/").to_ascii_lowercase();
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}
