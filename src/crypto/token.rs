//! Self-contained, attenuable `Ed25519` Capability Tokens (`sig1.<base64url-payload>.<hex-sig>`).
//!
//! Security Model (`SigNET v0.4.0` — `WP-CODEX-1` & `WP-CODEX-2`):
//! - **Root Authority Minting:** The root `Ed25519` authority signs a [`CapabilityClaims`] grant
//!   specifying allowed tools, denied tools, allowed workspace path prefixes, denied argument
//!   regexes, max calls per minute, and expiration timestamp (`expires_at_unix`).
//! - **Multi-Generation Lineage (`[CODEX-P0-01]`):** Every attenuated child token carries both
//!   `parent_token_hash` and the full ordered ancestor chain `lineage_token_hashes` (capped at
//!   [`MAX_DELEGATION_DEPTH`]), ensuring root or intermediate token revocation and rate-limit
//!   quotas enforce across arbitrary $T_0 \to T_1 \to \dots \to T_k$ delegation depth.
//! - **Unified Safe Path Subset Semantics (`[CODEX-P0-02]`):** Both token issuance/attenuation
//!   and runtime `tools/call` evaluation enforce the exact same canonical segment-boundary path
//!   subset relation (`crate::policy::verify_safe_path_subset`), blocking sibling-prefix privilege
//!   escalation (e.g. `/workspace/safe` -> `/workspace/safe_secrets`).

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{blake3_domain_hex, sign_bytes_hex, verify_bytes_hex};
use crate::policy::{canonicalize_and_validate_policy_path, verify_safe_path_subset};

const TOKEN_PREFIX: &str = "sig1";
const SIGNING_DOMAIN: &[u8] = b"signet-v1-cap-token:";

/// Maximum allowed attenuation chain depth ($T_0 \to T_1 \to \dots \to T_{16}$) (`[CODEX-P0-01]`).
pub const MAX_DELEGATION_DEPTH: usize = 16;

/// Least-privilege capability claims carried inside a `SigNET` token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityClaims {
    /// Unique token UUID (`jti`).
    pub token_id: String,
    /// Immediate parent `BLAKE3` token digest if attenuated from a parent capability token.
    pub parent_token_hash: Option<String>,
    /// Complete ordered ancestor `BLAKE3` token digest lineage (`[root_hash, ..., parent_hash]`) (`[CODEX-P0-01]`).
    #[serde(default)]
    pub lineage_token_hashes: Vec<String>,
    /// Agent or service identity subject (e.g., `"research-subagent"`, `"claude-code"`).
    pub subject: String,
    /// Explicit allowlist of MCP tool names (supports `"*"` for all non-denied tools).
    pub allow_tools: Vec<String>,
    /// Explicit denylist of MCP tool names (always overrides `allow_tools`).
    pub deny_tools: Vec<String>,
    /// Allowed filesystem path prefixes (empty means no path restriction beyond `..` traversal block).
    pub allowed_paths: Vec<String>,
    /// Regex patterns forbidden anywhere inside JSON-RPC tool arguments.
    pub denied_arg_patterns: Vec<String>,
    /// Maximum tool invocations permitted per 60-second window.
    pub max_calls_per_minute: u32,
    /// Issuance timestamp (Unix seconds).
    pub issued_at_unix: i64,
    /// Expiration timestamp (Unix seconds).
    pub expires_at_unix: i64,
}

/// Decoded and verified `SigNET` Capability Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedCapability {
    pub claims: CapabilityClaims,
    pub token_hash: String,
    pub raw_token: String,
}

impl CapabilityClaims {
    /// Construct a new root `CapabilityClaims` instance with a TTL in minutes.
    pub fn new(
        subject: impl Into<String>,
        allow_tools: Vec<String>,
        deny_tools: Vec<String>,
        allowed_paths: Vec<String>,
        denied_arg_patterns: Vec<String>,
        max_calls_per_minute: u32,
        ttl_mins: i64,
    ) -> Self {
        let now = Utc::now().timestamp();
        Self {
            token_id: Uuid::new_v4().to_string(),
            parent_token_hash: None,
            lineage_token_hashes: Vec::new(),
            subject: subject.into(),
            allow_tools,
            deny_tools,
            allowed_paths,
            denied_arg_patterns,
            max_calls_per_minute: max_calls_per_minute.max(1),
            issued_at_unix: now,
            expires_at_unix: now + (ttl_mins.max(1) * 60),
        }
    }

    /// Return all unique ancestor token hashes (combining `lineage_token_hashes` and `parent_token_hash`)
    /// so multi-generation CRL revocation and quota accounting cover every ancestor up to root $T_0$.
    pub fn all_ancestor_hashes(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.lineage_token_hashes.len() + 1);
        for h in &self.lineage_token_hashes {
            if !h.is_empty() && !out.contains(h) {
                out.push(h.clone());
            }
        }
        if let Some(ph) = &self.parent_token_hash
            && !ph.is_empty()
            && !out.contains(ph)
        {
            out.push(ph.clone());
        }
        out
    }
}

/// Mint and sign a `sig1.<base64url-claims>.<hex-ed25519-sig>` token string.
/// Validates path claims for traversal/UNC/ADS anomalies before signing (`[CODEX-P0-02]`).
pub fn mint_capability_token(
    signing_key: &SigningKey,
    claims: &CapabilityClaims,
) -> Result<String> {
    if claims.issued_at_unix > claims.expires_at_unix {
        return Err(anyhow!(
            "Invalid capability claims: issued_at_unix ({}) > expires_at_unix ({})",
            claims.issued_at_unix,
            claims.expires_at_unix
        ));
    }
    if claims.lineage_token_hashes.len() > MAX_DELEGATION_DEPTH {
        return Err(anyhow!(
            "Delegation depth ({}) exceeds MAX_DELEGATION_DEPTH ({MAX_DELEGATION_DEPTH})",
            claims.lineage_token_hashes.len()
        ));
    }
    for p in &claims.allowed_paths {
        canonicalize_and_validate_policy_path(p)
            .map_err(|e| anyhow!("Invalid allowed_path '{p}' in capability claims: {e}"))?;
    }

    let json_bytes = serde_json::to_vec(claims).context("failed to serialize CapabilityClaims")?;
    let b64_payload = URL_SAFE_NO_PAD.encode(&json_bytes);

    let msg = build_signing_message(&b64_payload);
    let sig_hex = sign_bytes_hex(signing_key, &msg);

    Ok(format!("{TOKEN_PREFIX}.{b64_payload}.{sig_hex}"))
}

/// Verify a `sig1.<base64url-claims>.<hex-sig>` token against `verifying_key` and current clock.
pub fn verify_capability_token(
    verifying_key: &VerifyingKey,
    raw_token: &str,
) -> Result<VerifiedCapability> {
    let parts: Vec<&str> = raw_token.trim().split('.').collect();
    if parts.len() != 3 || parts[0] != TOKEN_PREFIX {
        return Err(anyhow!(
            "Invalid SigNET token format (expected '{TOKEN_PREFIX}.<payload>.<sig>')"
        ));
    }

    let b64_payload = parts[1];
    let sig_hex = parts[2];

    let msg = build_signing_message(b64_payload);
    verify_bytes_hex(verifying_key, &msg, sig_hex)
        .context("SigNET capability token signature verification failed")?;

    let json_bytes = URL_SAFE_NO_PAD
        .decode(b64_payload)
        .context("invalid base64url payload in SigNET token")?;
    let claims: CapabilityClaims =
        serde_json::from_slice(&json_bytes).context("invalid JSON claims in SigNET token")?;

    if claims.issued_at_unix > claims.expires_at_unix {
        return Err(anyhow!(
            "SigNET capability token '{}' has inverted timestamps (issued_at={} > expires_at={})",
            claims.token_id,
            claims.issued_at_unix,
            claims.expires_at_unix
        ));
    }

    if claims.lineage_token_hashes.len() > MAX_DELEGATION_DEPTH {
        return Err(anyhow!(
            "SigNET capability token '{}' exceeds MAX_DELEGATION_DEPTH ({MAX_DELEGATION_DEPTH})",
            claims.token_id
        ));
    }

    let now = Utc::now().timestamp();
    if now > claims.expires_at_unix {
        return Err(anyhow!(
            "SigNET capability token '{}' expired at unix={} (now={})",
            claims.token_id,
            claims.expires_at_unix,
            now
        ));
    }

    let token_hash = blake3_domain_hex("signet-v1-token-hash", &[raw_token.trim().as_bytes()]);

    Ok(VerifiedCapability {
        claims,
        token_hash,
        raw_token: raw_token.trim().to_string(),
    })
}

/// Attenuate (strictly narrow) an existing verified parent token into a child token.
/// Rejects any attempt to escalate privileges (`allow_tools`, `allowed_paths`, `max_calls_per_minute`, or `expires_at_unix`).
#[allow(clippy::too_many_arguments)]
pub fn attenuate_capability_token(
    signing_key: &SigningKey,
    parent: &VerifiedCapability,
    child_subject: impl Into<String>,
    narrowed_allow_tools: Vec<String>,
    extra_deny_tools: Vec<String>,
    narrowed_paths: Vec<String>,
    max_calls_per_minute: u32,
    ttl_mins: i64,
) -> Result<String> {
    let p = &parent.claims;

    // 0. [CODEX-P0-01]: Re-verify parent has not expired at attenuation time & enforce max lineage depth
    let now = Utc::now().timestamp();
    if now > p.expires_at_unix {
        return Err(anyhow!(
            "Cannot attenuate expired parent token '{}' (expired at unix={}, now={now})",
            p.token_id,
            p.expires_at_unix
        ));
    }

    let mut child_lineage = p.all_ancestor_hashes();
    if child_lineage.len() >= MAX_DELEGATION_DEPTH {
        return Err(anyhow!(
            "Privilege delegation blocked: maximum attenuation depth ({MAX_DELEGATION_DEPTH}) reached"
        ));
    }
    if !child_lineage.contains(&parent.token_hash) {
        child_lineage.push(parent.token_hash.clone());
    }

    // 1. Verify narrowed_allow_tools is a strict subset of parent.allow_tools
    if narrowed_allow_tools.is_empty() {
        return Err(anyhow!(
            "Attenuated token must specify at least one allowed tool"
        ));
    }
    let parent_wildcard = p.allow_tools.iter().any(|t| t == "*");
    if !parent_wildcard {
        for tool in &narrowed_allow_tools {
            if tool == "*" || !p.allow_tools.contains(tool) {
                return Err(anyhow!(
                    "Privilege escalation blocked: child tool '{tool}' is not permitted by parent token '{}'",
                    p.token_id
                ));
            }
        }
    }

    // 2. [CODEX-P0-02]: Verify narrowed_paths using the unified platform-aware segment-boundary subset
    //    relation (`verify_safe_path_subset`) so `/workspace/safe` can NEVER mint `/workspace/safe_secrets`
    //    or `/workspace/safe/../etc`!
    if !p.allowed_paths.is_empty() {
        if narrowed_paths.is_empty() {
            return Err(anyhow!(
                "Privilege escalation blocked: cannot remove parent path restrictions"
            ));
        }
        for child_path in &narrowed_paths {
            verify_safe_path_subset(child_path, &p.allowed_paths).map_err(|reason| {
                anyhow!(
                    "Privilege escalation blocked: child path '{child_path}' violates parent allowed_paths {:?}: {reason}",
                    p.allowed_paths
                )
            })?;
        }
    } else {
        for child_path in &narrowed_paths {
            canonicalize_and_validate_policy_path(child_path).map_err(|reason| {
                anyhow!("Invalid child path '{child_path}' during attenuation: {reason}")
            })?;
        }
    }

    // 3. Verify rate limit does not exceed parent rate limit
    if max_calls_per_minute > p.max_calls_per_minute {
        return Err(anyhow!(
            "Privilege escalation blocked: child rate limit ({max_calls_per_minute} rpm) exceeds parent ({} rpm)",
            p.max_calls_per_minute
        ));
    }

    // 4. Compute union of deny lists and clamp expiration to parent expiration
    let mut combined_deny = p.deny_tools.clone();
    for d in extra_deny_tools {
        if !combined_deny.contains(&d) {
            combined_deny.push(d);
        }
    }

    let requested_exp = now + (ttl_mins.max(1) * 60);
    let clamped_exp = requested_exp.min(p.expires_at_unix);

    let child_claims = CapabilityClaims {
        token_id: Uuid::new_v4().to_string(),
        parent_token_hash: Some(parent.token_hash.clone()),
        lineage_token_hashes: child_lineage,
        subject: child_subject.into(),
        allow_tools: narrowed_allow_tools,
        deny_tools: combined_deny,
        allowed_paths: if narrowed_paths.is_empty() {
            p.allowed_paths.clone()
        } else {
            narrowed_paths
        },
        denied_arg_patterns: p.denied_arg_patterns.clone(),
        max_calls_per_minute: max_calls_per_minute.max(1),
        issued_at_unix: now,
        expires_at_unix: clamped_exp,
    };

    mint_capability_token(signing_key, &child_claims)
}

fn build_signing_message(b64_payload: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNING_DOMAIN.len() + b64_payload.len());
    msg.extend_from_slice(SIGNING_DOMAIN);
    msg.extend_from_slice(b64_payload.as_bytes());
    msg
}
