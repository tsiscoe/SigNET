//! Self-contained, attenuable `Ed25519` Capability Tokens (`sig1.<base64url-payload>.<hex-sig>`).
//!
//! Security Model:
//! - **Root Authority Minting:** The root `Ed25519` authority signs a [`CapabilityClaims`] grant
//!   specifying allowed tools, denied tools, allowed workspace path prefixes, denied argument
//!   regexes, max calls per minute, and expiration timestamp (`expires_at_unix`).
//! - **Cryptographic Attenuation (`attenuate`):** A holder of a valid token can mint a strictly
//!   narrower child token (`allow_tools` subset, `allowed_paths` sub-prefixes, lower `max_rpm`,
//!   earlier or equal `expires_at_unix`) signed by the authority or chained with a strict
//!   monotonicity proof (`verify_attenuation_subset`). Any attempt to widen privileges during
//!   attenuation is cryptographically and structurally rejected!

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{blake3_domain_hex, sign_bytes_hex, verify_bytes_hex};

const TOKEN_PREFIX: &str = "sig1";
const SIGNING_DOMAIN: &[u8] = b"signet-v1-cap-token:";

/// Least-privilege capability claims carried inside a `SigNET` token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityClaims {
    /// Unique token UUID (`jti`).
    pub token_id: String,
    /// Optional parent `BLAKE3` token digest if attenuated from a parent capability token.
    pub parent_token_hash: Option<String>,
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
}

/// Mint and sign a `sig1.<base64url-claims>.<hex-ed25519-sig>` token string.
pub fn mint_capability_token(
    signing_key: &SigningKey,
    claims: &CapabilityClaims,
) -> Result<String> {
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

    // 2. Verify narrowed_paths are sub-prefixes of parent.allowed_paths (if parent restricted paths)
    if !p.allowed_paths.is_empty() {
        if narrowed_paths.is_empty() {
            return Err(anyhow!(
                "Privilege escalation blocked: cannot remove parent path restrictions"
            ));
        }
        for child_path in &narrowed_paths {
            let norm_child = normalize_prefix(child_path);
            let covered = p
                .allowed_paths
                .iter()
                .any(|pp| norm_child.starts_with(&normalize_prefix(pp)));
            if !covered {
                return Err(anyhow!(
                    "Privilege escalation blocked: child path '{child_path}' is outside parent allowed paths {:?}",
                    p.allowed_paths
                ));
            }
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

    let now = Utc::now().timestamp();
    let requested_exp = now + (ttl_mins.max(1) * 60);
    let clamped_exp = requested_exp.min(p.expires_at_unix);

    let child_claims = CapabilityClaims {
        token_id: Uuid::new_v4().to_string(),
        parent_token_hash: Some(parent.token_hash.clone()),
        subject: child_subject.into(),
        allow_tools: narrowed_allow_tools,
        deny_tools: combined_deny,
        allowed_paths: if narrowed_paths.is_empty() {
            p.allowed_paths.clone()
        } else {
            narrowed_paths
        },
        denied_arg_patterns: p.denied_arg_patterns.clone(),
        max_calls_per_minute,
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

fn normalize_prefix(p: &str) -> String {
    p.replace('\\', "/").to_ascii_lowercase()
}
