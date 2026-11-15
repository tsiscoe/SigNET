//! Capability Firewall Policy Engine: evaluates `tools/call` requests against [`CapabilityClaims`],
//! deep JSON argument path containment, regex deny-lists, and per-token sliding-window rate limits.

pub mod pin;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use regex::Regex;
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

/// Stateful firewall evaluator tracking per-token sliding-window invocation timestamps.
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
    pub fn evaluate_tool_call(
        &self,
        claims: &CapabilityClaims,
        tool_name: &str,
        args: &Value,
    ) -> PolicyDecision {
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

        // 3. Sliding-window rate limit check (60-second window)
        if !self.check_and_record_rate_limit(&claims.token_id, claims.max_calls_per_minute) {
            return PolicyDecision::Deny {
                reason: format!(
                    "Rate limit exceeded for token '{}': max {} calls/min",
                    claims.token_id, claims.max_calls_per_minute
                ),
            };
        }

        // 4. Deep JSON argument inspection (path traversal `..` & allowed_paths prefix containment)
        let mut string_leaves = Vec::new();
        collect_json_strings(args, &mut string_leaves);

        for (key_hint, val_str) in &string_leaves {
            if contains_path_traversal(val_str) {
                return PolicyDecision::Deny {
                    reason: format!(
                        "Path traversal sequence ('..') blocked in argument '{key_hint}': '{val_str}'"
                    ),
                };
            }

            if !claims.allowed_paths.is_empty() && looks_like_path_arg(key_hint, val_str) {
                let norm_val = normalize_path_str(val_str);
                let allowed = claims
                    .allowed_paths
                    .iter()
                    .any(|prefix| norm_val.starts_with(&normalize_path_str(prefix)));
                if !allowed {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "Argument '{key_hint}' path '{val_str}' is outside allowed_paths {:?}",
                            claims.allowed_paths
                        ),
                    };
                }
            }
        }

        // 5. Denied argument regex patterns check
        let serialized_args = args.to_string();
        for pat_str in &claims.denied_arg_patterns {
            if let Ok(re) = Regex::new(pat_str)
                && re.is_match(&serialized_args)
            {
                return PolicyDecision::Deny {
                    reason: format!("Arguments matched denied pattern '{pat_str}'"),
                };
            }
        }

        PolicyDecision::Allow {
            reason: format!(
                "Permitted by capability token '{}' (subject='{}')",
                claims.token_id, claims.subject
            ),
        }
    }

    fn check_and_record_rate_limit(&self, token_id: &str, max_rpm: u32) -> bool {
        let mut guard = self.rate_windows.lock().expect("rate_windows mutex");
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let history = guard.entry(token_id.to_string()).or_default();
        history.retain(|&ts| now.duration_since(ts) < window);

        if history.len() >= max_rpm as usize {
            return false;
        }
        history.push(now);
        true
    }
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

fn contains_path_traversal(s: &str) -> bool {
    let norm = s.replace('\\', "/");
    norm == ".." || norm.starts_with("../") || norm.ends_with("/..") || norm.contains("/../")
}

fn looks_like_path_arg(key: &str, val: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if k.contains("path")
        || k.contains("file")
        || k.contains("dir")
        || k.contains("root")
        || k.contains("cwd")
        || k.contains("target")
    {
        return true;
    }
    val.starts_with('/')
        || val.starts_with('\\')
        || (val.len() >= 3
            && val.as_bytes()[1] == b':'
            && (val.as_bytes()[2] == b'\\' || val.as_bytes()[2] == b'/'))
}

fn normalize_path_str(p: &str) -> String {
    p.replace('\\', "/").to_ascii_lowercase()
}
