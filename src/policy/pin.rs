//! `BLAKE3` MCP tool schema pinning and prompt-injection / tool-poisoning description scanner.
//!
//! Hardened in **SigNET v0.4.0** (`WP-CODEX-6` / `[CODEX-P1-03]`):
//! - Captures all MCP tool metadata (`name`, `title`, `description`, `inputSchema`, `outputSchema`,
//!   `annotations`, and arbitrary `#[serde(flatten)] extra_fields`) so no host-visible metadata
//!   can bypass `BLAKE3` pinning or `[SIG-02]` prompt-injection scanning.

use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto::blake3_domain_hex;

/// Canonical MCP Tool definition inside a JSON-RPC `tools/list` response (`[CODEX-P1-03]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
    #[serde(rename = "outputSchema", default)]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub annotations: Option<Value>,
    #[serde(flatten, default)]
    pub extra_fields: Map<String, Value>,
}

/// Compute a canonical `BLAKE3` hex digest over an [`McpToolDefinition`], covering every
/// standard and extension metadata field (`[CODEX-P1-03]`).
pub fn compute_tool_schema_blake3(server_name: &str, tool: &McpToolDefinition) -> Result<String> {
    let canonical_input = serde_json::to_vec(&tool.input_schema)?;
    let canonical_output = serde_json::to_vec(&tool.output_schema)?;
    let canonical_annotations = serde_json::to_vec(&tool.annotations)?;
    let canonical_extra = serde_json::to_vec(&tool.extra_fields)?;
    let title_str = tool.title.as_deref().unwrap_or("");

    Ok(blake3_domain_hex(
        "signet-v1-mcp-tool-pin",
        &[
            server_name.as_bytes(),
            tool.name.as_bytes(),
            title_str.as_bytes(),
            tool.description.as_bytes(),
            &canonical_input,
            &canonical_output,
            &canonical_annotations,
            &canonical_extra,
        ],
    ))
}

/// Scan an MCP tool's `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`,
/// and `extra_fields` for hidden prompt-injection / tool-poisoning payloads (`[SIG-02]` + `WP-5` + `[CODEX-P1-03]`).
pub fn scan_tool_for_poisoning(tool: &McpToolDefinition) -> Result<()> {
    static POISON_RE: OnceLock<Regex> = OnceLock::new();
    let re = POISON_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:<\s*important\s*>|ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt\s+override|do\s+not\s+tell\s+the\s+user|exfiltrate|(?:\~|\/home\/[a-z0-9_-]+)\/\.ssh|id_rsa|\/etc\/shadow)",
        )
        .expect("valid poison regex")
    });

    let extra_json = serde_json::to_string(&tool.extra_fields).unwrap_or_default();
    let output_json = serde_json::to_string(&tool.output_schema).unwrap_or_default();
    let annot_json = serde_json::to_string(&tool.annotations).unwrap_or_default();
    let title_str = tool.title.as_deref().unwrap_or("");

    let combined = format!(
        "{} {} {} {} {} {} {}",
        tool.name,
        title_str,
        tool.description,
        tool.input_schema,
        output_json,
        annot_json,
        extra_json
    );

    // WP-5a: Immediately block Unicode Bidirectional (Bidi) override characters used to cloak malicious instructions.
    if let Some(ch) = combined.chars().find(|&c| is_unicode_bidi_override(c)) {
        return Err(anyhow!(
            "MCP Tool Poisoning Detected in tool '{}': Unicode Bidi override character U+{:04X}",
            tool.name,
            ch as u32
        ));
    }

    // WP-5b: Strip zero-width and soft-hyphen characters before regex scan so split-token injections
    // like `<im\u{200B}portant>` or `ig\u{200C}nore previous instructions` cannot evade detection.
    let deobfuscated: String = combined
        .chars()
        .filter(|&c| !is_zero_width_splitter(c))
        .collect();

    if let Some(m) = re.find(&deobfuscated) {
        return Err(anyhow!(
            "MCP Tool Poisoning Detected in tool '{}': suspicious directive '{}'",
            tool.name,
            m.as_str()
        ));
    }
    Ok(())
}

fn is_unicode_bidi_override(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

fn is_zero_width_splitter(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}'
    )
}
