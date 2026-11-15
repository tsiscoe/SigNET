//! `BLAKE3` MCP tool schema pinning and prompt-injection / tool-poisoning description scanner.

use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::blake3_domain_hex;

/// Canonical MCP Tool definition inside a JSON-RPC `tools/list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
}

/// Compute a canonical `BLAKE3` hex digest over an [`McpToolDefinition`].
pub fn compute_tool_schema_blake3(server_name: &str, tool: &McpToolDefinition) -> Result<String> {
    let canonical_schema = serde_json::to_vec(&tool.input_schema)?;
    Ok(blake3_domain_hex(
        "signet-v1-mcp-tool-pin",
        &[
            server_name.as_bytes(),
            tool.name.as_bytes(),
            tool.description.as_bytes(),
            &canonical_schema,
        ],
    ))
}

/// Scan an MCP tool's `description` and `inputSchema` for hidden prompt-injection / tool-poisoning
/// payloads (`[SIG-02]`: `<IMPORTANT>`, `ignore previous instructions`, `~/.ssh`, `exfiltrate`, etc.).
pub fn scan_tool_for_poisoning(tool: &McpToolDefinition) -> Result<()> {
    static POISON_RE: OnceLock<Regex> = OnceLock::new();
    let re = POISON_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:<\s*important\s*>|ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt\s+override|do\s+not\s+tell\s+the\s+user|exfiltrate|(?:\~|\/home\/[a-z0-9_-]+)\/\.ssh|id_rsa|\/etc\/shadow)",
        )
        .expect("valid poison regex")
    });

    let combined = format!("{} {}", tool.description, tool.input_schema);
    if let Some(m) = re.find(&combined) {
        return Err(anyhow!(
            "MCP Tool Poisoning Detected in tool '{}': suspicious directive '{}'",
            tool.name,
            m.as_str()
        ));
    }
    Ok(())
}
