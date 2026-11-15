//! JSON-RPC 2.0 MCP Stdio Interceptor & Line-Frame Firewall (`signet proxy`).
//!
//! Intercepts:
//! - Client -> Server `tools/call`: Verifies the active [`VerifiedCapability`] token, runs
//!   [`PolicyEvaluator::evaluate_tool_call`], logs an append-only `BLAKE3` + `Ed25519` receipt
//!   into [`SignetLedger`], and either forwards the request or returns a signed JSON-RPC `-32001`
//!   capability violation response immediately.
//! - Server -> Client `tools/list` responses: Scans every returned [`McpToolDefinition`] for
//!   prompt-injection poisoning (`[SIG-02]`) and verifies/records its `BLAKE3` schema pin.

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

use crate::crypto::token::VerifiedCapability;
use crate::ledger::SignetLedger;
use crate::policy::{
    PolicyDecision, PolicyEvaluator,
    pin::{McpToolDefinition, compute_tool_schema_blake3, scan_tool_for_poisoning},
};

/// Outcome of inspecting a single client -> server JSON-RPC message.
#[derive(Debug, Clone)]
pub enum ClientFrameAction {
    /// Forward the unmodified JSON-RPC line to the child MCP server.
    Forward(String),
    /// Block the request and return this JSON-RPC error response directly to the client.
    RejectWithJsonRpcError(String),
}

/// Inspect a single client -> server JSON-RPC line.
/// If it is a `tools/call` invocation, enforces capability policy and writes a signed Merkle receipt.
pub fn process_client_jsonrpc_line(
    ledger: &SignetLedger,
    evaluator: &PolicyEvaluator,
    capability: &VerifiedCapability,
    line: &str,
) -> Result<ClientFrameAction> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(ClientFrameAction::Forward(line.to_string()));
    }

    let Ok(msg) = serde_json::from_str::<Value>(trimmed) else {
        return Ok(ClientFrameAction::Forward(line.to_string()));
    };

    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method != "tools/call" {
        return Ok(ClientFrameAction::Forward(line.to_string()));
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
        PolicyDecision::Allow { .. } => Ok(ClientFrameAction::Forward(line.to_string())),
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

/// Inspect a `tools/list` result payload from an MCP server, verifying `BLAKE3` schema pins
/// and scanning tool descriptions for prompt-injection poisoning (`[SIG-02]`).
pub fn verify_server_tools_list_payload(
    ledger: &SignetLedger,
    server_name: &str,
    jsonrpc_response: &str,
) -> Result<usize> {
    let msg: Value = serde_json::from_str(jsonrpc_response.trim())
        .context("invalid JSON-RPC response from MCP server")?;

    let Some(tools_val) = msg.pointer("/result/tools") else {
        return Ok(0);
    };

    let tools: Vec<McpToolDefinition> = serde_json::from_value(tools_val.clone())
        .context("failed to parse MCP result.tools array")?;

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
        if let Err(rug_err) =
            ledger.verify_or_pin_tool_schema(server_name, &tool.name, &schema_hash)
        {
            let _ = ledger.append_audit_event(
                server_name,
                "mcp-schema-guard",
                &tool.name,
                &schema_hash,
                "DENY",
                &rug_err.to_string(),
            );
            return Err(rug_err);
        }
    }

    Ok(tools.len())
}

/// Run the asynchronous stdio proxy wrapping a child MCP server command.
pub async fn run_stdio_proxy(
    ledger: &SignetLedger,
    capability: &VerifiedCapability,
    server_name: &str,
    command_args: &[String],
) -> Result<()> {
    if command_args.is_empty() {
        return Err(anyhow!("No child MCP server command specified after '--'"));
    }

    let mut child = Command::new(&command_args[0])
        .args(&command_args[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn child MCP server '{}'", command_args[0]))?;

    let mut child_stdin = child.stdin.take().expect("piped stdin");
    let child_stdout = child.stdout.take().expect("piped stdout");

    let mut host_stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    let mut child_stdout_lines = BufReader::new(child_stdout).lines();
    let mut host_stdout = tokio::io::stdout();

    let evaluator = PolicyEvaluator::new();

    loop {
        tokio::select! {
            host_line = host_stdin_lines.next_line() => {
                match host_line? {
                    Some(line) => {
                        match process_client_jsonrpc_line(ledger, &evaluator, capability, &line)? {
                            ClientFrameAction::Forward(fwd) => {
                                child_stdin.write_all(fwd.as_bytes()).await?;
                                child_stdin.write_all(b"\n").await?;
                                child_stdin.flush().await?;
                            }
                            ClientFrameAction::RejectWithJsonRpcError(err_json) => {
                                host_stdout.write_all(err_json.as_bytes()).await?;
                                host_stdout.write_all(b"\n").await?;
                                host_stdout.flush().await?;
                            }
                        }
                    }
                    None => break,
                }
            }
            srv_line = child_stdout_lines.next_line() => {
                match srv_line? {
                    Some(line) => {
                        if line.contains("\"tools\"") {
                            verify_server_tools_list_payload(ledger, server_name, &line)?;
                        }
                        host_stdout.write_all(line.as_bytes()).await?;
                        host_stdout.write_all(b"\n").await?;
                        host_stdout.flush().await?;
                    }
                    None => break,
                }
            }
        }
    }

    let _ = child.kill().await;
    Ok(())
}
