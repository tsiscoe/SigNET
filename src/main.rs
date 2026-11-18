//! Entrypoint for the `signet` binary (**SigNET** Cryptographic MCP & Agent Capability Firewall).

#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde_json::Value;
use signet_firewall::{
    cli::{Cli, Commands, PinAction, TokenAction},
    crypto::token::{
        CapabilityClaims, attenuate_capability_token, mint_capability_token,
        verify_capability_token,
    },
    ledger::{SignetLedger, default_ledger_path},
    policy::{PolicyDecision, PolicyEvaluator},
    proxy::{parse_strict_json_no_dup_keys, run_stdio_proxy_with_options},
    tui::{SignetTuiApp, run_interactive_tui},
};

const KEYRING_SERVICE: &str = "signet-mcp-firewall";
const KEYRING_USER: &str = "authority-vault";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.clone().unwrap_or_else(default_ledger_path);
    let mut passphrase = resolve_passphrase(&cli)?;

    let ledger = SignetLedger::open_with_passphrase(&db_path, passphrase.as_bytes(), false)?;
    zeroize::Zeroize::zeroize(&mut passphrase);

    match cli.command {
        Commands::Init => {
            let report = ledger.verify_merkle_chain()?;
            println!("SigNET v0.4.0 Authority Vault Initialized");
            println!("  Ledger Path:       {}", ledger.db_path().display());
            println!("  Ed25519 PubKey:    {}", report.authority_pubkey_hex);
            println!("  Merkle Head Hash:  {}", report.head_hash);
        }

        Commands::Token { action } => match action {
            TokenAction::Mint {
                subject,
                allow,
                deny,
                paths,
                deny_arg_regex,
                max_rpm,
                ttl_mins,
            } => {
                let claims = CapabilityClaims::new(
                    subject,
                    allow,
                    deny,
                    paths,
                    deny_arg_regex,
                    max_rpm,
                    ttl_mins,
                );
                let token = mint_capability_token(ledger.signing_key(), &claims)?;
                println!("{token}");
            }

            TokenAction::Attenuate {
                parent,
                subject,
                allow,
                deny,
                paths,
                max_rpm,
                ttl_mins,
            } => {
                let verified_parent = verify_capability_token(ledger.verifying_key(), &parent)?;
                let child_token = attenuate_capability_token(
                    ledger.signing_key(),
                    &verified_parent,
                    subject,
                    allow,
                    deny,
                    paths,
                    max_rpm,
                    ttl_mins,
                )?;
                println!("{child_token}");
            }

            TokenAction::Inspect { token } => {
                let verified = verify_capability_token(ledger.verifying_key(), &token)?;
                println!("{}", serde_json::to_string_pretty(&verified.claims)?);
            }

            TokenAction::Revoke { token, reason } => {
                let (token_id, token_hash) = if token.trim().starts_with("sig1.") {
                    let verified = verify_capability_token(ledger.verifying_key(), &token)?;
                    (verified.claims.token_id, Some(verified.token_hash))
                } else {
                    (token.trim().to_string(), None)
                };
                let rec = ledger.revoke_token(&token_id, token_hash.as_deref(), &reason)?;
                println!(
                    "[SigNET REVOKED] token_id={} revoked_at={} reason=\"{}\"",
                    rec.token_id, rec.revoked_at, rec.reason
                );
            }
        },

        Commands::Pin { action } => match action {
            PinAction::List { json } => {
                let pins = ledger.list_tool_pins()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&pins)?);
                } else {
                    println!("SigNET PINNED MCP TOOL SCHEMAS // {} PINS", pins.len());
                    for p in pins {
                        println!(
                            "  {}::{:<24} -> BLAKE3: {} ({})",
                            p.server_name, p.tool_name, p.schema_blake3, p.pinned_at
                        );
                    }
                }
            }
        },

        Commands::Proxy {
            token,
            server_name,
            pass_env,
            strict_pins,
            cmd,
        } => {
            let verified = verify_capability_token(ledger.verifying_key(), &token)?;
            run_stdio_proxy_with_options(
                &ledger,
                &verified,
                &server_name,
                &cmd,
                &pass_env,
                strict_pins,
            )
            .await?;
        }

        Commands::Verify { token, tool, args } => {
            let verified = verify_capability_token(ledger.verifying_key(), &token)?;
            // [CODEX-P0-01]: Full multi-generation lineage CRL revocation check
            if let Some(revoked_reason) = ledger.is_capability_revoked(&verified)? {
                let receipt = ledger.append_audit_event(
                    &verified.claims.subject,
                    &verified.claims.token_id,
                    &tool,
                    &args,
                    "DENY",
                    &revoked_reason,
                )?;
                eprintln!(
                    "[SigNET DENY] seq={} tool={} reason=\"{}\" hash={}",
                    receipt.seq, tool, revoked_reason, receipt.entry_hash
                );
                std::process::exit(1);
            }

            // [CODEX-P1-04]: Enforce strict duplicate-key & depth-bounded JSON parsing on CLI hook `--args`
            let parsed_args: Value = match parse_strict_json_no_dup_keys(&args) {
                Ok(v) => v,
                Err(strict_err) => {
                    let reason = format!("Strict JSON guard rejected --args: {strict_err}");
                    let receipt = ledger.append_audit_event(
                        &verified.claims.subject,
                        &verified.claims.token_id,
                        &tool,
                        &args,
                        "DENY",
                        &reason,
                    )?;
                    eprintln!(
                        "[SigNET DENY] seq={} tool={} reason=\"{}\" hash={}",
                        receipt.seq, tool, reason, receipt.entry_hash
                    );
                    std::process::exit(1);
                }
            };

            // [CODEX-P1-04]: Enforce cross-process persistent SQLite rate-limit quotas
            if !ledger.check_and_record_persistent_rate_limit(&verified.claims)? {
                let reason = format!(
                    "Rate limit exceeded in persistent ledger for token '{}' (or ancestor lineage): max {} calls/min",
                    verified.claims.token_id, verified.claims.max_calls_per_minute
                );
                let receipt = ledger.append_audit_event(
                    &verified.claims.subject,
                    &verified.claims.token_id,
                    &tool,
                    &args,
                    "DENY",
                    &reason,
                )?;
                eprintln!(
                    "[SigNET DENY] seq={} tool={} reason=\"{}\" hash={}",
                    receipt.seq, tool, reason, receipt.entry_hash
                );
                std::process::exit(1);
            }

            let evaluator = PolicyEvaluator::new();
            let decision = evaluator.evaluate_tool_call(&verified.claims, &tool, &parsed_args);
            let receipt = ledger.append_audit_event(
                &verified.claims.subject,
                &verified.claims.token_id,
                &tool,
                &args,
                decision.code_str(),
                decision.reason(),
            )?;

            match decision {
                PolicyDecision::Allow { reason } => {
                    println!(
                        "[SigNET ALLOW] seq={} tool={} reason=\"{}\" hash={}",
                        receipt.seq, tool, reason, receipt.entry_hash
                    );
                }
                PolicyDecision::Deny { reason } => {
                    eprintln!(
                        "[SigNET DENY] seq={} tool={} reason=\"{}\" hash={}",
                        receipt.seq, tool, reason, receipt.entry_hash
                    );
                    std::process::exit(1);
                }
            }
        }

        Commands::Audit { json } => {
            let report = ledger.verify_merkle_chain()?;
            let receipts = ledger.list_audit_receipts()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "verification": report,
                        "receipts": receipts
                    }))?
                );
            } else {
                println!(
                    "SigNET MERKLE AUDIT // {} entries verified (VALID: {})",
                    report.total_entries, report.valid
                );
                println!("  Authority PubKey: {}", report.authority_pubkey_hex);
                println!("  Head BLAKE3 Hash: {}", report.head_hash);
                for r in receipts {
                    println!(
                        "  [#{:<4} {:<5}] {} -> {} ({})",
                        r.seq, r.decision, r.subject, r.tool_name, r.reason
                    );
                }
            }
        }

        Commands::Tui => {
            let (chain_valid, head_hash) = match ledger.verify_merkle_chain() {
                Ok(rep) => (rep.valid, rep.head_hash),
                Err(e) => (false, format!("TAMPERED: {e}")),
            };
            let receipts = ledger.list_audit_receipts().unwrap_or_default();
            let pins = ledger.list_tool_pins().unwrap_or_default();
            let app = SignetTuiApp::new(
                ledger.authority_pubkey_hex(),
                chain_valid,
                head_hash,
                receipts,
                pins,
            );
            run_interactive_tui(app)?;
        }
    }

    Ok(())
}

fn resolve_passphrase(cli: &Cli) -> Result<String> {
    if let Some(p) = &cli.passphrase
        && !p.is_empty()
    {
        if cli.keyring
            && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        {
            let _ = entry.set_password(p);
        }
        return Ok(p.clone());
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && let Ok(saved) = entry.get_password()
        && !saved.is_empty()
    {
        return Ok(saved);
    }

    let prompt_pass = rpassword::prompt_password("SigNET Authority Passphrase: ")
        .context("failed to read passphrase from terminal")?;
    if prompt_pass.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty"));
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
    {
        let _ = entry.set_password(&prompt_pass);
    }

    Ok(prompt_pass)
}
