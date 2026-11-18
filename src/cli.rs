//! Clap v4 CLI surface for **SigNET** (`init`, `token`, `pin`, `proxy`, `verify`, `audit`, `tui`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "signet",
    version,
    about = "SigNET: Cryptographic MCP & Agent Capability Firewall (Ed25519 + BLAKE3 Merkle Audit Log)"
)]
pub struct Cli {
    /// Path to the SigNET SQLite WAL vault and Merkle ledger (defaults to %APPDATA%/signet/signet.db).
    #[arg(long, env = "SIGNET_DB_PATH", global = true)]
    pub db: Option<PathBuf>,

    /// Passphrase used to unlock the XChaCha20-Poly1305 encrypted Ed25519 authority key.
    #[arg(long, env = "SIGNET_PASSPHRASE", global = true)]
    pub passphrase: Option<String>,

    /// Store or load the master passphrase from the OS native keyring (`windows-native`, `apple-native`, `linux-native`).
    #[arg(long, global = true, default_value_t = false)]
    pub keyring: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize the Ed25519 authority keypair and genesis BLAKE3 Merkle ledger.
    Init,

    /// Mint, attenuate (narrow), or inspect Ed25519-signed capability tokens.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// Pin and audit MCP server tool definitions (`BLAKE3` anti-rug-pull & prompt-injection scan).
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },

    /// Wrap a child stdio MCP server in a real-time JSON-RPC 2.0 capability firewall.
    Proxy {
        /// Active Ed25519 capability token string (`sig1.<payload>.<sig>`).
        #[arg(long, env = "SIGNET_TOKEN")]
        token: String,

        /// Logical MCP server name for BLAKE3 tool schema pinning.
        #[arg(long, default_value = "mcp-server")]
        server_name: String,

        /// Comma-separated list of additional environment variable names to pass through to the child MCP server.
        #[arg(long, value_delimiter = ',')]
        pass_env: Vec<String>,

        /// Reject any unpinned MCP tool in `tools/list` rather than Trust-On-First-Use (TOFU) pinning.
        #[arg(long, default_value_t = false)]
        strict_pins: bool,

        /// Child MCP server command and arguments (after `--`).
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Evaluate a single tool invocation against a capability token and record a signed Merkle receipt (PreToolUse hook gate).
    Verify {
        /// Active Ed25519 capability token string (`sig1.<payload>.<sig>`).
        #[arg(long, env = "SIGNET_TOKEN")]
        token: String,

        /// Tool name being invoked (e.g., `read_file`, `write_file`, `run_command`).
        #[arg(long)]
        tool: String,

        /// JSON object string of tool arguments (defaults to `{}`).
        #[arg(long, default_value = "{}")]
        args: String,
    },

    /// Cryptographically verify the append-only BLAKE3 Merkle hash-chain and Ed25519 row signatures.
    Audit {
        /// Emit audit receipts and chain verification report as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Launch the Ratatui v0.30+ 3-pane Firewall & Merkle Chain Inspector.
    Tui,
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    /// Mint a new root Ed25519 capability token.
    Mint {
        /// Agent or client subject identifier.
        #[arg(long)]
        subject: String,

        /// Comma-separated list of allowed tool names (or `*`).
        #[arg(long, value_delimiter = ',', default_value = "*")]
        allow: Vec<String>,

        /// Comma-separated list of explicitly denied tool names.
        #[arg(long, value_delimiter = ',')]
        deny: Vec<String>,

        /// Comma-separated list of allowed workspace path prefixes.
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,

        /// Comma-separated list of regex patterns forbidden in tool arguments.
        #[arg(long, value_delimiter = ',')]
        deny_arg_regex: Vec<String>,

        /// Maximum tool calls permitted per 60-second window.
        #[arg(long, default_value_t = 120)]
        max_rpm: u32,

        /// Token Time-To-Live (TTL) in minutes.
        #[arg(long, default_value_t = 60)]
        ttl_mins: i64,
    },

    /// Attenuate (strictly narrow) an existing parent capability token for a subagent.
    Attenuate {
        /// Parent capability token (`sig1.<payload>.<sig>`).
        #[arg(long)]
        parent: String,

        /// Subagent subject identifier.
        #[arg(long)]
        subject: String,

        /// Narrowed comma-separated list of allowed tool names (must be subset of parent).
        #[arg(long, value_delimiter = ',', required = true)]
        allow: Vec<String>,

        /// Additional comma-separated denied tool names.
        #[arg(long, value_delimiter = ',')]
        deny: Vec<String>,

        /// Narrowed comma-separated allowed path prefixes (must be sub-prefixes of parent).
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,

        /// Maximum calls per minute (must be <= parent max_rpm).
        #[arg(long, default_value_t = 60)]
        max_rpm: u32,

        /// Requested TTL in minutes (automatically clamped to parent expiration).
        #[arg(long, default_value_t = 30)]
        ttl_mins: i64,
    },

    /// Verify and decode a capability token's claims.
    Inspect {
        /// Capability token (`sig1.<payload>.<sig>`).
        #[arg(long)]
        token: String,
    },

    /// Immediately revoke a capability token by ID or full token string (`WP-4` CRL + parent cascade).
    Revoke {
        /// Token UUID (`jti`), BLAKE3 token hash, or full `sig1.<payload>.<sig>` token string.
        #[arg(long)]
        token: String,

        /// Reason recorded in the CRL and signed BLAKE3 Merkle audit log.
        #[arg(long, default_value = "Revoked by operator via CLI")]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PinAction {
    /// List all pinned MCP tool BLAKE3 digests.
    List {
        /// Emit as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}
