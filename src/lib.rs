//! **SigNET** (`signet-firewall`) — Cryptographic MCP & Agent Capability Firewall
//! (`Ed25519` Attenuable Capability Tokens + `BLAKE3` Anti-Rug-Pull Schema Pinning +
//! Append-Only `BLAKE3` Merkle Audit Log).
//!
//! Enforces `#![forbid(unsafe_code)]` across the entire crate.

#![forbid(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod ledger;
pub mod policy;
pub mod proxy;
pub mod tui;
