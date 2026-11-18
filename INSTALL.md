# Installing Sig**NET**

## Prerequisites

- **Rust Toolchain:** Rust `1.85+` (2024 Edition) via [rustup.rs](https://rustup.rs/)
- **Supported Platforms:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`, uses pure-Rust `linux-keyutils` for native keyring support)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

---

## Install from Source

```bash
git clone https://github.com/tsiscoe/SigNET.git
cd SigNET
cargo install --path .
```

Verify installation:

```bash
signet --version
```

---

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `SIGNET_PASSPHRASE` | Authority passphrase for non-interactive CLI / CI pipelines | Interactive prompt or OS Keyring (`--keyring`) |
| `SIGNET_DB_PATH` | Path to the SQLite WAL authority vault & Merkle ledger | `%APPDATA%\signet\signet.db` (Win) or `~/.local/share/signet/signet.db` (Unix) |
| `SIGNET_TOKEN` | Default `sig1.<payload>.<sig>` capability token for `signet proxy` and `signet verify` | Passed via `--token` |
