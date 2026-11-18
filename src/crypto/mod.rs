//! Cryptographic authority key vault (`Ed25519` + `Argon2id` + `HKDF-SHA256` + `XChaCha20-Poly1305`)
//! and `BLAKE3` Merkle digest primitives for **SigNET**.

pub mod token;

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id memory cost: 64 MiB (65,536 KiB).
pub const ARGON2_M_COST: u32 = 65_536;
/// Argon2id time cost: 3 iterations.
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism: 4 lanes.
pub const ARGON2_P_COST: u32 = 4;
/// XChaCha20-Poly1305 extended nonce size (24 bytes / 192 bits).
pub const XNONCE_LEN: usize = 24;
/// Salt size (16 bytes / 128 bits).
pub const SALT_LEN: usize = 16;

const HKDF_INFO_VAULT_AEAD: &[u8] = b"signet-v1-vault-aead-key";
const HKDF_INFO_VERIFY: &[u8] = b"signet-v1-key-verifier";

/// 32-byte root master seed derived via Argon2id.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed([u8; 32]);

/// Derived vault encryption key (`XChaCha20-Poly1305`) and verifier tag.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultSubKeys {
    pub aead_key: [u8; 32],
    pub verifier: [u8; 32],
}

impl MasterSeed {
    /// Derive a 32-byte `MasterSeed` from a passphrase and 128-bit salt via Argon2id.
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| anyhow!("invalid Argon2id parameters: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Fast deterministic derivation for unit and property-based tests.
    pub fn derive_fast_for_test(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(1024, 1, 1, Some(32))
            .map_err(|e| anyhow!("invalid Argon2id test parameters: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id test derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Expand the `MasterSeed` into an `XChaCha20-Poly1305` AEAD key and 32-byte verifier via HKDF-SHA256.
    pub fn derive_vault_subkeys(&self, salt: &[u8; SALT_LEN]) -> Result<VaultSubKeys> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut aead_key = [0u8; 32];
        let mut verifier = [0u8; 32];

        hk.expand(HKDF_INFO_VAULT_AEAD, &mut aead_key)
            .map_err(|_| anyhow!("HKDF expansion failed for aead_key"))?;
        hk.expand(HKDF_INFO_VERIFY, &mut verifier)
            .map_err(|_| anyhow!("HKDF expansion failed for verifier"))?;

        Ok(VaultSubKeys { aead_key, verifier })
    }
}

/// Generate a fresh 128-bit cryptographic salt from the OS CSPRNG.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a fresh RFC 8032 `Ed25519` authority signing keypair from the OS CSPRNG.
pub fn generate_ed25519_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Sign arbitrary canonical bytes with an `Ed25519` [`SigningKey`] and return a 64-byte hex signature.
pub fn sign_bytes_hex(signing_key: &SigningKey, msg: &[u8]) -> String {
    let sig: Signature = signing_key.sign(msg);
    hex::encode(sig.to_bytes())
}

/// Verify a 64-byte hex `Ed25519` signature against a 32-byte [`VerifyingKey`].
pub fn verify_bytes_hex(verifying_key: &VerifyingKey, msg: &[u8], sig_hex: &str) -> Result<()> {
    let sig_bytes = hex::decode(sig_hex).context("signature is not valid hexadecimal")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 signature must be exactly 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| anyhow!("Ed25519 cryptographic signature verification failed"))
}

/// Compute a 32-byte `BLAKE3` hex digest over domain-separated components.
pub fn blake3_domain_hex(domain: &str, parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0x00]);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}

/// Encrypt a secret payload (`Ed25519` 32-byte secret key) with `XChaCha20-Poly1305` and AAD.
pub fn aead_encrypt(key_bytes: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;

    let mut out = Vec::with_capacity(XNONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an `XChaCha20-Poly1305` blob and verify contextual AAD.
pub fn aead_decrypt(key_bytes: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<ZeroizeSecret> {
    if blob.len() < XNONCE_LEN + 16 {
        return Err(anyhow!("ciphertext blob too short"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(XNONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            anyhow!("XChaCha20-Poly1305 authentication failed (wrong passphrase or AAD)")
        })?;

    Ok(ZeroizeSecret(plaintext))
}

/// Zeroizing buffer wrapper for decrypted key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizeSecret(pub Vec<u8>);

/// Constant-time 32-byte equality comparison (`[SEC-06]` / `CWE-208` timing side-channel defense).
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    std::hint::black_box(diff) == 0
}
