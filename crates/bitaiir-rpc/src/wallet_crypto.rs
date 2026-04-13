//! Wallet encryption using Argon2id key derivation + AES-256-GCM.
//!
//! The user's passphrase is stretched into a 32-byte AES key via
//! Argon2id (16 MiB, 2 passes — fast enough for interactive use but
//! still memory-hard against brute force).  Each private key is then
//! encrypted with AES-256-GCM, which provides both confidentiality
//! and authenticity (tampered ciphertext is detected on decryption).
//!
//! Storage layout (all in the existing `wallet_keys` redb table):
//!
//! - **Unencrypted**: `address → privkey(32) + pubkey(33)` = 65 bytes
//! - **Encrypted**:   `address → nonce(12) + ciphertext(48) + pubkey(33)` = 93 bytes
//!
//! The `ciphertext` is the AES-256-GCM output of encrypting the
//! 32-byte private key (32 plaintext + 16 auth tag = 48).
//!
//! A separate metadata entry (`"wallet_salt"`) stores the 16-byte
//! random salt.  A test ciphertext (`"wallet_check"`) lets the daemon
//! verify the passphrase on startup without decrypting every key.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::RngCore;

/// Salt length for Argon2id derivation.
const SALT_LEN: usize = 16;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// Known plaintext used for password verification.
const CHECK_PLAINTEXT: &[u8; 16] = b"BitAiir Wallet!.";

/// Argon2id parameters for key derivation (lighter than mining PoW).
const KDF_MEMORY_KIB: u32 = 16_384; // 16 MiB
const KDF_TIME_COST: u32 = 2;
const KDF_PARALLELISM: u32 = 1;

/// Derive a 32-byte AES key from a passphrase + salt via Argon2id.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let params = argon2::Params::new(KDF_MEMORY_KIB, KDF_TIME_COST, KDF_PARALLELISM, Some(32))
        .expect("valid argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .expect("argon2 key derivation");
    key
}

/// Generate a random salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a random AES-GCM nonce.
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt a 32-byte private key.
/// Returns `nonce(12) + ciphertext(48)` = 60 bytes.
pub fn encrypt_privkey(key: &[u8; 32], privkey: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, privkey.as_slice()).expect("encrypt");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a private key from `nonce(12) + ciphertext(48)`.
/// Returns the 32-byte private key, or `None` if decryption fails
/// (wrong password or tampered data).
pub fn decrypt_privkey(key: &[u8; 32], encrypted: &[u8]) -> Option<[u8; 32]> {
    if encrypted.len() < NONCE_LEN + 16 {
        return None;
    }
    let nonce = Nonce::from_slice(&encrypted[..NONCE_LEN]);
    let ciphertext = &encrypted[NONCE_LEN..];
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    if plaintext.len() != 32 {
        return None;
    }
    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&plaintext);
    Some(privkey)
}

/// Create the "wallet_check" blob: `nonce(12) + ciphertext` of a
/// known plaintext.  Used to verify the passphrase on startup.
pub fn create_check_blob(key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, CHECK_PLAINTEXT.as_slice())
        .expect("encrypt check");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Verify a passphrase against the stored check blob.
pub fn verify_check_blob(key: &[u8; 32], blob: &[u8]) -> bool {
    if blob.len() < NONCE_LEN + 16 {
        return false;
    }
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let ciphertext = &blob[NONCE_LEN..];
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext.as_slice() == CHECK_PLAINTEXT,
        Err(_) => false,
    }
}
