//! Hierarchical Deterministic wallet (BIP32/39/44).
//!
//! A single 24-word mnemonic seed phrase generates every key the
//! wallet will ever need.  Derivation follows the BIP44 path
//! `m/44'/8888'/0'/0/<index>` where 8888 is BitAiir's coin type.
//!
//! Flow:
//! 1. Generate or import a BIP39 mnemonic (24 words, 256 bits).
//! 2. Derive a 512-bit seed via PBKDF2-HMAC-SHA512.
//! 3. Derive the BIP32 master key from the seed.
//! 4. Walk the BIP44 path to the account level.
//! 5. For each new address, derive the next child index.

use crate::hash::hash160;
use crate::key::{PrivateKey, PublicKey};
use rand::RngCore;

/// BIP44 coin type for BitAiir (unregistered placeholder).
const COIN_TYPE: u32 = 8888;

/// Generate a new 24-word BIP39 mnemonic from OS entropy.
pub fn generate_mnemonic() -> bip39::Mnemonic {
    let mut entropy = [0u8; 32]; // 256 bits → 24 words
    rand::thread_rng().fill_bytes(&mut entropy);
    bip39::Mnemonic::from_entropy(&entropy).expect("valid entropy for 24-word mnemonic")
}

/// Parse and validate a mnemonic phrase string.
pub fn parse_mnemonic(phrase: &str) -> Result<bip39::Mnemonic, String> {
    bip39::Mnemonic::parse(phrase).map_err(|e| format!("invalid mnemonic: {e}"))
}

/// Derive a keypair at the given BIP44 index from a mnemonic.
///
/// Path: `m/44'/8888'/0'/0/<index>`
///
/// Returns `(private_key, public_key, address, recipient_hash)`.
pub fn derive_keypair(
    mnemonic: &bip39::Mnemonic,
    index: u32,
) -> (PrivateKey, PublicKey, String, [u8; 20]) {
    let seed = mnemonic.to_seed("");

    // BIP44 path: m / 44' / 8888' / 0' / 0 / index
    let path: bip32::DerivationPath = format!("m/44'/{COIN_TYPE}'/0'/0/{index}")
        .parse()
        .expect("valid BIP44 path");

    let child = bip32::XPrv::derive_from_path(seed, &path).expect("BIP32 child derivation");

    let privkey_bytes: [u8; 32] = child.to_bytes();
    let privkey = PrivateKey::from_bytes(&privkey_bytes).expect("valid secp256k1 private key");
    let pubkey = privkey.public_key();

    let pubkey_bytes = pubkey.to_compressed();
    let recipient_hash = hash160(&pubkey_bytes);
    let address = crate::address::Address::from_recipient_hash(&recipient_hash).to_string();

    (privkey, pubkey, address, recipient_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_words() {
        let m = generate_mnemonic();
        assert_eq!(m.word_count(), 24);
    }

    #[test]
    fn parse_round_trips() {
        let m = generate_mnemonic();
        let phrase = m.to_string();
        let m2 = parse_mnemonic(&phrase).unwrap();
        assert_eq!(m.to_string(), m2.to_string());
    }

    #[test]
    fn derivation_is_deterministic() {
        let m = generate_mnemonic();
        let (_, _, addr1, _) = derive_keypair(&m, 0);
        let (_, _, addr2, _) = derive_keypair(&m, 0);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn different_indices_produce_different_addresses() {
        let m = generate_mnemonic();
        let (_, _, addr0, _) = derive_keypair(&m, 0);
        let (_, _, addr1, _) = derive_keypair(&m, 1);
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn derived_key_can_sign_and_verify() {
        use crate::hash::double_sha256;
        let m = generate_mnemonic();
        let (privkey, pubkey, _, _) = derive_keypair(&m, 0);
        let digest = double_sha256(b"test message");
        let sig = privkey.sign_digest(&digest);
        assert!(pubkey.verify_digest(&digest, &sig));
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(parse_mnemonic("not a valid mnemonic").is_err());
    }
}
