//! Hierarchical Deterministic wallet (BIP32/39/44).
//!
//! A single 24-word mnemonic seed phrase generates every key the
//! wallet will ever need.  Derivation follows the BIP44 path
//! `m/44'/coin_type'/0'/0/<index>`.  The `coin_type` is supplied by
//! the caller so this crate stays network-agnostic — see
//! [`bitaiir_types::Network::bip44_coin_type`] for BitAiir's values.
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
/// Path: `m/44'/<coin_type>'/0'/0/<index>`.  The caller supplies
/// `coin_type` (8800 for BitAiir mainnet, 1 for any testnet per
/// SLIP-0044).
///
/// Returns `(private_key, public_key, address, recipient_hash)`.
pub fn derive_keypair(
    mnemonic: &bip39::Mnemonic,
    coin_type: u32,
    index: u32,
) -> (PrivateKey, PublicKey, String, [u8; 20]) {
    let seed = mnemonic.to_seed("");

    let path: bip32::DerivationPath = format!("m/44'/{coin_type}'/0'/0/{index}")
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

    /// Mainnet coin type — used by every test below that doesn't
    /// specifically exercise the multi-network behaviour.
    const TEST_COIN_TYPE: u32 = 8800;

    #[test]
    fn derivation_is_deterministic() {
        let m = generate_mnemonic();
        let (_, _, addr1, _) = derive_keypair(&m, TEST_COIN_TYPE, 0);
        let (_, _, addr2, _) = derive_keypair(&m, TEST_COIN_TYPE, 0);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn different_indices_produce_different_addresses() {
        let m = generate_mnemonic();
        let (_, _, addr0, _) = derive_keypair(&m, TEST_COIN_TYPE, 0);
        let (_, _, addr1, _) = derive_keypair(&m, TEST_COIN_TYPE, 1);
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn different_coin_types_produce_different_addresses() {
        // Mainnet (8800) and testnet (1) must derive distinct
        // addresses from the same seed — that's the whole point of
        // the BIP44 coin_type field.
        let m = generate_mnemonic();
        let (_, _, mainnet_addr, _) = derive_keypair(&m, 8800, 0);
        let (_, _, testnet_addr, _) = derive_keypair(&m, 1, 0);
        assert_ne!(mainnet_addr, testnet_addr);
    }

    #[test]
    fn derived_key_can_sign_and_verify() {
        use crate::hash::double_sha256;
        let m = generate_mnemonic();
        let (privkey, pubkey, _, _) = derive_keypair(&m, TEST_COIN_TYPE, 0);
        let digest = double_sha256(b"test message");
        let sig = privkey.sign_digest(&digest);
        assert!(pubkey.verify_digest(&digest, &sig));
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        assert!(parse_mnemonic("not a valid mnemonic").is_err());
    }
}
