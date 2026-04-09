//! Cross-language test vectors for `bitaiir-crypto`.
//!
//! These tests load the JSON file produced by the Python reference
//! implementation (see `reference/python/src/bitaiir/tools/generate_vectors.py`)
//! and assert that the Rust implementation produces byte-for-byte identical
//! output. If anything in this file fails, either:
//!
//! 1. A bug was introduced in the Rust implementation, or
//! 2. The Python reference was changed without regenerating the vectors, or
//! 3. The vectors were regenerated but the Rust code was not updated.
//!
//! Phase A validates the `hash`, `hmac_sha256`, and `base58` sections.
//! Phase B adds the `keys` section (private keys, public keys, addresses,
//! and WIFs).
//! Phase C adds the `msg_magic`, `signatures`, and `verify_known` sections
//! (Bitcoin-style signed messages with public-key recovery).

use std::path::PathBuf;

use bitaiir_crypto::{Address, PrivateKey, base58, hash, hmac, signature, wif};
use serde::Deserialize;

// --- JSON shape --------------------------------------------------------- //

#[derive(Debug, Deserialize)]
struct Vectors {
    hash: Vec<HashVector>,
    hmac_sha256: Vec<HmacVector>,
    base58: Vec<Base58Vector>,
    keys: Vec<KeyVector>,
    msg_magic: Vec<MsgMagicVector>,
    signatures: Vec<SignatureVector>,
    verify_known: Vec<VerifyKnownVector>,
}

#[derive(Debug, Deserialize)]
struct HashVector {
    input_hex: String,
    sha256_hex: String,
    double_sha256_hex: String,
    ripemd160_hex: String,
    hash160_hex: String,
}

#[derive(Debug, Deserialize)]
struct HmacVector {
    key_hex: String,
    message_hex: String,
    hmac_sha256_hex: String,
}

#[derive(Debug, Deserialize)]
struct Base58Vector {
    input_hex: String,
    base58: String,
}

#[derive(Debug, Deserialize)]
struct KeyVector {
    private_key_hex: String,
    public_key_compressed_hex: String,
    public_key_uncompressed_hex: String,
    address_compressed: String,
    address_uncompressed: String,
    wif_compressed: String,
    wif_uncompressed: String,
}

#[derive(Debug, Deserialize)]
struct MsgMagicVector {
    message: String,
    msg_magic_hex: String,
    double_sha256_of_magic_hex: String,
}

// The Python generator emits either a full entry with `address_*` and
// `signature_*` fields, or a short entry with just an `error` field if
// signing raised. `#[serde(default)]` lets both shapes deserialize into the
// same struct, with the absent fields ending up as `None`.
#[derive(Debug, Deserialize)]
struct SignatureVector {
    message: String,
    wif_compressed: String,
    wif_uncompressed: String,
    #[serde(default)]
    address_compressed: Option<String>,
    #[serde(default)]
    address_uncompressed: Option<String>,
    #[serde(default)]
    signature_compressed_b64: Option<String>,
    #[serde(default)]
    signature_uncompressed_b64: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyKnownVector {
    address: String,
    message: String,
    signature: String,
    note: String,
    expected_verified: bool,
    #[serde(default)]
    recovered_public_key_hex: Option<String>,
    #[serde(default)]
    expected_error: Option<String>,
}

// --- Helpers ------------------------------------------------------------- //

/// Load `tests/vectors/crypto.json` from the workspace root, regardless of
/// where `cargo test` was invoked from. `CARGO_MANIFEST_DIR` is set by Cargo
/// at compile time to the directory containing the crate's `Cargo.toml`.
fn load_vectors() -> Vectors {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "tests",
        "vectors",
        "crypto.json",
    ]
    .iter()
    .collect();

    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex {s:?}: {e}"))
}

// --- Tests --------------------------------------------------------------- //

#[test]
fn hash_section() {
    let vectors = load_vectors();
    assert!(!vectors.hash.is_empty(), "hash section is empty");

    for (i, case) in vectors.hash.iter().enumerate() {
        let input = from_hex(&case.input_hex);

        assert_eq!(
            hex::encode(hash::sha256(&input)),
            case.sha256_hex,
            "hash[{i}] sha256 mismatch for input {:?}",
            case.input_hex,
        );
        assert_eq!(
            hex::encode(hash::double_sha256(&input)),
            case.double_sha256_hex,
            "hash[{i}] double_sha256 mismatch for input {:?}",
            case.input_hex,
        );
        assert_eq!(
            hex::encode(hash::ripemd160(&input)),
            case.ripemd160_hex,
            "hash[{i}] ripemd160 mismatch for input {:?}",
            case.input_hex,
        );
        assert_eq!(
            hex::encode(hash::hash160(&input)),
            case.hash160_hex,
            "hash[{i}] hash160 mismatch for input {:?}",
            case.input_hex,
        );
    }
}

#[test]
fn hmac_section() {
    let vectors = load_vectors();
    assert!(!vectors.hmac_sha256.is_empty(), "hmac section is empty");

    for (i, case) in vectors.hmac_sha256.iter().enumerate() {
        let key = from_hex(&case.key_hex);
        let message = from_hex(&case.message_hex);

        assert_eq!(
            hex::encode(hmac::hmac_sha256(&key, &message)),
            case.hmac_sha256_hex,
            "hmac[{i}] mismatch for key {:?}, message {:?}",
            case.key_hex,
            case.message_hex,
        );
    }
}

#[test]
fn base58_section_encode() {
    let vectors = load_vectors();
    assert!(!vectors.base58.is_empty(), "base58 section is empty");

    for (i, case) in vectors.base58.iter().enumerate() {
        let input = from_hex(&case.input_hex);
        assert_eq!(
            base58::encode(&input),
            case.base58,
            "base58[{i}] encode mismatch for input {:?}",
            case.input_hex,
        );
    }
}

#[test]
fn base58_section_decode_round_trip() {
    let vectors = load_vectors();

    for (i, case) in vectors.base58.iter().enumerate() {
        let expected = from_hex(&case.input_hex);
        let decoded = base58::decode(&case.base58)
            .unwrap_or_else(|e| panic!("base58[{i}] decode failed for {:?}: {e}", case.base58,));
        assert_eq!(
            decoded, expected,
            "base58[{i}] decode round-trip mismatch for input {:?}",
            case.base58,
        );
    }
}

#[test]
fn keys_section() {
    let vectors = load_vectors();
    assert!(!vectors.keys.is_empty(), "keys section is empty");

    for (i, case) in vectors.keys.iter().enumerate() {
        // Parse the fixed 32-byte private key from the vector. `try_into`
        // on a `Vec<u8>` produces a fixed-size array if (and only if) the
        // lengths match, which catches malformed vectors at parse time.
        let priv_bytes: [u8; 32] = from_hex(&case.private_key_hex)
            .try_into()
            .expect("private_key_hex must decode to exactly 32 bytes");

        let private_key = PrivateKey::from_bytes(&priv_bytes)
            .unwrap_or_else(|e| panic!("keys[{i}] PrivateKey::from_bytes failed: {e}"));
        let public_key = private_key.public_key();

        // Public key serialization, both formats.
        assert_eq!(
            hex::encode(public_key.to_compressed()),
            case.public_key_compressed_hex,
            "keys[{i}] public_key_compressed mismatch",
        );
        assert_eq!(
            hex::encode(public_key.to_uncompressed()),
            case.public_key_uncompressed_hex,
            "keys[{i}] public_key_uncompressed mismatch",
        );

        // Address derivation, both formats.
        assert_eq!(
            Address::from_compressed_public_key(&public_key).as_str(),
            case.address_compressed,
            "keys[{i}] address_compressed mismatch",
        );
        assert_eq!(
            Address::from_uncompressed_public_key(&public_key).as_str(),
            case.address_uncompressed,
            "keys[{i}] address_uncompressed mismatch",
        );

        // WIF encoding, both formats.
        assert_eq!(
            wif::encode(&private_key, true),
            case.wif_compressed,
            "keys[{i}] wif_compressed mismatch",
        );
        assert_eq!(
            wif::encode(&private_key, false),
            case.wif_uncompressed,
            "keys[{i}] wif_uncompressed mismatch",
        );

        // WIF decoding: should return the original private key bytes and
        // the correct compression flag for each of the two WIF forms.
        let (decoded_c, compressed_c) = wif::decode(&case.wif_compressed)
            .unwrap_or_else(|e| panic!("keys[{i}] wif decode (compressed) failed: {e}"));
        assert!(compressed_c, "keys[{i}] compressed WIF reported flag=false");
        assert_eq!(
            decoded_c.to_bytes(),
            priv_bytes,
            "keys[{i}] compressed WIF round-trip produced wrong bytes",
        );

        let (decoded_u, compressed_u) = wif::decode(&case.wif_uncompressed)
            .unwrap_or_else(|e| panic!("keys[{i}] wif decode (uncompressed) failed: {e}"));
        assert!(
            !compressed_u,
            "keys[{i}] uncompressed WIF reported flag=true",
        );
        assert_eq!(
            decoded_u.to_bytes(),
            priv_bytes,
            "keys[{i}] uncompressed WIF round-trip produced wrong bytes",
        );
    }
}

#[test]
fn msg_magic_section() {
    let vectors = load_vectors();
    assert!(!vectors.msg_magic.is_empty(), "msg_magic section is empty");

    for (i, case) in vectors.msg_magic.iter().enumerate() {
        let magic = signature::msg_magic(&case.message);
        assert_eq!(
            hex::encode(&magic),
            case.msg_magic_hex,
            "msg_magic[{i}] prefix+varint+message mismatch for {:?}",
            case.message,
        );
        assert_eq!(
            hex::encode(hash::double_sha256(&magic)),
            case.double_sha256_of_magic_hex,
            "msg_magic[{i}] double_sha256 mismatch",
        );
    }
}

#[test]
fn signatures_section() {
    let vectors = load_vectors();
    assert!(
        !vectors.signatures.is_empty(),
        "signatures section is empty"
    );

    for (i, case) in vectors.signatures.iter().enumerate() {
        // Skip entries where Python failed to sign (currently none, but the
        // schema allows it so we tolerate it here).
        if case.error.is_some() {
            continue;
        }

        let expected_sig_c = case
            .signature_compressed_b64
            .as_ref()
            .expect("non-error vector must include a compressed signature");
        let expected_sig_u = case
            .signature_uncompressed_b64
            .as_ref()
            .expect("non-error vector must include an uncompressed signature");
        let expected_addr_c = case
            .address_compressed
            .as_ref()
            .expect("non-error vector must include a compressed address");
        let expected_addr_u = case
            .address_uncompressed
            .as_ref()
            .expect("non-error vector must include an uncompressed address");

        // Compressed WIF path: sign -> match expected bytes -> self-verify.
        let signed_c = signature::sign_message(&case.wif_compressed, &case.message)
            .unwrap_or_else(|e| panic!("signatures[{i}] compressed sign failed: {e}"));
        assert_eq!(
            signed_c.signature, *expected_sig_c,
            "signatures[{i}] compressed signature mismatch (message={:?})",
            case.message,
        );
        assert_eq!(
            signed_c.address.as_str(),
            expected_addr_c,
            "signatures[{i}] compressed address mismatch",
        );
        let outcome_c = signature::verify_message(expected_addr_c, &case.message, expected_sig_c)
            .unwrap_or_else(|e| panic!("signatures[{i}] compressed verify failed: {e}"));
        assert!(
            outcome_c.verified,
            "signatures[{i}] compressed signature did not self-verify",
        );

        // Uncompressed WIF path: same thing, different header byte range.
        let signed_u = signature::sign_message(&case.wif_uncompressed, &case.message)
            .unwrap_or_else(|e| panic!("signatures[{i}] uncompressed sign failed: {e}"));
        assert_eq!(
            signed_u.signature, *expected_sig_u,
            "signatures[{i}] uncompressed signature mismatch",
        );
        assert_eq!(
            signed_u.address.as_str(),
            expected_addr_u,
            "signatures[{i}] uncompressed address mismatch",
        );
        let outcome_u = signature::verify_message(expected_addr_u, &case.message, expected_sig_u)
            .unwrap_or_else(|e| panic!("signatures[{i}] uncompressed verify failed: {e}"));
        assert!(
            outcome_u.verified,
            "signatures[{i}] uncompressed signature did not self-verify",
        );
    }
}

#[test]
fn verify_known_section() {
    let vectors = load_vectors();
    assert!(
        !vectors.verify_known.is_empty(),
        "verify_known section is empty",
    );

    for (i, case) in vectors.verify_known.iter().enumerate() {
        let result = signature::verify_message(&case.address, &case.message, &case.signature);

        if case.expected_error.is_some() {
            // Python reported a structural error for this input; Rust must
            // also reject it with an Err, regardless of which specific error
            // variant comes back.
            assert!(
                result.is_err(),
                "verify_known[{i}] expected error but got Ok ({})",
                case.note,
            );
            continue;
        }

        let outcome = result
            .unwrap_or_else(|e| panic!("verify_known[{i}] unexpected error: {e} ({})", case.note));

        assert_eq!(
            outcome.verified, case.expected_verified,
            "verify_known[{i}] verified flag mismatch ({})",
            case.note,
        );

        // When the Python reference captured the recovered public key, the
        // Rust implementation must recover the same one. It may be stored in
        // either the compressed or uncompressed form depending on the
        // address's flavor, so accept either serialization.
        if let Some(expected_pk) = &case.recovered_public_key_hex {
            let compressed_hex = hex::encode(outcome.recovered_public_key.to_compressed());
            let uncompressed_hex = hex::encode(outcome.recovered_public_key.to_uncompressed());
            assert!(
                compressed_hex == *expected_pk || uncompressed_hex == *expected_pk,
                "verify_known[{i}] recovered pubkey mismatch ({}): \
                 expected {expected_pk}, got compressed={compressed_hex}, \
                 uncompressed={uncompressed_hex}",
                case.note,
            );
        }
    }
}
