//! Bitcoin-style signed messages for BitAiir.
//!
//! This module implements the same message-signing scheme Bitcoin Core
//! exposes as `signmessage` / `verifymessage`, with two BitAiir-specific
//! differences:
//!
//! 1. The magic prefix string is `"BitAiir Signed Message:\n"` instead of
//!    `"Bitcoin Signed Message:\n"`.
//! 2. Addresses are derived using the `"aiir"` prefix defined in
//!    [`crate::address`].
//!
//! Signing uses RFC 6979 deterministic nonces via libsecp256k1, so the same
//! `(private_key, message)` pair always produces byte-identical output.
//! That property is what makes the fixed vectors in
//! `tests/vectors/crypto.json` useful: any divergence between Rust and the
//! Python reference is either a bug or an intentional protocol change.
//!
//! # Wire format
//!
//! A signed message is a 65-byte blob, base64-encoded:
//!
//! - 1 byte: header encoding the ECDSA recovery ID and the compression
//!   flag. Values `27..=30` mean "uncompressed P2PKH, recid = value - 27";
//!   values `31..=34` mean "compressed P2PKH, recid = value - 31".
//! - 32 bytes: big-endian `r`.
//! - 32 bytes: big-endian `s` (always the low-s canonical form).
//!
//! The ECDSA input is `double_sha256(msg_magic(message))`, where
//! [`msg_magic`] prepends a length-prefixed magic string to the user
//! message so signatures cannot be replayed outside the BitAiir context.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use secp256k1::{
    Message, SECP256K1,
    ecdsa::{RecoverableSignature, RecoveryId},
};

use crate::address::Address;
use crate::error::{Error, Result};
use crate::hash::double_sha256;
use crate::key::PublicKey;
use crate::wif;

/// The fixed magic prefix string inserted before every signed message,
/// before the user-supplied content and before its length varint.
pub const MESSAGE_MAGIC_PREFIX: &[u8] = b"BitAiir Signed Message:\n";

/// Total size of a decoded signature: one header byte plus 64 bytes of
/// compact `(r, s)`.
const SIGNATURE_LENGTH: usize = 65;

// --- Varint + msg_magic --------------------------------------------------- //

/// Encode an unsigned integer as a Bitcoin-style variable-length integer.
///
/// The output is 1, 3, 5, or 9 bytes depending on the value. This matches
/// the encoding used by Bitcoin and the BitAiir Python reference.
pub fn varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut out = Vec::with_capacity(3);
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out
    } else if n <= 0xffff_ffff {
        let mut out = Vec::with_capacity(5);
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out
    } else {
        let mut out = Vec::with_capacity(9);
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
        out
    }
}

/// Build the magic-prefixed byte sequence that is fed into ECDSA.
///
/// The layout is:
///
/// `varint(prefix_len) || MESSAGE_MAGIC_PREFIX || varint(msg_len) || msg`
///
/// Callers should hash the result with [`double_sha256`] before signing or
/// verifying.
pub fn msg_magic(message: &str) -> Vec<u8> {
    let msg_bytes = message.as_bytes();
    let prefix_len = varint(MESSAGE_MAGIC_PREFIX.len() as u64);
    let msg_len = varint(msg_bytes.len() as u64);

    let mut out = Vec::with_capacity(
        prefix_len.len() + MESSAGE_MAGIC_PREFIX.len() + msg_len.len() + msg_bytes.len(),
    );
    out.extend_from_slice(&prefix_len);
    out.extend_from_slice(MESSAGE_MAGIC_PREFIX);
    out.extend_from_slice(&msg_len);
    out.extend_from_slice(msg_bytes);
    out
}

// --- Public API types ----------------------------------------------------- //

/// A successfully signed message, ready to be transmitted.
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The BitAiir address associated with the signing key.
    pub address: Address,
    /// The original plaintext message.
    pub message: String,
    /// The base64-encoded 65-byte signature (header || r || s).
    pub signature: String,
}

/// Outcome of a successful `verify_message` call.
///
/// `verified` answers the yes/no question. `recovered_public_key` is the
/// public key whose address the recovered signature would correspond to,
/// surfaced so that callers (or tests) can inspect it.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub verified: bool,
    pub recovered_public_key: PublicKey,
}

// --- Sign ----------------------------------------------------------------- //

/// Sign `message` with the private key encoded in `wif_str`.
///
/// The compression flag stored in the WIF determines whether the resulting
/// signature's header byte advertises compressed (values `31..=34`) or
/// uncompressed (`27..=30`) P2PKH. The derived [`Address`] matches that
/// flag, so the output is self-consistent.
///
/// Because libsecp256k1 uses RFC 6979 internally, this function is
/// deterministic: identical inputs always produce identical output.
pub fn sign_message(wif_str: &str, message: &str) -> Result<SignedMessage> {
    let (private_key, compressed) = wif::decode(wif_str)?;
    let public_key = private_key.public_key();

    let address = if compressed {
        Address::from_compressed_public_key(&public_key)
    } else {
        Address::from_uncompressed_public_key(&public_key)
    };

    let digest = double_sha256(&msg_magic(message));
    let msg = Message::from_digest(digest);

    let recoverable = SECP256K1.sign_ecdsa_recoverable(&msg, private_key.as_secp256k1());
    let (recovery_id, compact) = recoverable.serialize_compact();

    let header = build_header_byte(recovery_id, compressed);
    let mut sig_bytes = Vec::with_capacity(SIGNATURE_LENGTH);
    sig_bytes.push(header);
    sig_bytes.extend_from_slice(&compact);

    Ok(SignedMessage {
        address,
        message: message.to_owned(),
        signature: BASE64.encode(&sig_bytes),
    })
}

// --- Verify --------------------------------------------------------------- //

/// Verify a signed message against an expected address.
///
/// Returns:
///
/// - `Err(Error::InvalidSignature(_))` — the signature is structurally
///   invalid (bad base64, wrong length, header byte out of range,
///   uninvertible `(r, s)`, or public-key recovery failed).
/// - `Ok(VerifyOutcome { verified: false, .. })` — the signature is
///   structurally valid but recovers a public key whose derived address
///   does not match `address`.
/// - `Ok(VerifyOutcome { verified: true, .. })` — the signature is valid
///   and the recovered address matches.
pub fn verify_message(address: &str, message: &str, signature_b64: &str) -> Result<VerifyOutcome> {
    let raw = BASE64
        .decode(signature_b64)
        .map_err(|_| Error::InvalidSignature("not valid base64"))?;
    if raw.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignature("wrong byte length"));
    }

    let header = raw[0];
    // `raw[1..]` is guaranteed to be 64 bytes because `raw.len() == 65`.
    let compact: [u8; 64] = raw[1..]
        .try_into()
        .expect("length was checked to be exactly 65");

    let (recovery_id, compressed) = parse_header_byte(header)?;
    let recoverable = RecoverableSignature::from_compact(&compact, recovery_id)
        .map_err(|_| Error::InvalidSignature("compact bytes out of range"))?;

    let digest = double_sha256(&msg_magic(message));
    let msg = Message::from_digest(digest);

    let recovered = SECP256K1
        .recover_ecdsa(&msg, &recoverable)
        .map_err(|_| Error::InvalidSignature("public-key recovery failed"))?;
    let recovered_public_key = PublicKey::from_secp256k1(recovered);

    let recovered_address = if compressed {
        Address::from_compressed_public_key(&recovered_public_key)
    } else {
        Address::from_uncompressed_public_key(&recovered_public_key)
    };

    Ok(VerifyOutcome {
        verified: recovered_address.as_str() == address,
        recovered_public_key,
    })
}

// --- Header byte helpers -------------------------------------------------- //

/// Pack a recovery ID and compression flag into a header byte.
///
/// The encoding is `27 + recovery_id + (4 if compressed else 0)`, matching
/// the convention used by Bitcoin's `signmessage`.
fn build_header_byte(recovery_id: RecoveryId, compressed: bool) -> u8 {
    let rid: i32 = recovery_id.into();
    debug_assert!((0..=3).contains(&rid), "recovery id must be in 0..=3");
    27 + rid as u8 + if compressed { 4 } else { 0 }
}

/// Unpack a header byte into a recovery ID and compression flag.
fn parse_header_byte(header: u8) -> Result<(RecoveryId, bool)> {
    if !(27..=34).contains(&header) {
        return Err(Error::InvalidSignature("header byte out of range"));
    }
    let compressed = header >= 31;
    let rid_value: i32 = if compressed {
        (header - 31) as i32
    } else {
        (header - 27) as i32
    };
    let recovery_id = RecoveryId::try_from(rid_value)
        .map_err(|_| Error::InvalidSignature("invalid recovery id"))?;
    Ok((recovery_id, compressed))
}
