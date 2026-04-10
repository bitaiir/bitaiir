//! **Proof of Aiir** — the block-level proof-of-work function.
//!
//! The full algorithm (protocol §8.2) wraps `double_sha256` in an
//! Argon2id memory-hard step so that ASIC and GPU miners cannot
//! outperform commodity CPUs:
//!
//! ```text
//! fn aiir_pow(header) -> Hash256:
//!     header_bytes = canonical_encode(header)
//!     seed         = sha256(header_bytes)                    // Step 1
//!     salt         = header.prev_block_hash[..16]            // 16 bytes
//!     memory_work  = argon2id(seed, salt, 64 MiB, 1, 1, 32) // Step 2
//!     return double_sha256(header_bytes || memory_work)       // Step 3
//! ```
//!
//! Steps 1 and 3 are fast SHA-256 operations already implemented in
//! `bitaiir-crypto`. Step 2 is the anti-ASIC barrier: Argon2id forces
//! every mining attempt to allocate and sequentially traverse tens of
//! megabytes of RAM, which commodity DDR4/DDR5 handles well but which
//! is prohibitively expensive to replicate in custom silicon.
//!
//! The function is pure: the same `BlockHeader` always produces the
//! same hash. Verification and mining run the identical code path.
//!
//! # Test vs production parameters
//!
//! The Argon2id memory cost is configured via
//! [`consensus::AIIR_POW_MEMORY_KIB`](crate::consensus::AIIR_POW_MEMORY_KIB).
//! In `#[cfg(test)]` builds this is 256 KiB for fast iteration; in
//! production it is the full 64 MiB specified by the protocol.

use argon2::{Algorithm, Argon2, Params, Version};
use bitaiir_crypto::hash::{double_sha256, sha256};
use bitaiir_types::{Hash256, encoding};

use crate::consensus::{
    AIIR_POW_MEMORY_KIB, AIIR_POW_OUTPUT_LEN, AIIR_POW_PARALLELISM, AIIR_POW_TIME_COST,
};

/// Compute the Proof-of-Aiir hash for a block header.
///
/// This is the function a miner grinds (varying `header.nonce`) and a
/// validator runs once to check the result against the target.
pub fn aiir_pow(header: &bitaiir_types::BlockHeader) -> Hash256 {
    // Canonical-encode the header into bytes. This is the data the
    // miner commits to; changing any header field (including nonce)
    // changes the resulting hash.
    let header_bytes = encoding::to_bytes(header).expect("BlockHeader always encodes");

    // Step 1: fast SHA-256 seed. This 32-byte digest feeds into
    // Argon2id as the "password" parameter.
    let seed = sha256(&header_bytes);

    // The salt is drawn from the header's prev_block_hash so each
    // chain tip produces a fresh Argon2id memory pattern and an
    // attacker cannot precompute a rainbow table of Argon2 outputs.
    let salt = &header.prev_block_hash.as_bytes()[..16];

    // Step 2: Argon2id memory-hard computation. This is the dominant
    // cost of each mining attempt and the reason ASICs cannot
    // trivially outperform CPUs.
    let params = Params::new(
        AIIR_POW_MEMORY_KIB,
        AIIR_POW_TIME_COST,
        AIIR_POW_PARALLELISM,
        Some(AIIR_POW_OUTPUT_LEN),
    )
    .expect("Argon2 params are known-valid constants");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut memory_work = [0u8; 32];
    argon2
        .hash_password_into(&seed, salt, &mut memory_work)
        .expect("Argon2 hash cannot fail with valid params and sufficient output buffer");

    // Step 3: final identity hash. Concatenate the original header
    // bytes with the Argon2 output, then double-SHA-256 the result.
    // This keeps the "Bitcoin-flavored" SHA-256d as the outermost
    // layer, which is a deliberate design choice (see protocol §8.2).
    let mut combined = Vec::with_capacity(header_bytes.len() + memory_work.len());
    combined.extend_from_slice(&header_bytes);
    combined.extend_from_slice(&memory_work);

    Hash256::from_bytes(double_sha256(&combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitaiir_types::BlockHeader;

    #[test]
    fn aiir_pow_is_deterministic() {
        let header = BlockHeader::default();
        assert_eq!(aiir_pow(&header), aiir_pow(&header));
    }

    #[test]
    fn aiir_pow_changes_with_nonce() {
        let h1 = BlockHeader::default();
        let h2 = BlockHeader {
            nonce: 1,
            ..BlockHeader::default()
        };
        assert_ne!(aiir_pow(&h1), aiir_pow(&h2));
    }

    #[test]
    fn aiir_pow_changes_with_prev_block_hash() {
        // The prev_block_hash feeds into the Argon2id salt, so two
        // headers that differ only in their parent should produce
        // different hashes even if everything else (including nonce)
        // is identical.
        let h1 = BlockHeader {
            prev_block_hash: Hash256::from_bytes([0x00; 32]),
            ..BlockHeader::default()
        };
        let h2 = BlockHeader {
            prev_block_hash: Hash256::from_bytes([0x01; 32]),
            ..BlockHeader::default()
        };
        assert_ne!(aiir_pow(&h1), aiir_pow(&h2));
    }

    #[test]
    fn aiir_pow_differs_from_plain_double_sha256() {
        // Confirm the Argon2id step is actually changing the result.
        // If we accidentally skip it, the hash would equal
        // double_sha256(header_bytes) — this test catches that.
        let header = BlockHeader::default();
        let header_bytes = encoding::to_bytes(&header).unwrap();
        let plain = Hash256::from_bytes(double_sha256(&header_bytes));
        let real = aiir_pow(&header);
        assert_ne!(real, plain, "aiir_pow must differ from plain double_sha256");
    }
}
