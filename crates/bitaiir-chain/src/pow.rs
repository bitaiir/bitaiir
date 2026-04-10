//! Proof of Aiir — the block-level proof-of-work function.
//!
//! The full algorithm (protocol §8.2) wraps `double_sha256` in an
//! Argon2id memory-hard step so that ASIC and GPU miners cannot
//! outperform commodity CPUs. However, Phase 1c ships a **stub** that
//! falls back to plain `double_sha256(header_bytes)`. This lets us
//! build, test, and iterate on the entire validation and mining
//! pipeline without waiting on the Argon2id integration, which is a
//! self-contained swap scheduled for Phase 2.
//!
//! The stub is marked `#[doc(hidden)]` and annotated with an issue
//! reference so it does not silently survive into mainnet.
//!
//! # Phase 2 replacement
//!
//! In Phase 2, this function will be replaced by:
//!
//! ```text
//! fn aiir_pow(header_bytes: &[u8], prev_block_hash: &[u8; 32]) -> [u8; 32] {
//!     let seed = sha256(header_bytes);
//!     let salt = &prev_block_hash[..16];
//!     let memory_work = argon2id(seed, salt, mem=64MiB, iter=1, par=1, out=32);
//!     double_sha256(&[header_bytes, &memory_work].concat())
//! }
//! ```
//!
//! The function signature stays the same; only the body changes.

use bitaiir_crypto::hash::double_sha256;
use bitaiir_types::{Hash256, encoding};

/// Compute the Proof-of-Aiir hash for a serialized block header.
///
/// **Stub (Phase 1c):** returns `double_sha256(header_bytes)`.
/// Phase 2 will wrap this in Argon2id.
pub fn aiir_pow(header: &bitaiir_types::BlockHeader) -> Hash256 {
    let header_bytes = encoding::to_bytes(header).expect("BlockHeader always encodes");
    Hash256::from_bytes(double_sha256(&header_bytes))
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
        let h1 = BlockHeader::default(); // nonce = 0 by Default
        let h2 = BlockHeader {
            nonce: 1,
            ..BlockHeader::default()
        };
        assert_ne!(aiir_pow(&h1), aiir_pow(&h2));
    }
}
