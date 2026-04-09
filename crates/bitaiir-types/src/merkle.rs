//! Merkle root computation, Bitcoin-style.
//!
//! Given a list of hashes (typically transaction IDs), the merkle root is
//! the recursive pairwise `double_sha256` of the list, reducing level by
//! level until a single hash remains.
//!
//! The construction is:
//!
//! 1. If the input is empty, the root is defined as [`Hash256::ZERO`].
//! 2. If the input has exactly one element, the root is that element.
//! 3. Otherwise, while the current level has more than one hash:
//!    - If the level has an odd number of hashes, duplicate the last hash
//!      so every hash has a partner.
//!    - Concatenate each pair into a 64-byte buffer and hash it with
//!      `double_sha256`. The resulting hashes form the next level.
//!
//! # CVE-2012-2459
//!
//! Bitcoin's merkle construction has a known malleability issue: a block
//! with `N` transactions and a block with `N + k` transactions where the
//! last `k` duplicate the preceding one can produce the same merkle root,
//! because the duplicate-last-on-odd rule is not injective. We inherit
//! that behavior here for protocol consistency. The mitigation — which
//! belongs in `bitaiir-chain`, not here — is to reject blocks containing
//! duplicate transactions.

use bitaiir_crypto::hash::double_sha256;

use crate::hash::Hash256;

/// Compute the merkle root of a slice of hashes.
pub fn merkle_root(hashes: &[Hash256]) -> Hash256 {
    if hashes.is_empty() {
        return Hash256::ZERO;
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current: Vec<Hash256> = hashes.to_vec();
    while current.len() > 1 {
        if current.len() % 2 == 1 {
            // Duplicate the last hash so the level has an even number of
            // entries. This is the CVE-2012-2459 quirk we deliberately
            // inherit.
            let last = *current
                .last()
                .expect("current.len() >= 1 checked above in the loop condition");
            current.push(last);
        }

        let mut next: Vec<Hash256> = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks_exact(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(pair[0].as_bytes());
            buf[32..].copy_from_slice(pair[1].as_bytes());
            next.push(Hash256::from_bytes(double_sha256(&buf)));
        }
        current = next;
    }

    current[0]
}
