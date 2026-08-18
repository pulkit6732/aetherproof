//! Merkle session tree — RFC 6962 style, byte-compatible with the Python
//! implementation in `aetherproof/core/session.py`.
//!
//! Author: Pulkit Kr Srivastava <pulkitsrivastavae@gmail.com>
//!
//! # Two properties the v0.2.x construction did not have
//!
//! 1. **No odd-leaf duplication.** Padding an odd level by hashing the last node
//!    against itself is the Bitcoin CVE-2012-2459 pattern: `[A,B,C]` and
//!    `[A,B,C,C]` produce an identical root, so a root does not identify a unique
//!    leaf set. An unpaired node is promoted to the next level unchanged.
//!
//! 2. **Leaf/internal domain separation.** Leaves hash under `0x00`, internal
//!    nodes under `0x01`, so an internal node cannot be presented as a leaf.
//!
//! # Encoding note, and why it looks odd
//!
//! Hashes are handled as lowercase hex **strings**, and the digest is taken over
//! the ASCII bytes of those strings rather than over the decoded 32-byte values:
//!
//! ```text
//! leaf(h)       = SHA256(0x00 ‖ ascii(h))
//! node(l, r)    = SHA256(0x01 ‖ ascii(l) ‖ ascii(r))
//! ```
//!
//! That is not the most compact choice, but it is what the Python implementation
//! and every receipt issued to date already do. Changing it here would silently
//! invalidate existing session seals, so this port matches it exactly. The
//! cross-language vector tests at the bottom of this file exist to keep it that
//! way.

use sha2::{Digest, Sha256};

/// Domain tag for leaves.
pub const LEAF_PREFIX: u8 = 0x00;

/// Domain tag for internal nodes.
pub const NODE_PREFIX: u8 = 0x01;

/// Which side of the parent a sibling sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is the left child; the running hash is the right child.
    Left,
    /// Sibling is the right child; the running hash is the left child.
    Right,
}

impl Side {
    /// The wire representation used by the Python implementation.
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Left => "L",
            Side::Right => "R",
        }
    }

    /// Parse the wire representation. Anything else is rejected.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "L" => Some(Side::Left),
            "R" => Some(Side::Right),
            _ => None,
        }
    }
}

/// One step of a sibling path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    pub side: Side,
    pub hash: String,
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex without a heap allocation per byte.
///
/// `format!("{b:02x}")` per byte allocates a `String` for every one of the 32
/// digest bytes, which dominated the cost of building a tree. This writes into a
/// single 64-byte stack buffer instead.
fn hex(digest: impl AsRef<[u8]>) -> String {
    let d = digest.as_ref();
    let mut out = vec![0u8; d.len() * 2];
    for (i, b) in d.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    // Every byte written is from HEX, so this is valid ASCII by construction.
    debug_assert!(out.is_ascii());
    unsafe { String::from_utf8_unchecked(out) }
}

/// Hash a leaf under the leaf domain tag.
pub fn merkle_leaf(leaf_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(leaf_hash.as_bytes());
    hex(h.finalize())
}

/// Hash an internal node under the node domain tag.
pub fn merkle_node(left: &str, right: &str) -> String {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    hex(h.finalize())
}

/// Bottom-up tree. `levels[0]` is the tagged leaves, `levels[last]` is `[root]`.
///
/// An empty input yields a single empty level, matching Python's `[[]]`.
pub fn build_levels(leaf_hashes: &[String]) -> Vec<Vec<String>> {
    if leaf_hashes.is_empty() {
        return vec![Vec::new()];
    }
    let leaves: Vec<String> = leaf_hashes.iter().map(|h| merkle_leaf(h)).collect();
    let mut levels: Vec<Vec<String>> = Vec::with_capacity(leaf_hashes.len().ilog2() as usize + 2);
    levels.push(leaves);

    while levels[levels.len() - 1].len() > 1 {
        let level = &levels[levels.len() - 1];
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node(&level[i], &level[i + 1]));
            } else {
                // Promote, never duplicate. See CVE-2012-2459.
                next.push(level[i].clone());
            }
            i += 2;
        }
        levels.push(next);
    }
    levels
}

/// Merkle root over the given leaf hashes. Empty input yields an empty string.
pub fn merkle_root(leaf_hashes: &[String]) -> String {
    if leaf_hashes.is_empty() {
        return String::new();
    }
    build_levels(leaf_hashes)
        .last()
        .and_then(|l| l.first())
        .cloned()
        .unwrap_or_default()
}

/// Sibling path for `index`.
///
/// A promoted node contributes no sibling at that level, so proofs are not all
/// the same length. That is expected, not a defect.
///
/// Returns `None` if `index` is out of range.
pub fn inclusion_proof(leaf_hashes: &[String], index: usize) -> Option<Vec<ProofStep>> {
    if index >= leaf_hashes.len() {
        return None;
    }
    let levels = build_levels(leaf_hashes);
    let mut proof = Vec::new();
    let mut idx = index;

    for level in &levels[..levels.len().saturating_sub(1)] {
        if idx % 2 == 0 {
            if idx + 1 < level.len() {
                proof.push(ProofStep {
                    side: Side::Right,
                    hash: level[idx + 1].clone(),
                });
            }
        } else {
            proof.push(ProofStep {
                side: Side::Left,
                hash: level[idx - 1].clone(),
            });
        }
        idx /= 2;
    }
    Some(proof)
}

/// Recompute the root from one leaf plus its sibling path and compare.
pub fn verify_inclusion(leaf_hash: &str, proof: &[ProofStep], root: &str) -> bool {
    let mut h = merkle_leaf(leaf_hash);
    for step in proof {
        h = match step.side {
            Side::Left => merkle_node(&step.hash, &h),
            Side::Right => merkle_node(&h, &step.hash),
        };
    }
    h == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<String> {
        (0..n).map(|i| hex(Sha256::digest(format!("turn-{i}")))).collect()
    }

    // ── Cross-language vectors ────────────────────────────────────────────────
    //
    // Generated by the Python implementation and pinned here. If either side's
    // encoding drifts, these fail. Regenerate with:
    //
    //   python -c "from aetherproof.core.session import merkle_root, inclusion_proof; ..."

    #[test]
    fn primitives_match_python_vectors() {
        assert_eq!(
            merkle_leaf(&"00".repeat(32)),
            "47eaf44a3be7b7c8abe73856caef3a30ac97094b85c34b79bfec2a79cd1c590b"
        );
        assert_eq!(
            merkle_node(&"aa".repeat(32), &"bb".repeat(32)),
            "7406acea1b8afac5f38946604c6f01133b29f252fd5bdefc1438f5e3a08ee7fd"
        );
    }

    #[test]
    fn roots_match_python_vectors() {
        // Every value produced by aetherproof/core/session.py::merkle_root over
        // leaves sha256("turn-0..n-1"). Sizes chosen to cover powers of two and
        // the odd-promotion cases between them.
        let expected: &[(usize, &str)] = &[
            (1,  "4dbad8342a2240656b97e52480adaaf7954b2b9813c534a9569af192c53dd3e4"),
            (2,  "9829f4139335ceb625ac092e88c68fc76eb0a3516be06f74d05e55149ed4cec5"),
            (3,  "4da490e57bf61c736b1b18abf5318f4ce430193afbdc884073514e7176a217b5"),
            (4,  "3ca28f3df3ea7fd1c7d0d1a0f7b558138260a5799911b75f899942410afe11ea"),
            (5,  "3185ed6541a5e9182d5eacf761b7c218ba6ec33fc5c8bf46612063f4d97093a9"),
            (7,  "61274ffe30d7e97a0d102660b14844b726968d42e10f189c97b9d057d0faa43f"),
            (8,  "8cd15a64cb8f02430d57b2a9c5a2d98910cfc852ea4bf8991ab69b4c5633b526"),
            (33, "809e90548dd36c6db0a656aac4c6cb6c443ab66718116e27b329ca2a2d37a429"),
        ];
        for (n, want) in expected {
            assert_eq!(
                merkle_root(&leaves(*n)),
                *want,
                "root over {n} leaves must match the Python implementation"
            );
        }
    }

    #[test]
    fn inclusion_proof_matches_python_vector() {
        // aetherproof/core/session.py::inclusion_proof(leaves(8), 3)
        let want: &[(Side, &str)] = &[
            (Side::Left,  "561f3f9028b884e7c55456d6ee3f9c05668e14d378f757e87cf5e028b031a175"),
            (Side::Left,  "9829f4139335ceb625ac092e88c68fc76eb0a3516be06f74d05e55149ed4cec5"),
            (Side::Right, "6e1e6ed81fdb93857e2a0e021f872e9b7d29a778f85a24558a69d854671754d6"),
        ];
        let l = leaves(8);
        let got = inclusion_proof(&l, 3).expect("index in range");
        assert_eq!(got.len(), want.len(), "proof length must match Python");
        for (i, (side, hash)) in want.iter().enumerate() {
            assert_eq!(got[i].side, *side, "step {i} side");
            assert_eq!(got[i].hash, *hash, "step {i} hash");
        }
        // And a proof built here must verify against the root Python computed.
        assert!(verify_inclusion(
            &l[3],
            &got,
            "8cd15a64cb8f02430d57b2a9c5a2d98910cfc852ea4bf8991ab69b4c5633b526"
        ));
    }

    #[test]
    fn empty_input_yields_empty_root() {
        assert_eq!(merkle_root(&[]), "");
        assert_eq!(build_levels(&[]), vec![Vec::<String>::new()]);
    }

    #[test]
    fn single_leaf_root_is_tagged_not_raw() {
        let l = leaves(1);
        let root = merkle_root(&l);
        assert_eq!(root, merkle_leaf(&l[0]));
        assert_ne!(root, l[0], "a one-leaf root must not be the raw input");
    }

    #[test]
    fn odd_leaf_is_promoted_not_duplicated() {
        // The CVE-2012-2459 property: [A,B,C] must differ from [A,B,C,C].
        let mut three = leaves(3);
        let mut four = three.clone();
        four.push(three[2].clone());
        assert_ne!(
            merkle_root(&three),
            merkle_root(&four),
            "duplicating the odd leaf must not produce the same root"
        );
        three.truncate(3);
    }

    #[test]
    fn domain_separation_holds() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        // A node hash must never collide with a leaf hash of the concatenation.
        assert_ne!(merkle_node(&a, &b), merkle_leaf(&format!("{a}{b}")));
    }

    #[test]
    fn every_leaf_proves_against_the_root() {
        for n in 1..=33usize {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let proof = inclusion_proof(&l, i).expect("index in range");
                assert!(
                    verify_inclusion(&l[i], &proof, &root),
                    "leaf {i} of {n} must prove against the root"
                );
            }
        }
    }

    #[test]
    fn proof_for_wrong_leaf_is_rejected() {
        let l = leaves(8);
        let root = merkle_root(&l);
        let proof = inclusion_proof(&l, 3).unwrap();
        assert!(verify_inclusion(&l[3], &proof, &root));
        assert!(
            !verify_inclusion(&l[4], &proof, &root),
            "a proof for turn 3 must not validate turn 4"
        );
    }

    #[test]
    fn tampered_sibling_breaks_the_proof() {
        let l = leaves(16);
        let root = merkle_root(&l);
        for i in 0..l.len() {
            let proof = inclusion_proof(&l, i).unwrap();
            for k in 0..proof.len() {
                let mut bad = proof.clone();
                let mut chars: Vec<char> = bad[k].hash.chars().collect();
                chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
                bad[k].hash = chars.into_iter().collect();
                assert!(
                    !verify_inclusion(&l[i], &bad, &root),
                    "flipping sibling {k} of leaf {i} must invalidate"
                );
            }
        }
    }

    #[test]
    fn flipped_side_breaks_the_proof() {
        let l = leaves(8);
        let root = merkle_root(&l);
        for i in 0..l.len() {
            let proof = inclusion_proof(&l, i).unwrap();
            for k in 0..proof.len() {
                let mut bad = proof.clone();
                bad[k].side = match bad[k].side {
                    Side::Left => Side::Right,
                    Side::Right => Side::Left,
                };
                // Swapping sides is only a no-op if the two children are equal,
                // which cannot happen for distinct leaves.
                assert!(
                    !verify_inclusion(&l[i], &bad, &root),
                    "flipping side at step {k} of leaf {i} must invalidate"
                );
            }
        }
    }

    #[test]
    fn out_of_range_index_returns_none() {
        let l = leaves(5);
        assert!(inclusion_proof(&l, 5).is_none());
        assert!(inclusion_proof(&l, 99).is_none());
        assert!(inclusion_proof(&[], 0).is_none());
    }

    #[test]
    fn proof_length_is_logarithmic() {
        let l = leaves(1000);
        let proof = inclusion_proof(&l, 500).unwrap();
        assert!(
            proof.len() <= 10,
            "1000 leaves must need at most ceil(log2(1000)) = 10 siblings, got {}",
            proof.len()
        );
    }

    #[test]
    fn reordering_leaves_changes_the_root() {
        let l = leaves(6);
        let mut swapped = l.clone();
        swapped.swap(0, 1);
        assert_ne!(merkle_root(&l), merkle_root(&swapped));
    }

    #[test]
    fn side_wire_format_roundtrips() {
        assert_eq!(Side::from_str("L"), Some(Side::Left));
        assert_eq!(Side::from_str("R"), Some(Side::Right));
        assert_eq!(Side::from_str("x"), None);
        assert_eq!(Side::Left.as_str(), "L");
        assert_eq!(Side::Right.as_str(), "R");
    }
}
