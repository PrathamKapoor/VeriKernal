//! Domain-separated Merkle trees and audit paths for uneven leaf counts.
use crate::ratchet::hash;
/// Hash a leaf with the RFC 9162 zero-byte domain separator. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn leaf_hash(d: &[u8]) -> [u8; 32] {
    hash(&[&[0], d])
}
/// Hash a pair of child digests with the internal-node separator. Complexity: O(1) time and space.
pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    hash(&[&[1], l, r])
}
/// Find the largest power of two strictly below the leaf count. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}
/// State retained by MerkleTree. Space O(n) in owned entries.
pub struct MerkleTree {
    pub leaves: Vec<Vec<u8>>,
}
impl MerkleTree {
    /// Compute the Merkle tree head using the largest-power split. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn root(&self) -> [u8; 32] {
        root(&self.leaves)
    }
    /// Build an audit path for a valid leaf index. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    pub fn prove_inclusion(&self, m: usize) -> Option<Vec<[u8; 32]>> {
        if m >= self.leaves.len() {
            return None;
        }
        Some(prove(m, &self.leaves))
    }
}
/// Compute the Merkle tree head using the largest-power split. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn root(d: &[Vec<u8>]) -> [u8; 32] {
    match d.len() {
        0 => hash(&[b""]),
        1 => leaf_hash(&d[0]),
        n => {
            let k = split(n);
            node_hash(&root(&d[..k]), &root(&d[k..]))
        }
    }
}
/// Collect sibling roots along the selected recursive branch. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
fn prove(m: usize, d: &[Vec<u8>]) -> Vec<[u8; 32]> {
    if d.len() == 1 {
        return vec![];
    }
    let k = split(d.len());
    let (mut p, s) = if m < k {
        (prove(m, &d[..k]), root(&d[k..]))
    } else {
        (prove(m - k, &d[k..]), root(&d[..k]))
    };
    p.push(s);
    p
}
/// Reconstruct an audit path and compare its root. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
pub fn verify_inclusion(d: &[u8], m: usize, n: usize, p: &[[u8; 32]], expected: &[u8; 32]) -> bool {
    /// Traverse the selected subtree and consume its audit siblings. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn walk(d: &[u8], m: usize, n: usize, p: &[[u8; 32]]) -> Option<[u8; 32]> {
        if n == 1 {
            return if p.is_empty() {
                Some(leaf_hash(d))
            } else {
                None
            };
        }
        let (s, rest) = p.split_last()?;
        let k = split(n);
        if m < k {
            Some(node_hash(&walk(d, m, k, rest)?, s))
        } else {
            Some(node_hash(s, &walk(d, m - k, n - k, rest)?))
        }
    }
    n > 0 && m < n && walk(d, m, n, p).as_ref() == Some(expected)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Check uneven trees against the expected result. Complexity: O(n + W) time and O(n + M) space, including called operations W and retained state M.
    fn uneven_trees() -> () {
        for n in 1..33 {
            let t = MerkleTree {
                leaves: (0..n).map(|i| vec![i as u8]).collect(),
            };
            for i in 0..n {
                let p = t.prove_inclusion(i).unwrap();
                assert!(verify_inclusion(&t.leaves[i], i, n, &p, &t.root()));
                assert!(!verify_inclusion(b"changed", i, n, &p, &t.root()));
            }
        }
    }
}
