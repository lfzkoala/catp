use crate::hash::{Commitment, CommitmentScheme};
use std::collections::HashMap;

const TREE_DEPTH: usize = 256;

/// A Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: Commitment,
    pub siblings: Vec<Commitment>,
    pub path_bits: Vec<bool>, // true = go right
}

/// Sparse Merkle Tree with 256-bit keys.
/// Leaves are Commitment values. Missing leaves are treated as zero (empty commitment).
pub struct SparseMerkleTree {
    nodes: HashMap<(usize, [u8; 32]), Commitment>,
    root: Commitment,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root: Self::zero_commitment(),
        }
    }

    fn zero_commitment() -> Commitment {
        Commitment([0u8; 32])
    }

    fn hash_nodes(left: &Commitment, right: &Commitment) -> Commitment {
        CommitmentScheme::commit_fields(&[left.as_bytes(), right.as_bytes()])
    }

    /// Get the current root commitment.
    pub fn root(&self) -> &Commitment {
        &self.root
    }

    /// Insert or update a leaf at the given key.
    pub fn insert(&mut self, key: [u8; 32], value: Commitment) {
        self.nodes.insert((TREE_DEPTH, key), value.clone());
        self.recompute_root(key);
    }

    /// Get the leaf value at key, or None if absent.
    pub fn get(&self, key: &[u8; 32]) -> Option<&Commitment> {
        self.nodes.get(&(TREE_DEPTH, *key))
    }

    fn recompute_root(&mut self, key: [u8; 32]) {
        // Walk from leaf to root, recomputing affected nodes.
        let mut current_key = key;
        let leaf = self
            .nodes
            .get(&(TREE_DEPTH, key))
            .cloned()
            .unwrap_or_else(Self::zero_commitment);
        let mut current = leaf;

        for depth in (0..TREE_DEPTH).rev() {
            let bit = (current_key[depth / 8] >> (7 - (depth % 8))) & 1;
            let sibling_key = Self::sibling_key(current_key, depth);
            let sibling = self
                .nodes
                .get(&(depth + 1, sibling_key))
                .cloned()
                .unwrap_or_else(Self::zero_commitment);

            let parent = if bit == 0 {
                Self::hash_nodes(&current, &sibling)
            } else {
                Self::hash_nodes(&sibling, &current)
            };

            // Zero out the bit to get the parent key
            current_key = Self::parent_key(current_key, depth);
            self.nodes.insert((depth, current_key), parent.clone());
            current = parent;
        }
        self.root = current;
    }

    fn sibling_key(mut key: [u8; 32], depth: usize) -> [u8; 32] {
        let byte_idx = depth / 8;
        let bit_idx = 7 - (depth % 8);
        key[byte_idx] ^= 1 << bit_idx; // flip the bit
        // zero out bits below depth
        for i in (byte_idx + 1)..32 {
            key[i] = 0;
        }
        if bit_idx > 0 {
            let mask = !((1u8 << bit_idx) - 1);
            key[byte_idx] &= mask;
        }
        key
    }

    fn parent_key(mut key: [u8; 32], depth: usize) -> [u8; 32] {
        let byte_idx = depth / 8;
        let bit_idx = 7 - (depth % 8);
        // zero out the bit at depth
        key[byte_idx] &= !(1 << bit_idx);
        // zero out bits below depth
        for i in (byte_idx + 1)..32 {
            key[i] = 0;
        }
        key
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::CommitmentScheme;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.root(), &SparseMerkleTree::zero_commitment());
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let initial_root = tree.root().clone();
        tree.insert(key(1), CommitmentScheme::commit(b"value1"));
        assert_ne!(tree.root(), &initial_root);
    }

    #[test]
    fn get_returns_inserted_value() {
        let mut tree = SparseMerkleTree::new();
        let val = CommitmentScheme::commit(b"value");
        tree.insert(key(42), val.clone());
        assert_eq!(tree.get(&key(42)), Some(&val));
    }

    #[test]
    fn different_keys_different_roots() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let val = CommitmentScheme::commit(b"v");
        t1.insert(key(1), val.clone());
        t2.insert(key(2), val);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn same_insertions_same_root() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let val = CommitmentScheme::commit(b"v");
        t1.insert(key(1), val.clone());
        t2.insert(key(1), val);
        assert_eq!(t1.root(), t2.root());
    }
}
