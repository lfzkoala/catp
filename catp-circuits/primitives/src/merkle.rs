use crate::hash::{Commitment, CommitmentScheme};
use std::collections::HashMap;

const TREE_DEPTH: usize = 256;

/// A Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub leaf: Commitment,
    pub siblings: Vec<Commitment>,
    pub path_bits: Vec<bool>, // true = go right
}

impl MerkleProof {
    /// Verify that this proof is valid for the given root.
    pub fn verify(&self, root: &Commitment) -> bool {
        if self.siblings.len() != TREE_DEPTH || self.path_bits.len() != TREE_DEPTH {
            return false;
        }

        let mut expected_key = self.key;
        let mut current = self.leaf.clone();
        for (i, (sibling, &goes_right)) in
            self.siblings.iter().zip(self.path_bits.iter()).enumerate()
        {
            let depth = TREE_DEPTH - 1 - i;
            let bit = (expected_key[depth / 8] >> (7 - (depth % 8))) & 1;
            if goes_right != (bit == 1) {
                return false;
            }
            current = if !goes_right {
                SparseMerkleTree::hash_nodes(&current, sibling)
            } else {
                SparseMerkleTree::hash_nodes(sibling, &current)
            };
            expected_key = SparseMerkleTree::parent_key(expected_key, depth);
        }
        &current == root
    }
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

    pub(crate) fn hash_nodes(left: &Commitment, right: &Commitment) -> Commitment {
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
        key[(byte_idx + 1)..].fill(0);
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
        key[(byte_idx + 1)..].fill(0);
        key
    }

    /// Generate a Merkle inclusion proof for the given key.
    /// Returns an error if the key has no value in the tree.
    pub fn prove(&self, key: [u8; 32]) -> crate::error::CatpResult<MerkleProof> {
        let leaf = self
            .get(&key)
            .cloned()
            .ok_or(crate::error::CatpError::MerkleProofInvalid)?;

        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut path_bits = Vec::with_capacity(TREE_DEPTH);
        let mut current_key = key;

        for depth in (0..TREE_DEPTH).rev() {
            let bit = (current_key[depth / 8] >> (7 - (depth % 8))) & 1;
            path_bits.push(bit == 1);
            let sibling_key = Self::sibling_key(current_key, depth);
            let sibling = self
                .nodes
                .get(&(depth + 1, sibling_key))
                .cloned()
                .unwrap_or_else(Self::zero_commitment);
            siblings.push(sibling);
            current_key = Self::parent_key(current_key, depth);
        }

        Ok(MerkleProof {
            key,
            leaf,
            siblings,
            path_bits,
        })
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

    #[test]
    fn prove_and_verify_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        let val = CommitmentScheme::commit(b"leaf-value");
        tree.insert(key(7), val);
        let proof = tree.prove(key(7)).unwrap();
        assert!(proof.verify(tree.root()));
    }

    #[test]
    fn prove_absent_key_returns_err() {
        let tree = SparseMerkleTree::new();
        assert!(tree.prove(key(99)).is_err());
    }

    #[test]
    fn proof_invalid_for_wrong_root() {
        let mut tree = SparseMerkleTree::new();
        let val = CommitmentScheme::commit(b"v");
        tree.insert(key(1), val);
        let proof = tree.prove(key(1)).unwrap();
        let wrong_root = CommitmentScheme::commit(b"wrong");
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn empty_proof_does_not_verify() {
        let leaf = CommitmentScheme::commit(b"leaf");
        let proof = MerkleProof {
            key: key(1),
            leaf: leaf.clone(),
            siblings: vec![],
            path_bits: vec![],
        };
        assert!(!proof.verify(&leaf));
    }

    #[test]
    fn truncated_proof_does_not_verify() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), CommitmentScheme::commit(b"v"));
        let mut proof = tree.prove(key(1)).unwrap();
        proof.siblings.pop();
        assert!(!proof.verify(tree.root()));
    }

    #[test]
    fn proof_invalid_for_wrong_key() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), CommitmentScheme::commit(b"v"));
        let mut proof = tree.prove(key(1)).unwrap();
        proof.key = key(2);
        assert!(!proof.verify(tree.root()));
    }

    #[test]
    fn prefix_collision_keys_produce_different_roots() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let val = CommitmentScheme::commit(b"v");
        // Two keys that share a long common prefix (differ only in last bit)
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1[31] = 0b00000000;
        k2[31] = 0b00000001;
        t1.insert(k1, val.clone());
        t2.insert(k2, val);
        assert_ne!(t1.root(), t2.root());
    }
}
