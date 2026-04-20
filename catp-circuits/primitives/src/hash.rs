use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// 32-byte commitment value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Native commitment scheme using SHA-256.
///
/// Note: Inside ZK circuits, use the Poseidon gadget from halo2_gadgets instead.
/// SHA-256 is ZK-unfriendly (~2000 constraints vs ~8 for Poseidon) but fine for
/// native (off-chain) commitment generation and verification.
pub struct CommitmentScheme;

impl CommitmentScheme {
    /// Compute commitment = SHA-256(data).
    pub fn commit(data: &[u8]) -> Commitment {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Commitment(hasher.finalize().into())
    }

    /// Commit to multiple fields concatenated with length-prefix encoding.
    pub fn commit_fields(fields: &[&[u8]]) -> Commitment {
        let mut hasher = Sha256::new();
        for field in fields {
            let len = (field.len() as u32).to_le_bytes();
            hasher.update(len);
            hasher.update(field);
        }
        Commitment(hasher.finalize().into())
    }

    /// Commit with a random salt for hiding.
    pub fn commit_with_salt(data: &[u8], salt: &[u8; 32]) -> Commitment {
        // Domain tag 0x01 distinguishes salted commitments from plain commit_fields output.
        Self::commit_fields(&[b"\x01", data, salt])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_deterministic() {
        let c1 = CommitmentScheme::commit(b"hello");
        let c2 = CommitmentScheme::commit(b"hello");
        assert_eq!(c1, c2);
    }

    #[test]
    fn commit_different_inputs() {
        let c1 = CommitmentScheme::commit(b"hello");
        let c2 = CommitmentScheme::commit(b"world");
        assert_ne!(c1, c2);
    }

    #[test]
    fn commit_fields_order_matters() {
        let c1 = CommitmentScheme::commit_fields(&[b"a", b"b"]);
        let c2 = CommitmentScheme::commit_fields(&[b"b", b"a"]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn commit_with_salt_differs_from_unsalted() {
        let salt = [0u8; 32];
        let c1 = CommitmentScheme::commit(b"hello");
        let c2 = CommitmentScheme::commit_with_salt(b"hello", &salt);
        assert_ne!(c1, c2);
    }
}
