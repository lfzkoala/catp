use thiserror::Error;

#[derive(Debug, Error)]
pub enum CatpError {
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("decryption error: {0}")]
    Decryption(String),
    #[error("key exchange error: {0}")]
    KeyExchange(String),
    #[error("merkle proof invalid")]
    MerkleProofInvalid,
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("proof verification failed")]
    ProofVerificationFailed,
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type CatpResult<T> = Result<T, CatpError>;
