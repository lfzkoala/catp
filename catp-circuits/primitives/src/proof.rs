use crate::error::CatpResult;

/// Opaque proof bytes. The concrete format is determined by the proving system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proof(pub Vec<u8>);

/// Opaque proving key bytes.
#[derive(Debug, Clone)]
pub struct ProvingKey(pub Vec<u8>);

/// Opaque verifying key bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyingKey(pub Vec<u8>);

/// Abstraction over a ZK proof system.
/// Concrete implementations (Halo2) live in catp-circuits/layer* crates.
pub trait ProofSystem {
    type PublicInputs: serde::Serialize + for<'de> serde::Deserialize<'de>;
    type PrivateInputs;

    fn prove(
        &self,
        pk: &ProvingKey,
        public: &Self::PublicInputs,
        private: &Self::PrivateInputs,
    ) -> CatpResult<Proof>;

    fn verify(
        &self,
        vk: &VerifyingKey,
        public: &Self::PublicInputs,
        proof: &Proof,
    ) -> CatpResult<bool>;
}
