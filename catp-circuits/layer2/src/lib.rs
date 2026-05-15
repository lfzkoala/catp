//! catp-layer2: ProveAuthorization Halo2 ZK circuit.
//!
//! Implements the CATP Layer 2 authorization proof system, allowing an AI agent
//! to prove it is authorized to perform an action without revealing its full
//! authorization policy on-chain.

pub mod circuit;
pub mod error;
pub mod proof;
pub mod proof_bytes;
pub mod types;

#[cfg(test)]
mod poseidon_probe;

pub use circuit::{
    action_public_fields, fr_from_be_bytes, fr_to_be_bytes, native_policy_commitment,
    AuthorizationConfig, AuthorizationPublicInputs, ProveAuthorization,
};
pub use error::{CatpError, CatpResult};
pub use proof::AuthorizationProofSystem;
pub use proof_bytes::Proof;
pub use types::{Action, ActionType, AuthorizationPolicy};
