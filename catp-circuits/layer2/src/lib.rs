//! catp-layer2: ProveAuthorization Halo2 ZK circuit.
//!
//! Implements the CATP Layer 2 authorization proof system, allowing an AI agent
//! to prove it is authorized to perform an action without revealing its full
//! authorization policy on-chain.

pub mod circuit;
pub mod proof;
pub mod types;

pub use circuit::{AuthorizationConfig, AuthorizationPublicInputs, ProveAuthorization};
pub use proof::AuthorizationProofSystem;
pub use types::{Action, ActionType, AuthorizationPolicy};
