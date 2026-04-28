//! Proof system wrappers for the ProveAuthorization circuit.
//!
//! Note: Full proof generation requires ~seconds of compute.
//! For fast correctness testing use MockProver (in circuit.rs tests).

use catp_primitives::error::{CatpError, CatpResult};
use catp_primitives::proof::Proof;
use halo2_proofs::{
    pasta::EqAffine,
    plonk,
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};

use crate::circuit::{AuthorizationPublicInputs, ProveAuthorization};
use crate::types::{Action, AuthorizationPolicy};

/// The Halo2-based authorization proof system.
pub struct AuthorizationProofSystem {
    params: Params<EqAffine>,
}

impl AuthorizationProofSystem {
    /// Create a new proof system. `k` controls circuit size: 2^k rows.
    /// k=8 (256 rows) is sufficient for ProveAuthorization.
    pub fn new(k: u32) -> Self {
        Self {
            params: Params::new(k),
        }
    }

    /// Generate a ZK proof that `action` is authorized by `policy`.
    ///
    /// Regenerates proving keys on every call. In production, cache the
    /// `AuthorizationProofSystem` and call this method with the same instance.
    pub fn prove_authorization(
        &self,
        policy: AuthorizationPolicy,
        action: Action,
        public_inputs: AuthorizationPublicInputs,
    ) -> CatpResult<Proof> {
        let empty_circuit = ProveAuthorization::default();
        let vk = plonk::keygen_vk(&self.params, &empty_circuit)
            .map_err(|e| CatpError::Serialization(e.to_string()))?;
        let pk = plonk::keygen_pk(&self.params, vk, &empty_circuit)
            .map_err(|e| CatpError::Serialization(e.to_string()))?;

        let circuit = ProveAuthorization {
            policy: Some(policy),
            action: Some(action),
            public_inputs: Some(public_inputs),
        };

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        plonk::create_proof(
            &self.params,
            &pk,
            &[circuit],
            &[&[&[], &[]]],
            rand::rngs::OsRng,
            &mut transcript,
        )
        .map_err(|e| CatpError::Serialization(e.to_string()))?;

        Ok(Proof(transcript.finalize()))
    }

    /// Verify a ZK proof for the ProveAuthorization circuit.
    ///
    /// The verifying key is regenerated deterministically from the params —
    /// halo2_proofs 0.3.2 provides no binary serialization for VerifyingKey.
    /// Returns `Ok(true)` on success, `Err` if the proof is invalid or malformed.
    pub fn verify_authorization(&self, proof: &Proof) -> CatpResult<bool> {
        let empty_circuit = ProveAuthorization::default();
        let vk = plonk::keygen_vk(&self.params, &empty_circuit)
            .map_err(|e| CatpError::Serialization(e.to_string()))?;

        let strategy = plonk::SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.0[..]);

        plonk::verify_proof(&self.params, &vk, strategy, &[&[&[], &[]]], &mut transcript)
            .map(|_| true)
            .map_err(|e| CatpError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, ActionType, AuthorizationPolicy};

    fn test_policy() -> AuthorizationPolicy {
        AuthorizationPolicy {
            allowed_action: ActionType::Swap,
            allowed_protocol: [1u8; 32],
            allowed_token: [2u8; 32],
            max_value_per_tx: 1000,
            max_value_total: 10000,
            valid_from: 1000,
            valid_until: 9000,
        }
    }

    fn test_action() -> Action {
        Action {
            action_type: ActionType::Swap,
            protocol: [1u8; 32],
            token: [2u8; 32],
            value: 500,
        }
    }

    fn test_public_inputs() -> AuthorizationPublicInputs {
        AuthorizationPublicInputs {
            policy_commitment: [0u8; 32],
            current_timestamp: 5000,
            cumulative_spend: 2000,
        }
    }

    #[test]
    fn prove_and_verify_roundtrip() {
        let ps = AuthorizationProofSystem::new(8);
        let proof = ps
            .prove_authorization(test_policy(), test_action(), test_public_inputs())
            .unwrap();
        assert!(!proof.0.is_empty());
        assert!(ps.verify_authorization(&proof).unwrap());
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let ps = AuthorizationProofSystem::new(8);
        let mut proof = ps
            .prove_authorization(test_policy(), test_action(), test_public_inputs())
            .unwrap();
        proof.0[0] ^= 0xFF;
        assert!(ps.verify_authorization(&proof).is_err());
    }
}
