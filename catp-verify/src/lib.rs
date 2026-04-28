use catp_layer2::AuthorizationProofSystem;
use catp_primitives::{proof::Proof, CatpResult};

/// Verify a ProveAuthorization proof.
///
/// `proof_bytes` is the raw bytes produced by `AuthorizationProofSystem::prove_authorization`.
/// Returns `Ok(true)` if valid, `Err` if the proof is malformed or verification fails.
pub fn verify(proof_bytes: &[u8]) -> CatpResult<bool> {
    let ps = AuthorizationProofSystem::new(8);
    ps.verify_authorization(&Proof(proof_bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use catp_layer2::{
        circuit::AuthorizationPublicInputs,
        types::{Action, ActionType, AuthorizationPolicy},
    };

    fn proof_bytes() -> Vec<u8> {
        let policy = AuthorizationPolicy {
            allowed_action: ActionType::Swap,
            allowed_protocol: [1u8; 32],
            allowed_token: [2u8; 32],
            max_value_per_tx: 1000,
            max_value_total: 10000,
            valid_from: 1000,
            valid_until: 9000,
        };
        let action = Action {
            action_type: ActionType::Swap,
            protocol: [1u8; 32],
            token: [2u8; 32],
            value: 500,
        };
        let public_inputs = AuthorizationPublicInputs {
            policy_commitment: [0u8; 32],
            current_timestamp: 5000,
            cumulative_spend: 2000,
        };
        let ps = AuthorizationProofSystem::new(8);
        ps.prove_authorization(policy, action, public_inputs)
            .unwrap()
            .0
    }

    #[test]
    fn valid_proof_returns_true() {
        assert!(verify(&proof_bytes()).unwrap());
    }

    #[test]
    fn tampered_proof_returns_err() {
        let mut bytes = proof_bytes();
        bytes[0] ^= 0xFF;
        assert!(verify(&bytes).is_err());
    }

    #[test]
    fn empty_proof_returns_err() {
        assert!(verify(&[]).is_err());
    }
}
