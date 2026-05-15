use catp_authorization::{
    fr_from_be_bytes, AuthorizationProofSystem, AuthorizationPublicInputs, CatpError, CatpResult,
    Proof,
};

const AUTHORIZATION_SRS: &[u8] =
    include_bytes!("../../catp-circuits/authorization/catp-authorization-k12.srs");

/// Verify a ProveAuthorization proof.
///
/// `proof_bytes` is the raw bytes produced by `AuthorizationProofSystem::prove_authorization`.
/// `public_inputs` must match the values used to generate the proof.
/// Returns `Ok(true)` if valid, `Err` if the proof is malformed or verification fails.
pub fn verify(proof_bytes: &[u8], public_inputs: &AuthorizationPublicInputs) -> CatpResult<bool> {
    let ps = AuthorizationProofSystem::from_bytes(AUTHORIZATION_SRS)?;
    ps.verify_authorization(&Proof(proof_bytes.to_vec()), public_inputs)
}

/// Parse a 0x-prefixed or plain 32-byte big-endian BN254 Fr hex string.
pub fn parse_policy_commitment(hex: &str) -> CatpResult<halo2curves::bn256::Fr> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    if clean.len() != 64 {
        return Err(CatpError::Serialization(
            "policy_commitment must be 32 bytes".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| CatpError::Serialization(e.to_string()))?;
        bytes[i] =
            u8::from_str_radix(s, 16).map_err(|e| CatpError::Serialization(e.to_string()))?;
    }

    fr_from_be_bytes(&bytes).ok_or_else(|| {
        CatpError::Serialization("policy_commitment is not a valid BN254 Fr".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use catp_authorization::{
        action_public_fields, native_policy_commitment,
        types::{Action, ActionType, AuthorizationPolicy},
    };

    fn proof_fixture() -> (Vec<u8>, AuthorizationPublicInputs) {
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
        let (action_type, action_protocol, action_token, action_value) =
            action_public_fields(&action);
        let public_inputs = AuthorizationPublicInputs {
            policy_commitment: native_policy_commitment(&policy),
            action_type,
            action_protocol,
            action_token,
            action_value,
            current_timestamp: 5000,
            cumulative_spend: 2000,
        };
        let ps = AuthorizationProofSystem::from_bytes(AUTHORIZATION_SRS).unwrap();
        let proof = ps
            .prove_authorization(policy, action, public_inputs.clone())
            .unwrap()
            .0;
        (proof, public_inputs)
    }

    #[test]
    fn valid_proof_returns_true() {
        let (proof, public_inputs) = proof_fixture();
        assert!(verify(&proof, &public_inputs).unwrap());
    }

    #[test]
    fn tampered_proof_returns_err() {
        let (mut bytes, public_inputs) = proof_fixture();
        bytes[0] ^= 0xFF;
        assert!(verify(&bytes, &public_inputs).is_err());
    }

    #[test]
    fn empty_proof_returns_err() {
        let (_, public_inputs) = proof_fixture();
        assert!(verify(&[], &public_inputs).is_err());
    }
}
