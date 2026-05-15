use catp_authorization::{
    action_public_fields, fr_from_be_bytes, fr_to_be_bytes, native_policy_commitment, Action,
    ActionType, AuthorizationPolicy, AuthorizationProofSystem, AuthorizationPublicInputs,
};
use halo2curves::bn256::Fr;
use std::path::Path;

fn srs_path() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/catp-authorization-k12.srs"
    ))
}

fn test_policy() -> AuthorizationPolicy {
    AuthorizationPolicy {
        allowed_action: ActionType::Swap,
        allowed_protocol: [0xAAu8; 32],
        allowed_token: [0xBBu8; 32],
        max_value_per_tx: 1_000,
        max_value_total: 10_000,
        valid_from: 1_000,
        valid_until: 9_999_999_999,
    }
}

fn test_action() -> Action {
    Action {
        action_type: ActionType::Swap,
        protocol: [0xAAu8; 32],
        token: [0xBBu8; 32],
        value: 500,
    }
}

fn test_public_inputs(policy_commitment: Fr) -> AuthorizationPublicInputs {
    let (action_type, action_protocol, action_token, action_value) =
        action_public_fields(&test_action());
    AuthorizationPublicInputs {
        policy_commitment,
        action_type,
        action_protocol,
        action_token,
        action_value,
        current_timestamp: 5_000,
        cumulative_spend: 200,
    }
}

/// Full trustless path: policy → Poseidon commitment → ZK proof → off-chain verify.
#[test]
fn e2e_trustless_verification() {
    let policy = test_policy();
    let commitment = native_policy_commitment(&policy);

    let ps = AuthorizationProofSystem::from_file(srs_path()).expect("failed to load committed SRS");

    let public_inputs = test_public_inputs(commitment);

    let proof = ps
        .prove_authorization(test_policy(), test_action(), public_inputs.clone())
        .expect("prove_authorization failed");

    assert!(!proof.0.is_empty(), "proof bytes must be non-empty");

    let valid = ps
        .verify_authorization(&proof, &public_inputs)
        .expect("verify_authorization returned an error");

    assert!(valid, "proof must verify with matching public inputs");
}

/// Tampered policyCommitment must fail verification.
#[test]
fn e2e_tampered_commitment_fails() {
    let policy = test_policy();
    let good_commitment = native_policy_commitment(&policy);

    let ps = AuthorizationProofSystem::from_file(srs_path()).expect("failed to load SRS");

    let good_inputs = test_public_inputs(good_commitment);

    let proof = ps
        .prove_authorization(test_policy(), test_action(), good_inputs)
        .expect("prove_authorization failed");

    // Flip a bit in the commitment's big-endian representation.
    let mut bad_be = fr_to_be_bytes(good_commitment);
    bad_be[0] ^= 0x01;
    let bad_commitment = fr_from_be_bytes(&bad_be).expect("tampered commitment must be a valid Fr");

    let bad_inputs = test_public_inputs(bad_commitment);

    let result = ps.verify_authorization(&proof, &bad_inputs);
    assert!(
        result.is_err(),
        "verification must fail when policyCommitment is tampered"
    );
}

/// Commitment round-trips correctly through big-endian bytes.
#[test]
fn commitment_roundtrip_be_bytes() {
    let commitment = native_policy_commitment(&test_policy());
    let be = fr_to_be_bytes(commitment);
    let recovered = fr_from_be_bytes(&be).expect("round-trip must produce valid Fr");
    assert_eq!(commitment, recovered);
}
