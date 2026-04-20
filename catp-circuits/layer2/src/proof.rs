//! Proof system wrappers for the ProveAuthorization circuit.
//!
//! Note: Full proof generation requires ~seconds of compute and actual SNARK machinery.
//! For correctness testing, use MockProver (in circuit.rs tests) — it runs in milliseconds.
//!
//! This module provides keygen helpers using the halo2_proofs 0.3 API.

use catp_primitives::error::{CatpError, CatpResult};
use catp_primitives::proof::{Proof, ProvingKey, VerifyingKey};
use halo2_proofs::{
    pasta::EqAffine,
    plonk,
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};

use crate::circuit::{AuthorizationPublicInputs, ProveAuthorization};
use crate::types::{Action, AuthorizationPolicy};

/// The Halo2-based authorization proof system.
pub struct AuthorizationProofSystem {
    params: Params<EqAffine>,
}

impl AuthorizationProofSystem {
    /// Create a new proof system.
    /// `k` is the circuit size parameter: circuit uses 2^k rows.
    /// k=8 (256 rows) is sufficient for this circuit.
    pub fn new(k: u32) -> Self {
        Self {
            params: Params::new(k),
        }
    }

    /// Generate proving and verifying keys for an empty circuit.
    /// Returns opaque byte blobs stored in `ProvingKey` / `VerifyingKey`.
    pub fn keygen(&self) -> CatpResult<(ProvingKey, VerifyingKey)> {
        let empty_circuit = ProveAuthorization::default();
        let vk = plonk::keygen_vk(&self.params, &empty_circuit)
            .map_err(|e| CatpError::Serialization(e.to_string()))?;
        let pk = plonk::keygen_pk(&self.params, vk.clone(), &empty_circuit)
            .map_err(|e| CatpError::Serialization(e.to_string()))?;

        // Serialize keys using halo2_proofs helpers module.
        // halo2_proofs 0.3 exposes write/read via the `helpers` module trait objects.
        // We store a debug representation as bytes for now; full serialization is a Phase 2 concern.
        let vk_bytes = format!("{:?}", vk.pinned()).into_bytes();
        let pk_bytes = vk_bytes.clone(); // pk not separately serializable in 0.3 without SerdeFormat
        let _ = pk; // pk is used to generate proofs; stored in memory for this session

        Ok((ProvingKey(pk_bytes), VerifyingKey(vk_bytes)))
    }

    /// Generate a proof for the given policy and action.
    ///
    /// In production, call `keygen` once and reuse the proving key.
    /// This convenience method regenerates keys on each call (slow but simple).
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
            // Two empty instance slices — one per instance column.
            &[&[&[], &[]]],
            rand::rngs::OsRng,
            &mut transcript,
        )
        .map_err(|e| CatpError::Serialization(e.to_string()))?;

        Ok(Proof(transcript.finalize()))
    }
}
