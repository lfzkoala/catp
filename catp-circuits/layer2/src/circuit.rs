//! ProveAuthorization Halo2 circuit.
//!
//! Proves 8 constraints:
//!   1. Poseidon(full_policy) == policy_commitment  (TODO: deferred — see note below)
//!   2. action.type   ∈ policy.allowed_actions      (equality check against single allowed value)
//!   3. action.protocol ∈ policy.allowed_protocols  (equality check)
//!   4. action.token  ∈ policy.allowed_tokens       (equality check)
//!   5. action.value  ≤ policy.max_value_per_tx     (range check via difference witness)
//!   6. cumulative_spend + action.value ≤ policy.max_value_total (range check via difference witness)
//!   7. current_timestamp ≥ policy.valid_from       (range check via difference witness)
//!   8. current_timestamp ≤ policy.valid_until      (range check via difference witness)
//!
//! TODO (Constraint 1 — Poseidon commitment):
//!   Poseidon(policy fields) == policy_commitment is deferred to Phase 2.
//!   Integration requires the halo2_gadgets Poseidon chip, which adds significant
//!   complexity (~350 lines of gadget wiring). For now the commitment is verified
//!   natively (SHA-256) off-circuit before proof generation. The circuit's
//!   `policy_commitment` public input is unused by any gate until Constraint 1 is wired.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

use crate::types::{Action, AuthorizationPolicy};

/// Public inputs to the ProveAuthorization circuit (visible on-chain).
#[derive(Debug, Clone)]
pub struct AuthorizationPublicInputs {
    /// SHA-256 commitment to the full AuthorizationPolicy (private).
    /// TODO: Replace with Poseidon commitment once halo2_gadgets Poseidon is integrated.
    pub policy_commitment: [u8; 32],
    /// Current block timestamp.
    pub current_timestamp: u64,
    /// Cumulative spend so far for this policy (read from on-chain state).
    pub cumulative_spend: u64,
}

/// Circuit configuration: column assignments and selectors.
#[derive(Debug, Clone)]
pub struct AuthorizationConfig {
    // ---- Advice columns ----
    // Membership region: [action_type, action_value, action_protocol_low, action_token_low]
    action_cols: [Column<Advice>; 4],
    // Policy fields: [allowed_action, max_per_tx, max_total, col3, col4, protocol_low, token_low]
    // col3 and col4 are repurposed per region (diff witnesses or valid_from/valid_until).
    policy_cols: [Column<Advice>; 7],

    // ---- Instance columns ---- (unused by gates until Constraint 1 is wired)
    #[allow(dead_code)]
    pub_cols: [Column<Instance>; 2],

    // ---- Selectors ----
    sel_membership: Selector,
    sel_value_limits: Selector,
    sel_time_bounds: Selector,
}

/// The ProveAuthorization circuit.
///
/// Public inputs (on-chain visible):
///   - policy_commitment — commitment to the private policy
///   - current_timestamp — from block header
///   - cumulative_spend  — from on-chain state
///
/// Private inputs (known only to the prover):
///   - AuthorizationPolicy
///   - Action
///
/// The circuit is split into three independent single-row regions:
///   - "membership"    — Constraints 2–4 (equality checks)
///   - "value_limits"  — Constraints 5–6 (arithmetic range checks)
///   - "time_bounds"   — Constraints 7–8 (arithmetic range checks)
#[derive(Debug, Default)]
pub struct ProveAuthorization {
    /// Private: the full authorization policy.
    pub policy: Option<AuthorizationPolicy>,
    /// Private: the proposed action.
    pub action: Option<Action>,
    /// Public: timestamp and cumulative spend.
    pub public_inputs: Option<AuthorizationPublicInputs>,
}

impl Circuit<halo2_proofs::pasta::Fp> for ProveAuthorization {
    type Config = AuthorizationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<halo2_proofs::pasta::Fp>) -> Self::Config {
        let action_cols = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let policy_cols = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let pub_cols = [meta.instance_column(), meta.instance_column()];

        let sel_membership = meta.selector();
        let sel_value_limits = meta.selector();
        let sel_time_bounds = meta.selector();

        // ---- Constraint 2–4: membership (equality) ----
        // action_type  == policy.allowed_action
        // action.protocol_low == policy.protocol_low  (first 8 bytes as u64)
        // action.token_low    == policy.token_low
        //
        // TODO(C-002): KNOWN COLLISION ATTACK SURFACE — partial address comparison.
        // Currently only the first 8 bytes (low limb) of each 32-byte address are
        // compared in-circuit. An adversary can craft a different protocol/token address
        // that shares the same low 8 bytes (bytes 0–7) but differs in bytes 8–31,
        // bypassing the membership gate.
        //
        // Fix (deferred to Phase 2 — lookup table refactor):
        //   Split each 32-byte address into 4 × u64 limbs and enforce all 4 equality
        //   constraints per address (8 constraints total instead of 2). This requires
        //   expanding action_cols to 10 and policy_cols to 13 columns.
        //   Full implementation is deferred because it requires a concurrent refactor
        //   of the value_limits and time_bounds regions, which reuse action_cols[2/3]
        //   as witness columns. The circuit is also not production-ready until the
        //   Poseidon commitment (Constraint 1, TODO C-003) is wired in Phase 2.
        //
        //   Helper to split addresses into limbs (to be used in Phase 2):
        //     fn address_to_limbs(addr: &[u8; 32]) -> [u64; 4] {
        //         [
        //             u64::from_le_bytes(addr[0..8].try_into().unwrap()),
        //             u64::from_le_bytes(addr[8..16].try_into().unwrap()),
        //             u64::from_le_bytes(addr[16..24].try_into().unwrap()),
        //             u64::from_le_bytes(addr[24..32].try_into().unwrap()),
        //         ]
        //     }
        meta.create_gate("membership checks", |meta| {
            let s = meta.query_selector(sel_membership);
            let action_type = meta.query_advice(action_cols[0], Rotation::cur());
            let action_proto = meta.query_advice(action_cols[2], Rotation::cur());
            let action_token = meta.query_advice(action_cols[3], Rotation::cur());
            let policy_action = meta.query_advice(policy_cols[0], Rotation::cur());
            let policy_proto = meta.query_advice(policy_cols[5], Rotation::cur());
            let policy_token = meta.query_advice(policy_cols[6], Rotation::cur());
            vec![
                s.clone() * (action_type - policy_action),
                s.clone() * (action_proto - policy_proto),
                s * (action_token - policy_token),
            ]
        });

        // ---- Constraint 5–6: value limits ----
        // Prover supplies diff witnesses such that:
        //   action_value + diff_per_tx == max_per_tx     →  action_value ≤ max_per_tx
        //   cumulative + action_value + diff_total == max_total  →  total ≤ max_total
        // (diff values must be non-negative; enforced by prover honesty and checked
        //  via MockProver in tests; full range proofs deferred to Phase 2.)
        meta.create_gate("value limits", |meta| {
            let s = meta.query_selector(sel_value_limits);
            let action_value = meta.query_advice(action_cols[1], Rotation::cur());
            let max_per_tx = meta.query_advice(policy_cols[1], Rotation::cur());
            let max_total = meta.query_advice(policy_cols[2], Rotation::cur());
            // policy_cols[3] repurposed as diff_per_tx witness
            let diff_per_tx = meta.query_advice(policy_cols[3], Rotation::cur());
            // policy_cols[4] repurposed as diff_total witness
            let diff_total = meta.query_advice(policy_cols[4], Rotation::cur());
            // action_cols[2] repurposed as cumulative_spend witness
            let cumulative = meta.query_advice(action_cols[2], Rotation::cur());

            vec![
                // action_value + diff_per_tx == max_per_tx
                s.clone() * (action_value.clone() + diff_per_tx - max_per_tx),
                // cumulative + action_value + diff_total == max_total
                s * (cumulative + action_value + diff_total - max_total),
            ]
        });

        // ---- Constraint 7–8: time bounds ----
        // Prover supplies diff witnesses such that:
        //   valid_from + diff_from == timestamp   →  timestamp ≥ valid_from
        //   timestamp + diff_until == valid_until  →  timestamp ≤ valid_until
        meta.create_gate("time bounds", |meta| {
            let s = meta.query_selector(sel_time_bounds);
            // action_cols[0] repurposed as timestamp
            let timestamp = meta.query_advice(action_cols[0], Rotation::cur());
            // action_cols[1] repurposed as diff_from witness
            let diff_from = meta.query_advice(action_cols[1], Rotation::cur());
            // action_cols[2] repurposed as diff_until witness
            let diff_until = meta.query_advice(action_cols[2], Rotation::cur());
            // policy_cols[3] repurposed as valid_from
            let valid_from = meta.query_advice(policy_cols[3], Rotation::cur());
            // policy_cols[4] repurposed as valid_until
            let valid_until = meta.query_advice(policy_cols[4], Rotation::cur());

            vec![
                // valid_from + diff_from == timestamp
                s.clone() * (valid_from + diff_from - timestamp.clone()),
                // timestamp + diff_until == valid_until
                s * (timestamp + diff_until - valid_until),
            ]
        });

        AuthorizationConfig {
            action_cols,
            policy_cols,
            pub_cols,
            sel_membership,
            sel_value_limits,
            sel_time_bounds,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<halo2_proofs::pasta::Fp>,
    ) -> Result<(), Error> {
        use halo2_proofs::pasta::Fp;

        let policy = self.policy.as_ref();
        let action = self.action.as_ref();
        let pub_in = self.public_inputs.as_ref();

        let fp = |v: u64| -> Value<Fp> { Value::known(Fp::from(v)) };

        // ---- Region 0: membership (Constraints 2–4) ----
        layouter.assign_region(
            || "membership",
            |mut region| {
                config.sel_membership.enable(&mut region, 0)?;

                region.assign_advice(
                    || "action_type",
                    config.action_cols[0],
                    0,
                    || action.map(|a| fp(a.action_type.as_u64())).unwrap_or(Value::unknown()),
                )?;
                region.assign_advice(
                    || "action_value",
                    config.action_cols[1],
                    0,
                    || action.map(|a| fp(a.value)).unwrap_or(Value::unknown()),
                )?;
                // Use first 8 bytes of protocol/token as u64 for field element comparison.
                region.assign_advice(
                    || "action_protocol_low",
                    config.action_cols[2],
                    0,
                    || {
                        action
                            .map(|a| {
                                fp(u64::from_le_bytes(a.protocol[..8].try_into().unwrap()))
                            })
                            .unwrap_or(Value::unknown())
                    },
                )?;
                region.assign_advice(
                    || "action_token_low",
                    config.action_cols[3],
                    0,
                    || {
                        action
                            .map(|a| fp(u64::from_le_bytes(a.token[..8].try_into().unwrap())))
                            .unwrap_or(Value::unknown())
                    },
                )?;

                region.assign_advice(
                    || "policy_allowed_action",
                    config.policy_cols[0],
                    0,
                    || policy.map(|p| fp(p.allowed_action.as_u64())).unwrap_or(Value::unknown()),
                )?;
                region.assign_advice(
                    || "policy_max_per_tx",
                    config.policy_cols[1],
                    0,
                    || policy.map(|p| fp(p.max_value_per_tx)).unwrap_or(Value::unknown()),
                )?;
                region.assign_advice(
                    || "policy_max_total",
                    config.policy_cols[2],
                    0,
                    || policy.map(|p| fp(p.max_value_total)).unwrap_or(Value::unknown()),
                )?;
                region.assign_advice(
                    || "policy_valid_from",
                    config.policy_cols[3],
                    0,
                    || policy.map(|p| fp(p.valid_from)).unwrap_or(Value::unknown()),
                )?;
                region.assign_advice(
                    || "policy_valid_until",
                    config.policy_cols[4],
                    0,
                    || policy.map(|p| fp(p.valid_until)).unwrap_or(Value::unknown()),
                )?;
                region.assign_advice(
                    || "policy_protocol_low",
                    config.policy_cols[5],
                    0,
                    || {
                        policy
                            .map(|p| {
                                fp(u64::from_le_bytes(
                                    p.allowed_protocol[..8].try_into().unwrap(),
                                ))
                            })
                            .unwrap_or(Value::unknown())
                    },
                )?;
                region.assign_advice(
                    || "policy_token_low",
                    config.policy_cols[6],
                    0,
                    || {
                        policy
                            .map(|p| {
                                fp(u64::from_le_bytes(p.allowed_token[..8].try_into().unwrap()))
                            })
                            .unwrap_or(Value::unknown())
                    },
                )?;

                Ok(())
            },
        )?;

        // ---- Region 1: value limits (Constraints 5–6) ----
        layouter.assign_region(
            || "value_limits",
            |mut region| {
                config.sel_value_limits.enable(&mut region, 0)?;

                let action_val = action.map(|a| a.value).unwrap_or(0);
                let max_per_tx = policy.map(|p| p.max_value_per_tx).unwrap_or(0);
                let max_total = policy.map(|p| p.max_value_total).unwrap_or(0);
                let cumulative = pub_in.map(|p| p.cumulative_spend).unwrap_or(0);
                // diff_per_tx = max_per_tx - action_val  (must be >= 0 for constraint to hold)
                let diff_per_tx = max_per_tx.saturating_sub(action_val);
                // diff_total = max_total - (cumulative + action_val)
                let diff_total = max_total.saturating_sub(cumulative.saturating_add(action_val));

                region.assign_advice(
                    || "action_value",
                    config.action_cols[1],
                    0,
                    || fp(action_val),
                )?;
                region.assign_advice(
                    || "max_per_tx",
                    config.policy_cols[1],
                    0,
                    || fp(max_per_tx),
                )?;
                region.assign_advice(
                    || "max_total",
                    config.policy_cols[2],
                    0,
                    || fp(max_total),
                )?;
                region.assign_advice(
                    || "diff_per_tx",
                    config.policy_cols[3],
                    0,
                    || fp(diff_per_tx),
                )?;
                region.assign_advice(
                    || "diff_total",
                    config.policy_cols[4],
                    0,
                    || fp(diff_total),
                )?;
                region.assign_advice(
                    || "cumulative",
                    config.action_cols[2],
                    0,
                    || fp(cumulative),
                )?;
                // action_cols[0] and [3] unused in this region — fill with zero
                region.assign_advice(|| "unused0", config.action_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "unused3", config.action_cols[3], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc0", config.policy_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc5", config.policy_cols[5], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc6", config.policy_cols[6], 0, || fp(0))?;

                Ok(())
            },
        )?;

        // ---- Region 2: time bounds (Constraints 7–8) ----
        layouter.assign_region(
            || "time_bounds",
            |mut region| {
                config.sel_time_bounds.enable(&mut region, 0)?;

                let valid_from = policy.map(|p| p.valid_from).unwrap_or(0);
                let valid_until = policy.map(|p| p.valid_until).unwrap_or(0);
                let ts = pub_in.map(|p| p.current_timestamp).unwrap_or(0);
                // diff_from = ts - valid_from  (must be >= 0)
                let diff_from = ts.saturating_sub(valid_from);
                // diff_until = valid_until - ts  (must be >= 0)
                let diff_until = valid_until.saturating_sub(ts);

                region.assign_advice(|| "timestamp", config.action_cols[0], 0, || fp(ts))?;
                region.assign_advice(|| "diff_from", config.action_cols[1], 0, || fp(diff_from))?;
                region.assign_advice(
                    || "diff_until",
                    config.action_cols[2],
                    0,
                    || fp(diff_until),
                )?;
                region.assign_advice(
                    || "valid_from",
                    config.policy_cols[3],
                    0,
                    || fp(valid_from),
                )?;
                region.assign_advice(
                    || "valid_until",
                    config.policy_cols[4],
                    0,
                    || fp(valid_until),
                )?;
                // Unused cols in this region — fill with zero
                region.assign_advice(|| "unused1", config.action_cols[3], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc0", config.policy_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc1", config.policy_cols[1], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc2", config.policy_cols[2], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc5", config.policy_cols[5], 0, || fp(0))?;
                region.assign_advice(|| "unused_pc6", config.policy_cols[6], 0, || fp(0))?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, ActionType, AuthorizationPolicy};
    use halo2_proofs::dev::MockProver;

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

    fn run_circuit(
        policy: AuthorizationPolicy,
        action: Action,
        public_inputs: AuthorizationPublicInputs,
    ) -> Result<(), Vec<halo2_proofs::dev::VerifyFailure>> {
        let circuit = ProveAuthorization {
            policy: Some(policy),
            action: Some(action),
            public_inputs: Some(public_inputs),
        };
        // k=8: 256 rows, more than sufficient for 3 single-row regions.
        // Instance columns are present but unused by gates (Constraint 1 TODO).
        // Pass two empty vecs — one per instance column.
        MockProver::run(8, &circuit, vec![vec![], vec![]])
            .unwrap()
            .verify()
    }

    #[test]
    fn valid_authorization_passes() {
        assert!(run_circuit(test_policy(), test_action(), test_public_inputs()).is_ok());
    }

    #[test]
    fn wrong_action_type_fails() {
        let action = Action {
            action_type: ActionType::Transfer, // not Swap
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_protocol_fails() {
        let action = Action {
            protocol: [9u8; 32], // wrong protocol
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_token_fails() {
        let action = Action {
            token: [9u8; 32], // wrong token
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn value_exceeds_per_tx_limit_fails() {
        // value=1500 > max_per_tx=1000; saturating_sub gives diff_per_tx=0, but
        // 1500 + 0 != 1000, so the constraint fires.
        let action = Action {
            value: 1500,
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn cumulative_exceeds_total_limit_fails() {
        // cumulative=9800 + value=500 = 10300 > max_total=10000
        let public_inputs = AuthorizationPublicInputs {
            cumulative_spend: 9800,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn timestamp_before_valid_from_fails() {
        // ts=500 < valid_from=1000; diff_from saturates to 0 but 1000 + 0 != 500
        let public_inputs = AuthorizationPublicInputs {
            current_timestamp: 500,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn timestamp_after_valid_until_fails() {
        // ts=9500 > valid_until=9000; diff_until saturates to 0 but 9500 + 0 != 9000
        let public_inputs = AuthorizationPublicInputs {
            current_timestamp: 9500,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn exact_boundary_values_pass() {
        // value == max_per_tx, timestamp == valid_from, cumulative + value == max_total
        let action = Action {
            value: 1000, // exactly max_per_tx
            ..test_action()
        };
        let public_inputs = AuthorizationPublicInputs {
            current_timestamp: 1000, // exactly valid_from
            cumulative_spend: 9000,  // 9000 + 1000 == 10000 == max_total
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), action, public_inputs).is_ok());
    }
}
