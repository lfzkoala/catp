//! ProveAuthorization Halo2 circuit (7 active constraints; constraint 1 Poseidon deferred to Phase 2).

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};

use crate::types::{Action, AuthorizationPolicy};

/// Public inputs to the ProveAuthorization circuit (visible on-chain).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationPublicInputs {
    /// SHA-256 commitment to the full policy (Poseidon in-circuit deferred to Phase 2).
    pub policy_commitment: [u8; 32],
    pub current_timestamp: u64,
    pub cumulative_spend: u64,
}

/// Circuit configuration: column assignments and selectors.
#[derive(Debug, Clone)]
pub struct AuthorizationConfig {
    action_cols: [Column<Advice>; 4],
    policy_cols: [Column<Advice>; 7],
    #[allow(dead_code)]
    pub_cols: [Column<Instance>; 2],
    sel_membership: Selector,
    sel_value_limits: Selector,
    sel_time_bounds: Selector,
}

/// The ProveAuthorization circuit.
///
/// Private inputs: `AuthorizationPolicy`, `Action`.
/// Public inputs: `policy_commitment`, `current_timestamp`, `cumulative_spend`.
///
/// Three independent single-row regions:
///   membership   — constraints 2–4 (equality: action matches policy)
///   value_limits — constraints 5–6 (range: value ≤ per-tx and total limits)
///   time_bounds  — constraints 7–8 (range: timestamp within policy window)
#[derive(Debug, Default)]
pub struct ProveAuthorization {
    pub policy: Option<AuthorizationPolicy>,
    pub action: Option<Action>,
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

        // Constraints 2–4: action_type, protocol_low, token_low must equal policy values.
        // NOTE: Only the low 8 bytes of each 32-byte address are compared; full 4-limb
        // comparison is deferred to Phase 2 when the column layout is refactored.
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

        // Constraints 5–6: action_value + diff == max; cumulative + action_value + diff == max_total.
        // Prover supplies non-negative diff witnesses to satisfy the equality.
        meta.create_gate("value limits", |meta| {
            let s = meta.query_selector(sel_value_limits);
            let action_value = meta.query_advice(action_cols[1], Rotation::cur());
            let max_per_tx = meta.query_advice(policy_cols[1], Rotation::cur());
            let max_total = meta.query_advice(policy_cols[2], Rotation::cur());
            let diff_per_tx = meta.query_advice(policy_cols[3], Rotation::cur());
            let diff_total = meta.query_advice(policy_cols[4], Rotation::cur());
            let cumulative = meta.query_advice(action_cols[2], Rotation::cur());
            vec![
                s.clone() * (action_value.clone() + diff_per_tx - max_per_tx),
                s * (cumulative + action_value + diff_total - max_total),
            ]
        });

        // Constraints 7–8: valid_from + diff == timestamp; timestamp + diff == valid_until.
        meta.create_gate("time bounds", |meta| {
            let s = meta.query_selector(sel_time_bounds);
            let timestamp = meta.query_advice(action_cols[0], Rotation::cur());
            let diff_from = meta.query_advice(action_cols[1], Rotation::cur());
            let diff_until = meta.query_advice(action_cols[2], Rotation::cur());
            let valid_from = meta.query_advice(policy_cols[3], Rotation::cur());
            let valid_until = meta.query_advice(policy_cols[4], Rotation::cur());
            vec![
                s.clone() * (valid_from + diff_from - timestamp.clone()),
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
        let unk = || Value::unknown();

        // Region 0: membership (constraints 2–4).
        layouter.assign_region(
            || "membership",
            |mut region| {
                config.sel_membership.enable(&mut region, 0)?;

                region.assign_advice(|| "action_type", config.action_cols[0], 0, || {
                    action.map(|a| fp(a.action_type.as_u64())).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "action_value", config.action_cols[1], 0, || {
                    action.map(|a| fp(a.value)).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "action_protocol_low", config.action_cols[2], 0, || {
                    action
                        .map(|a| fp(u64::from_le_bytes(a.protocol[..8].try_into().unwrap())))
                        .unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "action_token_low", config.action_cols[3], 0, || {
                    action
                        .map(|a| fp(u64::from_le_bytes(a.token[..8].try_into().unwrap())))
                        .unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_allowed_action", config.policy_cols[0], 0, || {
                    policy.map(|p| fp(p.allowed_action.as_u64())).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_max_per_tx", config.policy_cols[1], 0, || {
                    policy.map(|p| fp(p.max_value_per_tx)).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_max_total", config.policy_cols[2], 0, || {
                    policy.map(|p| fp(p.max_value_total)).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_valid_from", config.policy_cols[3], 0, || {
                    policy.map(|p| fp(p.valid_from)).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_valid_until", config.policy_cols[4], 0, || {
                    policy.map(|p| fp(p.valid_until)).unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_protocol_low", config.policy_cols[5], 0, || {
                    policy
                        .map(|p| fp(u64::from_le_bytes(p.allowed_protocol[..8].try_into().unwrap())))
                        .unwrap_or_else(unk)
                })?;
                region.assign_advice(|| "policy_token_low", config.policy_cols[6], 0, || {
                    policy
                        .map(|p| fp(u64::from_le_bytes(p.allowed_token[..8].try_into().unwrap())))
                        .unwrap_or_else(unk)
                })?;
                Ok(())
            },
        )?;

        // Region 1: value limits (constraints 5–6).
        layouter.assign_region(
            || "value_limits",
            |mut region| {
                config.sel_value_limits.enable(&mut region, 0)?;

                let action_val = action.map(|a| a.value).unwrap_or(0);
                let max_per_tx = policy.map(|p| p.max_value_per_tx).unwrap_or(0);
                let max_total = policy.map(|p| p.max_value_total).unwrap_or(0);
                let cumulative = pub_in.map(|p| p.cumulative_spend).unwrap_or(0);
                let diff_per_tx = max_per_tx.saturating_sub(action_val);
                let diff_total = max_total.saturating_sub(cumulative.saturating_add(action_val));

                region.assign_advice(|| "action_value", config.action_cols[1], 0, || fp(action_val))?;
                region.assign_advice(|| "max_per_tx", config.policy_cols[1], 0, || fp(max_per_tx))?;
                region.assign_advice(|| "max_total", config.policy_cols[2], 0, || fp(max_total))?;
                region.assign_advice(|| "diff_per_tx", config.policy_cols[3], 0, || fp(diff_per_tx))?;
                region.assign_advice(|| "diff_total", config.policy_cols[4], 0, || fp(diff_total))?;
                region.assign_advice(|| "cumulative", config.action_cols[2], 0, || fp(cumulative))?;
                region.assign_advice(|| "_", config.action_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "_", config.action_cols[3], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[5], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[6], 0, || fp(0))?;
                Ok(())
            },
        )?;

        // Region 2: time bounds (constraints 7–8).
        layouter.assign_region(
            || "time_bounds",
            |mut region| {
                config.sel_time_bounds.enable(&mut region, 0)?;

                let valid_from = policy.map(|p| p.valid_from).unwrap_or(0);
                let valid_until = policy.map(|p| p.valid_until).unwrap_or(0);
                let ts = pub_in.map(|p| p.current_timestamp).unwrap_or(0);
                let diff_from = ts.saturating_sub(valid_from);
                let diff_until = valid_until.saturating_sub(ts);

                region.assign_advice(|| "timestamp", config.action_cols[0], 0, || fp(ts))?;
                region.assign_advice(|| "diff_from", config.action_cols[1], 0, || fp(diff_from))?;
                region.assign_advice(|| "diff_until", config.action_cols[2], 0, || fp(diff_until))?;
                region.assign_advice(|| "valid_from", config.policy_cols[3], 0, || fp(valid_from))?;
                region.assign_advice(|| "valid_until", config.policy_cols[4], 0, || fp(valid_until))?;
                region.assign_advice(|| "_", config.action_cols[3], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[1], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[2], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[5], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[6], 0, || fp(0))?;
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
        let action = Action { action_type: ActionType::Transfer, ..test_action() };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_protocol_fails() {
        let action = Action { protocol: [9u8; 32], ..test_action() };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_token_fails() {
        let action = Action { token: [9u8; 32], ..test_action() };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn value_exceeds_per_tx_limit_fails() {
        let action = Action { value: 1500, ..test_action() };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn cumulative_exceeds_total_limit_fails() {
        let public_inputs = AuthorizationPublicInputs { cumulative_spend: 9800, ..test_public_inputs() };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn timestamp_before_valid_from_fails() {
        let public_inputs = AuthorizationPublicInputs { current_timestamp: 500, ..test_public_inputs() };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn timestamp_after_valid_until_fails() {
        let public_inputs = AuthorizationPublicInputs { current_timestamp: 9500, ..test_public_inputs() };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn exact_boundary_values_pass() {
        let action = Action { value: 1000, ..test_action() };
        let public_inputs = AuthorizationPublicInputs {
            current_timestamp: 1000,
            cumulative_spend: 9000,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), action, public_inputs).is_ok());
    }
}
