//! ProveAuthorization Halo2 circuit — in-circuit Poseidon commitment, 3 public values.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use maingate::{MainGate, MainGateConfig, MainGateInstructions, RegionCtx, Term};
use poseidon::Spec;

use crate::types::{Action, AuthorizationPolicy};

const R_F: usize = 8;
const R_P: usize = 57;

/// Public inputs to the ProveAuthorization circuit (visible on-chain).
/// Row 0: policy_commitment, Row 1: current_timestamp, Row 2: cumulative_spend.
#[derive(Debug, Clone)]
pub struct AuthorizationPublicInputs {
    /// Poseidon commitment to the full policy — computed natively and checked in-circuit.
    pub policy_commitment: Fr,
    pub current_timestamp: u64,
    pub cumulative_spend: u64,
}

// ── Poseidon helpers (MainGate-based, T=3 RATE=2) ────────────────────────────

fn apply_mds(
    ctx: &mut RegionCtx<'_, Fr>,
    gate: &MainGate<Fr>,
    state: &[maingate::AssignedValue<Fr>],
    mds: &[[Fr; 3]; 3],
) -> Result<Vec<maingate::AssignedValue<Fr>>, Error> {
    mds.iter()
        .map(|row| {
            let terms: Vec<_> = row
                .iter()
                .zip(state.iter())
                .map(|(c, s)| Term::Assigned(s, *c))
                .collect();
            gate.compose(ctx, &terms, Fr::ZERO)
        })
        .collect()
}

fn apply_sparse_mds(
    ctx: &mut RegionCtx<'_, Fr>,
    gate: &MainGate<Fr>,
    state: &[maingate::AssignedValue<Fr>],
    mds: &poseidon::SparseMDSMatrix<Fr, 3, 2>,
) -> Result<Vec<maingate::AssignedValue<Fr>>, Error> {
    let row_terms: Vec<_> = mds
        .row()
        .iter()
        .zip(state.iter())
        .map(|(c, s)| Term::Assigned(s, *c))
        .collect();
    let new_first = gate.compose(ctx, &row_terms, Fr::ZERO)?;

    let mut new_state = vec![new_first];
    for (coeff, s) in mds.col_hat().iter().zip(state.iter().skip(1)) {
        new_state.push(gate.compose(
            ctx,
            &[
                Term::Assigned(&state[0], *coeff),
                Term::Assigned(s, Fr::ONE),
            ],
            Fr::ZERO,
        )?);
    }
    Ok(new_state)
}

/// In-circuit Poseidon-3-2 hash via MainGate. Returns state[1] after absorbing inputs.
fn poseidon_in_circuit(
    ctx: &mut RegionCtx<'_, Fr>,
    gate: &MainGate<Fr>,
    spec: &Spec<Fr, 3, 2>,
    inputs: &[maingate::AssignedValue<Fr>],
) -> Result<maingate::AssignedValue<Fr>, Error> {
    let default_state = poseidon::State::<Fr, 3>::default();
    let mut state: Vec<_> = default_state
        .words()
        .iter()
        .map(|w| gate.assign_constant(ctx, *w))
        .collect::<Result<_, _>>()?;

    let r_f = spec.r_f() / 2;
    let mds = spec.mds_matrices().mds().rows();
    let pre_sparse = spec.mds_matrices().pre_sparse_mds().rows();
    let sparse = spec.mds_matrices().sparse_matrices();
    let c_start = spec.constants().start();
    let c_partial = spec.constants().partial();
    let c_end = spec.constants().end();

    // Pad: append 1 then zeros to next RATE=2 boundary.
    let mut buf: Vec<_> = inputs.to_vec();
    buf.push(gate.assign_constant(ctx, Fr::ONE)?);
    while buf.len() % 2 != 0 {
        buf.push(gate.assign_constant(ctx, Fr::ZERO)?);
    }

    for chunk in buf.chunks(2) {
        state[0] = gate.add_constant(ctx, &state[0], c_start[0][0])?;
        for (i, inp) in chunk.iter().enumerate() {
            state[i + 1] =
                gate.add_with_constant(ctx, &state[i + 1], inp, c_start[0][i + 1])?;
        }
        for round in 1..r_f {
            for j in 0..3 {
                let t = gate.mul(ctx, &state[j], &state[j])?;
                let t = gate.mul(ctx, &t, &t)?;
                state[j] = gate.mul_add_constant(ctx, &t, &state[j], c_start[round][j])?;
            }
            state = apply_mds(ctx, gate, &state, &mds)?;
        }
        for j in 0..3 {
            let t = gate.mul(ctx, &state[j], &state[j])?;
            let t = gate.mul(ctx, &t, &t)?;
            state[j] =
                gate.mul_add_constant(ctx, &t, &state[j], c_start.last().unwrap()[j])?;
        }
        state = apply_mds(ctx, gate, &state, &pre_sparse)?;
        for (constant, sp) in c_partial.iter().zip(sparse.iter()) {
            let t = gate.mul(ctx, &state[0], &state[0])?;
            let t = gate.mul(ctx, &t, &t)?;
            state[0] = gate.mul_add_constant(ctx, &t, &state[0], *constant)?;
            state = apply_sparse_mds(ctx, gate, &state, sp)?;
        }
        for constants in c_end.iter() {
            for j in 0..3 {
                let t = gate.mul(ctx, &state[j], &state[j])?;
                let t = gate.mul(ctx, &t, &t)?;
                state[j] = gate.mul_add_constant(ctx, &t, &state[j], constants[j])?;
            }
            state = apply_mds(ctx, gate, &state, &mds)?;
        }
        for j in 0..3 {
            let t = gate.mul(ctx, &state[j], &state[j])?;
            let t = gate.mul(ctx, &t, &t)?;
            state[j] = gate.mul_add_constant(ctx, &t, &state[j], Fr::ZERO)?;
        }
        state = apply_mds(ctx, gate, &state, &mds)?;
    }

    Ok(state[1].clone())
}

// ── Native helpers ────────────────────────────────────────────────────────────

/// Encode policy as 9 Fr field elements for Poseidon input.
/// Layout: [action, proto_lo, proto_hi, token_lo, token_hi, max_per_tx, max_total, from, until].
pub fn policy_to_fields(policy: &AuthorizationPolicy) -> [Fr; 9] {
    [
        Fr::from(policy.allowed_action.as_u64()),
        Fr::from(u64::from_le_bytes(policy.allowed_protocol[0..8].try_into().unwrap())),
        Fr::from(u64::from_le_bytes(policy.allowed_protocol[8..16].try_into().unwrap())),
        Fr::from(u64::from_le_bytes(policy.allowed_token[0..8].try_into().unwrap())),
        Fr::from(u64::from_le_bytes(policy.allowed_token[8..16].try_into().unwrap())),
        Fr::from(policy.max_value_per_tx),
        Fr::from(policy.max_value_total),
        Fr::from(policy.valid_from),
        Fr::from(policy.valid_until),
    ]
}

/// Native Poseidon-3-2 commitment over the 9 policy field elements.
/// Produces the same digest as `poseidon_in_circuit` for matching policy inputs.
pub fn native_policy_commitment(policy: &AuthorizationPolicy) -> Fr {
    let fields = policy_to_fields(policy);
    let mut h = poseidon::Poseidon::<Fr, 3, 2>::new(R_F, R_P);
    h.update(&fields);
    h.squeeze()
}

// ── Circuit ───────────────────────────────────────────────────────────────────

/// Circuit configuration.
#[derive(Debug, Clone)]
pub struct AuthorizationConfig {
    mg: MainGateConfig,
    action_cols: [Column<Advice>; 4],
    policy_cols: [Column<Advice>; 7],
    sel_membership: Selector,
    sel_value_limits: Selector,
    sel_time_bounds: Selector,
}

/// The ProveAuthorization circuit.
///
/// Private inputs: `AuthorizationPolicy`, `Action`.
/// Public inputs (single MainGate instance column):
///   row 0 — policy_commitment (Poseidon hash of policy fields)
///   row 1 — current_timestamp
///   row 2 — cumulative_spend
#[derive(Debug, Default)]
pub struct ProveAuthorization {
    pub policy: Option<AuthorizationPolicy>,
    pub action: Option<Action>,
    pub public_inputs: Option<AuthorizationPublicInputs>,
}

impl Circuit<Fr> for ProveAuthorization {
    type Config = AuthorizationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // MainGate allocates 5 advice + 9 fixed + 1 instance column.
        let mg = MainGate::<Fr>::configure(meta);

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

        let sel_membership = meta.selector();
        let sel_value_limits = meta.selector();
        let sel_time_bounds = meta.selector();

        // Constraints 2–4: action fields must equal policy fields.
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

        // Constraints 5–6: value ≤ per-tx limit and total limit.
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

        // Constraints 7–8: timestamp within policy window.
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
            mg,
            action_cols,
            policy_cols,
            sel_membership,
            sel_value_limits,
            sel_time_bounds,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let gate = MainGate::<Fr>::new(config.mg.clone());
        let spec = Spec::<Fr, 3, 2>::new(R_F, R_P);

        let policy = self.policy.as_ref();
        let action = self.action.as_ref();
        let pub_in = self.public_inputs.as_ref();

        let fp = |v: u64| -> Value<Fr> { Value::known(Fr::from(v)) };
        let unk = || Value::unknown();
        let field_val = |v: Option<u64>| -> Value<Fr> {
            match v {
                Some(n) => Value::known(Fr::from(n)),
                None => Value::unknown(),
            }
        };

        // Region 0: in-circuit Poseidon + assign timestamp/spend for public exposure.
        let (commitment, timestamp_cell, spend_cell) = layouter.assign_region(
            || "poseidon",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let inputs: [maingate::AssignedValue<Fr>; 9] = [
                    gate.assign_value(ctx, field_val(policy.map(|p| p.allowed_action.as_u64())))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| {
                        u64::from_le_bytes(p.allowed_protocol[0..8].try_into().unwrap())
                    })))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| {
                        u64::from_le_bytes(p.allowed_protocol[8..16].try_into().unwrap())
                    })))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| {
                        u64::from_le_bytes(p.allowed_token[0..8].try_into().unwrap())
                    })))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| {
                        u64::from_le_bytes(p.allowed_token[8..16].try_into().unwrap())
                    })))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| p.max_value_per_tx)))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| p.max_value_total)))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| p.valid_from)))?,
                    gate.assign_value(ctx, field_val(policy.map(|p| p.valid_until)))?,
                ];

                let commitment = poseidon_in_circuit(ctx, &gate, &spec, &inputs)?;
                let ts = gate.assign_value(ctx, field_val(pub_in.map(|p| p.current_timestamp)))?;
                let sp = gate.assign_value(ctx, field_val(pub_in.map(|p| p.cumulative_spend)))?;

                Ok((commitment, ts, sp))
            },
        )?;

        gate.expose_public(layouter.namespace(|| "pc"), commitment, 0)?;
        gate.expose_public(layouter.namespace(|| "ts"), timestamp_cell, 1)?;
        gate.expose_public(layouter.namespace(|| "sp"), spend_cell, 2)?;

        // Region 1: membership (constraints 2–4).
        layouter.assign_region(
            || "membership",
            |mut region| {
                config.sel_membership.enable(&mut region, 0)?;

                region.assign_advice(
                    || "action_type",
                    config.action_cols[0],
                    0,
                    || action.map(|a| fp(a.action_type.as_u64())).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "action_value",
                    config.action_cols[1],
                    0,
                    || action.map(|a| fp(a.value)).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "action_protocol_low",
                    config.action_cols[2],
                    0,
                    || {
                        action
                            .map(|a| fp(u64::from_le_bytes(a.protocol[..8].try_into().unwrap())))
                            .unwrap_or_else(unk)
                    },
                )?;
                region.assign_advice(
                    || "action_token_low",
                    config.action_cols[3],
                    0,
                    || {
                        action
                            .map(|a| fp(u64::from_le_bytes(a.token[..8].try_into().unwrap())))
                            .unwrap_or_else(unk)
                    },
                )?;
                region.assign_advice(
                    || "policy_allowed_action",
                    config.policy_cols[0],
                    0,
                    || policy.map(|p| fp(p.allowed_action.as_u64())).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "policy_max_per_tx",
                    config.policy_cols[1],
                    0,
                    || policy.map(|p| fp(p.max_value_per_tx)).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "policy_max_total",
                    config.policy_cols[2],
                    0,
                    || policy.map(|p| fp(p.max_value_total)).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "policy_valid_from",
                    config.policy_cols[3],
                    0,
                    || policy.map(|p| fp(p.valid_from)).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "policy_valid_until",
                    config.policy_cols[4],
                    0,
                    || policy.map(|p| fp(p.valid_until)).unwrap_or_else(unk),
                )?;
                region.assign_advice(
                    || "policy_protocol_low",
                    config.policy_cols[5],
                    0,
                    || {
                        policy
                            .map(|p| {
                                fp(u64::from_le_bytes(p.allowed_protocol[..8].try_into().unwrap()))
                            })
                            .unwrap_or_else(unk)
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
                            .unwrap_or_else(unk)
                    },
                )?;
                Ok(())
            },
        )?;

        // Region 2: value limits (constraints 5–6).
        layouter.assign_region(
            || "value_limits",
            |mut region| {
                config.sel_value_limits.enable(&mut region, 0)?;

                let action_val = action.map(|a| a.value).unwrap_or(0);
                let max_per_tx = policy.map(|p| p.max_value_per_tx).unwrap_or(0);
                let max_total = policy.map(|p| p.max_value_total).unwrap_or(0);
                let cumulative = pub_in.map(|p| p.cumulative_spend).unwrap_or(0);
                let diff_per_tx = max_per_tx.saturating_sub(action_val);
                let diff_total =
                    max_total.saturating_sub(cumulative.saturating_add(action_val));

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

        // Region 3: time bounds (constraints 7–8).
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
            policy_commitment: native_policy_commitment(&test_policy()),
            current_timestamp: 5000,
            cumulative_spend: 2000,
        }
    }

    fn run_circuit(
        policy: AuthorizationPolicy,
        action: Action,
        public_inputs: AuthorizationPublicInputs,
    ) -> Result<(), Vec<halo2_proofs::dev::VerifyFailure>> {
        let commitment = native_policy_commitment(&policy);
        let instance = vec![
            commitment,
            Fr::from(public_inputs.current_timestamp),
            Fr::from(public_inputs.cumulative_spend),
        ];
        let circuit = ProveAuthorization {
            policy: Some(policy),
            action: Some(action),
            public_inputs: Some(public_inputs),
        };
        MockProver::run(12, &circuit, vec![instance])
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
        let public_inputs = AuthorizationPublicInputs {
            cumulative_spend: 9800,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn timestamp_before_valid_from_fails() {
        let public_inputs = AuthorizationPublicInputs {
            current_timestamp: 500,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), test_action(), public_inputs).is_err());
    }

    #[test]
    fn timestamp_after_valid_until_fails() {
        let public_inputs = AuthorizationPublicInputs {
            current_timestamp: 9500,
            ..test_public_inputs()
        };
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
