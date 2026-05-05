//! ProveAuthorization Halo2 circuit — in-circuit Poseidon commitment, 13 public values.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::{bn256::Fr, ff::PrimeField};
use maingate::{MainGate, MainGateConfig, MainGateInstructions, RegionCtx, Term};
use poseidon::Spec;

use crate::types::{Action, AuthorizationPolicy};

const R_F: usize = 8;
const R_P: usize = 57;

/// Public inputs to the ProveAuthorization circuit (visible on-chain).
///
/// Rows:
/// 0 policy_commitment
/// 1 action_type
/// 2..5 action_protocol u64 little-endian limbs
/// 6..9 action_token u64 little-endian limbs
/// 10 action_value
/// 11 current_timestamp
/// 12 cumulative_spend
#[derive(Debug, Clone)]
pub struct AuthorizationPublicInputs {
    /// Poseidon commitment to the full policy — computed natively and checked in-circuit.
    pub policy_commitment: Fr,
    pub action_type: u64,
    pub action_protocol: [u64; 4],
    pub action_token: [u64; 4],
    pub action_value: u64,
    pub current_timestamp: u64,
    pub cumulative_spend: u64,
}

pub fn action_public_fields(action: &Action) -> (u64, [u64; 4], [u64; 4], u64) {
    let mut protocol = [0u64; 4];
    let mut token = [0u64; 4];
    for i in 0..4 {
        protocol[i] = u64::from_le_bytes(action.protocol[i * 8..(i + 1) * 8].try_into().unwrap());
        token[i] = u64::from_le_bytes(action.token[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    (action.action_type.as_u64(), protocol, token, action.value)
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
            state[i + 1] = gate.add_with_constant(ctx, &state[i + 1], inp, c_start[0][i + 1])?;
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
            state[j] = gate.mul_add_constant(ctx, &t, &state[j], c_start.last().unwrap()[j])?;
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

/// Encode policy as 13 Fr field elements for Poseidon input.
/// Layout: [action, proto[0..4], token[0..4], max_per_tx, max_total, from, until].
pub fn policy_to_fields(policy: &AuthorizationPolicy) -> [Fr; 13] {
    [
        Fr::from(policy.allowed_action.as_u64()),
        Fr::from(u64::from_le_bytes(
            policy.allowed_protocol[0..8].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_protocol[8..16].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_protocol[16..24].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_protocol[24..32].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_token[0..8].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_token[8..16].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_token[16..24].try_into().unwrap(),
        )),
        Fr::from(u64::from_le_bytes(
            policy.allowed_token[24..32].try_into().unwrap(),
        )),
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

/// Convert a BN254 Fr field element to 32 big-endian bytes (EVM `bytes32` format).
pub fn fr_to_be_bytes(fr: Fr) -> [u8; 32] {
    let le = fr.to_repr(); // [u8; 32] little-endian
    let mut be = [0u8; 32];
    for (i, b) in le.as_ref().iter().enumerate() {
        be[31 - i] = *b;
    }
    be
}

/// Parse 32 big-endian bytes back to Fr. Returns `None` if the value is out of field.
pub fn fr_from_be_bytes(be: &[u8; 32]) -> Option<Fr> {
    let mut le = [0u8; 32];
    for (i, b) in be.iter().enumerate() {
        le[31 - i] = *b;
    }
    Fr::from_repr(le.into()).into()
}

// ── Circuit ───────────────────────────────────────────────────────────────────

/// Circuit configuration.
#[derive(Debug, Clone)]
pub struct AuthorizationConfig {
    mg: MainGateConfig,
    action_cols: [Column<Advice>; 10],
    policy_cols: [Column<Advice>; 13],
    range_bit_col: Column<Advice>,
    range_acc_col: Column<Advice>,
    sel_membership: Selector,
    sel_value_limits: Selector,
    sel_time_bounds: Selector,
    sel_range: Selector,
    sel_bit: Selector,
}

/// The ProveAuthorization circuit.
///
/// Private inputs: `AuthorizationPolicy`, `Action`.
/// Public inputs (single MainGate instance column):
///   row 0 — policy_commitment (Poseidon hash of policy fields)
///   row 1 — action_type
///   rows 2..5 — action_protocol limbs
///   rows 6..9 — action_token limbs
///   row 10 — action_value
///   row 11 — current_timestamp
///   row 12 — cumulative_spend
#[derive(Debug, Default)]
pub struct ProveAuthorization {
    pub policy: Option<AuthorizationPolicy>,
    pub action: Option<Action>,
    pub public_inputs: Option<AuthorizationPublicInputs>,
}

fn range_check_u64(
    config: &AuthorizationConfig,
    region: &mut Region<'_, Fr>,
    start: usize,
    cell: &AssignedCell<Fr, Fr>,
    value: Option<u64>,
) -> Result<usize, Error> {
    let mut acc = 0u64;
    for i in 0..64 {
        config.sel_range.enable(region, start + i)?;
        config.sel_bit.enable(region, start + i)?;
        let shift = 63 - i;
        let bit = value.map(|v| (v >> shift) & 1);
        region.assign_advice(
            || format!("range_acc_{i}"),
            config.range_acc_col,
            start + i,
            || {
                value
                    .map(|_| Fr::from(acc))
                    .map(Value::known)
                    .unwrap_or_else(Value::unknown)
            },
        )?;
        region.assign_advice(
            || format!("range_bit_{i}"),
            config.range_bit_col,
            start + i,
            || {
                bit.map(Fr::from)
                    .map(Value::known)
                    .unwrap_or_else(Value::unknown)
            },
        )?;
        if let Some(b) = bit {
            acc = acc * 2 + b;
        }
    }

    cell.copy_advice(|| "range_value", region, config.range_acc_col, start + 64)?;
    Ok(start + 65)
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

        let action_cols = std::array::from_fn(|_| meta.advice_column());
        let policy_cols = std::array::from_fn(|_| meta.advice_column());
        let range_bit_col = meta.advice_column();
        let range_acc_col = meta.advice_column();
        for col in action_cols
            .iter()
            .chain(policy_cols.iter())
            .chain([range_acc_col].iter())
        {
            meta.enable_equality(*col);
        }

        let sel_membership = meta.selector();
        let sel_value_limits = meta.selector();
        let sel_time_bounds = meta.selector();
        let sel_range = meta.selector();
        let sel_bit = meta.selector();

        // Constraints 2–4: action fields must equal policy fields.
        meta.create_gate("membership checks", |meta| {
            let s = meta.query_selector(sel_membership);
            let action_type = meta.query_advice(action_cols[0], Rotation::cur());
            let policy_action = meta.query_advice(policy_cols[0], Rotation::cur());
            let mut constraints = vec![s.clone() * (action_type - policy_action)];
            for i in 0..4 {
                let action_proto = meta.query_advice(action_cols[2 + i], Rotation::cur());
                let policy_proto = meta.query_advice(policy_cols[5 + i], Rotation::cur());
                constraints.push(s.clone() * (action_proto - policy_proto));
            }
            for i in 0..4 {
                let action_token = meta.query_advice(action_cols[6 + i], Rotation::cur());
                let policy_token = meta.query_advice(policy_cols[9 + i], Rotation::cur());
                constraints.push(s.clone() * (action_token - policy_token));
            }
            constraints
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

        meta.create_gate("boolean range bit", |meta| {
            let s = meta.query_selector(sel_bit);
            let bit = meta.query_advice(range_bit_col, Rotation::cur());
            vec![s * bit.clone() * (bit - Expression::Constant(Fr::ONE))]
        });

        meta.create_gate("u64 accumulator", |meta| {
            let s = meta.query_selector(sel_range);
            let acc = meta.query_advice(range_acc_col, Rotation::cur());
            let next = meta.query_advice(range_acc_col, Rotation::next());
            let bit = meta.query_advice(range_bit_col, Rotation::cur());
            vec![s * (next - acc * Fr::from(2) - bit)]
        });

        AuthorizationConfig {
            mg,
            action_cols,
            policy_cols,
            range_bit_col,
            range_acc_col,
            sel_membership,
            sel_value_limits,
            sel_time_bounds,
            sel_range,
            sel_bit,
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

        // Region 0: in-circuit Poseidon + assign public inputs.
        let (commitment, timestamp_cell, spend_cell) = layouter.assign_region(
            || "poseidon",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let inputs: [maingate::AssignedValue<Fr>; 13] = [
                    gate.assign_value(ctx, field_val(policy.map(|p| p.allowed_action.as_u64())))?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_protocol[0..8].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_protocol[8..16].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_protocol[16..24].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_protocol[24..32].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_token[0..8].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_token[8..16].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_token[16..24].try_into().unwrap())
                        })),
                    )?,
                    gate.assign_value(
                        ctx,
                        field_val(policy.map(|p| {
                            u64::from_le_bytes(p.allowed_token[24..32].try_into().unwrap())
                        })),
                    )?,
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
        gate.expose_public(layouter.namespace(|| "ts"), timestamp_cell, 11)?;
        gate.expose_public(layouter.namespace(|| "sp"), spend_cell, 12)?;

        // Region 1: membership (constraints 2–4).
        let action_cells = layouter.assign_region(
            || "membership",
            |mut region| {
                config.sel_membership.enable(&mut region, 0)?;

                let action_type_cell = region.assign_advice(
                    || "action_type",
                    config.action_cols[0],
                    0,
                    || {
                        action
                            .map(|a| fp(a.action_type.as_u64()))
                            .unwrap_or_else(unk)
                    },
                )?;
                region.assign_advice(
                    || "action_value",
                    config.action_cols[1],
                    0,
                    || action.map(|a| fp(a.value)).unwrap_or_else(unk),
                )?;
                let mut public_cells = vec![action_type_cell];
                for i in 0..4 {
                    let cell = region.assign_advice(
                        || format!("action_protocol_{i}"),
                        config.action_cols[2 + i],
                        0,
                        || {
                            action
                                .map(|a| {
                                    fp(u64::from_le_bytes(
                                        a.protocol[i * 8..(i + 1) * 8].try_into().unwrap(),
                                    ))
                                })
                                .unwrap_or_else(unk)
                        },
                    )?;
                    public_cells.push(cell);
                }
                for i in 0..4 {
                    let cell = region.assign_advice(
                        || format!("action_token_{i}"),
                        config.action_cols[6 + i],
                        0,
                        || {
                            action
                                .map(|a| {
                                    fp(u64::from_le_bytes(
                                        a.token[i * 8..(i + 1) * 8].try_into().unwrap(),
                                    ))
                                })
                                .unwrap_or_else(unk)
                        },
                    )?;
                    public_cells.push(cell);
                }
                region.assign_advice(
                    || "policy_allowed_action",
                    config.policy_cols[0],
                    0,
                    || {
                        policy
                            .map(|p| fp(p.allowed_action.as_u64()))
                            .unwrap_or_else(unk)
                    },
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
                for i in 0..4 {
                    region.assign_advice(
                        || format!("policy_protocol_{i}"),
                        config.policy_cols[5 + i],
                        0,
                        || {
                            policy
                                .map(|p| {
                                    fp(u64::from_le_bytes(
                                        p.allowed_protocol[i * 8..(i + 1) * 8].try_into().unwrap(),
                                    ))
                                })
                                .unwrap_or_else(unk)
                        },
                    )?;
                }
                for i in 0..4 {
                    region.assign_advice(
                        || format!("policy_token_{i}"),
                        config.policy_cols[9 + i],
                        0,
                        || {
                            policy
                                .map(|p| {
                                    fp(u64::from_le_bytes(
                                        p.allowed_token[i * 8..(i + 1) * 8].try_into().unwrap(),
                                    ))
                                })
                                .unwrap_or_else(unk)
                        },
                    )?;
                }
                Ok(public_cells)
            },
        )?;
        for (i, cell) in action_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.mg.instance, i + 1)?;
        }

        // Region 2: value limits (constraints 5–6).
        let action_value_cell = layouter.assign_region(
            || "value_limits",
            |mut region| {
                config.sel_value_limits.enable(&mut region, 0)?;

                let action_val = action.map(|a| a.value).unwrap_or(0);
                let max_per_tx = policy.map(|p| p.max_value_per_tx).unwrap_or(0);
                let max_total = policy.map(|p| p.max_value_total).unwrap_or(0);
                let cumulative = pub_in.map(|p| p.cumulative_spend).unwrap_or(0);
                let diff_per_tx = max_per_tx.saturating_sub(action_val);
                let diff_total = max_total.saturating_sub(cumulative.saturating_add(action_val));

                let action_cell = region.assign_advice(
                    || "action_value",
                    config.action_cols[1],
                    0,
                    || fp(action_val),
                )?;
                let max_per_tx_cell = region.assign_advice(
                    || "max_per_tx",
                    config.policy_cols[1],
                    0,
                    || fp(max_per_tx),
                )?;
                let max_total_cell = region.assign_advice(
                    || "max_total",
                    config.policy_cols[2],
                    0,
                    || fp(max_total),
                )?;
                let diff_per_tx_cell = region.assign_advice(
                    || "diff_per_tx",
                    config.policy_cols[3],
                    0,
                    || fp(diff_per_tx),
                )?;
                let diff_total_cell = region.assign_advice(
                    || "diff_total",
                    config.policy_cols[4],
                    0,
                    || fp(diff_total),
                )?;
                let cumulative_cell = region.assign_advice(
                    || "cumulative",
                    config.action_cols[2],
                    0,
                    || fp(cumulative),
                )?;
                region.assign_advice(|| "_", config.action_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "_", config.action_cols[3], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[5], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[6], 0, || fp(0))?;
                let mut offset = 2;
                offset =
                    range_check_u64(&config, &mut region, offset, &action_cell, Some(action_val))?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &max_per_tx_cell,
                    Some(max_per_tx),
                )?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &max_total_cell,
                    Some(max_total),
                )?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &diff_per_tx_cell,
                    Some(diff_per_tx),
                )?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &diff_total_cell,
                    Some(diff_total),
                )?;
                let _ = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &cumulative_cell,
                    Some(cumulative),
                )?;
                Ok(action_cell)
            },
        )?;
        layouter.constrain_instance(action_value_cell.cell(), config.mg.instance, 10)?;

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

                let ts_cell =
                    region.assign_advice(|| "timestamp", config.action_cols[0], 0, || fp(ts))?;
                let diff_from_cell = region.assign_advice(
                    || "diff_from",
                    config.action_cols[1],
                    0,
                    || fp(diff_from),
                )?;
                let diff_until_cell = region.assign_advice(
                    || "diff_until",
                    config.action_cols[2],
                    0,
                    || fp(diff_until),
                )?;
                let valid_from_cell = region.assign_advice(
                    || "valid_from",
                    config.policy_cols[3],
                    0,
                    || fp(valid_from),
                )?;
                let valid_until_cell = region.assign_advice(
                    || "valid_until",
                    config.policy_cols[4],
                    0,
                    || fp(valid_until),
                )?;
                region.assign_advice(|| "_", config.action_cols[3], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[0], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[1], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[2], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[5], 0, || fp(0))?;
                region.assign_advice(|| "_", config.policy_cols[6], 0, || fp(0))?;
                let mut offset = 2;
                offset = range_check_u64(&config, &mut region, offset, &ts_cell, Some(ts))?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &diff_from_cell,
                    Some(diff_from),
                )?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &diff_until_cell,
                    Some(diff_until),
                )?;
                offset = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &valid_from_cell,
                    Some(valid_from),
                )?;
                let _ = range_check_u64(
                    &config,
                    &mut region,
                    offset,
                    &valid_until_cell,
                    Some(valid_until),
                )?;
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
        let (action_type, action_protocol, action_token, action_value) =
            action_public_fields(&test_action());
        AuthorizationPublicInputs {
            policy_commitment: native_policy_commitment(&test_policy()),
            action_type,
            action_protocol,
            action_token,
            action_value,
            current_timestamp: 5000,
            cumulative_spend: 2000,
        }
    }

    fn run_circuit(
        policy: AuthorizationPolicy,
        action: Action,
        public_inputs: AuthorizationPublicInputs,
    ) -> Result<(), Vec<halo2_proofs::dev::VerifyFailure>> {
        let mut instance = Vec::with_capacity(13);
        instance.push(public_inputs.policy_commitment);
        instance.push(Fr::from(public_inputs.action_type));
        instance.extend(public_inputs.action_protocol.iter().copied().map(Fr::from));
        instance.extend(public_inputs.action_token.iter().copied().map(Fr::from));
        instance.push(Fr::from(public_inputs.action_value));
        instance.push(Fr::from(public_inputs.current_timestamp));
        instance.push(Fr::from(public_inputs.cumulative_spend));
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
        let action = Action {
            action_type: ActionType::Transfer,
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_protocol_fails() {
        let action = Action {
            protocol: [9u8; 32],
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_protocol_suffix_fails() {
        let mut protocol = test_action().protocol;
        protocol[31] ^= 0x01;
        let action = Action {
            protocol,
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_token_fails() {
        let action = Action {
            token: [9u8; 32],
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn wrong_token_suffix_fails() {
        let mut token = test_action().token;
        token[31] ^= 0x01;
        let action = Action {
            token,
            ..test_action()
        };
        assert!(run_circuit(test_policy(), action, test_public_inputs()).is_err());
    }

    #[test]
    fn value_exceeds_per_tx_limit_fails() {
        let action = Action {
            value: 1500,
            ..test_action()
        };
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
        let action = Action {
            value: 1000,
            ..test_action()
        };
        let (action_type, action_protocol, action_token, action_value) =
            action_public_fields(&action);
        let public_inputs = AuthorizationPublicInputs {
            action_type,
            action_protocol,
            action_token,
            action_value,
            current_timestamp: 1000,
            cumulative_spend: 9000,
            ..test_public_inputs()
        };
        assert!(run_circuit(test_policy(), action, public_inputs).is_ok());
    }
}
