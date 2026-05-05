//! Probes the minimum k required for in-circuit Poseidon (MainGate-based) over
//! the 9 Fr elements that encode an AuthorizationPolicy.
//! Run: cargo test poseidon_probe -- --nocapture

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::bn256::Fr;
    use maingate::{MainGate, MainGateConfig, MainGateInstructions, RegionCtx, Term};
    use poseidon::Spec;

    const R_F: usize = 8;
    const R_P: usize = 57;
    const N_INPUTS: usize = 9; // 7 u64 policy fields + 2 extra limbs for 32-byte values

    // ── helpers ──────────────────────────────────────────────────────────────

    fn apply_mds<F, const T: usize>(
        ctx: &mut RegionCtx<'_, F>,
        gate: &MainGate<F>,
        state: &[maingate::AssignedValue<F>],
        mds: &[[F; T]; T],
    ) -> Result<Vec<maingate::AssignedValue<F>>, Error>
    where
        F: halo2curves::group::ff::PrimeField + std::fmt::Debug,
    {
        mds.iter()
            .map(|row| {
                let terms: Vec<_> = row
                    .iter()
                    .zip(state.iter())
                    .map(|(c, s)| Term::Assigned(s, *c))
                    .collect();
                gate.compose(ctx, &terms, F::ZERO)
            })
            .collect()
    }

    fn apply_sparse_mds<F, const T: usize, const RATE: usize>(
        ctx: &mut RegionCtx<'_, F>,
        gate: &MainGate<F>,
        state: &[maingate::AssignedValue<F>],
        mds: &poseidon::SparseMDSMatrix<F, T, RATE>,
    ) -> Result<Vec<maingate::AssignedValue<F>>, Error>
    where
        F: halo2curves::group::ff::PrimeField + std::fmt::Debug,
    {
        let row_terms: Vec<_> = mds
            .row()
            .iter()
            .zip(state.iter())
            .map(|(c, s)| Term::Assigned(s, *c))
            .collect();
        let new_first = gate.compose(ctx, &row_terms, F::ZERO)?;

        let mut new_state = vec![new_first];
        for (coeff, s) in mds.col_hat().iter().zip(state.iter().skip(1)) {
            new_state.push(gate.compose(
                ctx,
                &[
                    Term::Assigned(&state[0], *coeff),
                    Term::Assigned(s, F::ONE),
                ],
                F::ZERO,
            )?);
        }
        Ok(new_state)
    }

    /// In-circuit Poseidon hash via MainGate. Returns state[1] after absorbing inputs.
    fn poseidon_in_circuit<F, const T: usize, const RATE: usize>(
        ctx: &mut RegionCtx<'_, F>,
        gate: &MainGate<F>,
        spec: &Spec<F, T, RATE>,
        inputs: &[maingate::AssignedValue<F>],
    ) -> Result<maingate::AssignedValue<F>, Error>
    where
        F: halo2curves::group::ff::PrimeField
            + halo2curves::group::ff::FromUniformBytes<64>
            + std::fmt::Debug,
    {
        let default_state = poseidon::State::<F, T>::default();
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

        // Pad inputs: append 1 then zeros to next RATE boundary
        let mut buf: Vec<_> = inputs.to_vec();
        buf.push(gate.assign_constant(ctx, F::ONE)?);
        while buf.len() % RATE != 0 {
            buf.push(gate.assign_constant(ctx, F::ZERO)?);
        }

        for chunk in buf.chunks(RATE) {
            // absorb pre-constants
            state[0] = gate.add_constant(ctx, &state[0], c_start[0][0])?;
            for (i, inp) in chunk.iter().enumerate() {
                state[i + 1] = gate.add_with_constant(
                    ctx, &state[i + 1], inp, c_start[0][i + 1],
                )?;
            }
            // first r_f-1 full rounds
            for round in 1..r_f {
                for j in 0..T {
                    let t = gate.mul(ctx, &state[j], &state[j])?;
                    let t = gate.mul(ctx, &t, &t)?;
                    state[j] = gate.mul_add_constant(ctx, &t, &state[j], c_start[round][j])?;
                }
                state = apply_mds(ctx, gate, &state, &mds)?;
            }
            // transition to partial rounds
            for j in 0..T {
                let t = gate.mul(ctx, &state[j], &state[j])?;
                let t = gate.mul(ctx, &t, &t)?;
                state[j] = gate.mul_add_constant(
                    ctx, &t, &state[j], c_start.last().unwrap()[j],
                )?;
            }
            state = apply_mds(ctx, gate, &state, &pre_sparse)?;
            // partial rounds
            for (constant, sp) in c_partial.iter().zip(sparse.iter()) {
                let t = gate.mul(ctx, &state[0], &state[0])?;
                let t = gate.mul(ctx, &t, &t)?;
                state[0] = gate.mul_add_constant(ctx, &t, &state[0], *constant)?;
                state = apply_sparse_mds(ctx, gate, &state, sp)?;
            }
            // second half full rounds
            for constants in c_end.iter() {
                for j in 0..T {
                    let t = gate.mul(ctx, &state[j], &state[j])?;
                    let t = gate.mul(ctx, &t, &t)?;
                    state[j] = gate.mul_add_constant(ctx, &t, &state[j], constants[j])?;
                }
                state = apply_mds(ctx, gate, &state, &mds)?;
            }
            // final round (zero constants)
            for j in 0..T {
                let t = gate.mul(ctx, &state[j], &state[j])?;
                let t = gate.mul(ctx, &t, &t)?;
                state[j] = gate.mul_add_constant(ctx, &t, &state[j], F::ZERO)?;
            }
            state = apply_mds(ctx, gate, &state, &mds)?;
        }

        Ok(state[1].clone())
    }

    // ── probe circuit ────────────────────────────────────────────────────────

    struct ProbeCircuit<const T: usize, const RATE: usize> {
        inputs: [Fr; N_INPUTS],
        expected: Fr,
    }

    impl<const T: usize, const RATE: usize> ProbeCircuit<T, RATE>
    where
        Fr: halo2curves::group::ff::FromUniformBytes<64>,
    {
        fn new(inputs: [Fr; N_INPUTS]) -> Self {
            let mut h = poseidon::Poseidon::<Fr, T, RATE>::new(R_F, R_P);
            h.update(&inputs);
            let expected = h.squeeze();
            Self { inputs, expected }
        }
    }

    #[derive(Clone)]
    struct ProbeConfig {
        mg: MainGateConfig,
    }

    impl<const T: usize, const RATE: usize> Circuit<Fr> for ProbeCircuit<T, RATE>
    where
        Fr: halo2curves::group::ff::FromUniformBytes<64>,
    {
        type Config = ProbeConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { inputs: [Fr::zero(); N_INPUTS], expected: Fr::zero() }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            ProbeConfig { mg: MainGate::<Fr>::configure(meta) }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let gate = MainGate::<Fr>::new(config.mg.clone());
            let spec = Spec::<Fr, T, RATE>::new(R_F, R_P);

            let hash = layouter.assign_region(
                || "poseidon",
                |region| {
                    let ctx = &mut RegionCtx::new(region, 0);
                    let assigned: Vec<_> = self
                        .inputs
                        .iter()
                        .map(|v| gate.assign_constant(ctx, *v))
                        .collect::<Result<_, _>>()?;
                    poseidon_in_circuit::<Fr, T, RATE>(ctx, &gate, &spec, &assigned)
                },
            )?;

            gate.expose_public(layouter, hash, 0)
        }
    }

    fn probe_k<const T: usize, const RATE: usize>(k: u32) -> bool
    where
        Fr: halo2curves::group::ff::FromUniformBytes<64>,
    {
        let inputs = core::array::from_fn(|i| Fr::from((i + 1) as u64));
        let circuit = ProbeCircuit::<T, RATE>::new(inputs);
        let instance = vec![circuit.expected];
        // MockProver::run panics when usable_rows is exceeded; catch it so we
        // can iterate k upward without aborting the test thread.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MockProver::run(k, &circuit, vec![instance])
                .map(|p| p.verify().is_ok())
                .unwrap_or(false)
        }))
        .unwrap_or(false)
    }

    #[test]
    fn poseidon_probe_t5_rate4() {
        println!();
        for k in 8u32..=16 {
            let ok = probe_k::<5, 4>(k);
            println!("  T=5 RATE=4  k={k}: {}", if ok { "PASS ✓" } else { "too small" });
            if ok {
                return;
            }
        }
        panic!("T=5 RATE=4 needs k > 16");
    }

    #[test]
    fn poseidon_probe_t3_rate2() {
        println!();
        for k in 8u32..=16 {
            let ok = probe_k::<3, 2>(k);
            println!("  T=3 RATE=2  k={k}: {}", if ok { "PASS ✓" } else { "too small" });
            if ok {
                return;
            }
        }
        panic!("T=3 RATE=2 needs k > 16");
    }
}
