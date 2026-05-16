# CATP WASM Bindings

This crate exposes the Halo2/off-chain `authorization_v1` helpers to
JavaScript:

- `compute_policy_commitment`
- `prove_authorization`
- `verify_authorization`

The generated `pkg/` directory is intentionally excluded from git. Build it as
a local package artifact when needed:

```bash
npm run wasm:build
```

CATP does not currently publish this as a `catp-wasm` package. The active
EVM/testnet path is `authorization_groth16_v1`, generated through the Go/Gnark
Groth16 prover under `catp-circuits/groth16` and the repository scripts.

The bindings embed `../authorization/catp-authorization-k12.srs`, which is suitable for
development and testnet consistency only. Mainnet Halo2 usage requires
documented SRS provenance or replacement with an accepted ceremony output.
